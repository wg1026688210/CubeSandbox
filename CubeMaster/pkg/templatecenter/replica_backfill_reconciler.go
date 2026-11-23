// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package templatecenter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/constants"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/db/models"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/log"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/node"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/service/sandbox/types"
)

// Template replica backfill sweep.
//
// WHY THIS EXISTS
// ---------------
// Distribution only ever ran at create/redo time, against the healthy-node
// set of THAT moment. Anything that changes the node set afterwards leaves
// replicas stale:
//
//   - a NEW cubelet node joins (Kubernetes clusters scale out routinely);
//   - a NotReady node recovers;
//   - a node's distribution RPC failed during the original push and the job
//     still went READY on partial success (distributionFailure only fails
//     the job when ZERO nodes came up).
//
// In all three cases the node ends up schedulable for the template's
// instance type but without the template's rootfs artifact, and nothing
// pushed it again -- the only escape was a manual redo. The TC split did not
// change this: TC builds, Master distributes, and Master's distribution set
// was still point-in-time.
//
// The sweep closes the gap: for every READY template definition it computes
// (healthy nodes in scope) MINUS (nodes holding a READY replica) and pushes
// the artifact to exactly the difference. Pushing alone only lands the
// ext4 image, so on the non-jfs branch the sweep then runs the same
// per-node AppSnapshot prepare the create/redo path uses and persists the
// outcome via UpsertReplica; the replica row converges to READY and the node
// becomes schedulable again. CreateImage is idempotent on the
// cubelet, the artifact URL is re-signed at push time, and the per-artifact
// resume lock dedups sweep passes in this process (the same lock table as
// the remote-build BUILT replay — but the keys do not always match, and a
// live in-process redo takes no lock at all, so interleavings are possible
// and converge via AppSnapshot's AlreadyExists semantics plus FAILED rows).
// The sweep runs inside the image-job reconcile pass (advisory lock already
// held), so a multi-master deployment sweeps once per tick, not once per
// master.

// backfillDefinition is the definition projection the sweep needs.
type backfillDefinition struct {
	TemplateID       string `gorm:"column:template_id"`
	InstanceType     string `gorm:"column:instance_type"`
	RootfsArtifactID string `gorm:"column:rootfs_artifact_id"`
}

// Seams so the orchestration is testable without a database or live nodes.
var (
	listBackfillDefinitions = func(ctx context.Context, limit int) ([]backfillDefinition, error) {
		var defs []backfillDefinition
		err := store.db.WithContext(ctx).
			Table(constants.TemplateDefinitionTableName).
			Select("template_id, instance_type, rootfs_artifact_id").
			Where("status = ?", StatusReady).
			Limit(limit).
			Find(&defs).Error
		return defs, err
	}
	backfillLatestJob = func(ctx context.Context, templateID string) (*models.TemplateImageJob, error) {
		return getLatestCreateRedoImageJobByTemplateIDTx(store.db.WithContext(ctx), templateID)
	}
	backfillArtifact        = getRootfsArtifactByID
	backfillReplicas        = ListReplicas
	backfillResolveNodes    = resolveTemplateNodes
	backfillDistribute      = distributeRootfsArtifactToNodes
	backfillPlacements      = listArtifactNodePlacements
	backfillCreateReplica   = createReplicaOnNode
	backfillUpsertReplica   = UpsertReplica
	backfillGetDefinition   = GetDefinition
	backfillCleanupReplicas = cleanupTemplateReplicasOnNodes
)

// reconcileTemplateReplicaBackfill pushes READY templates to healthy nodes
// that lack a READY replica. Runs inside the image-job reconcile pass.
func reconcileTemplateReplicaBackfill(ctx context.Context) error {
	if !isReady() {
		return nil
	}
	defs, err := listBackfillDefinitions(ctx, imageJobReconcileBatch)
	if err != nil {
		return fmt.Errorf("scan ready definitions: %w", err)
	}
	logger := log.G(ctx).WithFields(map[string]any{"component": "image_job_reconcile"})
	for _, def := range defs {
		if err := backfillTemplateReplicas(ctx, def); err != nil {
			// Per-template failures must not stop the pass; the next tick
			// retries this template anyway.
			logger.Warnf("template replica backfill: template=%s err=%v", def.TemplateID, err)
		}
	}
	return nil
}

// backfillTemplateReplicas distributes one template's artifact to the
// healthy in-scope nodes that do not already hold a READY replica.
func backfillTemplateReplicas(ctx context.Context, def backfillDefinition) error {
	job, err := backfillLatestJob(ctx, def.TemplateID)
	if err != nil {
		// No create/redo job: the definition predates job bookkeeping or the
		// job rows were cleaned. Nothing to derive the original request from,
		// so there is no safe way to reconstruct the distribution input.
		return fmt.Errorf("load latest create/redo job: %w", err)
	}
	artifactID := strings.TrimSpace(def.RootfsArtifactID)
	if artifactID == "" {
		artifactID = strings.TrimSpace(job.ArtifactID)
	}
	if artifactID == "" {
		return fmt.Errorf("no artifact reference on definition or job")
	}
	artifact, err := backfillArtifact(ctx, artifactID)
	if err != nil {
		return fmt.Errorf("load artifact %s: %w", artifactID, err)
	}
	if err := ensureArtifactDistributable(ctx, artifact); err != nil {
		return err
	}

	var req types.CreateTemplateFromImageReq
	if err := json.Unmarshal([]byte(job.RequestJSON), &req); err != nil {
		return fmt.Errorf("decode job request snapshot: %w", err)
	}
	// A jfs template is one package on the shared volume: nodes never build
	// their own replica, so replica rows say nothing about ext4 coverage and
	// nodesWithoutReadyReplica would flag every non-builder node forever.
	// The sweep still warms the ext4 cache for nodes that joined or
	// recovered after create: create-time distribution recorded an artifact
	// placement row per node, and only the in-scope nodes without one are
	// pushed here.
	if constants.IsJFSBackend(req.Backend) {
		if strings.TrimSpace(req.WritableLayerSize) == "" {
			req.WritableLayerSize = artifact.WritableLayerSize
		}
		instanceType := def.InstanceType
		if instanceType == "" {
			instanceType = req.InstanceType
		}
		targets, err := backfillResolveNodes(instanceType, req.DistributionScope)
		if err != nil {
			return err
		}
		placements, err := backfillPlacements(ctx, artifact.ArtifactID)
		if err != nil {
			return fmt.Errorf("list artifact placements: %w", err)
		}
		missing := nodesWithoutArtifactPlacement(placements, targets)
		if len(missing) == 0 {
			return nil
		}
		release := acquireResumeArtifactLock(artifact.ArtifactID)
		defer release()
		logger := log.G(ctx).WithFields(map[string]any{
			"component":   "image_job_reconcile",
			"template_id": def.TemplateID,
			"artifact_id": artifact.ArtifactID,
		})
		// trackReplicas=false: a placement push must not fabricate replica
		// rows on nodes that only hold the ext4 cache.
		_, _, ready, failed, distErr := backfillDistribute(ctx, &req, nil, artifact, def.TemplateID, job.JobID, missing, false)
		logger.Infof("jfs artifact backfill: %d node(s) missing the ext4 artifact, distributed ready=%d failed=%d err=%v",
			len(missing), ready, failed, distErr)
		return distErr
	}
	// The artifact row may be SHARED between templates (identical
	// fingerprint): GeneratedRequestJSON carries the FIRST builder's template
	// id and request, so rebuilding the per-template create request from THIS
	// job's request — the way redo does — keeps the AppSnapshot annotation
	// keyed to def.TemplateID. Reusing the artifact snapshot verbatim would
	// prepare (and mark READY) the wrong template on the node.
	var imageCfg DockerImageConfig
	if strings.TrimSpace(artifact.ImageConfigJSON) != "" {
		imageCfg, err = decodeImageConfigJSON(artifact.ImageConfigJSON)
		if err != nil {
			return fmt.Errorf("decode artifact image config: %w", err)
		}
	}
	if strings.TrimSpace(req.WritableLayerSize) == "" {
		req.WritableLayerSize = artifact.WritableLayerSize
	}
	req.TemplateID = def.TemplateID
	generatedReq, err := generateTemplateCreateRequest(ctx, withResolvedTemplateUser(&req, resolvedTemplateUserFromArtifact(artifact)), artifact, imageCfg, artifact.MasterNodeIP)
	if err != nil {
		return fmt.Errorf("generate template create request: %w", err)
	}
	generatedTemplateID := strings.TrimSpace(generatedReq.Annotations[constants.CubeAnnotationAppSnapshotTemplateID])
	if generatedTemplateID != def.TemplateID {
		return fmt.Errorf("generated template request id mismatch: got %q, want %q", generatedTemplateID, def.TemplateID)
	}

	instanceType := def.InstanceType
	if instanceType == "" {
		instanceType = req.InstanceType
	}
	targets, err := backfillResolveNodes(instanceType, req.DistributionScope)
	if err != nil {
		return err
	}
	replicas, err := backfillReplicas(ctx, def.TemplateID)
	if err != nil {
		return fmt.Errorf("list replicas: %w", err)
	}
	missing := nodesWithoutReadyReplica(replicas, targets)
	if len(missing) == 0 {
		return nil
	}

	// Best-effort dedup against the remote-build BUILT callback/replay (same
	// in-process lock table; the resume path keys it by TemplateSpecFingerprint
	// and a live in-process redo takes no lock, so treat interleavings as
	// possible and converge via AlreadyExists + FAILED rows).
	release := acquireResumeArtifactLock(artifact.ArtifactID)
	defer release()

	// The listing above predates the lock: a live redo of this template can
	// converge rows while we wait, and cleaning up or preparing from that
	// stale view could delete a fresh node package or clobber a fresh row.
	// Re-read and re-derive the work set under the lock.
	replicas, err = backfillReplicas(ctx, def.TemplateID)
	if err != nil {
		return fmt.Errorf("list replicas after resume lock: %w", err)
	}
	missing = nodesWithoutReadyReplica(replicas, targets)
	if len(missing) == 0 {
		return nil
	}

	logger := log.G(ctx).WithFields(map[string]any{
		"component":   "image_job_reconcile",
		"template_id": def.TemplateID,
		"artifact_id": artifact.ArtifactID,
	})
	// Last check before touching any node: a redo can switch the definition to
	// a new artifact mid-pass, and distributing/cleaning/preparing from this
	// stale view would delete the fresh package the redo just built (and the
	// READY row it wrote would leave the node silently broken). Skip the whole
	// pass; the next tick loads the new artifact. This narrows, not closes,
	// the window — the prepare-time recheck below still guards it.
	definition, err := backfillGetDefinition(ctx, def.TemplateID)
	if err != nil {
		if errors.Is(err, ErrTemplateNotFound) {
			return nil
		}
		return fmt.Errorf("recheck definition before cleanup: %w", err)
	}
	if want := strings.TrimSpace(definition.RootfsArtifactID); want != "" && want != artifact.ArtifactID {
		logger.Infof("template replica backfill: definition switched artifact (%s -> %s), skipping this pass", artifact.ArtifactID, want)
		return nil
	}
	readyTargets, _, ready, failed, distErr := backfillDistribute(ctx, &req, generatedReq, artifact, def.TemplateID, job.JobID, missing, true)
	logger.Infof("template replica backfill: %d node(s) missing a READY replica, distributed ready=%d failed=%d err=%v",
		len(missing), ready, failed, distErr)

	// Distribute only lands the artifact; stale rows (FAILED /
	// cleanup_required) mean leftover CoW state on the node, and AppSnapshot
	// refuses to overwrite it (AlreadyExists) — clear it the way redo does
	// first. Cubelet keeps the package when a live sandbox still restores
	// from it, in which case the prepare below fails again and the next
	// sweep retries.
	stale := make([]models.TemplateReplica, 0, len(replicas))
	for _, replica := range replicas {
		if replicaNeedsRedo(replica) {
			stale = append(stale, replica)
		}
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(ctx, backfillCleanupTimeout)
	defer cleanupCancel()
	if cerr := backfillCleanupReplicas(cleanupCtx, def.TemplateID, stale, readyTargets, storageBackendFromCreate(generatedReq)); cerr != nil {
		logger.Warnf("template replica backfill: cleanup stale replicas fail, template=%s err=%v", def.TemplateID, cerr)
	}
	// AppSnapshot takes tens of seconds per node; bound the concurrency so a
	// scale-out does not hold the cluster-wide reconcile lock serially for
	// minutes.
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var preparedMu sync.Mutex
	prepared := make([]ReplicaStatus, 0, len(readyTargets))
	for _, target := range readyTargets {
		target := target
		if target == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				return
			}
			replica, persisted := backfillPrepareReplicaOnNode(ctx, def, instanceType, artifact, job, target, generatedReq)
			if persisted && replica.Status == ReplicaStatusReady {
				preparedMu.Lock()
				prepared = append(prepared, replica)
				preparedMu.Unlock()
			}
		}()
	}
	wg.Wait()
	// Publish once for all freshly persisted READY rows. Per-goroutine
	// invalidate/register would stomp each other: InvalidateImageState wipes
	// the whole template's registrations, so only the last goroutine's node
	// would survive. Same order as refreshTemplateReplicaSummary: invalidate
	// first, then register.
	if len(prepared) > 0 {
		invalidateTemplateCaches(def.TemplateID)
		registerReadyTemplateReplicas(def.TemplateID, prepared)
	}
	return distErr
}

// backfillCleanupTimeout bounds one cleanup batch (one RPC per node,
// sequential) against a hung cubelet. shortcut: per-batch budget — a batch
// with more stale nodes than fit in 60s partially fails and is retried next
// tick; the real fix is a timeout on the CleanupTemplate RPC itself
// (cubelet/actions.go), which also covers the delete path.
const backfillCleanupTimeout = 60 * time.Second

// backfillPrepareReplicaOnNode runs the AppSnapshot prepare for one backfill
// target and persists the outcome via UpsertReplica, returning the replica
// and whether it was persisted. Failed prepares are persisted as FAILED rows
// and only logged: they do not abort the other targets and distErr keeps its
// contract. Before persisting, the definition is re-checked for every
// outcome: a DeleteTemplate landing mid-prepare must not be resurrected as a
// fresh READY row that the orphan reconciler (which only scans
// cleanup_required rows) would never reclaim, and a redo that switched the
// definition to a new artifact must not have its fresh row clobbered with
// our stale-artifact result.
func backfillPrepareReplicaOnNode(ctx context.Context, def backfillDefinition, instanceType string, artifact *models.RootfsArtifact, job *models.TemplateImageJob, target *node.Node, generatedReq *types.CreateCubeSandboxReq) (ReplicaStatus, bool) {
	logger := log.G(ctx).WithFields(map[string]any{
		"component":   "image_job_reconcile",
		"template_id": def.TemplateID,
		"artifact_id": artifact.ArtifactID,
	})
	replica, _ := backfillCreateReplica(ctx, target, def.TemplateID, generatedReq, replicaRunOptions{
		ArtifactID: artifact.ArtifactID,
		JobID:      job.JobID,
	})
	dropNodePackage := func() {
		dropCtx, cancel := context.WithTimeout(ctx, backfillCleanupTimeout)
		defer cancel()
		if cerr := backfillCleanupReplicas(dropCtx, def.TemplateID,
			[]models.TemplateReplica{{NodeID: replica.NodeID, NodeIP: replica.NodeIP}},
			[]*node.Node{target}, storageBackendFromCreate(generatedReq)); cerr != nil {
			logger.Warnf("template replica backfill: drop node package cleanup fail, node=%s err=%v", target.ID(), cerr)
		}
	}
	definition, err := backfillGetDefinition(ctx, def.TemplateID)
	if err != nil {
		if errors.Is(err, ErrTemplateNotFound) {
			// DeleteTemplate won the race: drop the just-created node
			// package and persist nothing, or it leaks on disk.
			if replica.Status == ReplicaStatusReady {
				dropNodePackage()
			}
			logger.Warnf("template replica backfill: definition gone mid-prepare, dropped node package, node=%s", target.ID())
		} else {
			logger.Warnf("template replica backfill: recheck definition before persist fail, node=%s err=%v", target.ID(), err)
		}
		return replica, false
	}
	if want := strings.TrimSpace(definition.RootfsArtifactID); want != "" && want != artifact.ArtifactID {
		// Redo switched the definition to a new artifact mid-prepare: our
		// package (if the prepare succeeded) belongs to the old artifact.
		// Drop it and persist nothing.
		if replica.Status == ReplicaStatusReady {
			dropNodePackage()
		}
		logger.Warnf("template replica backfill: definition points at artifact %s now, dropped stale prepare outcome, node=%s", want, target.ID())
		return replica, false
	}
	if upsertErr := backfillUpsertReplica(ctx, def.TemplateID, instanceType, replica); upsertErr != nil {
		logger.Warnf("template replica backfill: persist prepare result fail, node=%s err=%v", target.ID(), upsertErr)
		return replica, false
	}
	if replica.Status != ReplicaStatusReady {
		logger.Warnf("template replica backfill: prepare replica fail, node=%s err=%s", target.ID(), replica.ErrorMessage)
		return replica, false
	}
	return replica, true
}

// nodesWithoutReadyReplica returns the targets that do not hold a READY,
// clean replica for the template. A replica row needing redo (failed, or
// marked cleanup_required by an interrupted delete) counts as missing so the
// sweep also repairs half-cleaned nodes.
func nodesWithoutReadyReplica(replicas []models.TemplateReplica, targets []*node.Node) []*node.Node {
	ready := make(map[string]struct{}, len(replicas)*2)
	for _, replica := range replicas {
		if replicaNeedsRedo(replica) {
			continue
		}
		if id := strings.TrimSpace(replica.NodeID); id != "" {
			ready[id] = struct{}{}
		}
		if ip := strings.TrimSpace(replica.NodeIP); ip != "" {
			ready[ip] = struct{}{}
		}
	}
	missing := make([]*node.Node, 0, len(targets))
	for _, target := range targets {
		if target == nil {
			continue
		}
		if _, ok := ready[target.ID()]; ok {
			continue
		}
		if _, ok := ready[target.HostIP()]; ok {
			continue
		}
		missing = append(missing, target)
	}
	return missing
}

// nodesWithoutArtifactPlacement returns the in-scope targets without a
// recorded ext4 placement for the artifact. jfs uses this instead of
// nodesWithoutReadyReplica: replica rows mean "built the shared package"
// there, so coverage is tracked by the placement rows distribution writes.
func nodesWithoutArtifactPlacement(placements []models.ArtifactNodePlacement, targets []*node.Node) []*node.Node {
	have := make(map[string]struct{}, len(placements)*2)
	for _, placement := range placements {
		if id := strings.TrimSpace(placement.NodeID); id != "" {
			have[id] = struct{}{}
		}
		if ip := strings.TrimSpace(placement.NodeIP); ip != "" {
			have[ip] = struct{}{}
		}
	}
	missing := make([]*node.Node, 0, len(targets))
	for _, target := range targets {
		if target == nil {
			continue
		}
		if _, ok := have[target.ID()]; ok {
			continue
		}
		if _, ok := have[target.HostIP()]; ok {
			continue
		}
		missing = append(missing, target)
	}
	return missing
}
