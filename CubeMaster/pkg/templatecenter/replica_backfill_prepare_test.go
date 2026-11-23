// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package templatecenter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/constants"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/db/models"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/node"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/localcache"
	sandboxtypes "github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/service/sandbox/types"
)

// The replica-backfill sweep must not stop at DISTRIBUTED: after a successful
// CreateImage push to a node without a READY replica, the non-jfs branch must
// run the AppSnapshot step on every ready target and persist the outcome via
// UpsertReplica so the row converges to READY. jfs stays placement-only and
// must never run AppSnapshot.
//
// Every collaborator the sweep touches is a package-level seam (the same
// style as backfillDistribute/backfillReplicas); the tests observe the calls
// through recorders, no gomonkey.

type backfillPrepareFixture struct {
	job        *models.TemplateImageJob
	artifact   *models.RootfsArtifact
	nodes      []*node.Node
	replicas   []models.TemplateReplica
	placements []models.ArtifactNodePlacement

	// distribute behavior
	distFailed int32
	distErr    error

	// createReplicaOnNode (AppSnapshot) behavior: nodeID -> failure message
	snapshotErrByNode map[string]string

	// upsert behavior
	upsertErr error

	// definition recheck behavior: nil = found; RootfsArtifactID on the returned row
	definitionErr        error
	definitionErrAfter   int // >0: return definitionErr only from this call index (0-based)
	definitionArtifactID string
	// per-call RootfsArtifactID sequence (last value repeats), simulating a
	// redo that switches the artifact between the pre-cleanup and pre-persist
	// rechecks
	definitionArtifactIDs []string
	definitionCalls       int

	// when set, backfillReplicas pops one entry per call (simulates rows
	// changing between the pre-lock listing and the post-lock re-list)
	replicasSeq     [][]models.TemplateReplica
	replicasSeqCall int

	// cleanup behavior
	cleanupErr error

	mu            sync.Mutex
	events        []string // "cleanup" / "snapshot:<node>" / "defcheck" — call order
	distCalls     []backfillDistributeCall
	snapshotCalls []backfillSnapshotCall
	upserts       []backfillUpsertCall
	cleanups      []backfillCleanupCall
}

type backfillSnapshotCall struct {
	nodeID       string
	templateID   string
	instanceType string
	annotationID string
	artifactID   string
	jobID        string
}

type backfillUpsertCall struct {
	templateID   string
	instanceType string
	replica      ReplicaStatus
}

type backfillCleanupCall struct {
	templateID string
	replicas   []models.TemplateReplica
	targets    []*node.Node
}

func (f *backfillPrepareFixture) record(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

// newBackfillPrepareFixture builds the standard non-jfs (xfs) job/artifact
// pair: a READY servable artifact with a generated request snapshot left by
// the FIRST builder (tpl-other) — the sweep must derive its own per-template
// request and not reuse that snapshot.
func newBackfillPrepareFixture(t *testing.T, backend string) *backfillPrepareFixture {
	t.Helper()
	raw, err := json.Marshal(&sandboxtypes.CreateTemplateFromImageReq{
		Request:      &sandboxtypes.Request{RequestID: "req-1"},
		Backend:      backend,
		InstanceType: "cubebox",
	})
	if err != nil {
		t.Fatalf("marshal job request: %v", err)
	}
	// Simulates an artifact row SHARED with an earlier template: the persisted
	// generated request carries tpl-other's template id and request.
	genRaw, err := json.Marshal(&sandboxtypes.CreateCubeSandboxReq{
		Annotations: map[string]string{
			constants.CubeAnnotationAppSnapshotTemplateID: "tpl-other",
		},
	})
	if err != nil {
		t.Fatalf("marshal generated request: %v", err)
	}
	imageCfgRaw, err := json.Marshal(&DockerImageConfig{
		Entrypoint: []string{"/bin/sh"},
		Cmd:        []string{"-c", "sleep 1"},
	})
	if err != nil {
		t.Fatalf("marshal image config: %v", err)
	}
	return &backfillPrepareFixture{
		job: &models.TemplateImageJob{JobID: "job-1", RequestJSON: string(raw)},
		artifact: &models.RootfsArtifact{
			ArtifactID:           "rfs-xfs-1",
			Status:               ArtifactStatusReady,
			Ext4SHA256:           "deadbeef",
			Ext4SizeBytes:        1024,
			DownloadToken:        "tok",
			MasterNodeIP:         "http://cube-master:8089",
			ImageConfigJSON:      string(imageCfgRaw),
			WritableLayerSize:    "4Gi",
			GeneratedRequestJSON: string(genRaw),
		},
	}
}

// stub swaps every seam the sweep touches and restores them on cleanup. The
// real generateTemplateCreateRequest still runs, so the tests exercise the
// per-template request derivation (shared artifacts included).
func (f *backfillPrepareFixture) stub(t *testing.T) {
	t.Helper()
	stubRemoteTier(t, true, servableProbe(http.StatusPartialContent, f.artifact.ArtifactID))

	origJob, origArt, origRepl, origResolve, origPlace, origDist :=
		backfillLatestJob, backfillArtifact, backfillReplicas, backfillResolveNodes, backfillPlacements, backfillDistribute
	origCreate, origUpsert, origDef, origCleanup :=
		backfillCreateReplica, backfillUpsertReplica, backfillGetDefinition, backfillCleanupReplicas
	t.Cleanup(func() {
		backfillLatestJob, backfillArtifact, backfillReplicas, backfillResolveNodes, backfillPlacements, backfillDistribute =
			origJob, origArt, origRepl, origResolve, origPlace, origDist
		backfillCreateReplica, backfillUpsertReplica, backfillGetDefinition, backfillCleanupReplicas =
			origCreate, origUpsert, origDef, origCleanup
	})
	backfillLatestJob = func(context.Context, string) (*models.TemplateImageJob, error) { return f.job, nil }
	backfillArtifact = func(context.Context, string) (*models.RootfsArtifact, error) { return f.artifact, nil }
	backfillReplicas = func(context.Context, string) ([]models.TemplateReplica, error) {
		if f.replicasSeq != nil {
			i := f.replicasSeqCall
			f.replicasSeqCall++
			if i >= len(f.replicasSeq) {
				return nil, nil
			}
			return f.replicasSeq[i], nil
		}
		return f.replicas, nil
	}
	backfillResolveNodes = func(string, []string) ([]*node.Node, error) { return f.nodes, nil }
	backfillPlacements = func(context.Context, string) ([]models.ArtifactNodePlacement, error) {
		return f.placements, nil
	}
	backfillDistribute = func(ctx context.Context, req *sandboxtypes.CreateTemplateFromImageReq, generatedReq *sandboxtypes.CreateCubeSandboxReq, art *models.RootfsArtifact, templateID, jobID string, targets []*node.Node, trackReplicas bool) ([]*node.Node, int32, int32, int32, error) {
		f.mu.Lock()
		f.distCalls = append(f.distCalls, backfillDistributeCall{
			targets:       targets,
			trackReplicas: trackReplicas,
			generatedReq:  generatedReq,
		})
		f.mu.Unlock()
		return targets, int32(len(targets)), int32(len(targets)), f.distFailed, f.distErr
	}
	backfillCreateReplica = func(_ context.Context, target *node.Node, templateID string, req *sandboxtypes.CreateCubeSandboxReq, opts replicaRunOptions) (ReplicaStatus, string) {
		f.record("snapshot:" + target.ID())
		f.mu.Lock()
		defer f.mu.Unlock()
		f.snapshotCalls = append(f.snapshotCalls, backfillSnapshotCall{
			nodeID:       target.ID(),
			templateID:   templateID,
			instanceType: req.InstanceType,
			annotationID: req.Annotations[constants.CubeAnnotationAppSnapshotTemplateID],
			artifactID:   opts.ArtifactID,
			jobID:        opts.JobID,
		})
		replica := ReplicaStatus{
			NodeID:       target.ID(),
			NodeIP:       target.HostIP(),
			InstanceType: req.InstanceType,
			ArtifactID:   opts.ArtifactID,
			LastJobID:    opts.JobID,
		}
		if msg := f.snapshotErrByNode[target.ID()]; msg != "" {
			replica.Status = ReplicaStatusFailed
			replica.Phase = ReplicaPhaseFailed
			replica.LastErrorPhase = ReplicaPhaseFailed
			replica.CleanupRequired = true
			replica.ErrorMessage = msg
			return replica, ""
		}
		replica.Status = ReplicaStatusReady
		replica.Phase = ReplicaPhaseReady
		replica.CleanupRequired = false
		return replica, ""
	}
	backfillUpsertReplica = func(_ context.Context, templateID, instanceType string, replica ReplicaStatus) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.upserts = append(f.upserts, backfillUpsertCall{templateID: templateID, instanceType: instanceType, replica: replica})
		return f.upsertErr
	}
	backfillGetDefinition = func(context.Context, string) (*models.TemplateDefinition, error) {
		f.record("defcheck")
		call := f.definitionCalls
		f.definitionCalls++
		if f.definitionErr != nil && call >= f.definitionErrAfter {
			return nil, f.definitionErr
		}
		id := f.definitionArtifactID
		if len(f.definitionArtifactIDs) > 0 {
			i := call
			if i >= len(f.definitionArtifactIDs) {
				i = len(f.definitionArtifactIDs) - 1
			}
			id = f.definitionArtifactIDs[i]
		}
		return &models.TemplateDefinition{RootfsArtifactID: id}, nil
	}
	backfillCleanupReplicas = func(_ context.Context, templateID string, replicas []models.TemplateReplica, targets []*node.Node, backend string) error {
		f.record("cleanup")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.cleanups = append(f.cleanups, backfillCleanupCall{templateID: templateID, replicas: replicas, targets: targets})
		return f.cleanupErr
	}
}

func (f *backfillPrepareFixture) eventsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *backfillPrepareFixture) upsertsSnapshot() []backfillUpsertCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]backfillUpsertCall(nil), f.upserts...)
}

// Normal path: a node missing its replica gets CreateImage (distribute), then
// the AppSnapshot prepare step, and the persisted row is READY/READY.
func TestBackfillPrepareReplicaReadyAfterDistribute(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.distCalls) != 1 || !f.distCalls[0].trackReplicas {
		t.Fatalf("distribute calls = %+v, want 1 call with trackReplicas=true", f.distCalls)
	}
	if len(f.snapshotCalls) != 1 {
		t.Fatalf("AppSnapshot calls = %d, want 1 (the sweep must prepare the replica after CreateImage)", len(f.snapshotCalls))
	}
	call := f.snapshotCalls[0]
	if call.nodeID != "node-a" || call.templateID != "tpl-1" || call.instanceType != "cubebox" ||
		call.artifactID != f.artifact.ArtifactID || call.jobID != "job-1" {
		t.Fatalf("AppSnapshot call = %+v, want node-a/tpl-1/cubebox/rfs-xfs-1/job-1", call)
	}
	if call.annotationID != "tpl-1" {
		t.Fatalf("AppSnapshot annotation template id = %q, want tpl-1 (derived from THIS template, not the artifact snapshot)", call.annotationID)
	}
	if len(f.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1", len(f.upserts))
	}
	up := f.upserts[0]
	if up.templateID != "tpl-1" || up.instanceType != "cubebox" {
		t.Fatalf("upsert keys = %q/%q, want tpl-1/cubebox", up.templateID, up.instanceType)
	}
	r := up.replica
	if r.NodeID != "node-a" || r.Status != ReplicaStatusReady || r.Phase != ReplicaPhaseReady {
		t.Fatalf("replica = %+v, want node-a Status=READY Phase=READY", r)
	}
	if r.CleanupRequired {
		t.Fatalf("a READY replica must not be cleanup_required: %+v", r)
	}
	if r.ErrorMessage != "" {
		t.Fatalf("a READY replica must carry no error message: %+v", r)
	}
}

// A SHARED artifact (identical fingerprint, first builder tpl-other) must
// still prepare the sweep's OWN template: the AppSnapshot annotation and the
// distribute/upsert keys all carry def.TemplateID, never the artifact
// snapshot's. This is the data-corruption case from review: reusing
// GeneratedRequestJSON marked T2 READY while recreating T1 on disk.
func TestBackfillSharedArtifactUsesOwnTemplateID(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-2", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.distCalls) != 1 {
		t.Fatalf("distribute calls = %d, want 1", len(f.distCalls))
	}
	if got := f.distCalls[0].generatedReq.Annotations[constants.CubeAnnotationAppSnapshotTemplateID]; got != "tpl-2" {
		t.Fatalf("distribute generated request annotation = %q, want tpl-2", got)
	}
	if len(f.snapshotCalls) != 1 {
		t.Fatalf("AppSnapshot calls = %d, want 1", len(f.snapshotCalls))
	}
	if got := f.snapshotCalls[0].annotationID; got != "tpl-2" {
		t.Fatalf("AppSnapshot annotation = %q, want tpl-2 (the artifact snapshot says tpl-other)", got)
	}
	upserts := f.upsertsSnapshot()
	if len(upserts) != 1 || upserts[0].templateID != "tpl-2" {
		t.Fatalf("upserts = %+v, want one row keyed tpl-2", upserts)
	}
}

// AppSnapshot failure: the FAILED outcome is persisted with an error message,
// is not fatal to the sweep, and the node stays in the missing set so the
// next tick retries it.
func TestBackfillPrepareReplicaFailureRecordedAndRetried(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.snapshotErrByNode = map[string]string{"node-a": "appsnapshot exploded"}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("a failed AppSnapshot must be recorded, not returned as a sweep error: %v", err)
	}
	if len(f.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1", len(f.upserts))
	}
	r := f.upserts[0].replica
	if r.Status != ReplicaStatusFailed || r.ErrorMessage == "" {
		t.Fatalf("failed prepare must upsert Status=FAILED with an error message, got %+v", r)
	}

	// Next sweep: the FAILED row (as replicaNeedsRedo sees it) leaves the node
	// in the missing set, so the push AND the prepare run again.
	f.replicas = []models.TemplateReplica{{NodeID: "node-a", NodeIP: "10.0.0.1", Status: ReplicaStatusFailed, Phase: ReplicaPhaseFailed}}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("retry sweep: %v", err)
	}
	if len(f.distCalls) != 2 {
		t.Fatalf("distribute calls = %d, want 2 (failed node retried next sweep)", len(f.distCalls))
	}
	if got := f.distCalls[1].targets; len(got) != 1 || got[0].ID() != "node-a" {
		t.Fatalf("retry targets = %v, want [node-a]", got)
	}
	if len(f.snapshotCalls) != 2 {
		t.Fatalf("AppSnapshot calls = %d, want 2 (retried node is prepared again)", len(f.snapshotCalls))
	}
}

// A node holding a READY clean replica is skipped entirely: no CreateImage,
// no AppSnapshot, no upsert. Guards the existing behavior against the fix.
func TestBackfillSkipsNodeWithReadyReplica(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.replicas = []models.TemplateReplica{{NodeID: "node-a", NodeIP: "10.0.0.1", Status: ReplicaStatusReady}}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.distCalls) != 0 || len(f.snapshotCalls) != 0 || len(f.upserts) != 0 {
		t.Fatalf("READY replica must skip distribute/appsnapshot/upsert, got dist=%d snap=%d upsert=%d",
			len(f.distCalls), len(f.snapshotCalls), len(f.upserts))
	}
}

// A replica stuck at Status=FAILED Phase=DISTRIBUTED (CreateImage succeeded,
// AppSnapshot never ran) counts as missing, so the sweep re-pushes AND
// prepares it — and this time the row must converge to READY instead of
// looping back to DISTRIBUTED.
func TestBackfillRedoesStaleDistributedReplica(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.replicas = []models.TemplateReplica{{
		NodeID: "node-a", NodeIP: "10.0.0.1",
		Status: ReplicaStatusFailed, Phase: ReplicaPhaseDistributed,
	}}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.distCalls) != 1 {
		t.Fatalf("stale DISTRIBUTED replica must be re-pushed, distribute calls = %d", len(f.distCalls))
	}
	if len(f.snapshotCalls) != 1 {
		t.Fatalf("stale DISTRIBUTED replica must get the AppSnapshot prepare step, calls = %d", len(f.snapshotCalls))
	}
	upserts := f.upsertsSnapshot()
	if len(upserts) != 1 || upserts[0].replica.Status != ReplicaStatusReady || upserts[0].replica.Phase != ReplicaPhaseReady {
		t.Fatalf("upserts = %+v, want one READY/READY row (converges instead of looping)", upserts)
	}

	// And the loop is actually broken: with the READY row in place the next
	// sweep pushes nothing.
	f.replicas = []models.TemplateReplica{{NodeID: "node-a", NodeIP: "10.0.0.1", Status: ReplicaStatusReady, Phase: ReplicaPhaseReady}}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("converged sweep: %v", err)
	}
	if len(f.distCalls) != 1 {
		t.Fatalf("after convergence distribute calls = %d, want still 1 (no redistribute loop)", len(f.distCalls))
	}
}

// Leftover CoW state (a FAILED / cleanup_required row means volumes are still
// on the node, and cubelet's AppSnapshot refuses AlreadyExists forever): the
// sweep must run the redo-style cleanup BEFORE the prepare, and hand the
// stale rows to it.
func TestBackfillCleanupStaleReplicasBeforePrepare(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	stale := models.TemplateReplica{
		NodeID: "node-a", NodeIP: "10.0.0.1",
		Status: ReplicaStatusFailed, Phase: ReplicaPhaseFailed, CleanupRequired: true,
	}
	f.replicas = []models.TemplateReplica{stale}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	events := f.eventsSnapshot()
	// defcheck (pre-cleanup artifact guard) -> cleanup -> prepare.
	if len(events) < 3 || events[0] != "defcheck" || events[1] != "cleanup" || events[2] != "snapshot:node-a" {
		t.Fatalf("call order = %v, want defcheck before cleanup before snapshot:node-a", events)
	}
	if len(f.cleanups) != 1 {
		t.Fatalf("cleanups = %d, want 1", len(f.cleanups))
	}
	cl := f.cleanups[0]
	if cl.templateID != "tpl-1" || len(cl.replicas) != 1 || cl.replicas[0].NodeID != "node-a" {
		t.Fatalf("cleanup call = %+v, want tpl-1 with the stale node-a row", cl)
	}
	if len(f.snapshotCalls) != 1 {
		t.Fatalf("AppSnapshot calls = %d, want 1 (prepare still runs after cleanup)", len(f.snapshotCalls))
	}
}

// A cleanup failure must not block the prepare: the prepare still runs and
// its outcome is persisted. (The cleanup-failure + prepare-failure combo —
// the FAILED row landing despite cleanup failing — is covered by
// TestBackfillPrepareReplicaFailureRecordedAndRetried.)
func TestBackfillCleanupErrorDoesNotBlockPrepare(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.replicas = []models.TemplateReplica{{
		NodeID: "node-a", NodeIP: "10.0.0.1",
		Status: ReplicaStatusFailed, CleanupRequired: true,
	}}
	f.cleanupErr = errors.New("cleanup rpc failed")
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("a cleanup failure must be logged, not returned: %v", err)
	}
	if len(f.snapshotCalls) != 1 {
		t.Fatalf("AppSnapshot calls = %d, want 1 despite cleanup failure", len(f.snapshotCalls))
	}
	upserts := f.upsertsSnapshot()
	if len(upserts) != 1 || upserts[0].replica.Status != ReplicaStatusReady {
		t.Fatalf("upserts = %+v, want one READY row", upserts)
	}
}

// jfs: the sweep stays on the placement path (trackReplicas=false) and must
// NEVER run the AppSnapshot prepare step or write replica rows.
func TestBackfillJFSNeverRunsAppSnapshot(t *testing.T) {
	f := newBackfillPrepareFixture(t, "jfs")
	f.nodes = []*node.Node{
		testNode("node-a", "10.0.0.1"),
		testNode("node-new", "10.0.0.4"),
	}
	f.placements = []models.ArtifactNodePlacement{
		{ArtifactID: f.artifact.ArtifactID, NodeID: "node-a", NodeIP: "10.0.0.1", InstanceType: "cubebox"},
	}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.distCalls) != 1 || f.distCalls[0].trackReplicas {
		t.Fatalf("jfs sweep must distribute once with trackReplicas=false, got %+v", f.distCalls)
	}
	if len(f.snapshotCalls) != 0 || len(f.upserts) != 0 {
		t.Fatalf("jfs sweep must never run AppSnapshot or write replica rows, snap=%d upsert=%d",
			len(f.snapshotCalls), len(f.upserts))
	}
}

// Two missing nodes, one AppSnapshot failure: the other node's replica still
// converges to READY, the failure is persisted for the bad node, the sweep
// does not abort, and only the failed node is retried next sweep.
func TestBackfillPartialPrepareFailureDoesNotBlockOtherNodes(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{
		testNode("node-a", "10.0.0.1"),
		testNode("node-b", "10.0.0.2"),
	}
	f.snapshotErrByNode = map[string]string{"node-b": "node-b appsnapshot failed"}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("one node's AppSnapshot failure must not fail the sweep: %v", err)
	}
	if len(f.snapshotCalls) != 2 {
		t.Fatalf("AppSnapshot calls = %d, want 2 (both ready targets prepared)", len(f.snapshotCalls))
	}
	upserts := f.upsertsSnapshot()
	if len(upserts) != 2 {
		t.Fatalf("upserts = %d, want 2", len(upserts))
	}
	byNode := map[string]ReplicaStatus{}
	for _, up := range upserts {
		byNode[up.replica.NodeID] = up.replica
	}
	if r := byNode["node-a"]; r.Status != ReplicaStatusReady || r.Phase != ReplicaPhaseReady {
		t.Fatalf("node-a replica = %+v, want READY/READY (failure of node-b must not drag it down)", r)
	}
	if r := byNode["node-b"]; r.Status != ReplicaStatusFailed || r.ErrorMessage == "" {
		t.Fatalf("node-b replica = %+v, want FAILED with error message", r)
	}

	// Next sweep: node-a's READY row (upserted above) is in the listing, so
	// only the failed node-b is retried.
	f.replicas = []models.TemplateReplica{
		{NodeID: "node-a", NodeIP: "10.0.0.1", Status: ReplicaStatusReady, Phase: ReplicaPhaseReady},
		{NodeID: "node-b", NodeIP: "10.0.0.2", Status: ReplicaStatusFailed, Phase: ReplicaPhaseFailed},
	}
	f.snapshotErrByNode = nil // node-b heals on retry
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("retry sweep: %v", err)
	}
	if len(f.distCalls) != 2 {
		t.Fatalf("distribute calls = %d, want 2", len(f.distCalls))
	}
	if got := f.distCalls[1].targets; len(got) != 1 || got[0].ID() != "node-b" {
		t.Fatalf("retry targets = %v, want [node-b] only", got)
	}
	upserts = f.upsertsSnapshot()
	if len(upserts) != 3 || upserts[2].replica.Status != ReplicaStatusReady {
		t.Fatalf("retry upserts = %+v, want a third READY row for node-b", upserts)
	}
}

// The prepare step must survive a non-nil distribute error too: whatever
// readyTargets distribute returned still gets prepared, and the distribute
// error is reported (current contract), not masked by prepare failures.
func TestBackfillPrepareRunsDespiteDistributeError(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.distErr = errors.New("node-b create image failed")
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	err := backfillTemplateReplicas(context.Background(), def)
	if err == nil || !errors.Is(err, f.distErr) {
		t.Fatalf("backfillTemplateReplicas err = %v, want it to carry the distribute error", err)
	}
	upserts := f.upsertsSnapshot()
	if len(f.snapshotCalls) != 1 || len(upserts) != 1 || upserts[0].replica.Status != ReplicaStatusReady {
		t.Fatalf("ready targets must be prepared even when distribute reports an error: snap=%d upserts=%+v",
			len(f.snapshotCalls), upserts)
	}
}

// A persist failure must be logged and swallowed (distErr contract
// unchanged), must not register scheduling caches for a row that does not
// exist, and the node is retried next sweep.
func TestBackfillUpsertFailureRecordedAndNotCached(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.upsertErr = errors.New("upsert exploded")
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-upsert", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("an upsert failure must not fail the sweep: %v", err)
	}
	if len(f.snapshotCalls) != 1 || len(f.upserts) != 1 {
		t.Fatalf("snap=%d upserts=%d, want 1/1", len(f.snapshotCalls), len(f.upserts))
	}
	if state := localcache.GetImageStateByNode("tpl-upsert", "node-a"); state != nil {
		t.Fatalf("a failed upsert must not register the node in the locality cache: %+v", state)
	}
}

// After a READY upsert the sweep must publish the node to the scheduling
// caches: the replica registry sees the node and the stale locality/query
// caches are dropped so the next read reloads from the persisted row.
func TestBackfillCacheRefreshedAfterReadyUpsert(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.stub(t)

	// Pre-seed a stale locality snapshot as a previous tick left it.
	setTemplateLocalityCache("tpl-cache", []ReplicaStatus{{NodeID: "node-old", NodeIP: "10.0.0.9", Status: ReplicaStatusReady, Phase: ReplicaPhaseReady}})
	t.Cleanup(func() { invalidateTemplateCaches("tpl-cache"); localcache.InvalidateImageState("tpl-cache") })

	def := backfillDefinition{TemplateID: "tpl-cache", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if state := localcache.GetImageStateByNode("tpl-cache", "node-a"); state == nil {
		t.Fatalf("READY upsert must register node-a in the replica locality cache")
	}
	if _, ok := getCachedTemplateLocality("tpl-cache"); ok {
		t.Fatalf("READY upsert must drop the stale locality cache so it reloads from the persisted row")
	}
}

// DeleteTemplate racing an in-flight AppSnapshot: the definition is gone at
// persist time (the pre-cleanup check passed), so the sweep must write NO row
// (the orphan reconciler only scans cleanup_required rows and would never
// reclaim it) and must remove the just-created package from the node.
func TestBackfillDeleteTemplateRaceDropsReplica(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.definitionErr = ErrTemplateNotFound
	f.definitionErrAfter = 1 // pre-cleanup check sees the template; the pre-persist one does not
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	upserts := f.upsertsSnapshot()
	if len(upserts) != 0 {
		t.Fatalf("upserts = %+v, want none when the definition is gone mid-prepare", upserts)
	}
	if len(f.cleanups) != 2 {
		t.Fatalf("cleanups = %d, want 2 (stale sweep + the raced node package)", len(f.cleanups))
	}
	raced := f.cleanups[1]
	if raced.templateID != "tpl-1" || len(raced.replicas) != 1 || raced.replicas[0].NodeID != "node-a" || len(raced.targets) != 1 {
		t.Fatalf("raced cleanup = %+v, want tpl-1 package on node-a only", raced)
	}
}

// A transient GetDefinition error at persist time: no row is written (the
// prepare outcome cannot be attributed safely), and no cache is refreshed.
func TestBackfillDefinitionRecheckErrorSkipsPersist(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.definitionErr = errors.New("db unavailable")
	f.definitionErrAfter = 1 // pre-cleanup check passes; the pre-persist one fails
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-defcheck", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	upserts := f.upsertsSnapshot()
	if len(upserts) != 0 {
		t.Fatalf("upserts = %+v, want none when the definition recheck fails", upserts)
	}
	if state := localcache.GetImageStateByNode("tpl-defcheck", "node-a"); state != nil {
		t.Fatalf("a skipped persist must not register the node in the locality cache: %+v", state)
	}
}

// A definition that already points at a NEW artifact when the pass reaches the
// pre-cleanup check (redo switched mid-pass): skip everything for this tick —
// no push, no cleanup, no prepare, no rows. The next tick loads the new
// artifact. Cleaning from the stale view would delete the fresh package the
// redo just built.
func TestBackfillSkipsPassWhenDefinitionArtifactChanged(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.definitionArtifactIDs = []string{"rfs-new-artifact"}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.distCalls) != 0 || len(f.cleanups) != 0 || len(f.snapshotCalls) != 0 || len(f.upserts) != 0 {
		t.Fatalf("a definition that switched artifacts must skip the whole pass: dist=%d cleanups=%d snap=%d upserts=%d",
			len(f.distCalls), len(f.cleanups), len(f.snapshotCalls), len(f.upserts))
	}
}

// A transient error from the pre-cleanup definition check aborts the pass (the
// sweep logs it and retries next tick) instead of cleaning/preparing blind.
func TestBackfillSkipsPassWhenPreCleanupDefinitionCheckFails(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.definitionErr = errors.New("db unavailable")
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err == nil {
		t.Fatalf("backfillTemplateReplicas err = nil, want the definition check error")
	}
	if len(f.distCalls) != 0 || len(f.cleanups) != 0 || len(f.snapshotCalls) != 0 || len(f.upserts) != 0 {
		t.Fatalf("a failing definition check must abort before touching nodes: dist=%d cleanups=%d snap=%d upserts=%d",
			len(f.distCalls), len(f.cleanups), len(f.snapshotCalls), len(f.upserts))
	}
}

// Concurrent prepares must publish ALL freshly READY nodes, not just the
// last goroutine's: per-goroutine invalidate/register stomps each other
// because InvalidateImageState wipes the whole template's registrations.
func TestBackfillCacheRegistersAllReadyNodes(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{
		testNode("node-a", "10.0.0.1"),
		testNode("node-b", "10.0.0.2"),
	}
	f.stub(t)
	t.Cleanup(func() { invalidateTemplateCaches("tpl-cache2"); localcache.InvalidateImageState("tpl-cache2") })

	def := backfillDefinition{TemplateID: "tpl-cache2", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	for _, nodeID := range []string{"node-a", "node-b"} {
		if state := localcache.GetImageStateByNode("tpl-cache2", nodeID); state == nil {
			t.Fatalf("READY upsert must register %s in the replica locality cache (both nodes, not just the last finisher)", nodeID)
		}
	}
	if _, ok := getCachedTemplateLocality("tpl-cache2"); ok {
		t.Fatalf("READY upsert must drop the stale locality cache so it reloads from the persisted rows")
	}
}

// The pre-lock listing can go stale while the sweep waits on the artifact
// lock: a live redo may converge the node to READY in the meantime. The
// sweep must re-list under the lock and stand down instead of pushing,
// cleaning, or preparing against the old view.
func TestBackfillReloadsReplicasAfterLock(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	f.replicasSeq = [][]models.TemplateReplica{
		{{NodeID: "node-a", NodeIP: "10.0.0.1", Status: ReplicaStatusFailed, Phase: ReplicaPhaseFailed}},
		{{NodeID: "node-a", NodeIP: "10.0.0.1", Status: ReplicaStatusReady, Phase: ReplicaPhaseReady}},
	}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.distCalls) != 0 || len(f.cleanups) != 0 || len(f.snapshotCalls) != 0 || len(f.upserts) != 0 {
		t.Fatalf("a node that converged to READY while we waited for the lock must be left alone: dist=%d cleanups=%d snap=%d upserts=%d",
			len(f.distCalls), len(f.cleanups), len(f.snapshotCalls), len(f.upserts))
	}
}

// Redo switched the definition to a NEW artifact while our prepare ran
// (per-artifact locks do not serialize against a redo producing a different
// artifact). Persisting our stale-artifact outcome would clobber the redone
// row; a READY package built for the old artifact must be dropped.
func TestBackfillPrepareOutcomeDroppedOnArtifactMismatch(t *testing.T) {
	f := newBackfillPrepareFixture(t, "xfs")
	f.nodes = []*node.Node{testNode("node-a", "10.0.0.1")}
	// The pre-cleanup check still sees OUR artifact; the redo switches the
	// definition during the prepare, so the pre-persist check sees the new one.
	f.definitionArtifactIDs = []string{f.artifact.ArtifactID, "rfs-new-artifact"}
	f.stub(t)

	def := backfillDefinition{TemplateID: "tpl-1", InstanceType: "cubebox", RootfsArtifactID: f.artifact.ArtifactID}
	if err := backfillTemplateReplicas(context.Background(), def); err != nil {
		t.Fatalf("backfillTemplateReplicas: %v", err)
	}
	if len(f.snapshotCalls) != 1 {
		t.Fatalf("AppSnapshot calls = %d, want 1 (the prepare itself still runs)", len(f.snapshotCalls))
	}
	upserts := f.upsertsSnapshot()
	if len(upserts) != 0 {
		t.Fatalf("upserts = %+v, want none when the definition points at another artifact now", upserts)
	}
	if len(f.cleanups) != 2 {
		t.Fatalf("cleanups = %d, want 2 (stale sweep batch + the dropped node package)", len(f.cleanups))
	}
	dropped := f.cleanups[1]
	if dropped.templateID != "tpl-1" || len(dropped.replicas) != 1 || dropped.replicas[0].NodeID != "node-a" {
		t.Fatalf("dropped cleanup = %+v, want tpl-1 package on node-a", dropped)
	}
}
