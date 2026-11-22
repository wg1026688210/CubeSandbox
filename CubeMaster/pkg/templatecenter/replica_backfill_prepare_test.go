// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package templatecenter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/db/models"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/node"
	sandboxtypes "github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/service/sandbox/types"
)

// The replica-backfill sweep must not stop at DISTRIBUTED: after a successful
// CreateImage push to a node without a READY replica, the non-jfs branch must
// run the AppSnapshot step (createReplicaOnNode) on every ready target and
// persist the outcome via UpsertReplica so the row converges to READY. jfs
// stays placement-only and must never run AppSnapshot.
//
// createReplicaOnNode / UpsertReplica are patched with gomonkey (the same
// style as store_test.go); the tests fail if the sweep never calls them.

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

	upsertErr error

	// recordings
	distCalls     []backfillDistributeCall
	snapshotCalls []backfillSnapshotCall
	upserts       []backfillUpsertCall
}

type backfillSnapshotCall struct {
	nodeID       string
	templateID   string
	instanceType string
	artifactID   string
	jobID        string
}

type backfillUpsertCall struct {
	templateID   string
	instanceType string
	replica      ReplicaStatus
}

// newBackfillPrepareFixture builds the standard non-jfs (xfs) job/artifact
// pair: a READY servable artifact with a generated request snapshot, which is
// what backfillTemplateReplicas requires for the non-jfs branch.
func newBackfillPrepareFixture(t *testing.T, backend string) *backfillPrepareFixture {
	t.Helper()
	raw, err := json.Marshal(&sandboxtypes.CreateTemplateFromImageReq{
		Backend:      backend,
		InstanceType: "cubebox",
	})
	if err != nil {
		t.Fatalf("marshal job request: %v", err)
	}
	genRaw, err := json.Marshal(&sandboxtypes.CreateCubeSandboxReq{InstanceType: "cubebox"})
	if err != nil {
		t.Fatalf("marshal generated request: %v", err)
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
			GeneratedRequestJSON: string(genRaw),
		},
	}
}

// stub swaps every seam the sweep touches. The distribute seam is replaced
// wholesale (so no real cubelet RPC happens); createReplicaOnNode and
// UpsertReplica are patched with gomonkey so the test observes whether the
// sweep runs the AppSnapshot prepare step and persists its outcome.
func (f *backfillPrepareFixture) stub(t *testing.T) {
	t.Helper()
	stubRemoteTier(t, true, servableProbe(http.StatusPartialContent, f.artifact.ArtifactID))

	origJob, origArt, origRepl, origResolve, origPlace, origDist :=
		backfillLatestJob, backfillArtifact, backfillReplicas, backfillResolveNodes, backfillPlacements, backfillDistribute
	t.Cleanup(func() {
		backfillLatestJob, backfillArtifact, backfillReplicas, backfillResolveNodes, backfillPlacements, backfillDistribute =
			origJob, origArt, origRepl, origResolve, origPlace, origDist
	})
	backfillLatestJob = func(context.Context, string) (*models.TemplateImageJob, error) { return f.job, nil }
	backfillArtifact = func(context.Context, string) (*models.RootfsArtifact, error) { return f.artifact, nil }
	backfillReplicas = func(context.Context, string) ([]models.TemplateReplica, error) { return f.replicas, nil }
	backfillResolveNodes = func(string, []string) ([]*node.Node, error) { return f.nodes, nil }
	backfillPlacements = func(context.Context, string) ([]models.ArtifactNodePlacement, error) {
		return f.placements, nil
	}
	backfillDistribute = func(ctx context.Context, req *sandboxtypes.CreateTemplateFromImageReq, generatedReq *sandboxtypes.CreateCubeSandboxReq, art *models.RootfsArtifact, templateID, jobID string, targets []*node.Node, trackReplicas bool) ([]*node.Node, int32, int32, int32, error) {
		f.distCalls = append(f.distCalls, backfillDistributeCall{
			targets:       targets,
			trackReplicas: trackReplicas,
			generatedReq:  generatedReq,
		})
		return targets, int32(len(targets)), int32(len(targets)), f.distFailed, f.distErr
	}

	patches := gomonkey.NewPatches()
	t.Cleanup(patches.Reset)
	patches.ApplyFunc(createReplicaOnNode, func(_ context.Context, target *node.Node, templateID string, req *sandboxtypes.CreateCubeSandboxReq, opts replicaRunOptions) (ReplicaStatus, string) {
		f.snapshotCalls = append(f.snapshotCalls, backfillSnapshotCall{
			nodeID:       target.ID(),
			templateID:   templateID,
			instanceType: req.InstanceType,
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
	})
	patches.ApplyFunc(UpsertReplica, func(_ context.Context, templateID, instanceType string, replica ReplicaStatus) error {
		f.upserts = append(f.upserts, backfillUpsertCall{templateID: templateID, instanceType: instanceType, replica: replica})
		return f.upsertErr
	})
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
	if len(f.upserts) != 1 || f.upserts[0].replica.Status != ReplicaStatusReady || f.upserts[0].replica.Phase != ReplicaPhaseReady {
		t.Fatalf("upserts = %+v, want one READY/READY row (converges instead of looping)", f.upserts)
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
	if len(f.upserts) != 2 {
		t.Fatalf("upserts = %d, want 2", len(f.upserts))
	}
	byNode := map[string]ReplicaStatus{}
	for _, up := range f.upserts {
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
	if len(f.upserts) != 3 || f.upserts[2].replica.Status != ReplicaStatusReady {
		t.Fatalf("retry upserts = %+v, want a third READY row for node-b", f.upserts)
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
	if len(f.snapshotCalls) != 1 || len(f.upserts) != 1 || f.upserts[0].replica.Status != ReplicaStatusReady {
		t.Fatalf("ready targets must be prepared even when distribute reports an error: snap=%d upserts=%+v",
			len(f.snapshotCalls), f.upserts)
	}
}
