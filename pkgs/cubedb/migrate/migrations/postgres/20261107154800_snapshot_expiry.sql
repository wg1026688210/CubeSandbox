-- Copyright (c) 2026 Tencent Inc.
-- SPDX-License-Identifier: Apache-2.0
--
-- Optional expiry timestamps let the snapshot reconciler retire user snapshots
-- without affecting historical snapshots that have no expiration.

-- +goose Up
ALTER TABLE t_cube_snapshot
  ADD COLUMN IF NOT EXISTS expires_at timestamp(3) with time zone NULL;
CREATE INDEX IF NOT EXISTS idx_cube_snapshot_expires_at
  ON t_cube_snapshot (expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_cube_snapshot_expires_at;
ALTER TABLE t_cube_snapshot DROP COLUMN IF EXISTS expires_at;
