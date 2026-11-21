// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Restart an interrupted, fixed-anchor bootstrap in one writer transaction.
//! This never clears a verified checkpoint. Callers supply the persisted trusted
//! consensus anchor and must keep state RPCs unavailable until full hashing ends.
const std = @import("std");
const kv = @import("kv.zig");
const branches = @import("branches.zig");
const snapshots = @import("snapshot.zig");
const types = @import("../types.zig");

pub fn restart(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator, expected: [32]u8) !types.BlockHeader {
    if (try snapshots.readCheckpoint(store, txn, allocator) != null) return error.StateAlreadyVerified;
    const selected = try branches.state(store, txn) orelse return error.IncompleteStateCheckpoint;
    const header = selected.head;
    if (!std.meta.eql(selected.base.hash(), header.hash()) or !std.meta.eql(header.hash(), expected))
        return error.BootstrapBranchMismatch;
    if (header.slot_number == null or header.block_access_list_hash == null) return error.PostGloasRequired;
    // Range ingestion appends in key order. Replaying a full scan into partial
    // flat tables would violate that contract, so discard only unverified data.
    // All tables and the missing-checkpoint guard belong to this transaction;
    // interruption leaves either the old partial state or the empty restart.
    inline for (.{ .accounts, .storage, .codes, .account_trie, .storage_tries }) |table|
        try store.table(txn, table).drop(false);
    return header;
}
