// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Restart an interrupted, authorized bootstrap in one writer transaction.
//! This never clears a verified checkpoint. Callers supply the persisted trusted
//! consensus anchor and must keep state RPCs unavailable until full hashing ends.
const std = @import("std");
const kv = @import("kv.zig");
const branches = @import("branches.zig");
const snapshots = @import("snapshot.zig");
const types = @import("../types.zig");
const tip_key = "bootstrap-authorized-tip-v1";

/// Caller supplies the hash from a refreshed, execution-verified finalized CL
/// anchor. The entire bounded extension must link to the prior bootstrap base.
/// Persisting a tip authorizes only partial-state healing, never state reads.
pub fn advance(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator, expected_base: [32]u8, expected_tip: [32]u8, headers: []const types.BlockHeader) !void {
    if (try snapshots.readCheckpoint(store, txn, allocator) != null) return error.StateAlreadyVerified;
    const selected = try branches.state(store, txn) orelse return error.IncompleteStateCheckpoint;
    if (!std.meta.eql(selected.base.hash(), expected_base) or !std.meta.eql(selected.head.hash(), expected_base))
        return error.BootstrapBranchMismatch;
    if (headers.len == 0 or headers.len > branches.extension_limit) return error.BootstrapAnchorGapTooLarge;
    if (!std.meta.eql(headers[headers.len - 1].hash(), expected_tip)) return error.BootstrapBranchMismatch;
    for (headers) |header| if (header.slot_number == null or header.block_access_list_hash == null) return error.PostGloasRequired;
    try branches.select(store, txn, allocator, selected.head, headers);
    try store.table(txn, .state_meta).set(tip_key, &expected_tip, .Upsert);
}

pub fn completeAdvance(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator, expected_tip: [32]u8) !void {
    const marker = try store.table(txn, .state_meta).get(tip_key) orelse return error.BootstrapBranchMismatch;
    if (!std.mem.eql(u8, marker, &expected_tip)) return error.BootstrapBranchMismatch;
    _ = try branches.rebaseUnverified(store, txn, allocator, expected_tip);
    try store.table(txn, .state_meta).delete(tip_key);
}

pub fn restart(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator, expected: [32]u8) !types.BlockHeader {
    if (try snapshots.readCheckpoint(store, txn, allocator) != null) return error.StateAlreadyVerified;
    const selected = try branches.state(store, txn) orelse return error.IncompleteStateCheckpoint;
    const header = selected.head;
    if (!std.meta.eql(header.hash(), expected)) return error.BootstrapBranchMismatch;
    if (!std.meta.eql(selected.base.hash(), header.hash())) {
        const marker = try store.table(txn, .state_meta).get(tip_key) orelse return error.BootstrapBranchMismatch;
        if (!std.mem.eql(u8, marker, &expected)) return error.BootstrapBranchMismatch;
    }
    if (header.slot_number == null or header.block_access_list_hash == null) return error.PostGloasRequired;
    // Range ingestion appends in key order. Replaying a full scan into partial
    // flat tables would violate that contract, so discard only unverified data.
    // All tables and the missing-checkpoint guard belong to this transaction;
    // interruption leaves either the old partial state or the empty restart.
    inline for (.{ .accounts, .storage, .codes, .account_trie, .storage_tries }) |table|
        try store.table(txn, table).drop(false);
    _ = try branches.rebaseUnverified(store, txn, allocator, expected);
    store.table(txn, .state_meta).delete(tip_key) catch |e| if (e != @import("lmdbx").Error.MDBX_NOTFOUND) return e;
    return header;
}
