// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recent selected headers are transactional and distinct from immutable branch
//! headers. Never splice a height-only extension into a different parent chain.
const std = @import("std");
const rlp = @import("rlp");
const kv = @import("kv.zig");
const types = @import("../types.zig");
// Leave room for 256 ancestors of every retained state view plus active branch
// work. These immutable headers do not enlarge the writable rewind window.
const History = @import("history.zig").History(.branch_headers, 4096, 8 << 20);

const meta_key = "selected-branch-v1";
pub const window = 256;
pub const extension_limit = 128;
pub const State = struct { base: types.BlockHeader, head: types.BlockHeader };

pub fn state(store: *kv.Store, txn: kv.Transaction) !?State {
    const bytes = try store.table(txn, .state_meta).get(meta_key) orelse return null;
    if (bytes.len > 4096) return error.InvalidBranchHeader;
    // BlockHeader's custom RLP decoder allocates a temporary field list, even
    // though the returned header owns all of its fields inline.
    var scratch: [16384]u8 = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(&scratch);
    var result: State = undefined;
    if (try rlp.deserialize(State, allocator.allocator(), bytes, &result) != bytes.len or result.head.number < result.base.number)
        return error.InvalidBranchHeader;
    return result;
}

fn decode(bytes: []const u8) !types.BlockHeader {
    if (bytes.len > 2048) return error.InvalidBranchHeader;
    var scratch: [8192]u8 = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(&scratch);
    var header: types.BlockHeader = undefined;
    if (try rlp.deserialize(types.BlockHeader, allocator.allocator(), bytes, &header) != bytes.len) return error.InvalidBranchHeader;
    return header;
}

fn numberKey(number: u64) [8]u8 {
    var key: [8]u8 = undefined;
    std.mem.writeInt(u64, &key, number, .big);
    return key;
}

pub fn read(store: *kv.Store, txn: kv.Transaction, number: u64) !?types.BlockHeader {
    const selected = try state(store, txn) orelse return null;
    if (number == selected.head.number) return selected.head;
    if (number == selected.base.number) return selected.base;
    if (number < selected.base.number or number > selected.head.number) return null;
    const bytes = try store.table(txn, .branch_numbers).get(&numberKey(number)) orelse return null;
    const header = try decode(bytes);
    if (header.number != number) return error.InvalidBranchHeader;
    return header;
}

pub fn byHash(store: *kv.Store, txn: kv.Transaction, hash: [32]u8) !?types.BlockHeader {
    if (try state(store, txn)) |selected| {
        if (std.meta.eql(selected.base.hash(), hash)) return selected.base;
        if (std.meta.eql(selected.head.hash(), hash)) return selected.head;
    }
    const bytes = try store.table(txn, .branch_headers).get(&hash) orelse return null;
    const header = try decode(bytes);
    if (!std.meta.eql(header.hash(), hash)) return error.InvalidBranchHeader;
    return header;
}

fn writeHeader(store: *kv.Store, txn: kv.Transaction, a: std.mem.Allocator, header: types.BlockHeader) !void {
    const encoded = try encodeHeader(a, header);
    defer a.free(encoded);
    try History.put(store, txn, a, header.hash(), encoded);
    try store.table(txn, .branch_numbers).set(&numberKey(header.number), encoded, .Upsert);
}

fn encodeHeader(a: std.mem.Allocator, header: types.BlockHeader) ![]u8 {
    var encoded = std.array_list.Managed(u8).init(a);
    errdefer encoded.deinit();
    try rlp.serialize(types.BlockHeader, a, header, &encoded);
    if (encoded.items.len > 2048) return error.InvalidBranchHeader;
    return encoded.toOwnedSlice();
}

pub const AncestorGap = struct { hash: [32]u8, count: u64 };

/// A parent-linked hash, not a height, authorizes the next peer header request.
pub fn missingAncestor(store: *kv.Store, txn: kv.Transaction, parent: types.BlockHeader) !?AncestorGap {
    const count = @as(u64, @min(255, parent.number)) + 1;
    var header = parent;
    var i: u64 = 1;
    while (i < count) : (i += 1) {
        const previous = try byHash(store, txn, header.parent_hash) orelse return .{ .hash = header.parent_hash, .count = count - i };
        if (previous.number != header.number - 1) return error.BranchParentMismatch;
        header = previous;
    }
    return null;
}

/// Cache ascending headers whose last hash was already committed by a known
/// child's parent_hash. Backfilling never changes selected heights or state.
/// Validate the entire response before writing; caller owns the RW transaction.
pub fn rememberAncestors(store: *kv.Store, txn: kv.Transaction, a: std.mem.Allocator, expected: [32]u8, headers: []const types.BlockHeader) !void {
    if (headers.len == 0 or headers.len > 256) return error.AncestorQueryLimit;
    if (!std.meta.eql(headers[headers.len - 1].hash(), expected)) return error.BranchAncestorMismatch;
    for (headers[1..], headers[0 .. headers.len - 1]) |header, previous| {
        if (previous.number == std.math.maxInt(u64) or header.number != previous.number + 1 or
            !std.meta.eql(header.parent_hash, previous.hash())) return error.BranchParentMismatch;
    }
    // History metadata is temporary per insertion. Reusing bounded scratch
    // avoids accumulating O(headers * history capacity) in the caller's arena.
    const backing = try a.alloc(u8, 4 << 20);
    defer a.free(backing);
    var scratch = std.heap.FixedBufferAllocator.init(backing);
    for (headers) |header| {
        scratch.reset();
        const encoded = try encodeHeader(scratch.allocator(), header);
        try History.put(store, txn, scratch.allocator(), header.hash(), encoded);
    }
}

fn writeState(store: *kv.Store, txn: kv.Transaction, a: std.mem.Allocator, selected: State) !void {
    var encoded = std.array_list.Managed(u8).init(a);
    defer encoded.deinit();
    try rlp.serialize(State, a, selected, &encoded);
    try store.table(txn, .state_meta).set(meta_key, encoded.items, .Upsert);
}

/// Called atomically with the first fully verified state checkpoint. History
/// preceding this base is unavailable for state rewind and must be rejected.
pub fn initialize(store: *kv.Store, txn: kv.Transaction, a: std.mem.Allocator, base: types.BlockHeader) !void {
    if (try state(store, txn) != null) return;
    try writeHeader(store, txn, a, base);
    try writeState(store, txn, a, .{ .base = base, .head = base });
}

/// Drop only an incomplete bootstrap's selected-number window after its exact
/// authorized tip is adopted. A verified state checkpoint may never use this.
pub fn rebaseUnverified(store: *kv.Store, txn: kv.Transaction, a: std.mem.Allocator, expected: [32]u8) !types.BlockHeader {
    if (try @import("snapshot.zig").readCheckpoint(store, txn, a) != null) return error.StateAlreadyVerified;
    const selected = try state(store, txn) orelse return error.IncompleteStateCheckpoint;
    if (!std.meta.eql(selected.head.hash(), expected)) return error.BootstrapBranchMismatch;
    try store.table(txn, .branch_numbers).drop(false);
    try writeHeader(store, txn, a, selected.head);
    try writeState(store, txn, a, .{ .base = selected.head, .head = selected.head });
    return selected.head;
}

/// Startup-only replacement after the partial-state clear committed. The caller
/// authenticates `fresh` against its current finalized CL anchor and persists
/// that anchor in this same transaction. This does not authorize state reads or
/// skip ancestry for a verified checkpoint or a populated rolling bootstrap.
pub fn reanchorClearedUnverified(store: *kv.Store, txn: kv.Transaction, a: std.mem.Allocator, expected: [32]u8, fresh: types.BlockHeader) !void {
    if (try @import("snapshot.zig").readCheckpoint(store, txn, a) != null) return error.StateAlreadyVerified;
    const selected = try state(store, txn) orelse return error.IncompleteStateCheckpoint;
    if (!std.meta.eql(selected.base.hash(), expected) or !std.meta.eql(selected.head.hash(), expected))
        return error.BootstrapBranchMismatch;
    if (fresh.slot_number == null or fresh.block_access_list_hash == null) return error.PostGloasRequired;
    if (fresh.number < selected.head.number or (fresh.number == selected.head.number and !std.meta.eql(fresh.hash(), expected)))
        return error.BootstrapBranchMismatch;
    inline for (.{ .accounts, .storage, .codes, .account_trie, .storage_tries }) |table|
        if ((try store.table(txn, table).stat()).entries != 0) return error.BootstrapStateNotCleared;
    try store.table(txn, .branch_numbers).drop(false);
    try writeHeader(store, txn, a, fresh);
    try writeState(store, txn, a, .{ .base = fresh, .head = fresh });
}

/// Caller also rewinds state if needed, in this same RW transaction. Validate the
/// entire extension before changing its selected-number mapping or head marker.
pub fn select(store: *kv.Store, txn: kv.Transaction, a: std.mem.Allocator, ancestor: types.BlockHeader, headers: []const types.BlockHeader) !void {
    const selected = try state(store, txn) orelse return error.StateNotReady;
    if (headers.len > extension_limit) return error.BranchExtensionLimit;
    const known = try read(store, txn, ancestor.number) orelse return error.BranchAncestorUnavailable;
    if (!std.meta.eql(known.hash(), ancestor.hash())) return error.BranchAncestorMismatch;
    var previous = ancestor;
    for (headers) |header| {
        if (header.number != previous.number + 1 or !std.meta.eql(header.parent_hash, previous.hash()))
            return error.BranchParentMismatch;
        previous = header;
    }
    if (selected.head.number - ancestor.number > window) return error.BranchAncestorUnavailable;
    const numbers = store.table(txn, .branch_numbers);
    var number = ancestor.number + 1;
    while (number <= selected.head.number) : (number += 1) {
        numbers.delete(&numberKey(number)) catch |e| if (e != @import("lmdbx").Error.MDBX_NOTFOUND) return e;
    }
    if (headers.len != 0) {
        const backing = try a.alloc(u8, 4 << 20);
        defer a.free(backing);
        var scratch = std.heap.FixedBufferAllocator.init(backing);
        for (headers) |header| {
            scratch.reset();
            try writeHeader(store, txn, scratch.allocator(), header);
        }
    }
    const oldest = previous.number -| (window - 1);
    const cursor = try numbers.cursor();
    defer cursor.deinit();
    while (try cursor.seekLowerBound(&@as([8]u8, @splat(0)))) |entry| {
        if (entry.entry.key.len != 8) return error.InvalidBranchHeader;
        if (std.mem.readInt(u64, entry.entry.key[0..8], .big) >= oldest) break;
        try cursor.del(.Current);
    }
    try writeState(store, txn, a, .{ .base = selected.base, .head = previous });
}
