// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Logical preimages for complete-state BAL updates. State, journal and checkpoint
//! share one MDBX commit. Rollback recomputes and checks every restored state root;
//! old read transactions remain immutable while the writer returns to an ancestor.
const std = @import("std");
const rlp = @import("rlp");
const kv = @import("kv.zig");
const types = @import("../types.zig");
const Eth = @import("eth.zig").Eth;
const snapshot = @import("snapshot.zig");
const Collector = @import("../trie/trie.zig").NodeCollector;
const History = @import("history.zig").History(.state_undo, depth_limit, 128 << 20);

pub const depth_limit = 32;
pub const max_record_bytes = 32 << 20;
const max_accounts = 16384;
const max_slots = 131072;
pub const Slot = struct { key: [32]u8, value: u256 };
pub const Account = struct { key: [32]u8, present: u8, value: types.Account, slots: []Slot };
pub const Record = struct { parent: types.BlockHeader, accounts: []Account };

/// Must run before any BAL mutation. Partial initial sync must never use this API.
pub fn capture(eth: *Eth, txn: kv.Transaction, allocator: std.mem.Allocator, parent: types.BlockHeader, changes: types.HashedBlockAccessLists) !Record {
    const checkpoint = try snapshot.readCheckpoint(eth.kv_store, txn, allocator) orelse return error.StateNotReady;
    if (!std.meta.eql(checkpoint.hash(), parent.hash())) return error.StateCheckpointBranchMismatch;
    if (changes.changes.len > max_accounts) return error.StateHistoryLimit;
    var result: std.ArrayList(Account) = .empty;
    const cursor = try eth.kv_store.table(txn, .storage).cursor();
    defer cursor.deinit();
    var slot_count: usize = 0;
    for (changes.changes, changes.account_hashes, changes.slot_hashes) |change, key, keys| {
        if (change.readOnly()) continue;
        if (keys.len > max_slots - slot_count) return error.StateHistoryLimit;
        slot_count += keys.len;
        const old = try eth.readAccount(txn, key);
        const slots = try allocator.alloc(Slot, keys.len);
        for (keys, slots) |slot_key, *slot| {
            var value: u256 = 0;
            if (old != null) {
                if (try eth.readStorage(cursor, key, slot_key)) |bytes| {
                    if (try rlp.deserialize(u256, allocator, bytes, &value) != bytes.len) return error.MalformedStorage;
                }
            }
            slot.* = .{ .key = slot_key, .value = value };
        }
        try result.append(allocator, .{ .key = key, .present = @intFromBool(old != null), .value = old orelse types.EmptyAccount, .slots = slots });
    }
    return .{ .parent = parent, .accounts = result.items };
}

pub fn save(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator, child: types.BlockHeader, record: Record) !void {
    if (child.number != record.parent.number + 1 or !std.meta.eql(child.parent_hash, record.parent.hash()))
        return error.StateCheckpointBranchMismatch;
    // The downloader's slab allocator caps a single allocation at 32 MiB;
    // allocating this through an arena also needs its header/growth overhead.
    // Map the bounded large workspace directly and release it on every path.
    const backing = try std.heap.page_allocator.alloc(u8, max_record_bytes);
    defer std.heap.page_allocator.free(backing);
    var buffer = std.heap.FixedBufferAllocator.init(backing);
    var encoded = std.array_list.Managed(u8).init(buffer.allocator());
    rlp.serialize(Record, buffer.allocator(), record, &encoded) catch |e| {
        if (e == error.OutOfMemory) return error.StateHistoryLimit;
        return e;
    };
    try History.put(store, txn, allocator, child.hash(), encoded.items);
}

/// Caller aborts its transaction on *any* error, including a later missing record.
/// This makes an unsupported deep reorg leave the old checkpoint and state intact.
pub fn rewind(eth: *Eth, txn: kv.Transaction, allocator: std.mem.Allocator, target: [32]u8) !types.BlockHeader {
    var current = try snapshot.readCheckpoint(eth.kv_store, txn, allocator) orelse return error.StateNotReady;
    if (std.meta.eql(current.hash(), target)) return current;
    const scratch_bytes = try std.heap.page_allocator.alloc(u8, 64 << 20);
    defer std.heap.page_allocator.free(scratch_bytes);
    var scratch = std.heap.FixedBufferAllocator.init(scratch_bytes);
    for (0..depth_limit) |_| {
        if (std.meta.eql(current.hash(), target)) return current;
        scratch.reset();
        const a = scratch.allocator();
        const raw = try eth.kv_store.table(txn, .state_undo).get(&current.hash()) orelse return error.StateHistoryUnavailable;
        if (raw.len > max_record_bytes) return error.InvalidStateHistory;
        const bytes = try a.dupe(u8, raw);
        var record: Record = undefined;
        if (try rlp.deserialize(Record, a, bytes, &record) != bytes.len) return error.InvalidStateHistory;
        try restore(eth, txn, a, current, record);
        current = record.parent;
    }
    if (!std.meta.eql(current.hash(), target)) return error.StateHistoryUnavailable;
    return current;
}

fn restore(eth: *Eth, txn: kv.Transaction, a: std.mem.Allocator, current: types.BlockHeader, record: Record) !void {
    if (current.number != record.parent.number + 1 or !std.meta.eql(current.parent_hash, record.parent.hash()) or record.accounts.len > max_accounts)
        return error.InvalidStateHistory;
    var collector = try Collector.init(a, record.accounts.len * 66);
    var at = (try eth.openAccountTrie(a, txn, current.state_root)).withCollector(&collector);
    defer eth.closeAccountTrie(&at);
    var slot_count: usize = 0;
    for (record.accounts) |account| {
        if (account.present > 1 or account.slots.len > max_slots - slot_count) return error.InvalidStateHistory;
        slot_count += account.slots.len;
        const now = (try eth.readAccount(txn, account.key)) orelse types.EmptyAccount;
        if (account.slots.len != 0) {
            const keys = try a.alloc([32]u8, account.slots.len);
            const values = try a.alloc(u256, account.slots.len);
            for (account.slots, keys, values) |slot, *key, *value| {
                key.* = slot.key;
                value.* = slot.value;
            }
            var sc = try Collector.init(a, keys.len * 66);
            var st = (try eth.openStorageTrie(a, txn, account.key, now.storage_hash)).withCollector(&sc);
            defer eth.closeStorageTrie(&st);
            try st.update(keys, values);
            const expected = if (account.present == 1) account.value.storage_hash else types.empty_root_hash;
            if (!std.meta.eql(try st.rootHash(), expected)) return error.UndoStorageRootMismatch;
            try eth.commitStorageTrieNodes(txn, account.key, &sc);
            for (keys, values) |key, value| try eth.writeStorage(txn, account.key, key, value);
        } else if (account.present == 1 and !std.meta.eql(now.storage_hash, account.value.storage_hash)) return error.UndoStorageRootMismatch;
        try at.updateUnsorted(&.{account.key}, &.{if (account.present == 1) account.value else null});
        if (account.present == 1) try eth.writeAccount(a, txn, account.key, account.value) else try eth.deleteAccount(txn, account.key);
    }
    if (!std.meta.eql(try at.rootHash(), record.parent.state_root)) return error.UndoStateRootMismatch;
    try eth.commitAccountTrieNodes(txn, &collector);
    try snapshot.writeCheckpoint(eth.kv_store, txn, a, record.parent);
}
