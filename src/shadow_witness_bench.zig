// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local-only benchmark: real MDBX state, fixed authenticated parent, no network.
const std = @import("std");
const builtin = @import("builtin");
const rlp = @import("rlp");
const types = @import("types.zig");
const kv = @import("db/kv.zig");
const Eth = @import("db/eth.zig").Eth;
const snapshots = @import("db/snapshot.zig");
const Shadow = @import("rpc/shadow.zig").Shadow;
const rpc = @import("rpc/jsonrpc.zig");
const hex = @import("rpc/hex.zig");
const trie = @import("trie/trie.zig");
const AccountTrie = @import("trie/account_trie.zig").AccountTrie;
const StorageTrie = @import("trie/storage_trie.zig").StorageTrie;
const genesis = @import("node/blockchain.zig").glamsterdam_devnet8_config.genesis_header;
const keccak = @import("evm/crypto/hash.zig").keccak256;
const scratch_size = 16 << 20;
const contract: u160 = 0x1001;
const code = [_]u8{ 0x60, 0x00, 0x00 };

const Fixture = struct {
    io: std.Io,
    parent_dir: std.Io.Dir,
    name: [32]u8,
    store: kv.Store,

    fn init(io: std.Io, a: std.mem.Allocator) !Fixture {
        const parent_dir = try std.Io.Dir.cwd().createDirPathOpen(io, ".zig-cache/shadow-witness-bench", .{});
        errdefer parent_dir.close(io);
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        try parent_dir.createDir(io, &name, .default_dir);
        errdefer parent_dir.deleteTree(io, &name) catch {};
        var path: [1024]u8 = undefined;
        const length = try parent_dir.realPathFile(io, &name, &path);
        return .{ .io = io, .parent_dir = parent_dir, .name = name, .store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20) };
    }

    fn deinit(self: *Fixture) void {
        self.store.deinit() catch unreachable;
        self.parent_dir.deleteTree(self.io, &self.name) catch unreachable;
        self.parent_dir.close(self.io);
    }

    fn populate(self: *Fixture, a: std.mem.Allocator) !types.BlockHeader {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const alloc = arena.allocator();
        var eth = Eth.init(&self.store);
        const txn = try self.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        const Slot = struct {
            key: [32]u8,
            value: u256,
            fn less(_: void, left: @This(), right: @This()) bool {
                return std.mem.order(u8, &left.key, &right.key) == .lt;
            }
        };
        var slots: [128]Slot = undefined;
        for (&slots, 0..) |*slot, i| slot.* = .{ .key = types.keccakOfU256(i), .value = 1000 + i * 3 };
        std.mem.sort(Slot, &slots, {}, Slot.less);
        var keys: [128][32]u8 = undefined;
        var values: [128]u256 = undefined;
        for (slots, &keys, &values) |slot, *key, *value| {
            key.* = slot.key;
            value.* = slot.value;
        }
        var sc = try trie.NodeCollector.init(alloc, 128 * 66);
        var st = StorageTrie.init(alloc).withCollector(&sc);
        try st.updateNoDeletions(&keys, &values);
        const storage_root = try st.rootHash();
        const owner = types.keccakOfU160(contract);
        try eth.commitStorageTrieNodes(txn, owner, &sc);
        for (slots) |slot| try eth.writeStorage(txn, owner, slot.key, slot.value);
        const code_hash = try eth.writeCode(txn, &code);

        const Account = struct {
            key: [32]u8,
            value: types.Account,
            fn less(_: void, left: @This(), right: @This()) bool {
                return std.mem.order(u8, &left.key, &right.key) == .lt;
            }
        };
        var accounts: [16]Account = undefined;
        for (&accounts, 0..) |*account, i| account.* = .{
            .key = types.keccakOfU160(0x1000 + @as(u160, @intCast(i))),
            .value = .{
                .nonce = i + 7,
                .balance = 42 + i,
                .storage_hash = if (i == 1) storage_root else types.empty_root_hash,
                .code_hash = if (i == 1) code_hash else types.empty_code_hash,
            },
        };
        std.mem.sort(Account, &accounts, {}, Account.less);
        var account_keys: [16][32]u8 = undefined;
        var account_values: [16]types.Account = undefined;
        for (accounts, &account_keys, &account_values) |account, *key, *value| {
            key.* = account.key;
            value.* = account.value;
            try eth.writeAccount(alloc, txn, account.key, account.value);
        }
        var ac = try trie.NodeCollector.init(alloc, 16 * 66);
        var at = AccountTrie.init(alloc).withCollector(&ac);
        try at.updateNoDeletions(&account_keys, &account_values);
        var header = genesis;
        header.number = 777;
        header.slot_number = 888;
        header.block_access_list_hash = @splat(0x44);
        header.state_root = try at.rootHash();
        try eth.commitAccountTrieNodes(txn, &ac);
        try snapshots.writeCheckpoint(&self.store, txn, alloc, header);
        try txn.commit();
        return header;
    }
};

const Timing = struct { total: u64 = 0, allocation: u64 = 0, read: u64 = 0, serialize: u64 = 0, release: u64 = 0, scratch_used: usize = 0 };

fn elapsed(io: std.Io, start: std.Io.Timestamp) u64 {
    return @intCast(start.durationTo(.now(io, .awake)).toNanoseconds());
}

// Retain this explicit old path even when the runtime adopts workspace reuse.
// Only backing lifetime differs: every call gets a fresh bounded FBA and calls
// the same authenticated Shadow.read. This harness is single-threaded.
const Handler = struct {
    api: *Shadow,
    backing: ?[]u8,
    last: Timing = .{},

    fn witness(self: *Handler, io: std.Io, out: std.mem.Allocator, parent: Shadow.Parent, queries: []const Shadow.Query) !rpc.RawJson {
        self.last = .{};
        const alloc_start = std.Io.Timestamp.now(io, .awake);
        const backing = self.backing orelse try std.heap.page_allocator.alloc(u8, scratch_size);
        self.last.allocation = elapsed(io, alloc_start);
        defer if (self.backing == null) {
            const release_start = std.Io.Timestamp.now(io, .awake);
            std.heap.page_allocator.free(backing);
            self.last.release = elapsed(io, release_start);
        };
        var scratch = std.heap.FixedBufferAllocator.init(backing);
        const read_start = std.Io.Timestamp.now(io, .awake);
        const result = try self.api.read(scratch.allocator(), parent, queries);
        self.last.read = elapsed(io, read_start);
        self.last.scratch_used = scratch.end_index;
        const encode_start = std.Io.Timestamp.now(io, .awake);
        const raw = try std.fmt.allocPrint(out, "{f}", .{std.json.fmt(result, .{})});
        self.last.serialize = elapsed(io, encode_start);
        return .{ .raw = raw };
    }
};

const Mode = enum { typed_fresh, typed_reused, witness_fresh, witness_reused, rpc_fresh, rpc_reused, rpc_runtime };
const modes = std.enums.values(Mode);

fn proofValue(a: std.mem.Allocator, root: [32]u8, key: [32]u8, proof: []const hex.Bytes) !?[]const u8 {
    var nodes: trie.NodesHashMap = .empty;
    for (proof) |node| try nodes.put(a, keccak(node.bytes), node.bytes);
    const proven = try trie.loadFromNodesMap(a, root, &nodes, null);
    return proven.get(key);
}

fn authenticate(a: std.mem.Allocator, parent: Shadow.Parent, witness: Shadow.Witness, query: Shadow.Query, absent: bool) !void {
    if (!std.meta.eql(parent.blockHash, witness.parent.blockHash) or !std.meta.eql(parent.stateRoot, witness.parent.stateRoot) or witness.accounts.len != 1)
        return error.ParentMismatch;
    const account = witness.accounts[0];
    const key = types.keccakOfU160(std.mem.readInt(u160, &query.address.bytes, .big));
    const encoded = try proofValue(a, parent.stateRoot.bytes, key, account.accountProof);
    if (absent) {
        if (encoded != null or account.balance.number != 0 or account.nonce.number != 0 or account.code.bytes.len != 0) return error.AbsenceMismatch;
        return;
    }
    var proven: types.Account = undefined;
    const bytes = encoded orelse return error.MissingAccount;
    if (try rlp.deserialize(types.Account, a, bytes, &proven) != bytes.len or
        proven.balance != 43 or proven.nonce != 8 or !std.meta.eql(proven.code_hash, keccak(&code)) or
        !std.meta.eql(proven.storage_hash, account.storageHash.bytes) or !std.meta.eql(proven.code_hash, account.codeHash.bytes) or
        account.balance.number != proven.balance or account.nonce.number != proven.nonce or !std.mem.eql(u8, account.code.bytes, &code))
        return error.AccountMismatch;
    if (account.storageProof.len != query.storageKeys.len) return error.StorageCountMismatch;
    for (account.storageProof, query.storageKeys) |slot, requested| {
        const value_bytes = (try proofValue(a, proven.storage_hash, types.keccakOfU256(requested.number), slot.proof)) orelse return error.MissingStorage;
        var value: u256 = undefined;
        if (try rlp.deserialize(u256, a, value_bytes, &value) != value_bytes.len or value != 1000 + requested.number * 3 or
            slot.key.number != requested.number or slot.value.number != value) return error.StorageValueMismatch;
    }
}

const Result = struct { bytes: []const u8, timing: Timing };

fn measure(io: std.Io, out: std.mem.Allocator, mode: Mode, api: *Shadow, parent: Shadow.Parent, queries: []const Shadow.Query, fresh: *Handler, reused: *Handler, servers: *[3]rpc.Server, request: []const u8) !Result {
    const start = std.Io.Timestamp.now(io, .awake);
    switch (mode) {
        .typed_fresh, .typed_reused => {
            var timing: Timing = .{};
            const backing = if (mode == .typed_fresh) try std.heap.page_allocator.alloc(u8, scratch_size) else reused.backing.?;
            timing.allocation = elapsed(io, start);
            var released = mode != .typed_fresh;
            defer if (!released) std.heap.page_allocator.free(backing);
            var scratch = std.heap.FixedBufferAllocator.init(backing);
            const read_start = std.Io.Timestamp.now(io, .awake);
            const witness = try api.read(scratch.allocator(), parent, queries);
            timing.read = elapsed(io, read_start);
            timing.total = elapsed(io, start);
            timing.scratch_used = scratch.end_index;
            // Equality checking/serialization is outside typed-read timing, but
            // happens before releasing the memory that owns the witness bytes.
            const raw = try std.fmt.allocPrint(out, "{f}", .{std.json.fmt(witness, .{})});
            if (!released) {
                const release_start = std.Io.Timestamp.now(io, .awake);
                std.heap.page_allocator.free(backing);
                released = true;
                timing.release = elapsed(io, release_start);
                timing.total += timing.release;
            }
            return .{ .bytes = raw, .timing = timing };
        },
        .witness_fresh, .witness_reused => {
            const handler = if (mode == .witness_fresh) fresh else reused;
            const result = try handler.witness(io, out, parent, queries);
            handler.last.total = elapsed(io, start);
            return .{ .bytes = result.raw, .timing = handler.last };
        },
        .rpc_fresh, .rpc_reused, .rpc_runtime => {
            const index: usize = switch (mode) {
                .rpc_fresh => 0,
                .rpc_reused => 1,
                else => 2,
            };
            const response = try servers[index].handle(io, out, request);
            var timing: Timing = if (index == 0) fresh.last else if (index == 1) reused.last else .{};
            timing.total = elapsed(io, start);
            return .{ .bytes = response.raw, .timing = timing };
        },
    }
}

const Stats = struct { min: u64, median: u64, p90: u64, max: u64, mean: u64 };

fn stats(a: std.mem.Allocator, timings: []const Timing, comptime field: []const u8) !Stats {
    const values = try a.alloc(u64, timings.len);
    var sum: u128 = 0;
    for (timings, values) |timing, *v| {
        v.* = @field(timing, field);
        sum += v.*;
    }
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    const mid = values.len / 2;
    return .{
        .min = values[0],
        .median = if (values.len % 2 == 0) (values[mid - 1] + values[mid]) / 2 else values[mid],
        .p90 = values[(values.len * 9 + 9) / 10 - 1],
        .max = values[values.len - 1],
        .mean = @intCast(sum / values.len),
    };
}

fn emit(io: std.Io, value: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(value, .{}, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}

pub fn main(init: std.process.Init) !void {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    var iterations: usize = 40;
    var warmup: usize = 3;
    while (args.next()) |arg| {
        const value = args.next() orelse return error.MissingArgument;
        if (std.mem.eql(u8, arg, "--iterations")) iterations = try std.fmt.parseInt(usize, value, 10) else if (std.mem.eql(u8, arg, "--warmup")) warmup = try std.fmt.parseInt(usize, value, 10) else return error.InvalidArguments;
    }
    if (iterations == 0 or iterations > 1000 or warmup > 50) return error.RepeatLimit;
    const a = init.arena.allocator();
    var fixture = try Fixture.init(init.io, a);
    defer fixture.deinit();
    const header = try fixture.populate(a);
    var eth = Eth.init(&fixture.store);
    var views: snapshots.Snapshots = .{ .io = init.io, .store = &fixture.store };
    defer views.deinit();
    try views.publish(a);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    defer if (@hasDecl(Shadow, "deinit")) api.deinit();
    const parent: Shadow.Parent = .{ .blockHash = .{ .bytes = header.hash() }, .stateRoot = .{ .bytes = header.state_root } };
    const backing = try std.heap.page_allocator.alloc(u8, scratch_size);
    defer std.heap.page_allocator.free(backing);
    var fresh: Handler = .{ .api = &api, .backing = null };
    var reused: Handler = .{ .api = &api, .backing = backing };
    var servers: [3]rpc.Server = @splat(.{});
    defer for (&servers) |*server| server.deinit(a);
    try servers[0].register(a, "zevm_getStateWitnessV1", &fresh, Handler.witness);
    try servers[1].register(a, "zevm_getStateWitnessV1", &reused, Handler.witness);
    try api.register(a, &servers[2]);
    var keys: [128]hex.Number(u256) = undefined;
    for (&keys, 0..) |*key, i| key.* = .init(i);
    var output = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer output.deinit();
    const shapes = [_]struct { name: []const u8, slots: usize, address: u160 }{
        .{ .name = "absent_account", .slots = 0, .address = 0xf0001 },
        .{ .name = "account_only", .slots = 0, .address = contract },
        .{ .name = "one_slot", .slots = 1, .address = contract },
        .{ .name = "128_slots", .slots = 128, .address = contract },
    };
    for (shapes) |shape| {
        var address: [20]u8 = undefined;
        std.mem.writeInt(u160, &address, shape.address, .big);
        const query: Shadow.Query = .{ .address = .{ .bytes = address }, .storageKeys = keys[0..shape.slots] };
        var reference = std.heap.FixedBufferAllocator.init(backing);
        const witness = try api.read(reference.allocator(), parent, &.{query});
        try authenticate(a, parent, witness, query, shape.address != contract);
        const expected = try std.fmt.allocPrint(a, "{f}", .{std.json.fmt(witness, .{})});
        const expected_rpc = try std.fmt.allocPrint(a, "{{\"jsonrpc\":\"2.0\",\"result\":{s},\"id\":1}}", .{expected});
        const request = try std.fmt.allocPrint(a, "{{\"jsonrpc\":\"2.0\",\"method\":\"zevm_getStateWitnessV1\",\"params\":{f},\"id\":1}}", .{std.json.fmt(.{ parent, &[_]Shadow.Query{query} }, .{})});
        var samples: [modes.len][]Timing = undefined;
        for (&samples) |*s| s.* = try a.alloc(Timing, iterations);
        // Rotate mode order each iteration to avoid always warming a later mode.
        for (0..warmup + iterations) |repeat| {
            for (0..modes.len) |offset| {
                const index = (repeat + offset) % modes.len;
                const mode = modes[index];
                const result = try measure(init.io, output.allocator(), mode, &api, parent, &.{query}, &fresh, &reused, &servers, request);
                const json_rpc = mode == .rpc_fresh or mode == .rpc_reused or mode == .rpc_runtime;
                if (!std.mem.eql(u8, if (json_rpc) expected_rpc else expected, result.bytes)) return error.WitnessMismatch;
                if (repeat >= warmup) samples[index][repeat - warmup] = result.timing;
                _ = output.reset(.retain_capacity);
            }
        }
        for (modes, samples) |mode, times| {
            var used: usize = 0;
            for (times) |timing| used = @max(used, timing.scratch_used);
            try emit(init.io, .{
                .kind = "measurement",
                .shape = shape.name,
                .mode = @tagName(mode),
                .optimize = @tagName(builtin.mode),
                .iterations = iterations,
                .warmup = warmup,
                .totalNs = try stats(a, times, "total"),
                .allocationNs = if (mode == .rpc_runtime) @as(?Stats, null) else try stats(a, times, "allocation"),
                .readNs = if (mode == .rpc_runtime) @as(?Stats, null) else try stats(a, times, "read"),
                .serializeNs = if (mode == .rpc_runtime) @as(?Stats, null) else try stats(a, times, "serialize"),
                .releaseNs = if (mode == .rpc_runtime) @as(?Stats, null) else try stats(a, times, "release"),
                .scratchBytes = scratch_size,
                .usedScratchBytes = if (mode == .rpc_runtime) @as(?usize, null) else used,
                .serializationExcludedFromTiming = mode == .typed_fresh or mode == .typed_reused,
                .witnessBytes = expected.len,
                .requestBytes = request.len,
                .witnessKeccak = std.fmt.bytesToHex(keccak(expected), .lower),
                .exactEquality = true,
                .proofsAuthenticated = true,
            });
        }
    }
    try emit(init.io, .{
        .kind = "summary",
        .shapes = shapes.len,
        .modes = modes.len,
        .iterations = iterations,
        .warmup = warmup,
        .blockHash = std.fmt.bytesToHex(header.hash(), .lower),
        .stateRoot = std.fmt.bytesToHex(header.state_root, .lower),
        .fixtureAccounts = 16,
        .fixtureStorageSlots = 128,
        .scratchBytes = scratch_size,
        .runtimeHasScratchDeinit = @hasDecl(Shadow, "deinit"),
        .limits = "Local warm same-parent fixture; RPC means Server.handle without sockets. Typed timing excludes JSON/equality checks but includes fresh backing allocation/release. No live latency or throughput claim.",
    });
}
