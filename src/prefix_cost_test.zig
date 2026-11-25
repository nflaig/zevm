// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Opt-in matched intake service-cost fixture. Signing, announcement/request
//! setup and cleanup are outside the interval; the sink only records hashes.
//! This is neither end-to-end readiness nor a sustained peer/constructor load.
//! The arena backing and seen table use std.testing.allocator (debug allocator).
const std = @import("std");
const rlp = @import("rlp");
const Public = @import("node/public_intake.zig");
const types = @import("types.zig");
const hash = @import("evm/crypto/hash.zig").keccak256;
const secp = @import("zig-eth-secp256k1");
const a = std.testing.allocator;
const io = std.testing.io;
const peer: Public.Peer = .{ .index = 0, .epoch = 1 };
const preserves = @hasField(Public.Stats, "signature_preserved_decoded");

fn encode(allocator: std.mem.Allocator, value: anytype) ![]const u8 {
    var bytes = std.array_list.Managed(u8).init(allocator);
    errdefer bytes.deinit();
    try rlp.serialize(@TypeOf(value), allocator, value, &bytes);
    return bytes.toOwnedSlice();
}

const Fixture = struct {
    count: usize,
    wire: []const u8,
    announcement: []const u8,
    hashes: []const Public.Hash,
    fn init(allocator: std.mem.Allocator, count: usize, heavy: bool, response: bool) !Fixture {
        const C = struct {
            extern fn secp256k1_context_destroy(context: *anyopaque) void;
        };
        const signer = try secp.Secp256k1.init();
        defer C.secp256k1_context_destroy(signer.context);
        const txs = try allocator.alloc(rlp.RawValue, count);
        const hashes = try allocator.alloc(Public.Hash, count);
        const kinds = try allocator.alloc(u8, count);
        @memset(kinds, 0);
        const sizes = try allocator.alloc(u32, count);
        const data = try allocator.alloc(u8, if (heavy) 130400 else 0);
        @memset(data, 0x42);
        for (0..count) |i| {
            var tx: types.Transaction = .{ .legacy = .{
                .nonce = i,
                .gas_price = 10,
                .gas_limit = 3_000_000,
                .to = @as([20]u8, @splat(0x11)),
                .value = 0,
                .data = if (i == 0) &.{} else data,
                .v = 37,
                .r = 0,
                .s = 0,
            } };
            const signature = try signer.sign(try tx.signingHash(allocator, 1), @as([31]u8, @splat(0)) ++ [_]u8{1});
            tx.legacy.r = std.mem.readInt(u256, signature[0..32], .big);
            tx.legacy.s = std.mem.readInt(u256, signature[32..64], .big);
            tx.legacy.v = 37 + @as(u256, signature[64]);
            const body = try encode(allocator, tx.legacy);
            try std.testing.expect(body.len <= Public.max_tx_bytes);
            txs[i] = .{ .value = body };
            hashes[i] = hash(body);
            sizes[i] = @intCast(body.len);
        }
        const wire = if (response) try encode(allocator, .{ @as(u64, 1), @as([]const rlp.RawValue, txs) }) else try encode(allocator, @as([]const rlp.RawValue, txs));
        try std.testing.expect(wire.len <= Public.max_message_bytes);
        if (heavy) try std.testing.expect(wire.len > Public.max_message_bytes * 99 / 100);
        return .{
            .count = count,
            .wire = wire,
            .announcement = try encode(allocator, .{ @as([]const u8, kinds), @as([]const u32, sizes), @as([]const Public.Hash, hashes) }),
            .hashes = hashes,
        };
    }
};

const Receiver = struct {
    count: usize = 0,
    hashes: [Public.max_broadcast_transactions]Public.Hash = undefined,
    fn accept(ctx: *anyopaque, record: Public.Record) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.hashes[self.count] = record.hash;
        self.count += 1;
        return true;
    }
};

fn measure(fixture: Fixture, response: bool, tokens: usize, round: usize, emit: bool) !void {
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const alloc = scratch.allocator();
    var receiver: Receiver = .{};
    var source: Public.Intake = .{ .allocator = a, .chain_id = 1, .sink = .{ .context = &receiver, .accept = Receiver.accept } };
    defer source.deinit();
    if (response) {
        try source.announce(alloc, peer, fixture.announcement, 0);
        const request = source.nextRequest(1, 0).?;
        try std.testing.expectEqual(fixture.count, request.count);
        try std.testing.expectEqualSlices(Public.Hash, fixture.hashes, request.hashes[0..request.count]);
    }
    source.signature_budget = .{ .last_ms = 0, .milli_tokens = tokens * 1000 };
    const cpu_begin = std.Io.Clock.cpu_process.now(io);
    const wall_begin = std.Io.Clock.awake.now(io);
    const result = if (response) source.response(alloc, peer, fixture.wire, .{ .mono_ms = 0 }) else source.broadcast(alloc, peer, fixture.wire, .{ .mono_ms = 0 });
    const wall_ns = wall_begin.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds();
    const cpu_ns = cpu_begin.durationTo(std.Io.Clock.cpu_process.now(io)).toNanoseconds();
    const limited = tokens < fixture.count;
    if (limited) try std.testing.expectError(error.SignatureRateLimit, result) else try result;
    const expected = if (limited) (if (preserves) tokens else 0) else fixture.count;
    try std.testing.expectEqual(expected, source.stats.accepted);
    try std.testing.expectEqual(expected, receiver.count);
    try std.testing.expectEqualSlices(Public.Hash, fixture.hashes[0..expected], receiver.hashes[0..receiver.count]);
    try std.testing.expectEqual(tokens, source.stats.decoded);
    try std.testing.expectEqual(0, source.signature_budget.milli_tokens);
    try std.testing.expectEqual(256000 - tokens * 1000, source.peer_work[peer.index].signatures.milli_tokens);
    try std.testing.expectEqual(0, source.stats.frame_rate_drops);
    if (emit) std.debug.print("PREFIX_COST arm={s} transport={s} items={} bytes={} tokens={} round={} wall_ns={} cpu_ns={} accepted={} decoded={} discarded={} unprocessed={} frame_hash={x}\n", .{
        if (preserves) "prefix" else "base", if (response) "response" else "broadcast", fixture.count,         fixture.wire.len,     tokens,                                   round,
        wall_ns,                             cpu_ns,                                    source.stats.accepted, source.stats.decoded, source.stats.signature_discarded_decoded, source.stats.signature_unprocessed_items,
        hash(fixture.wire),
    });
}

test "prefix cost normal maximum batches and bounded quota suffix" {
    if (std.testing.environ.getPosix("ZEVMPREFIX_COST") == null) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    const Case = struct { fixture: Fixture, response: bool, tokens: usize };
    var cases: [8]Case = undefined;
    var count: usize = 0;
    for ([_]bool{ true, false }) |response| {
        const normal_count: usize = if (response) Public.max_request_hashes else Public.max_broadcast_transactions;
        cases[count] = .{ .fixture = try Fixture.init(allocator, normal_count, false, response), .response = response, .tokens = normal_count };
        count += 1;
        const heavy = try Fixture.init(allocator, 17, true, response);
        for ([_]usize{ 0, 1, 17 }) |tokens| {
            cases[count] = .{ .fixture = heavy, .response = response, .tokens = tokens };
            count += 1;
        }
    }
    const full_heavy_only = std.testing.environ.getPosix("ZEVMPREFIX_COST_HEAVY_FULL_ONLY") != null;
    for (cases) |case| {
        if (full_heavy_only and !(case.fixture.count == 17 and case.tokens == 17)) continue;
        try measure(case.fixture, case.response, case.tokens, 0, false);
    }
    for (0..9) |round| {
        for (0..cases.len) |offset| {
            const case = cases[(round + offset) % cases.len];
            if (full_heavy_only and !(case.fixture.count == 17 and case.tokens == 17)) continue;
            try measure(case.fixture, case.response, case.tokens, round, true);
        }
    }
}
