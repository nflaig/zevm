// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only target tracking from a trusted local post-Gloas beacon node. The
//! execution header is still fetched from peers and must hash to this CL target.
//! No EL RPC, Engine API mutation, transaction submission or bid publication.
const std = @import("std");
const HexHash = @import("../rpc/hex.zig").Data(32);
const log = std.log.scoped(.shadow_consensus);

fn requestError(request: *std.http.Client.Request, err: anyerror) anyerror {
    // std.http wraps transport cancellation in ReadFailed/WriteFailed. Preserve
    // cancellation before a reconnect loop consumes its one notification.
    if (request.connection) |connection| {
        if (err == error.ReadFailed) {
            if (connection.stream_reader.err) |actual| return actual;
        }
        if (err == error.WriteFailed) {
            if (connection.stream_writer.err) |actual| return actual;
        }
    }
    return err;
}

pub const Anchor = struct { beacon_root: [32]u8, execution_hash: [32]u8, slot: u64 };
pub const Head = struct { hash: [32]u8, slot: u64 };
pub const Update = struct { anchor: Anchor, head: Head, observed_at_ms: i64 };

fn nonzero(hash: [32]u8) ![32]u8 {
    if (std.mem.allEqual(u8, &hash, 0)) return error.UnavailableExecutionHead;
    return hash;
}

pub fn finalizedHeader(a: std.mem.Allocator, json: []const u8) !struct { root: [32]u8, slot: u64 } {
    const Response = struct {
        execution_optimistic: bool = true,
        finalized: bool = false,
        data: struct { root: HexHash, canonical: bool = false, header: struct { message: struct { slot: []const u8 } } },
    };
    const parsed = try std.json.parseFromSlice(Response, a, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const r = parsed.value;
    if (r.execution_optimistic or !r.finalized or !r.data.canonical) return error.UnverifiedConsensusAnchor;
    return .{ .root = try nonzero(r.data.root.bytes), .slot = try std.fmt.parseInt(u64, r.data.header.message.slot, 10) };
}

pub fn finalizedParent(a: std.mem.Allocator, json: []const u8, root: [32]u8, slot: u64) !Anchor {
    const Response = struct {
        version: []const u8,
        execution_optimistic: bool = true,
        finalized: bool = false,
        data: struct { message: struct {
            slot: []const u8,
            body: struct { signed_execution_payload_bid: ?struct { message: struct { parent_block_hash: HexHash } } = null },
        } },
    };
    const parsed = try std.json.parseFromSlice(Response, a, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const r = parsed.value;
    if (!std.mem.eql(u8, r.version, "gloas") and !std.mem.eql(u8, r.version, "heze")) return error.PostGloasRequired;
    if (r.execution_optimistic or !r.finalized or try std.fmt.parseInt(u64, r.data.message.slot, 10) != slot)
        return error.UnverifiedConsensusAnchor;
    const bid = r.data.message.body.signed_execution_payload_bid orelse return error.UnverifiedConsensusAnchor;
    // The bid's own payload can be absent. Its parent is committed by the
    // finalized, execution-validated beacon block and is the safe sync anchor.
    return .{ .beacon_root = root, .slot = slot, .execution_hash = try nonzero(bid.message.parent_block_hash.bytes) };
}

pub fn selectedHead(a: std.mem.Allocator, json: []const u8) !Head {
    const Node = struct {
        slot: []const u8,
        block_root: HexHash,
        payload_status: []const u8,
        validity: []const u8,
        execution_block_hash: HexHash,
        extra_data: struct { execution_optimistic: bool = true },
    };
    const Response = struct { data: struct {
        extra_data: struct { head: struct { block_root: HexHash, payload_status: []const u8 } },
        fork_choice_nodes: []Node,
    } };
    const parsed = try std.json.parseFromSlice(Response, a, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const data = parsed.value.data;
    const head = data.extra_data.head;
    if (!std.mem.eql(u8, head.payload_status, "full") and !std.mem.eql(u8, head.payload_status, "empty")) return error.UnavailableExecutionHead;
    var result: ?Head = null;
    for (data.fork_choice_nodes) |node| {
        if (!std.meta.eql(node.block_root.bytes, head.block_root.bytes) or !std.mem.eql(u8, node.payload_status, head.payload_status)) continue;
        if (result != null or !std.mem.eql(u8, node.validity, "valid") or node.extra_data.execution_optimistic)
            return error.UnverifiedConsensusHead;
        result = .{ .hash = try nonzero(node.execution_block_hash.bytes), .slot = try std.fmt.parseInt(u64, node.slot, 10) };
    }
    return result orelse error.UnavailableExecutionHead;
}

pub const Tracker = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    updates: *std.Io.Queue(Update),
    client: std.http.Client,
    anchor: ?Anchor = null,
    latest_hash: ?[32]u8 = null,
    publish_mutex: std.Io.Mutex = .init,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, url: []const u8, updates: *std.Io.Queue(Update)) !Tracker {
        const uri = try std.Uri.parse(url);
        if (!std.mem.eql(u8, uri.scheme, "http") or uri.user != null or uri.password != null or uri.query != null or uri.fragment != null)
            return error.TrustedLocalBeaconRequired;
        var host_buffer: [256]u8 = undefined;
        const host = try (uri.host orelse return error.TrustedLocalBeaconRequired).toRaw(&host_buffer);
        // This API is a trust boundary, not a public bootstrap discovery URL.
        if (!std.mem.eql(u8, host, "127.0.0.1") and !std.mem.eql(u8, host, "localhost") and !std.mem.eql(u8, host, "[::1]"))
            return error.TrustedLocalBeaconRequired;
        return .{ .io = io, .allocator = allocator, .url = std.mem.trimEnd(u8, url, "/"), .updates = updates, .client = .{ .allocator = allocator, .io = io } };
    }

    pub fn deinit(self: *Tracker) void {
        self.client.deinit();
    }

    fn get(self: *Tracker, a: std.mem.Allocator, path: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(a, "{s}{s}", .{ self.url, path });
        var request = try self.client.request(.GET, try std.Uri.parse(url), .{
            .redirect_behavior = .unhandled,
            .headers = .{ .accept_encoding = .{ .override = "identity" } },
        });
        defer request.deinit();
        request.sendBodiless() catch |e| return requestError(&request, e);
        var redirect: [1024]u8 = undefined;
        var response = request.receiveHead(&redirect) catch |e| return requestError(&request, e);
        if (response.head.status != .ok) return error.ConsensusHttpError;
        var transfer: [8192]u8 = undefined;
        return response.reader(&transfer).allocRemaining(a, .limited(4 << 20)) catch |e| return requestError(&request, e);
    }

    fn timedGet(self: *Tracker, a: std.mem.Allocator, path: []const u8) ![]const u8 {
        const Event = union(enum) { response: anyerror![]const u8, timeout: anyerror!void };
        var buffer: [2]Event = undefined;
        var select: std.Io.Select(Event) = .init(self.io, &buffer);
        defer select.cancelDiscard();
        try select.concurrent(.response, get, .{ self, a, path });
        try select.concurrent(.timeout, std.Io.sleep, .{ self.io, .fromSeconds(2), .awake });
        return switch (try select.await()) {
            .response => |result| try result,
            .timeout => error.ConsensusTimeout,
        };
    }

    fn bootstrap(self: *Tracker) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const checkpoint = try finalizedHeader(a, try self.timedGet(a, "/eth/v1/beacon/headers/finalized"));
        const path = try std.fmt.allocPrint(a, "/eth/v2/beacon/blocks/0x{s}", .{std.fmt.bytesToHex(checkpoint.root, .lower)});
        self.anchor = try finalizedParent(a, try self.timedGet(a, path), checkpoint.root, checkpoint.slot);
        log.info("trusted post-Gloas anchor: slot {} beacon {x} execution {x}", .{ checkpoint.slot, checkpoint.root, self.anchor.?.execution_hash });
    }

    fn publishHead(self: *Tracker) !void {
        // Serialize lookups as well as publication: a slower reconciliation
        // response must not overwrite a newer event-triggered target.
        try self.publish_mutex.lock(self.io);
        defer self.publish_mutex.unlock(self.io);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const head = try selectedHead(a, try self.timedGet(a, "/eth/v2/debug/fork_choice"));
        if (self.latest_hash) |previous| if (std.meta.eql(previous, head.hash)) return;
        try self.updates.putOne(self.io, .{ .anchor = self.anchor.?, .head = head, .observed_at_ms = @intCast(std.Io.Clock.real.now(self.io).toMilliseconds()) });
        self.latest_hash = head.hash;
    }

    fn stream(self: *Tracker) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const url = try std.fmt.allocPrint(arena.allocator(), "{s}/eth/v1/events?topics=head_v2,head,execution_payload", .{self.url});
        var request = try self.client.request(.GET, try std.Uri.parse(url), .{
            .redirect_behavior = .unhandled,
            .headers = .{ .accept_encoding = .{ .override = "identity" } },
            .extra_headers = &.{.{ .name = "accept", .value = "text/event-stream" }},
        });
        defer request.deinit();
        request.sendBodiless() catch |e| return requestError(&request, e);
        var redirect: [1024]u8 = undefined;
        var response = request.receiveHead(&redirect) catch |e| return requestError(&request, e);
        if (response.head.status != .ok) return error.ConsensusEventStreamUnavailable;
        var transfer: [8192]u8 = undefined;
        const reader = response.reader(&transfer);
        var interesting = false;
        var frame_size: usize = 0;
        while (true) {
            const line = (reader.takeDelimiter('\n') catch |e| return requestError(&request, e)) orelse return error.EndOfStream;
            if (line.len > 65536 - frame_size) return error.ConsensusEventTooLarge;
            frame_size += line.len;
            const text = std.mem.trimEnd(u8, line, "\r");
            if (text.len == 0) {
                if (interesting) self.publishHead() catch |e| {
                    if (e == error.Canceled) return e;
                    log.warn("head event lookup: {t}", .{e});
                };
                interesting = false;
                frame_size = 0;
            } else if (std.mem.startsWith(u8, text, "event:")) {
                const name = std.mem.trim(u8, text[6..], " ");
                interesting = std.mem.eql(u8, name, "head_v2") or std.mem.eql(u8, name, "head") or std.mem.eql(u8, name, "execution_payload");
            }
        }
    }

    fn streamLoop(self: *Tracker) !void {
        while (true) {
            self.stream() catch |e| {
                if (e == error.Canceled) return e;
                log.warn("event stream reconnect: {t}", .{e});
            };
            try std.Io.sleep(self.io, .fromSeconds(1), .awake);
        }
    }

    fn reconcileLoop(self: *Tracker) !void {
        while (true) {
            self.publishHead() catch |e| {
                if (e == error.Canceled) return e;
                log.warn("head reconciliation: {t}", .{e});
            };
            try std.Io.sleep(self.io, .fromSeconds(5), .awake);
        }
    }

    pub fn run(self: *Tracker) !void {
        while (self.anchor == null) {
            self.bootstrap() catch |e| {
                if (e == error.Canceled) return e;
                log.warn("waiting for a verified consensus anchor: {t}", .{e});
                try std.Io.sleep(self.io, .fromSeconds(1), .awake);
            };
        }
        const Event = union(enum) { stream: anyerror!void, reconcile: anyerror!void };
        var buffer: [2]Event = undefined;
        var select: std.Io.Select(Event) = .init(self.io, &buffer);
        defer select.cancelDiscard();
        try select.concurrent(.stream, streamLoop, .{self});
        try select.concurrent(.reconcile, reconcileLoop, .{self});
        switch (try select.await()) {
            .stream => |result| try result,
            .reconcile => |result| try result,
        }
    }
};

const test_root = "0x" ++ std.fmt.bytesToHex(@as([32]u8, @splat(0x11)), .lower);
const test_parent = "0x" ++ std.fmt.bytesToHex(@as([32]u8, @splat(0x22)), .lower);
const test_payload = "0x" ++ std.fmt.bytesToHex(@as([32]u8, @splat(0x33)), .lower);

test "consensus bootstrap requires finalized canonical execution-verified Gloas data" {
    const a = std.testing.allocator;
    const good = "{\"execution_optimistic\":false,\"finalized\":true,\"data\":{\"root\":\"" ++ test_root ++ "\",\"canonical\":true,\"header\":{\"message\":{\"slot\":\"123\"}}}}";
    const checkpoint = try finalizedHeader(a, good);
    try std.testing.expectEqual(@as(u64, 123), checkpoint.slot);
    inline for (.{ "\"execution_optimistic\":false", "\"finalized\":true", "\"canonical\":true" }, .{ "\"execution_optimistic\":true", "\"finalized\":false", "\"canonical\":false" }) |from, to| {
        const bad = try std.mem.replaceOwned(u8, a, good, from, to);
        defer a.free(bad);
        try std.testing.expectError(error.UnverifiedConsensusAnchor, finalizedHeader(a, bad));
    }
    const block = "{\"version\":\"gloas\",\"execution_optimistic\":false,\"finalized\":true,\"data\":{\"message\":{\"slot\":\"123\",\"body\":{\"signed_execution_payload_bid\":{\"message\":{\"parent_block_hash\":\"" ++ test_parent ++ "\",\"block_hash\":\"" ++ test_payload ++ "\"}}}}}}";
    const anchor = try finalizedParent(a, block, checkpoint.root, checkpoint.slot);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), anchor.execution_hash);
    try std.testing.expectError(error.UnverifiedConsensusAnchor, finalizedParent(a, block, checkpoint.root, 124));
    const old_fork = try std.mem.replaceOwned(u8, a, block, "gloas", "fulu");
    defer a.free(old_fork);
    try std.testing.expectError(error.PostGloasRequired, finalizedParent(a, old_fork, checkpoint.root, 123));
}

const test_nodes = "[{\"slot\":\"124\",\"block_root\":\"" ++ test_root ++ "\",\"payload_status\":\"empty\",\"validity\":\"valid\",\"execution_block_hash\":\"" ++ test_parent ++ "\",\"extra_data\":{\"execution_optimistic\":false}},{\"slot\":\"124\",\"block_root\":\"" ++ test_root ++ "\",\"payload_status\":\"full\",\"validity\":\"valid\",\"execution_block_hash\":\"" ++ test_payload ++ "\",\"extra_data\":{\"execution_optimistic\":false}}]";

fn testForkChoice(a: std.mem.Allocator, status: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{{\"data\":{{\"extra_data\":{{\"head\":{{\"block_root\":\"{s}\",\"payload_status\":\"{s}\"}}}},\"fork_choice_nodes\":{s}}}}}", .{ test_root, status, test_nodes });
}

test "consensus head selects FULL or EMPTY using both root and payload status" {
    const a = std.testing.allocator;
    inline for (.{ "empty", "full" }, .{ 0x22, 0x33 }) |status, byte| {
        const json = try testForkChoice(a, status);
        defer a.free(json);
        const head = try selectedHead(a, json);
        try std.testing.expectEqual(@as(u64, 124), head.slot);
        try std.testing.expectEqual(@as([32]u8, @splat(byte)), head.hash);
    }
}

test "consensus head rejects optimistic invalid pending absent and ambiguous selection" {
    const a = std.testing.allocator;
    const json = try testForkChoice(a, "full");
    defer a.free(json);
    inline for (.{ "\"execution_optimistic\":false", "\"validity\":\"valid\"", "\"payload_status\":\"empty\"" }, .{ "\"execution_optimistic\":true", "\"validity\":\"invalid\"", "\"payload_status\":\"full\"" }) |from, to| {
        const bad = try std.mem.replaceOwned(u8, a, json, from, to);
        defer a.free(bad);
        try std.testing.expectError(error.UnverifiedConsensusHead, selectedHead(a, bad));
    }
    const pending = try testForkChoice(a, "pending");
    defer a.free(pending);
    try std.testing.expectError(error.UnavailableExecutionHead, selectedHead(a, pending));
    const absent = try std.mem.replaceOwned(u8, a, json, "\"fork_choice_nodes\":" ++ test_nodes, "\"fork_choice_nodes\":[]");
    defer a.free(absent);
    try std.testing.expectError(error.UnavailableExecutionHead, selectedHead(a, absent));
    const zero = try std.mem.replaceOwned(u8, a, json, test_payload, "0x" ++ std.fmt.bytesToHex(@as([32]u8, @splat(0)), .lower));
    defer a.free(zero);
    try std.testing.expectError(error.UnavailableExecutionHead, selectedHead(a, zero));
}

test "consensus tracker accepts only explicit trusted local endpoints" {
    const a = std.testing.allocator;
    var buffer: [4]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    for ([_][]const u8{ "http://127.0.0.1:9596", "http://localhost:9596", "http://[::1]:9596" }) |url| {
        var tracker = try Tracker.init(std.testing.io, a, url, &queue);
        tracker.deinit();
    }
    for ([_][]const u8{ "https://example.com", "http://example.com", "http://127.0.0.1@external.test", "http://user:password@localhost", "http://localhost?test", "http://localhost#test" }) |url|
        try std.testing.expectError(error.TrustedLocalBeaconRequired, Tracker.init(std.testing.io, a, url, &queue));
}
