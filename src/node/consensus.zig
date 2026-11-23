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

/// Borrowed only for accept(). This event's exact EL/beacon parent was matched
/// to an execution-verified forkchoice node. It is a permitted branch target,
/// not a claim that warm FULL is currently canonical. The sink must copy into a
/// bounded mailbox and return; execution, state reads and KZG cannot run here.
pub const AttributesEvent = struct {
    json: []const u8,
    parent: Head,
    beacon_root: [32]u8,
    received_wall_ms: i64,
    received_mono_ms: i64,
};
pub const AttributesSink = struct {
    context: *anyopaque,
    accept: *const fn (*anyopaque, AttributesEvent) bool,
    /// Invalidate queued authority after loss of the trusted feed/validation.
    /// This only signals the owner; it must not wait for construction to stop.
    invalidate: *const fn (*anyopaque) void,
};

pub const TargetHint = struct {
    beacon_root: [32]u8,
    execution_hash: [32]u8,
    slot: ?u64 = null,
    full_only: bool = false,
};

const Node = struct {
    slot: []const u8,
    block_root: HexHash,
    payload_status: []const u8,
    validity: []const u8,
    execution_block_hash: HexHash,
    extra_data: struct { execution_optimistic: bool = true },

    fn verified(self: Node) !Head {
        if (!std.mem.eql(u8, self.validity, "valid") or self.extra_data.execution_optimistic)
            return error.UnverifiedConsensusHead;
        return .{ .hash = try nonzero(self.execution_block_hash.bytes), .slot = try std.fmt.parseInt(u64, self.slot, 10) };
    }
};
const ForkChoice = struct { data: struct {
    extra_data: struct { head: struct { block_root: HexHash, payload_status: []const u8 } },
    fork_choice_nodes: []Node,
} };

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
    const parsed = try std.json.parseFromSlice(ForkChoice, a, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return selectedNode(parsed.value);
}

fn selectedNode(graph: ForkChoice) !Head {
    const data = graph.data;
    const head = data.extra_data.head;
    if (!std.mem.eql(u8, head.payload_status, "full") and !std.mem.eql(u8, head.payload_status, "empty")) return error.UnavailableExecutionHead;
    var result: ?Head = null;
    for (data.fork_choice_nodes) |node| {
        if (!std.meta.eql(node.block_root.bytes, head.block_root.bytes) or !std.mem.eql(u8, node.payload_status, head.payload_status)) continue;
        if (result != null) return error.UnverifiedConsensusHead;
        result = try node.verified();
    }
    return result orelse error.UnavailableExecutionHead;
}

/// Warm a verified payload before forkchoice's timeliness decision selects FULL.
/// This selects work for a read-only state cache, not the beacon's canonical head.
pub fn targetHead(a: std.mem.Allocator, json: []const u8, hint: ?TargetHint) !Head {
    const parsed = try std.json.parseFromSlice(ForkChoice, a, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return targetNode(parsed.value, hint);
}

fn targetNode(graph: ForkChoice, hint: ?TargetHint) !Head {
    if (hint) |wanted| {
        var result: ?Head = null;
        for (graph.data.fork_choice_nodes) |node| {
            if (!std.meta.eql(node.block_root.bytes, wanted.beacon_root) or
                !std.meta.eql(node.execution_block_hash.bytes, wanted.execution_hash)) continue;
            if (!std.mem.eql(u8, node.payload_status, "full") and
                (wanted.full_only or !std.mem.eql(u8, node.payload_status, "empty"))) continue;
            const head = try node.verified();
            if (result != null or (wanted.slot != null and wanted.slot.? != head.slot)) return error.UnverifiedConsensusHead;
            result = head;
        }
        return result orelse error.UnavailableExecutionHead;
    }
    const selected = try selectedNode(graph);
    // Reconciliation must not undo warm FULL state just because the beacon still
    // selects EMPTY. Its execution parent remains available in a retained view.
    if (std.mem.eql(u8, graph.data.extra_data.head.payload_status, "empty")) {
        var full: ?Head = null;
        for (graph.data.fork_choice_nodes) |node| {
            if (!std.meta.eql(node.block_root.bytes, graph.data.extra_data.head.block_root.bytes) or
                !std.mem.eql(u8, node.payload_status, "full")) continue;
            const verified = node.verified() catch continue;
            if (full != null) return error.UnverifiedConsensusHead;
            full = verified;
        }
        if (full) |head| return head;
    }
    return selected;
}

pub const EventKind = enum { head, execution_payload, payload_attributes };

pub fn eventHint(a: std.mem.Allocator, kind: EventKind, json: []const u8) !?TargetHint {
    switch (kind) {
        .head => return null,
        .execution_payload => {
            const Event = struct { slot: []const u8, block_root: HexHash, block_hash: HexHash, execution_optimistic: bool = true };
            const parsed = try std.json.parseFromSlice(Event, a, json, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const event = parsed.value;
            if (event.execution_optimistic) return error.UnverifiedConsensusHead;
            return .{ .beacon_root = try nonzero(event.block_root.bytes), .execution_hash = try nonzero(event.block_hash.bytes), .slot = try std.fmt.parseInt(u64, event.slot, 10), .full_only = true };
        },
        .payload_attributes => {
            const Event = struct { version: []const u8, data: struct { parent_block_root: HexHash, parent_block_hash: HexHash } };
            const parsed = try std.json.parseFromSlice(Event, a, json, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const event = parsed.value;
            if (!std.mem.eql(u8, event.version, "gloas") and !std.mem.eql(u8, event.version, "heze")) return error.PostGloasRequired;
            return .{ .beacon_root = try nonzero(event.data.parent_block_root.bytes), .execution_hash = try nonzero(event.data.parent_block_hash.bytes) };
        },
    }
}

pub const Tracker = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    updates: *std.Io.Queue(Update),
    client: std.http.Client,
    anchor: ?Anchor = null,
    latest_hash: ?[32]u8 = null,
    published_anchor: ?Anchor = null,
    publish_mutex: std.Io.Mutex = .init,
    attributes_sink: ?AttributesSink = null,

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

    fn refreshAnchor(self: *Tracker) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const checkpoint = try finalizedHeader(a, try self.timedGet(a, "/eth/v1/beacon/headers/finalized"));
        const path = try std.fmt.allocPrint(a, "/eth/v2/beacon/blocks/0x{s}", .{std.fmt.bytesToHex(checkpoint.root, .lower)});
        const anchor = try finalizedParent(a, try self.timedGet(a, path), checkpoint.root, checkpoint.slot);
        // Network I/O does not hold the event publication lock. A delayed
        // refresh cannot overwrite a newer finalized anchor or race publication.
        if (try self.installAnchor(anchor))
            log.info("trusted post-Gloas anchor: slot {} beacon {x} execution {x}", .{ anchor.slot, anchor.beacon_root, anchor.execution_hash });
    }

    fn installAnchor(self: *Tracker, anchor: Anchor) !bool {
        try self.publish_mutex.lock(self.io);
        defer self.publish_mutex.unlock(self.io);
        return self.acceptAnchor(anchor);
    }

    fn acceptAnchor(self: *Tracker, anchor: Anchor) !bool {
        if (self.anchor) |previous| {
            if (anchor.slot < previous.slot) return false;
            if (anchor.slot == previous.slot) {
                if (!std.meta.eql(anchor, previous)) return error.ConflictingConsensusAnchor;
                return false;
            }
        }
        self.anchor = anchor;
        return true;
    }

    fn publishHead(self: *Tracker, kind: EventKind, data: []const u8) !void {
        const observed_at_ms: i64 = @intCast(std.Io.Clock.real.now(self.io).toMilliseconds());
        const observed_mono_ms: i64 = @intCast(std.Io.Clock.awake.now(self.io).toMilliseconds());
        // Serialize lookups as well as publication: a slower reconciliation
        // response must not overwrite a newer event-triggered target.
        try self.publish_mutex.lock(self.io);
        defer self.publish_mutex.unlock(self.io);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        try self.publishForkChoice(a, kind, data, try self.timedGet(a, "/eth/v2/debug/fork_choice"), observed_at_ms, observed_mono_ms);
    }

    fn publishForkChoice(self: *Tracker, a: std.mem.Allocator, kind: EventKind, data: []const u8, graph: []const u8, observed_at_ms: i64, observed_mono_ms: i64) !void {
        const hint = try eventHint(a, kind, data);
        const parsed = try std.json.parseFromSlice(ForkChoice, a, graph, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        const branch = try targetNode(parsed.value, hint);
        // Attribute/payload hints authorize one exact branch, not a change to
        // the writer's preferred target. EMPTY/older-parent notifications must
        // not cancel a pending FULL download and leave it waiting for the next
        // five-second reconciliation. Select both from the same verified graph;
        // FULL on the selected beacon root may still warm before its timeliness
        // decision, and a real same-height reorg remains a new writer target.
        const preferred = if (hint == null) branch else targetNode(parsed.value, null) catch |err| {
            // A valid retained branch remains useful if the selected head is
            // temporarily unavailable. Deliver only its authenticated attrs;
            // never promote that hint as a fallback state-sync target.
            try self.publishVerified(kind, data, hint, branch, null, observed_at_ms, observed_mono_ms);
            return err;
        };
        try self.publishVerified(kind, data, hint, branch, preferred, observed_at_ms, observed_mono_ms);
    }

    fn publishVerified(self: *Tracker, kind: EventKind, data: []const u8, hint: ?TargetHint, head: Head, preferred: ?Head, observed_at_ms: i64, observed_mono_ms: i64) !void {
        // Attribute identity includes target slot, beacon parent and all fields.
        // Repeated EL parents can describe distinct legitimate build requests.
        // Deliver before the sync-target dedup and before any queue backpressure.
        if (kind == .payload_attributes) if (self.attributes_sink) |sink| {
            const wanted = hint orelse return error.UnverifiedConsensusHead;
            if (!std.meta.eql(wanted.execution_hash, head.hash)) return error.UnverifiedConsensusHead;
            if (!sink.accept(sink.context, .{
                .json = data,
                .parent = head,
                .beacon_root = wanted.beacon_root,
                .received_wall_ms = observed_at_ms,
                .received_mono_ms = observed_mono_ms,
            })) log.warn("native attribute mailbox full", .{});
        };
        const sync_head = preferred orelse return;
        if (self.latest_hash) |previous| if (std.meta.eql(previous, sync_head.hash) and
            self.published_anchor != null and std.meta.eql(self.published_anchor.?, self.anchor.?)) return;
        try self.updates.putOne(self.io, .{ .anchor = self.anchor.?, .head = sync_head, .observed_at_ms = observed_at_ms });
        self.latest_hash = sync_head.hash;
        self.published_anchor = self.anchor;
    }

    fn invalidate(self: *Tracker) void {
        if (self.attributes_sink) |sink| sink.invalidate(sink.context);
    }

    fn stream(self: *Tracker) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const url = try std.fmt.allocPrint(arena.allocator(), "{s}/eth/v1/events?topics=head_v2,head,execution_payload,payload_attributes", .{self.url});
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
        var kind: ?EventKind = null;
        var data = std.array_list.Managed(u8).init(self.allocator);
        defer data.deinit();
        var frame_size: usize = 0;
        while (true) {
            const line = (reader.takeDelimiter('\n') catch |e| return requestError(&request, e)) orelse return error.EndOfStream;
            if (line.len > 65536 - frame_size) return error.ConsensusEventTooLarge;
            frame_size += line.len;
            const text = std.mem.trimEnd(u8, line, "\r");
            if (text.len == 0) {
                if (kind) |event_kind| self.publishHead(event_kind, data.items) catch |e| {
                    if (e == error.Canceled) return e;
                    // Reject only this uncertified target. An early FULL event
                    // or transient lookup timeout does not revoke a previously
                    // verified EMPTY/parent context. Stream loss invalidates the
                    // feed below; every accepted request has a short deadline.
                    log.warn("head event lookup: {t}", .{e});
                };
                kind = null;
                data.clearRetainingCapacity();
                frame_size = 0;
            } else if (std.mem.startsWith(u8, text, "event:")) {
                const name = std.mem.trim(u8, text[6..], " ");
                kind = if (std.mem.eql(u8, name, "head_v2") or std.mem.eql(u8, name, "head")) .head else std.meta.stringToEnum(EventKind, name);
            } else if (std.mem.startsWith(u8, text, "data:")) {
                // SSE permits multiple data lines; bound their aggregate too.
                const value = std.mem.trimStart(u8, text[5..], " ");
                if (data.items.len + value.len + 1 > 65536) return error.ConsensusEventTooLarge;
                try data.appendSlice(value);
                try data.append('\n');
            }
        }
    }

    fn streamLoop(self: *Tracker) !void {
        while (true) {
            self.stream() catch |e| {
                self.invalidate();
                if (e == error.Canceled) return e;
                log.warn("event stream reconnect: {t}", .{e});
            };
            try std.Io.sleep(self.io, .fromSeconds(1), .awake);
        }
    }

    fn reconcileLoop(self: *Tracker) !void {
        while (true) {
            self.refreshAnchor() catch |e| {
                if (e == error.Canceled) return e;
                log.warn("finalized anchor reconciliation: {t}", .{e});
            };
            self.publishHead(.head, "") catch |e| {
                if (e == error.Canceled) return e;
                log.warn("head reconciliation: {t}", .{e});
            };
            try std.Io.sleep(self.io, .fromSeconds(5), .awake);
        }
    }

    pub fn run(self: *Tracker) !void {
        while (self.anchor == null) {
            self.refreshAnchor() catch |e| {
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

test "delayed finalized refresh cannot regress authority and anchor change bypasses head dedup" {
    var buffer: [4]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(std.testing.io, std.testing.allocator, "http://localhost:9596", &queue);
    defer tracker.deinit();
    const old: Anchor = .{ .slot = 100, .beacon_root = @splat(1), .execution_hash = @splat(2) };
    const newer: Anchor = .{ .slot = 132, .beacon_root = @splat(3), .execution_hash = @splat(4) };
    const head: Head = .{ .slot = 200, .hash = @splat(5) };
    try std.testing.expect(try tracker.acceptAnchor(old));
    try tracker.publishVerified(.head, "", null, head, head, 1, 1);
    try std.testing.expectEqual(old, (try queue.getOne(std.testing.io)).anchor);
    try std.testing.expect(try tracker.acceptAnchor(newer));
    // Model a slower refresh completing after the newer response. The same
    // publication lock covers acceptAnchor and publishVerified in production.
    try std.testing.expect(!try tracker.acceptAnchor(old));
    try std.testing.expect(!try tracker.acceptAnchor(newer));
    var conflicting = newer;
    conflicting.execution_hash = @splat(9);
    try std.testing.expectError(error.ConflictingConsensusAnchor, tracker.acceptAnchor(conflicting));
    try std.testing.expectEqual(newer, tracker.anchor.?);
    try tracker.publishVerified(.head, "", null, head, head, 2, 2);
    try std.testing.expectEqual(newer, (try queue.getOne(std.testing.io)).anchor);
    try tracker.publishVerified(.head, "", null, head, head, 3, 3);
    try std.testing.expectEqual(0, try queue.get(std.testing.io, &buffer, 0));
}

test "concurrent finalized refresh serializes delayed older authority" {
    const io = std.testing.io;
    var buffer: [2]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(io, std.testing.allocator, "http://localhost:9596", &queue);
    defer tracker.deinit();
    const old: Anchor = .{ .slot = 100, .beacon_root = @splat(1), .execution_hash = @splat(2) };
    const newer: Anchor = .{ .slot = 132, .beacon_root = @splat(3), .execution_hash = @splat(4) };
    // Hold the actual publication mutex while the late response's task starts.
    try tracker.publish_mutex.lock(io);
    var locked = true;
    defer if (locked) tracker.publish_mutex.unlock(io);
    const Delayed = struct {
        fn run(owner: *Tracker, anchor: Anchor) !bool {
            return owner.installAnchor(anchor);
        }
    };
    var response = io.concurrent(Delayed.run, .{ &tracker, old }) catch return error.SkipZigTest;
    defer _ = response.cancel(io) catch {};
    try std.testing.expect(try tracker.acceptAnchor(newer));
    tracker.publish_mutex.unlock(io);
    locked = false;
    try std.testing.expect(!try response.await(io));
    try std.testing.expectEqual(newer, tracker.anchor.?);
}

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

test "verified FULL state warms before EMPTY selection changes and hints bind exact parents" {
    const a = std.testing.allocator;
    const json = try testForkChoice(a, "empty");
    defer a.free(json);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), (try selectedHead(a, json)).hash);
    try std.testing.expectEqual(@as([32]u8, @splat(0x33)), (try targetHead(a, json, null)).hash);
    const hint: TargetHint = .{ .beacon_root = @splat(0x11), .execution_hash = @splat(0x33), .slot = 124, .full_only = true };
    try std.testing.expectEqual(@as([32]u8, @splat(0x33)), (try targetHead(a, json, hint)).hash);
    var bad = hint;
    bad.beacon_root = @splat(0x99);
    try std.testing.expectError(error.UnavailableExecutionHead, targetHead(a, json, bad));
    bad = hint;
    bad.slot = 125;
    try std.testing.expectError(error.UnverifiedConsensusHead, targetHead(a, json, bad));
    bad = hint;
    bad.execution_hash = @splat(0x22);
    try std.testing.expectError(error.UnavailableExecutionHead, targetHead(a, json, bad));
    bad.full_only = false;
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), (try targetHead(a, json, bad)).hash);
    // A verified EMPTY node must not make an optimistic FULL payload eligible.
    const optimistic = try std.mem.replaceOwned(u8, a, json, "\"execution_block_hash\":\"" ++ test_payload ++ "\",\"extra_data\":{\"execution_optimistic\":false}", "\"execution_block_hash\":\"" ++ test_payload ++ "\",\"extra_data\":{\"execution_optimistic\":true}");
    defer a.free(optimistic);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), (try targetHead(a, optimistic, null)).hash);
    try std.testing.expectError(error.UnverifiedConsensusHead, targetHead(a, optimistic, hint));
}

test "parent notifications reject optimistic payloads and pre-Gloas attributes" {
    const a = std.testing.allocator;
    const payload = "{\"slot\":\"124\",\"block_root\":\"" ++ test_root ++ "\",\"block_hash\":\"" ++ test_payload ++ "\",\"execution_optimistic\":false}";
    const hint = (try eventHint(a, .execution_payload, payload)).?;
    try std.testing.expect(hint.full_only);
    try std.testing.expectEqual(@as(u64, 124), hint.slot.?);
    const bad = try std.mem.replaceOwned(u8, a, payload, "false", "true");
    defer a.free(bad);
    try std.testing.expectError(error.UnverifiedConsensusHead, eventHint(a, .execution_payload, bad));
    const attrs = "{\"version\":\"gloas\",\"data\":{\"parent_block_root\":\"" ++ test_root ++ "\",\"parent_block_hash\":\"" ++ test_parent ++ "\"}}";
    const parent = (try eventHint(a, .payload_attributes, attrs)).?;
    try std.testing.expect(!parent.full_only and parent.slot == null);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), parent.execution_hash);
    const old_fork = try std.mem.replaceOwned(u8, a, attrs, "gloas", "fulu");
    defer a.free(old_fork);
    try std.testing.expectError(error.PostGloasRequired, eventHint(a, .payload_attributes, old_fork));
}

const AttributesTestSink = struct {
    const Copy = struct {
        bytes: [1024]u8 = undefined,
        len: usize = 0,
        parent: Head = undefined,
        beacon_root: [32]u8 = undefined,
        wall_ms: i64 = 0,
        mono_ms: i64 = 0,
    };
    copies: [4]Copy = undefined,
    count: usize = 0,
    accepting: bool = true,
    invalidations: usize = 0,

    fn sink(self: *AttributesTestSink) AttributesSink {
        return .{ .context = self, .accept = accept, .invalidate = invalidate };
    }

    fn accept(context: *anyopaque, event: AttributesEvent) bool {
        const self: *AttributesTestSink = @ptrCast(@alignCast(context));
        std.debug.assert(self.count < self.copies.len and event.json.len <= 1024);
        const copy = &self.copies[self.count];
        copy.* = .{
            .len = event.json.len,
            .parent = event.parent,
            .beacon_root = event.beacon_root,
            .wall_ms = event.received_wall_ms,
            .mono_ms = event.received_mono_ms,
        };
        @memcpy(copy.bytes[0..copy.len], event.json);
        self.count += 1;
        return self.accepting;
    }

    fn invalidate(context: *anyopaque) void {
        const self: *AttributesTestSink = @ptrCast(@alignCast(context));
        self.invalidations += 1;
    }
};

const test_attributes = "{\"version\":\"gloas\",\"data\":{\"proposal_slot\":\"125\",\"parent_block_root\":\"" ++ test_root ++ "\",\"parent_block_hash\":\"" ++ test_parent ++ "\"}}";
const test_anchor: Anchor = .{ .beacon_root = @splat(0x44), .execution_hash = @splat(0x55), .slot = 120 };

test "consensus attributes repeat on the same parent before sync dedup with exact receipt stamps" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [1]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(io, a, "http://127.0.0.1:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    var sink: AttributesTestSink = .{};
    tracker.attributes_sink = sink.sink();
    const graph = try testForkChoice(a, "empty");
    defer a.free(graph);
    const hint = try eventHint(a, .payload_attributes, test_attributes);
    const head = try targetHead(a, graph, hint);
    const wall: i64 = 1795357860123;
    const mono: i64 = 490123;
    try tracker.publishVerified(.payload_attributes, test_attributes, hint, head, head, wall, mono);

    // Closing the now-full sync queue makes this a bounded regression: each
    // later attribute must still reach the sink but must not enqueue a target.
    queue.close(io);
    const next_slot = try std.mem.replaceOwned(u8, a, test_attributes, "125", "126");
    defer a.free(next_slot);
    try tracker.publishVerified(.payload_attributes, next_slot, hint, head, head, wall + 12000, mono + 12000);
    try tracker.publishVerified(.payload_attributes, next_slot, hint, head, head, wall + 12007, mono + 12007);
    try std.testing.expectEqual(@as(usize, 3), sink.count);
    for (sink.copies[0..sink.count], 0..) |copy, i| {
        const expected = if (i == 0) test_attributes else next_slot;
        try std.testing.expectEqualStrings(expected, copy.bytes[0..copy.len]);
        try std.testing.expectEqualDeep(head, copy.parent);
        try std.testing.expectEqual(hint.?.beacon_root, copy.beacon_root);
        const delta: i64 = if (i == 0) 0 else if (i == 1) 12000 else 12007;
        try std.testing.expectEqual(wall + delta, copy.wall_ms);
        try std.testing.expectEqual(mono + delta, copy.mono_ms);
    }
    const update = try queue.getOne(io);
    try std.testing.expectEqualDeep(test_anchor, update.anchor);
    try std.testing.expectEqualDeep(head, update.head);
    try std.testing.expectEqual(wall, update.observed_at_ms);
    try std.testing.expectError(error.Closed, queue.getOne(io));
    try std.testing.expectEqual(head.hash, tracker.latest_hash.?);
}

test "declined attribute delivery preserves sync updates and same-parent dedup" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [2]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(io, a, "http://localhost:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    var sink: AttributesTestSink = .{ .accepting = false };
    tracker.attributes_sink = sink.sink();
    const graph = try testForkChoice(a, "empty");
    defer a.free(graph);
    const empty_hint = try eventHint(a, .payload_attributes, test_attributes);
    const empty = try targetHead(a, graph, empty_hint);
    try tracker.publishVerified(.payload_attributes, test_attributes, empty_hint, empty, empty, 101, 51);
    const full_json = try std.mem.replaceOwned(u8, a, test_attributes, test_parent, test_payload);
    defer a.free(full_json);
    const full_hint = try eventHint(a, .payload_attributes, full_json);
    const full = try targetHead(a, graph, full_hint);
    try tracker.publishVerified(.payload_attributes, full_json, full_hint, full, full, 102, 52);
    queue.close(io);
    try tracker.publishVerified(.payload_attributes, full_json, full_hint, full, full, 103, 53);

    try std.testing.expectEqual(@as(usize, 3), sink.count);
    const first = try queue.getOne(io);
    const second = try queue.getOne(io);
    try std.testing.expectEqualDeep(empty, first.head);
    try std.testing.expectEqualDeep(full, second.head);
    try std.testing.expectEqual(@as(i64, 101), first.observed_at_ms);
    try std.testing.expectEqual(@as(i64, 102), second.observed_at_ms);
    try std.testing.expectError(error.Closed, queue.getOne(io));
    try std.testing.expectEqual(full.hash, tracker.latest_hash.?);
}

test "unbound or mismatched verified attributes never reach the sink or change sync target" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [1]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    queue.close(io);
    var tracker = try Tracker.init(io, a, "http://localhost:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    var sink: AttributesTestSink = .{};
    tracker.attributes_sink = sink.sink();
    const head: Head = .{ .hash = @splat(0x22), .slot = 124 };
    tracker.latest_hash = head.hash;
    try std.testing.expectError(error.UnverifiedConsensusHead, tracker.publishVerified(.payload_attributes, test_attributes, null, head, head, 1, 2));
    var hint = (try eventHint(a, .payload_attributes, test_attributes)).?;
    hint.execution_hash = @splat(0x99);
    try std.testing.expectError(error.UnverifiedConsensusHead, tracker.publishVerified(.payload_attributes, test_attributes, hint, head, head, 1, 2));
    try std.testing.expectEqual(@as(usize, 0), sink.count);
    try std.testing.expectEqual(head.hash, tracker.latest_hash.?);
    try std.testing.expectError(error.Closed, queue.getOne(io));
}

test "consensus attribute invalidation is optional and independent of sync state" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [1]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(io, a, "http://localhost:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    tracker.invalidate(); // The default node has no constructor callback.
    var sink: AttributesTestSink = .{};
    tracker.attributes_sink = sink.sink();
    const hint = try eventHint(a, .payload_attributes, test_attributes);
    const head: Head = .{ .hash = hint.?.execution_hash, .slot = 124 };
    try tracker.publishVerified(.payload_attributes, test_attributes, hint, head, head, 9, 4);
    queue.close(io);
    tracker.invalidate();
    tracker.invalidate();
    try std.testing.expectEqual(@as(usize, 2), sink.invalidations);
    try std.testing.expectEqual(@as(usize, 1), sink.count);
    try std.testing.expectEqual(head.hash, tracker.latest_hash.?);
    try std.testing.expectEqualDeep(head, (try queue.getOne(io)).head);
    try std.testing.expectError(error.Closed, queue.getOne(io));
    // A renewed verified event reaches the sink even if the sync target stayed
    // unchanged across invalidation. Host generation admission owns its policy.
    try tracker.publishVerified(.payload_attributes, test_attributes, hint, head, head, 10, 5);
    try std.testing.expectEqual(@as(usize, 2), sink.count);
}

test "ordinary consensus head notifications never enter the attribute sink" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [1]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(io, a, "http://localhost:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    var sink: AttributesTestSink = .{};
    tracker.attributes_sink = sink.sink();
    const head: Head = .{ .hash = @splat(0x33), .slot = 124 };
    try tracker.publishVerified(.head, "", null, head, head, 1, 2);
    queue.close(io);
    try tracker.publishVerified(.execution_payload, "opaque payload event", null, head, head, 3, 4);
    try std.testing.expectEqual(@as(usize, 0), sink.count);
    try std.testing.expectEqualDeep(head, (try queue.getOne(io)).head);
    try std.testing.expectError(error.Closed, queue.getOne(io));
}

test "branch attributes cannot supersede the verified FULL sync target" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [1]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(io, a, "http://localhost:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    var sink: AttributesTestSink = .{};
    tracker.attributes_sink = sink.sink();
    const graph = try testForkChoice(a, "empty");
    defer a.free(graph);
    const full = try std.mem.replaceOwned(u8, a, test_attributes, test_parent, test_payload);
    defer a.free(full);
    const alternate = try std.mem.replaceOwned(u8, a, test_attributes, "{\"version\":", "{\"context\":{\"role\":\"alternate\"},\"version\":");
    defer a.free(alternate);
    try tracker.publishForkChoice(a, .payload_attributes, full, graph, 100, 10);
    queue.close(io); // a second sync enqueue fails, rather than hanging the test
    try tracker.publishForkChoice(a, .payload_attributes, alternate, graph, 101, 11);
    try tracker.publishForkChoice(a, .payload_attributes, test_attributes, graph, 102, 12);
    try std.testing.expectEqual(@as(usize, 3), sink.count);
    try std.testing.expectEqualStrings(alternate, sink.copies[1].bytes[0..sink.copies[1].len]);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), sink.copies[1].parent.hash);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), sink.copies[2].parent.hash);
    try std.testing.expectEqual(@as([32]u8, @splat(0x33)), (try queue.getOne(io)).head.hash);
    try std.testing.expectEqual(@as([32]u8, @splat(0x33)), tracker.latest_hash.?);
    try std.testing.expectError(error.Closed, queue.getOne(io));
}

fn testReorgForkChoice(a: std.mem.Allocator, optimistic: bool) ![]u8 {
    const root = "0x" ++ std.fmt.bytesToHex(@as([32]u8, @splat(0x66)), .lower);
    const payload = "0x" ++ std.fmt.bytesToHex(@as([32]u8, @splat(0x77)), .lower);
    const old_nodes = test_nodes[0 .. test_nodes.len - 1];
    return std.fmt.allocPrint(a, "{{\"data\":{{\"extra_data\":{{\"head\":{{\"block_root\":\"{s}\",\"payload_status\":\"full\"}}}},\"fork_choice_nodes\":{s},{{\"slot\":\"124\",\"block_root\":\"{s}\",\"payload_status\":\"full\",\"validity\":\"valid\",\"execution_block_hash\":\"{s}\",\"extra_data\":{{\"execution_optimistic\":{s}}}}}]}}}}", .{ root, old_nodes, root, payload, if (optimistic) "true" else "false" });
}

test "same-height reorg changes sync target while older FULL branch remains authenticated" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [3]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    var tracker = try Tracker.init(io, a, "http://localhost:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    var sink: AttributesTestSink = .{};
    tracker.attributes_sink = sink.sink();
    const old = try testForkChoice(a, "empty");
    defer a.free(old);
    const reorg = try testReorgForkChoice(a, false);
    defer a.free(reorg);
    const full = try std.mem.replaceOwned(u8, a, test_attributes, test_parent, test_payload);
    defer a.free(full);
    try tracker.publishForkChoice(a, .payload_attributes, full, old, 100, 10);
    try tracker.publishForkChoice(a, .payload_attributes, full, reorg, 101, 11);
    // A stale execution-payload hint is verified but cannot restore the old
    // writer target either. An actual selected-root reorg back can do so.
    const payload = "{\"slot\":\"124\",\"block_root\":\"" ++ test_root ++ "\",\"block_hash\":\"" ++ test_payload ++ "\",\"execution_optimistic\":false}";
    try tracker.publishForkChoice(a, .execution_payload, payload, reorg, 102, 12);
    try tracker.publishForkChoice(a, .head, "", old, 103, 13);
    queue.close(io);
    try std.testing.expectEqual(@as(usize, 2), sink.count);
    try std.testing.expectEqual(@as([32]u8, @splat(0x33)), sink.copies[1].parent.hash);
    const first = try queue.getOne(io);
    const second = try queue.getOne(io);
    const third = try queue.getOne(io);
    try std.testing.expectEqual(@as([32]u8, @splat(0x33)), first.head.hash);
    try std.testing.expectEqual(@as([32]u8, @splat(0x77)), second.head.hash);
    try std.testing.expectEqual(first.head.slot, second.head.slot);
    try std.testing.expectEqualDeep(first.head, third.head);
    try std.testing.expectError(error.Closed, queue.getOne(io));
}

test "unverified preferred head never turns a valid branch hint into a sync fallback" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var buffer: [1]Update = undefined;
    var queue: std.Io.Queue(Update) = .init(&buffer);
    queue.close(io);
    var tracker = try Tracker.init(io, a, "http://localhost:9596", &queue);
    defer tracker.deinit();
    tracker.anchor = test_anchor;
    var sink: AttributesTestSink = .{};
    tracker.attributes_sink = sink.sink();
    const graph = try testReorgForkChoice(a, true);
    defer a.free(graph);
    try std.testing.expectError(error.UnverifiedConsensusHead, tracker.publishForkChoice(a, .payload_attributes, test_attributes, graph, 100, 10));
    try std.testing.expectEqual(@as(usize, 1), sink.count);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), sink.copies[0].parent.hash);
    try std.testing.expectEqual(@as(?[32]u8, null), tracker.latest_hash);
    try std.testing.expectError(error.Closed, queue.getOne(io));
    const unbound = try std.mem.replaceOwned(u8, a, test_attributes, test_parent, "0x" ++ std.fmt.bytesToHex(@as([32]u8, @splat(0x88)), .lower));
    defer a.free(unbound);
    try std.testing.expectError(error.UnavailableExecutionHead, tracker.publishForkChoice(a, .payload_attributes, unbound, graph, 101, 11));
    try std.testing.expectEqual(@as(usize, 1), sink.count);
}
