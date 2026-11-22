// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Optional receive-only adapter for the downloader's ETH queue. All intake
//! mutation stays on that queue's owning thread; the public sink never sees
//! private transactions, and nothing in this adapter broadcasts or serves them.
const std = @import("std");
const eth = @import("../devp2p/eth.zig");
const Intake = @import("public_intake.zig").Intake;
const intake = @import("public_intake.zig");
const log = std.log.scoped(.public_intake);

comptime {
    if (@import("../devp2p/rlpx.zig").Server.max_peers > intake.max_peer_slots)
        @compileError("public intake slot bounds must cover the ETH provider");
}

pub const Driver = struct {
    source: *Intake,
    provider: *eth.Provider,
    invalid: u64 = 0,
    oversized: u64 = 0,
    stale: u64 = 0,
    last_report_ms: i64 = 0,

    pub fn handle(self: *Driver, a: std.mem.Allocator, received: eth.Provider.ParsedMessage, receipt: intake.ReceiptTime) void {
        const now = receipt.mono_ms;
        const peer: intake.Peer = .{ .index = received.read.peer.peer_index, .epoch = received.read.peer.peer_epoch };
        const result = switch (received.msg) {
            // Use the complete frame: Provider.next also returns a decoded
            // RawValue whose view could otherwise omit trailing RLP bytes.
            .new_pooled_transaction_hashes => self.source.announce(a, peer, received.read.payload, now),
            .pooled_transactions => self.source.response(a, peer, received.read.payload, receipt),
            .transactions => self.source.broadcast(a, peer, received.read.payload, receipt),
            else => return,
        };
        result catch |err| {
            switch (err) {
                error.UnsolicitedResponse, error.ExpiredResponse => self.stale += 1,
                error.OutOfMemory => self.source.stats.bounded_drops += 1,
                // Do not scan the inventory or drain outgoing work after
                // refusal. response() may release that peer's one request,
                // bounded by 16 request slots and 64 reserved hashes.
                error.FrameRateLimit, error.SignatureRateLimit => return,
                error.ResponseByteLimit, error.AnnouncementByteLimit, error.TransactionByteLimit, error.WireItemLimit => {
                    // These are our admission limits, not consensus-invalid
                    // transactions. Release reservations without banning peers
                    // that use larger valid transaction gossip batches.
                    self.oversized += 1;
                    self.source.disconnect(peer);
                },
                else => {
                    self.invalid += 1;
                    self.source.disconnect(peer);
                    // Observer admission is not a verdict on the shared sync
                    // connection. Never disconnect state/BAL peers here.
                },
            }
        };
        self.drain(a, now);
    }

    pub fn tick(self: *Driver, a: std.mem.Allocator, now: i64) void {
        self.source.expire(now);
        for (self.source.requests) |optional| if (optional) |request| {
            _ = self.provider.timeoutFor(.{ .peer_index = request.peer.index, .peer_epoch = request.peer.epoch }, .get_pooled_transactions) catch {
                self.source.disconnect(request.peer);
            };
        };
        self.drain(a, now);
        if (now - self.last_report_ms < 60000) return;
        self.last_report_ms = now;
        var outstanding: usize = 0;
        for (self.source.requests) |request| if (request != null) {
            outstanding += 1;
        };
        const s = self.source.stats;
        log.info("public_intake_stats accepted={} decoded={} announced={} requested={} duplicate={} deferred_blobs={} unsupported={} invalid={} oversized={} stale={} outstanding={} pending={} capacity_drops={} sink_full={} timeouts={} frame_rate_drops={} signature_rate_drops={} peer_pending_drops={} backoff_skips={} frame_refused_requests={} signature_discarded_decoded={} signature_unprocessed_items={}", .{
            s.accepted,                    s.decoded,          s.announced,            s.requested,          s.duplicate,                 s.deferred_blobs,         s.unsupported,
            self.invalid,                  self.oversized,     self.stale,             outstanding,          self.source.pending.count(), s.bounded_drops,          s.sink_full,
            s.expired_requests,            s.frame_rate_drops, s.signature_rate_drops, s.peer_pending_drops, s.backoff_skips,             s.frame_refused_requests, s.signature_discarded_decoded,
            s.signature_unprocessed_items,
        });
        log.info("public_blob_intake_stats requested={} queued={} ready={} failed={} sink_full={} inventory_drops={} request_rate_drops={} frame_rate_drops={}", .{
            s.blob_requested, s.blob_queued, s.blob_ready, s.blob_failed, s.blob_sink_full, s.blob_inventory_drops, s.blob_request_rate_drops, s.blob_frame_rate_drops,
        });
    }

    fn drain(self: *Driver, a: std.mem.Allocator, now: i64) void {
        // Bound work per event even if every selected peer disconnected. The
        // reservation is rolled back on serialization/send failure.
        for (0..intake.max_requests) |_| {
            const request = self.source.nextRequest(self.provider.nextRequestId(), now) orelse break;
            const bytes = Intake.encodeRequest(a, &request) catch {
                self.source.disconnect(request.peer);
                self.source.stats.bounded_drops += 1;
                break;
            };
            defer a.free(bytes);
            self.provider.send(.{ .peer_index = request.peer.index, .peer_epoch = request.peer.epoch }, .{ .get_pooled_transactions = .{ .value = bytes } }) catch {
                self.source.disconnect(request.peer);
            };
        }
    }
};

/// Hash/time-only measurement sink. It cannot feed the production constructor
/// or disclose transaction bodies; replace this with a bounded native builder
/// sink after the independent intake is qualified.
pub const Observer = struct {
    io: std.Io,
    window_second: i64 = -1,
    logged_in_window: u32 = 0,
    logged: u64 = 0,
    skipped: u64 = 0,
    last_report_ms: i64 = 0,
    pub const max_logs_per_second = 512;
    pub fn sink(self: *Observer) intake.Sink {
        return .{ .context = self, .accept = accept };
    }
    fn accept(ctx: *anyopaque, record: intake.Record) bool {
        const self: *Observer = @ptrCast(@alignCast(ctx));
        const mono = std.Io.Timestamp.now(self.io, .awake).toMilliseconds();
        if (self.permitLog(mono)) {
            log.info("public_transaction hash={x} bytes={} announced_mono_ms={} frame_received_mono_ms={} frame_received_wall_ms={} accepted_wall_ms={}", .{
                record.hash, record.bytes.len, record.announced_at_ms, record.received_at_ms, record.frame_received_wall_ms orelse -1, std.Io.Timestamp.now(self.io, .real).toMilliseconds(),
            });
        }
        if (mono - self.last_report_ms >= 60000) {
            self.last_report_ms = mono;
            log.info("public_intake_observer_stats logged={} skipped={} max_per_second={}", .{ self.logged, self.skipped, max_logs_per_second });
        }
        return true;
    }
    fn permitLog(self: *Observer, mono: i64) bool {
        const second = @divTrunc(mono, 1000);
        if (self.window_second != second) {
            self.window_second = second;
            self.logged_in_window = 0;
        }
        if (self.logged_in_window < max_logs_per_second) {
            self.logged_in_window += 1;
            self.logged += 1;
            return true;
        }
        self.skipped += 1;
        return false;
    }
};

test "public intake adapter rejects trailing bytes outside the provider RawValue" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var provider = try eth.Provider.init(a);
    // A connected sync peer with no backing server deliberately makes an
    // accidental provider.disconnect fail. Intake errors must preserve it.
    provider.peers[0].info.store(.{ .epoch = 1, .offset = 16 }, .release);
    const UnexpectedSink = struct {
        fn accept(_: *anyopaque, _: intake.Record) bool {
            @panic("empty or malformed announcement cannot reach sink");
        }
    };
    var marker: u8 = 0;
    var source: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = .{ .context = &marker, .accept = UnexpectedSink.accept } };
    defer source.deinit();
    var driver: Driver = .{ .source = &source, .provider = &provider };
    const payload = try a.dupe(u8, &.{ 0xc3, 0x80, 0xc0, 0xc0, 0x00 });
    const message: eth.Provider.ParsedMessage = .{
        .msg = .{ .new_pooled_transaction_hashes = .{ .value = payload[0..4] } },
        .read = .{ .peer = .{ .peer_index = 0, .peer_epoch = 1 }, .id = 8, .payload = payload },
    };
    driver.handle(a, message, .{ .mono_ms = 1 });
    try std.testing.expectEqual(1, driver.invalid);
    try std.testing.expectEqual(16, provider.peers[0].info.load(.acquire).offset);
    try std.testing.expectEqual(0, source.pending.count());
    var valid = message;
    valid.read.payload = payload[0..4];
    driver.handle(a, valid, .{ .mono_ms = 2 });
    try std.testing.expectEqual(1, driver.invalid);
    const bad_tx = try a.dupe(u8, &.{ 0xc1, 0xc0 });
    driver.handle(a, .{
        .msg = .{ .transactions = .{ .value = bad_tx } },
        .read = .{ .peer = .{ .peer_index = 0, .peer_epoch = 1 }, .id = 2, .payload = bad_tx },
    }, .{ .mono_ms = 3 });
    try std.testing.expectEqual(2, driver.invalid);
    try std.testing.expectEqual(16, provider.peers[0].info.load(.acquire).offset);
}

test "public intake observer bounds hash logs and counts omitted records" {
    var observer: Observer = .{ .io = std.testing.io };
    for (0..Observer.max_logs_per_second) |_| try std.testing.expect(observer.permitLog(1000));
    try std.testing.expect(!observer.permitLog(1999));
    try std.testing.expectEqual(1, observer.skipped);
    try std.testing.expect(observer.permitLog(2000));
    try std.testing.expectEqual(Observer.max_logs_per_second + 1, observer.logged);
}

test "public intake denied frames do not scan cleanup or drain outgoing work" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var provider = try eth.Provider.init(a);
    provider.peers[0].info.store(.{ .epoch = 1, .offset = 16 }, .release);
    const UnexpectedSink = struct {
        fn accept(_: *anyopaque, _: intake.Record) bool {
            @panic("denied frame cannot reach sink");
        }
    };
    var marker: u8 = 0;
    var source: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = .{ .context = &marker, .accept = UnexpectedSink.accept } };
    defer source.deinit();
    var driver: Driver = .{ .source = &source, .provider = &provider };
    var announcement: [38]u8 = @splat(0);
    @memcpy(announcement[0..6], &[_]u8{ 0xe5, 0x00, 0xc1, 0x64, 0xe1, 0xa0 });
    try source.announce(a, .{ .index = 0, .epoch = 1 }, &announcement, 0);
    source.frame_budget = .{ .last_ms = 0, .milli_tokens = 0 };
    const payload = try a.dupe(u8, &.{ 0xc1, 0xc0 });
    driver.handle(a, .{
        .msg = .{ .transactions = .{ .value = payload } },
        .read = .{ .peer = .{ .peer_index = 0, .peer_epoch = 1 }, .id = 2, .payload = payload },
    }, .{ .mono_ms = 0 });
    try std.testing.expectEqual(1, source.stats.frame_rate_drops);
    try std.testing.expectEqual(0, driver.invalid);
    try std.testing.expectEqual(1, source.pending.count());
    try std.testing.expect(source.pending.values()[0].peers[0] != null);
    for (source.requests) |request| try std.testing.expect(request == null);
    try std.testing.expectEqual(16, provider.peers[0].info.load(.acquire).offset);
}

test "public intake driver drops refused responses without draining or penalizing the responder" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]bool{ false, true }) |deny_signature| {
        var provider = try eth.Provider.init(a);
        provider.peers[0].info.store(.{ .epoch = 1, .offset = 16 }, .release);
        provider.peers[1].info.store(.{ .epoch = 1, .offset = 16 }, .release);
        const UnexpectedSink = struct {
            fn accept(_: *anyopaque, _: intake.Record) bool {
                @panic("refused response cannot reach sink");
            }
        };
        var marker: u8 = 0;
        var source: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = .{ .context = &marker, .accept = UnexpectedSink.accept } };
        defer source.deinit();
        var driver: Driver = .{ .source = &source, .provider = &provider };
        var announcement: [38]u8 = @splat(0);
        @memcpy(announcement[0..6], &[_]u8{ 0xe5, 0x00, 0xc1, 0x01, 0xe1, 0xa0 });
        const tx_hash = @import("../evm/crypto/hash.zig").keccak256(&.{0xc0});
        @memcpy(announcement[6..], &tx_hash);
        try source.announce(a, .{ .index = 0, .epoch = 1 }, &announcement, 0);
        _ = source.nextRequest(1, 0).?;
        // A second peer's eligible work would call provider.send (and fail on
        // its deliberately absent server) if the refusal accidentally drained.
        announcement[37] ^= 1;
        try source.announce(a, .{ .index = 1, .epoch = 1 }, &announcement, 0);
        if (deny_signature) {
            source.signature_budget = .{ .last_ms = 0, .milli_tokens = 0 };
        } else {
            source.frame_budget = .{ .last_ms = 0, .milli_tokens = 0 };
        }
        const payload = try a.dupe(u8, &.{ 0xc3, 0x01, 0xc1, 0xc0 });
        driver.handle(a, .{
            .msg = .{ .pooled_transactions = .{ .value = payload } },
            .read = .{ .peer = .{ .peer_index = 0, .peer_epoch = 1 }, .id = 10, .payload = payload },
        }, .{ .mono_ms = 0 });
        for (source.requests) |request| try std.testing.expect(request == null);
        try std.testing.expectEqual(2, source.pending.count());
        try std.testing.expectEqual(@intFromBool(!deny_signature), source.stats.frame_refused_requests);
        try std.testing.expectEqual(@intFromBool(deny_signature), source.stats.signature_unprocessed_items);
        source.expire(2500);
        try std.testing.expectEqual(0, source.stats.expired_requests);
        try std.testing.expectEqual(0, source.peer_work[0].retry_after_ms);
        try std.testing.expectEqual(0, driver.invalid);
        try std.testing.expectEqual(16, provider.peers[0].info.load(.acquire).offset);
        try std.testing.expectEqual(16, provider.peers[1].info.load(.acquire).offset);
    }
}

test "malformed blob response cannot disconnect the shared state sync peer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var provider = try eth.Provider.init(a);
    provider.peers[0].info.store(.{ .epoch = 1, .offset = 16 }, .release);
    const Receiver = struct {
        fn ordinary(_: *anyopaque, _: intake.Record) bool {
            @panic("blob cannot enter ordinary sink");
        }
        fn available(_: *anyopaque) bool {
            return true;
        }
        fn accept(_: *anyopaque, _: intake.Handoff.Transaction) bool {
            @panic("malformed blob cannot reach owner");
        }
        fn status(_: *anyopaque, _: intake.Hash, _: i64) intake.Handoff.BlobStatus {
            return .missing;
        }
    };
    var context: u8 = 0;
    var source: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = .{
        .context = &context,
        .accept = Receiver.ordinary,
        .blobs = .{ .context = &context, .available = Receiver.available, .accept = Receiver.accept, .status = Receiver.status },
    } };
    defer source.deinit();
    // One type-3 hash, advertised size 2. Its response carries bare 03 c0.
    var announcement: [38]u8 = @splat(0);
    @memcpy(announcement[0..6], &[_]u8{ 0xe5, 0x03, 0xc1, 0x02, 0xe1, 0xa0 });
    try source.announce(a, .{ .index = 0, .epoch = 1 }, &announcement, 0);
    _ = source.nextRequest(1, 0).?;
    const payload = try a.dupe(u8, &.{ 0xc5, 0x01, 0xc3, 0x82, 0x03, 0xc0 });
    var driver: Driver = .{ .source = &source, .provider = &provider };
    driver.handle(a, .{ .msg = .{ .pooled_transactions = .{ .value = payload } }, .read = .{
        .peer = .{ .peer_index = 0, .peer_epoch = 1 },
        .id = 10,
        .payload = payload,
    } }, .{ .mono_ms = 1 });
    try std.testing.expectEqual(1, driver.invalid);
    try std.testing.expectEqual(16, provider.peers[0].info.load(.acquire).offset);
    for (source.requests) |request| try std.testing.expect(request == null);
    try std.testing.expectEqual(0, source.stats.blob_queued);
}
