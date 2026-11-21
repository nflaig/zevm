// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded, receive-only ETH/71 public transaction intake. One owning thread
//! drives this object; it neither serves transactions nor knows private orders.
//! The sink borrows canonical bytes and decoded fields only during accept().
//! State-dependent eligibility, replacement and block selection belong to the
//! builder. Blob announcements are deliberately deferred until a sidecar source
//! can authenticate availability: a bare blob transaction is never ready input.
const std = @import("std");
const rlp = @import("rlp");
const types = @import("../types.zig");
const processor = @import("../processor/processor.zig");
const hash = @import("../evm/crypto/hash.zig").keccak256;

pub const Hash = [32]u8;
pub const Peer = struct { index: usize, epoch: usize };
pub const max_announcements = 4096;
pub const max_pending = 2048;
pub const max_pending_per_peer = 256;
pub const max_peer_slots = 64;
pub const max_requests = 16;
pub const max_request_hashes = 64;
pub const max_broadcast_transactions = 256;
pub const max_tx_bytes = 128 * 1024;
pub const max_message_bytes = 2 * 1024 * 1024;
const max_seen = 8192;
const request_timeout_ms = 1500;
const pending_lifetime_ms = 10000;
const seen_lifetime_ms = 30000;

// Fixed-rate work admission, independent of advertised transaction fees. The
// observer shares a CPU with state sync and must remain bounded under signed
// junk, duplicates and peer reconnects. Budgets stay attached to peer slots.
const Bucket = struct {
    milli_tokens: u64 = 0,
    last_ms: ?i64 = null,
    fn replenish(self: *Bucket, now: i64, rate: u64, burst: u64) void {
        if (self.last_ms) |last| {
            const elapsed: u64 = @intCast(@max(0, now - last));
            self.milli_tokens = @min(burst * 1000, self.milli_tokens +| (elapsed *| rate));
            self.last_ms = @max(last, now);
        } else {
            self.milli_tokens = burst * 1000;
            self.last_ms = now;
        }
    }
};
const PeerWork = struct {
    frames: Bucket = .{},
    bytes: Bucket = .{},
    signatures: Bucket = .{},
    retry_after_ms: i64 = 0,
    timeouts: u8 = 0,
};

pub const ReceiptTime = struct { mono_ms: i64, wall_ms: ?i64 = null };

pub const Record = struct {
    hash: Hash,
    sender: u160,
    tx: types.Transaction,
    bytes: []const u8,
    peer: Peer,
    announced_at_ms: i64,
    received_at_ms: i64,
    frame_received_wall_ms: ?i64 = null,
};
pub const Sink = struct {
    context: *anyopaque,
    /// Return false under backpressure. No borrowed field may survive this call.
    accept: *const fn (*anyopaque, Record) bool,
};
pub const Request = struct {
    id: u64,
    peer: Peer,
    hashes: [max_request_hashes]Hash = undefined,
    announced: [max_request_hashes]struct { kind: u8, size: u32, at_ms: i64 } = undefined,
    count: usize = 0,
    deadline_ms: i64,
};
const Advertisement = struct { peer: Peer, kind: u8, size: u32 };
const Pending = struct {
    owner_index: usize,
    first_seen_ms: i64,
    expires_ms: i64,
    peers: [2]?Advertisement = .{ null, null },
    requested: ?u64 = null,
};
pub const Stats = struct {
    announced: u64 = 0,
    duplicate: u64 = 0,
    deferred_blobs: u64 = 0,
    unsupported: u64 = 0,
    bounded_drops: u64 = 0,
    requested: u64 = 0,
    accepted: u64 = 0,
    decoded: u64 = 0,
    sink_full: u64 = 0,
    expired_requests: u64 = 0,
    frame_rate_drops: u64 = 0,
    signature_rate_drops: u64 = 0,
    peer_pending_drops: u64 = 0,
    backoff_skips: u64 = 0,
};

pub const Intake = struct {
    allocator: std.mem.Allocator,
    chain_id: u64,
    sink: Sink,
    pending: std.AutoArrayHashMapUnmanaged(Hash, Pending) = .empty,
    seen: std.AutoArrayHashMapUnmanaged(Hash, i64) = .empty,
    requests: [max_requests]?Request = @splat(null),
    stats: Stats = .{},
    byte_budget: Bucket = .{},
    frame_budget: Bucket = .{},
    signature_budget: Bucket = .{},
    peer_work: [max_peer_slots]PeerWork = @splat(.{}),

    pub fn deinit(self: *Intake) void {
        self.pending.deinit(self.allocator);
        self.seen.deinit(self.allocator);
    }

    /// ETH/68..71 encoding, explicitly not the four-field ETH/72 message.
    /// Decode from the bounded raw frame rather than allocating an unbounded
    /// protocol array before checking counts. This arena is caller-owned.
    pub fn announce(self: *Intake, a: std.mem.Allocator, peer: Peer, raw: []const u8, now: i64) !void {
        try self.reserveFrame(peer, raw.len, now);
        if (raw.len > 192 * 1024) return error.AnnouncementByteLimit;
        const Announcement = struct { kinds: []const u8, sizes: BoundedList(u32, max_announcements), hashes: BoundedList(Hash, max_announcements) };
        var msg: Announcement = undefined;
        if (try rlp.deserialize(Announcement, a, raw, &msg) != raw.len) return error.TrailingRlp;
        if (msg.kinds.len != msg.sizes.count or msg.kinds.len != msg.hashes.count) return error.AnnouncementShape;
        if (msg.hashes.count > max_announcements) return error.AnnouncementCountLimit;
        if (msg.hashes.count == 0) return;
        for (msg.kinds, msg.sizes.slice()) |kind, size| {
            if (kind <= 4 and size == 0) return error.AnnouncementSize;
        }
        var owned: usize = 0;
        for (self.pending.values()) |entry| {
            if (entry.owner_index == peer.index) owned += 1;
        }
        for (msg.kinds, msg.sizes.slice(), msg.hashes.slice()) |kind, size, tx_hash| {
            self.stats.announced += 1;
            if (kind == 3) {
                self.stats.deferred_blobs += 1;
                continue;
            }
            if (kind > 4 or size > max_tx_bytes) {
                self.stats.unsupported += 1;
                continue;
            }
            if (self.seen.get(tx_hash)) |until| {
                if (now < until) {
                    self.stats.duplicate += 1;
                    continue;
                }
                _ = self.seen.swapRemove(tx_hash);
            }
            if (self.pending.getPtr(tx_hash)) |entry| {
                // Bind metadata to its advertiser: a dishonest first peer must
                // not poison a correct announcement from another peer.
                addPeer(entry, .{ .peer = peer, .kind = kind, .size = size });
                self.stats.duplicate += 1;
                continue;
            }
            if (self.pending.count() >= max_pending) {
                self.stats.bounded_drops += 1;
                continue;
            }
            if (owned >= max_pending_per_peer) {
                self.stats.peer_pending_drops += 1;
                self.stats.bounded_drops += 1;
                continue;
            }
            try self.pending.put(self.allocator, tx_hash, .{
                .owner_index = peer.index,
                .first_seen_ms = now,
                .expires_ms = now +| pending_lifetime_ms,
                .peers = .{ .{ .peer = peer, .kind = kind, .size = size }, null },
            });
            owned += 1;
        }
    }

    /// Reserve before sending. Call disconnect if the transport rejects a send.
    /// One request per peer prevents a busy peer from consuming every slot.
    pub fn nextRequest(self: *Intake, id: u64, now: i64) ?Request {
        var free: ?usize = null;
        for (self.requests, 0..) |request, i| {
            if (request) |existing| {
                if (existing.id == id) return null;
            }
            if (request == null) {
                free = i;
            }
        }
        const slot = free orelse return null;
        for (self.pending.values()) |entry| {
            if (entry.requested != null or now >= entry.expires_ms) continue;
            for (entry.peers) |optional_peer| {
                const peer = (optional_peer orelse continue).peer;
                if (now < self.peer_work[peer.index].retry_after_ms) {
                    self.stats.backoff_skips += 1;
                    continue;
                }
                if (self.peerBusy(peer)) continue;
                var request: Request = .{ .id = id, .peer = peer, .deadline_ms = now +| request_timeout_ms };
                var bytes: usize = 0;
                for (self.pending.keys(), self.pending.values()) |tx_hash, *candidate| {
                    if (candidate.requested != null or now >= candidate.expires_ms) continue;
                    const advertisement = getAdvertisement(candidate, peer) orelse continue;
                    if (request.count == max_request_hashes or bytes + advertisement.size > max_message_bytes) break;
                    request.hashes[request.count] = tx_hash;
                    request.announced[request.count] = .{ .kind = advertisement.kind, .size = advertisement.size, .at_ms = candidate.first_seen_ms };
                    request.count += 1;
                    bytes += advertisement.size;
                    candidate.requested = id;
                    removePeer(candidate, peer);
                }
                self.requests[slot] = request;
                self.stats.requested += request.count;
                return request;
            }
        }
        return null;
    }

    pub fn encodeRequest(a: std.mem.Allocator, request: *const Request) ![]const u8 {
        var encoded = std.array_list.Managed(u8).init(a);
        errdefer encoded.deinit();
        try rlp.serialize(struct { id: u64, hashes: []const Hash }, a, .{
            .id = request.id,
            .hashes = request.hashes[0..request.count],
        }, &encoded);
        return encoded.toOwnedSlice();
    }

    /// Validate the complete bounded response before admitting any transaction.
    /// Missing hashes are normal (peer eviction/response limits); alternatives
    /// remain eligible after this request releases its reservation.
    pub fn response(self: *Intake, a: std.mem.Allocator, peer: Peer, raw: []const u8, receipt: ReceiptTime) !void {
        const now = receipt.mono_ms;
        try self.reserveFrame(peer, raw.len, now);
        if (raw.len > max_message_bytes + 1024) return error.ResponseByteLimit;
        const Response = struct { id: u64, transactions: BoundedList(rlp.RawValue, max_request_hashes) };
        var msg: Response = undefined;
        if (try rlp.deserialize(Response, a, raw, &msg) != raw.len) return error.TrailingRlp;
        const slot = self.findRequest(peer, msg.id) orelse return error.UnsolicitedResponse;
        const request = self.requests[slot].?;
        defer self.release(slot);
        if (now >= request.deadline_ms) return error.ExpiredResponse;
        if (msg.transactions.count > request.count) return error.ResponseCountLimit;
        var records: [max_request_hashes]Record = undefined;
        var record_count: usize = 0;
        var cursor: usize = 0;
        for (msg.transactions.slice()) |raw_tx| {
            const bytes = try canonicalBytes(a, raw_tx.value);
            const tx_hash = hash(bytes);
            while (cursor < request.count and !std.mem.eql(u8, &request.hashes[cursor], &tx_hash)) : (cursor += 1) {}
            if (cursor == request.count) return error.UnrequestedTransaction;
            const entry = request.announced[cursor];
            cursor += 1;
            if (bytes.len != entry.size or transactionKind(bytes) != entry.kind) return error.AnnouncementMismatch;
            if (self.known(tx_hash, now)) {
                self.stats.duplicate += 1;
                continue;
            }
            try self.reserveSignature(peer, now);
            records[record_count] = try decodeRecord(a, self.chain_id, peer, bytes, entry.at_ms, now);
            records[record_count].frame_received_wall_ms = receipt.wall_ms;
            record_count += 1;
            self.stats.decoded += 1;
        }
        for (records[0..record_count]) |record| try self.deliver(record, now);
        self.peer_work[peer.index].timeouts = 0;
        self.peer_work[peer.index].retry_after_ms = 0;
    }

    /// Full public Transactions gossip. These records use receive time for the
    /// announcement timestamp; unsolicited blob broadcasts are rejected.
    pub fn broadcast(self: *Intake, a: std.mem.Allocator, peer: Peer, raw: []const u8, receipt: ReceiptTime) !void {
        const now = receipt.mono_ms;
        try self.reserveFrame(peer, raw.len, now);
        if (raw.len > max_message_bytes) return error.ResponseByteLimit;
        var msg: BoundedList(rlp.RawValue, max_broadcast_transactions) = undefined;
        if (try rlp.deserialize(@TypeOf(msg), a, raw, &msg) != raw.len) return error.TrailingRlp;
        const txs = msg.slice();
        var records: [max_broadcast_transactions]Record = undefined;
        var count: usize = 0;
        for (txs) |tx| {
            const bytes = try canonicalBytes(a, tx.value);
            const tx_hash = hash(bytes);
            var duplicate = self.known(tx_hash, now);
            if (!duplicate) for (records[0..count]) |record| {
                if (std.mem.eql(u8, &record.hash, &tx_hash)) {
                    duplicate = true;
                    break;
                }
            };
            if (duplicate) {
                self.stats.duplicate += 1;
                continue;
            }
            try self.reserveSignature(peer, now);
            records[count] = try decodeRecord(a, self.chain_id, peer, bytes, now, now);
            records[count].frame_received_wall_ms = receipt.wall_ms;
            count += 1;
            self.stats.decoded += 1;
        }
        for (records[0..count]) |record| try self.deliver(record, now);
    }

    fn known(self: *const Intake, tx_hash: Hash, now: i64) bool {
        return now < (self.seen.get(tx_hash) orelse return false);
    }

    fn reserveFrame(self: *Intake, peer: Peer, bytes: usize, now: i64) !void {
        if (peer.index >= max_peer_slots) return error.PeerSlotLimit;
        const local = &self.peer_work[peer.index].bytes;
        const local_frames = &self.peer_work[peer.index].frames;
        self.byte_budget.replenish(now, 4 * 1024 * 1024, 4 * 1024 * 1024);
        local.replenish(now, 1024 * 1024, max_message_bytes + 1024);
        self.frame_budget.replenish(now, 512, 256);
        local_frames.replenish(now, 128, 128);
        const cost: u64 = @as(u64, @intCast(bytes)) *| 1000;
        if (self.frame_budget.milli_tokens < 1000 or local_frames.milli_tokens < 1000 or self.byte_budget.milli_tokens < cost or local.milli_tokens < cost) {
            self.stats.frame_rate_drops += 1;
            return error.FrameRateLimit;
        }
        self.byte_budget.milli_tokens -= cost;
        local.milli_tokens -= cost;
        self.frame_budget.milli_tokens -= 1000;
        local_frames.milli_tokens -= 1000;
    }

    fn reserveSignature(self: *Intake, peer: Peer, now: i64) !void {
        const local = &self.peer_work[peer.index].signatures;
        self.signature_budget.replenish(now, 256, 256);
        local.replenish(now, 64, 256);
        if (self.signature_budget.milli_tokens < 1000 or local.milli_tokens < 1000) {
            self.stats.signature_rate_drops += 1;
            return error.SignatureRateLimit;
        }
        self.signature_budget.milli_tokens -= 1000;
        local.milli_tokens -= 1000;
    }

    fn deliver(self: *Intake, record: Record, now: i64) !void {
        if (self.seen.get(record.hash)) |until| {
            if (now < until) {
                self.stats.duplicate += 1;
                return;
            }
        }
        // Reserve bookkeeping before invoking the sink, so successful delivery
        // cannot be followed by an allocation failure and accidental redelivery.
        try self.seen.ensureUnusedCapacity(self.allocator, 1);
        if (!self.sink.accept(self.sink.context, record)) {
            self.stats.sink_full += 1;
            return;
        }
        if (self.seen.count() == max_seen) self.seen.swapRemoveAt(0);
        self.seen.putAssumeCapacity(record.hash, now +| seen_lifetime_ms);
        _ = self.pending.swapRemove(record.hash);
        self.stats.accepted += 1;
    }

    pub fn expire(self: *Intake, now: i64) void {
        for (self.requests, 0..) |request, i| if (request) |req| {
            if (now >= req.deadline_ms) {
                const work = &self.peer_work[req.peer.index];
                work.timeouts = @min(5, work.timeouts + 1);
                const delay = @min(@as(i64, 10000), @as(i64, 1000) << @as(u6, @intCast(work.timeouts - 1)));
                work.retry_after_ms = now +| delay;
                self.release(i);
                self.stats.expired_requests += 1;
            }
        };
        var i: usize = 0;
        while (i < self.pending.count()) {
            const entry = self.pending.values()[i];
            if (entry.requested == null and (now >= entry.expires_ms or (entry.peers[0] == null and entry.peers[1] == null))) {
                self.pending.swapRemoveAt(i);
            } else i += 1;
        }
        i = 0;
        while (i < self.seen.count()) {
            if (now >= self.seen.values()[i]) self.seen.swapRemoveAt(i) else i += 1;
        }
    }

    pub fn disconnect(self: *Intake, peer: Peer) void {
        for (self.requests, 0..) |request, i| if (request) |req| {
            if (samePeer(peer, req.peer)) self.release(i);
        };
        for (self.pending.values()) |*entry| removePeer(entry, peer);
    }

    fn release(self: *Intake, slot: usize) void {
        const request = self.requests[slot].?;
        for (request.hashes[0..request.count]) |tx_hash| {
            if (self.pending.getPtr(tx_hash)) |entry| {
                if (entry.requested == request.id) {
                    entry.requested = null;
                    // Re-announcements during a stalled request must not put
                    // that same peer ahead of the retained alternative again.
                    removePeer(entry, request.peer);
                }
            }
        }
        self.requests[slot] = null;
    }
    fn findRequest(self: *const Intake, peer: Peer, id: u64) ?usize {
        for (self.requests, 0..) |request, i| if (request) |req| {
            if (req.id == id and samePeer(peer, req.peer)) return i;
        };
        return null;
    }
    fn peerBusy(self: *const Intake, peer: Peer) bool {
        for (self.requests) |request| if (request) |req| {
            if (samePeer(peer, req.peer)) return true;
        };
        return false;
    }
};

fn samePeer(a: Peer, b: Peer) bool {
    return a.index == b.index and a.epoch == b.epoch;
}
fn getAdvertisement(entry: *const Pending, peer: Peer) ?Advertisement {
    for (entry.peers) |p| if (p) |candidate| {
        if (samePeer(candidate.peer, peer)) return candidate;
    };
    return null;
}
fn addPeer(entry: *Pending, advertisement: Advertisement) void {
    if (getAdvertisement(entry, advertisement.peer) != null) return;
    for (&entry.peers) |*p| if (p.* == null) {
        p.* = advertisement;
        return;
    };
}
fn removePeer(entry: *Pending, peer: Peer) void {
    for (&entry.peers) |*p| if (p.*) |candidate| {
        if (samePeer(candidate.peer, peer)) p.* = null;
    };
}

fn transactionKind(bytes: []const u8) u8 {
    return if (bytes[0] >= 0xc0) 0 else bytes[0];
}
fn canonicalBytes(a: std.mem.Allocator, raw: []const u8) ![]const u8 {
    if (raw.len == 0) return error.EmptyTransaction;
    if (raw[0] >= 0xc0) {
        if (raw.len > max_tx_bytes) return error.TransactionByteLimit;
        return raw;
    }
    // Typed transactions are byte strings in the ETH message's RLP list.
    if (raw[0] < 0x80) return error.InvalidTypedWrapper;
    var bytes: []const u8 = undefined;
    if (try rlp.deserialize([]const u8, a, raw, &bytes) != raw.len) return error.TrailingRlp;
    if (bytes.len == 0) return error.EmptyTransaction;
    if (bytes.len > max_tx_bytes) return error.TransactionByteLimit;
    if (bytes[0] == 0 or bytes[0] >= 0x80) return error.InvalidTypedWrapper;
    return bytes;
}

fn decodeRecord(a: std.mem.Allocator, chain_id: u64, peer: Peer, bytes: []const u8, announced: i64, now: i64) !Record {
    const kind = transactionKind(bytes);
    if (kind == 3) return error.BlobSidecarRequired;
    if (kind > 4) return error.UnsupportedTransaction;
    var tx: types.Transaction = undefined;
    const consumed = try tx.decodeFromRLP(a, bytes);
    if (consumed + @intFromBool(kind != 0) != bytes.len) return error.TrailingTransaction;
    // The upstream decoder accepts optional empty recipients in either list or
    // string form. Canonical round-trip also catches that ambiguity at intake.
    var encoded = std.array_list.Managed(u8).init(a);
    defer encoded.deinit();
    if (kind != 0) try encoded.append(kind);
    switch (tx) {
        inline else => |value| {
            if (value.gas_limit == 0) return error.ZeroGasLimit;
            if (@hasField(@TypeOf(value), "gas_priority_fee") and value.gas_priority_fee > value.gas_price) return error.PriorityAboveFeeCap;
            try rlp.serialize(@TypeOf(value), a, value, &encoded);
        },
    }
    if (!std.mem.eql(u8, bytes, encoded.items)) return error.NonCanonicalTransaction;
    return .{
        .hash = hash(bytes),
        .sender = try processor.recoverTxSender(a, &tx, chain_id),
        .tx = tx,
        .bytes = bytes,
        .peer = peer,
        .announced_at_ms = announced,
        .received_at_ms = now,
    };
}

/// Bounded wire arrays reject excess items before allocating or decoding them.
fn BoundedList(comptime T: type, comptime maximum: usize) type {
    return struct {
        items: [maximum]T = undefined,
        count: usize = 0,
        fn slice(self: *const @This()) []const T {
            return self.items[0..self.count];
        }
        pub fn decodeFromRLP(self: *@This(), a: std.mem.Allocator, serialized: []const u8) !usize {
            if (serialized.len == 0 or serialized[0] < 0xc0) return error.NotAnRLPList;
            var container: rlp.RawValue = undefined;
            const consumed = try rlp.deserialize(rlp.RawValue, a, serialized, &container);
            const prefix = serialized[0];
            const start: usize = if (prefix <= 0xf7) 1 else 1 + @as(usize, prefix - 0xf7);
            var offset = start;
            self.count = 0;
            while (offset < consumed) {
                if (self.count == maximum) return error.WireItemLimit;
                offset += try rlp.deserialize(T, a, serialized[offset..consumed], &self.items[self.count]);
                self.count += 1;
            }
            return consumed;
        }
    };
}

const fixture_hex = "f860800a830186a0941257767465d91292f29c15df1e25e063daed8b59808026a0a7eaaef383a6b7fc7192d2adbdaf0331b4d82f352f89956ce8be97e9fe5d0590a01a5ae493968f37d3462cdca0d30f0e3bb4799025e48682bcb1eefe152c847d52";
const peer_a: Peer = .{ .index = 1, .epoch = 2 };
const peer_b: Peer = .{ .index = 2, .epoch = 2 };
const Recorder = struct {
    count: usize = 0,
    full: bool = false,
    last_hash: Hash = undefined,
    last_announced: i64 = 0,
    last_received_wall: ?i64 = null,
    fn accept(ctx: *anyopaque, record: Record) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.full) return false;
        self.count += 1;
        self.last_hash = record.hash;
        self.last_announced = record.announced_at_ms;
        self.last_received_wall = record.frame_received_wall_ms;
        return true;
    }
    fn sink(self: *@This()) Sink {
        return .{ .context = self, .accept = accept };
    }
};
fn fixture(a: std.mem.Allocator) ![]const u8 {
    const bytes = try a.alloc(u8, fixture_hex.len / 2);
    return std.fmt.hexToBytes(bytes, fixture_hex);
}
fn encode(a: std.mem.Allocator, value: anytype) ![]const u8 {
    var bytes = std.array_list.Managed(u8).init(a);
    errdefer bytes.deinit();
    try rlp.serialize(@TypeOf(value), a, value, &bytes);
    return bytes.toOwnedSlice();
}
fn announceOne(a: std.mem.Allocator, bytes: []const u8, kind: u8) ![]const u8 {
    return encode(a, .{ @as([]const u8, &.{kind}), @as([]const u32, &.{@intCast(bytes.len)}), @as([]const Hash, &.{hash(bytes)}) });
}
fn responseOne(a: std.mem.Allocator, id: u64, bytes: []const u8) ![]const u8 {
    const wrapped = if (bytes[0] >= 0xc0) bytes else try encode(a, bytes);
    return encode(a, .{ id, @as([]const rlp.RawValue, &.{.{ .value = wrapped }}) });
}

test "public intake authenticates an announced transaction and deduplicates both peer paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    const announcement = try announceOne(a, bytes, 0);
    try intake.announce(a, peer_a, announcement, 100);
    try intake.announce(a, peer_b, announcement, 101);
    try std.testing.expectEqual(1, intake.pending.count());
    const request = intake.nextRequest(11, 102).?;
    try std.testing.expectEqual(1, request.count);
    try std.testing.expect(intake.nextRequest(12, 102) == null);
    try intake.response(a, peer_a, try responseOne(a, 11, bytes), .{ .mono_ms = 110, .wall_ms = 12345 });
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expectEqual(hash(bytes), recorder.last_hash);
    try std.testing.expectEqual(100, recorder.last_announced);
    try std.testing.expectEqual(@as(?i64, 12345), recorder.last_received_wall);
    const broadcast = try encode(a, @as([]const rlp.RawValue, &.{.{ .value = bytes }}));
    try intake.broadcast(a, peer_b, broadcast, .{ .mono_ms = 111 });
    try intake.announce(a, peer_b, announcement, 112);
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expect(intake.nextRequest(13, 113) == null);
    try std.testing.expectEqual(1, intake.stats.decoded);
}

test "public intake peer epochs request ids and timeout fallback are bound" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    const announcement = try announceOne(a, bytes, 0);
    try intake.announce(a, peer_a, announcement, 0);
    try intake.announce(a, peer_b, announcement, 0);
    _ = intake.nextRequest(1, 1).?;
    try intake.announce(a, peer_a, announcement, 2);
    try std.testing.expectError(error.UnsolicitedResponse, intake.response(a, .{ .index = peer_a.index, .epoch = 3 }, try responseOne(a, 1, bytes), .{ .mono_ms = 2 }));
    try std.testing.expectError(error.UnsolicitedResponse, intake.response(a, peer_a, try responseOne(a, 2, bytes), .{ .mono_ms = 2 }));
    intake.expire(1501);
    const retry = intake.nextRequest(2, 1502).?;
    try std.testing.expectEqual(peer_b, retry.peer);
    try std.testing.expectError(error.UnsolicitedResponse, intake.response(a, peer_a, try responseOne(a, 1, bytes), .{ .mono_ms = 1503 }));
    try intake.response(a, peer_b, try responseOne(a, 2, bytes), .{ .mono_ms = 1504 });
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expectEqual(1, intake.stats.expired_requests);
}

test "public intake empty response disconnect and sink pressure allow another peer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{ .full = true };
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    const announcement = try announceOne(a, bytes, 0);
    try intake.announce(a, peer_a, announcement, 0);
    try intake.announce(a, peer_b, announcement, 0);
    _ = intake.nextRequest(1, 1).?;
    try intake.response(a, peer_a, try encode(a, .{ @as(u64, 1), @as([]const rlp.RawValue, &.{}) }), .{ .mono_ms = 2 });
    try std.testing.expectEqual(peer_b, intake.nextRequest(2, 3).?.peer);
    try intake.response(a, peer_b, try responseOne(a, 2, bytes), .{ .mono_ms = 4 });
    try std.testing.expectEqual(0, recorder.count);
    try std.testing.expectEqual(0, intake.seen.count());
    try intake.announce(a, peer_a, announcement, 5);
    _ = intake.nextRequest(3, 6).?;
    intake.disconnect(peer_a);
    try intake.announce(a, peer_b, announcement, 7);
    recorder.full = false;
    _ = intake.nextRequest(4, 8).?;
    try intake.response(a, peer_b, try responseOne(a, 4, bytes), .{ .mono_ms = 9 });
    try std.testing.expectEqual(1, recorder.count);
}

test "public intake deferred blobs and wire shape bounds do not create requests" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    try intake.announce(a, peer_a, try announceOne(a, bytes, 3), 0);
    try std.testing.expectEqual(1, intake.stats.deferred_blobs);
    try std.testing.expectEqual(0, intake.pending.count());
    const malformed = try encode(a, .{ @as([]const u8, &.{ 0, 0 }), @as([]const u32, &.{1}), @as([]const Hash, &.{hash(bytes)}) });
    try std.testing.expectError(error.AnnouncementShape, intake.announce(a, peer_a, malformed, 1));
    const oversized = try a.alloc(u8, 192 * 1024 + 1);
    try std.testing.expectError(error.AnnouncementByteLimit, intake.announce(a, peer_a, oversized, 1));
    const sizes = try a.alloc(u32, max_announcements + 1);
    @memset(sizes, 1);
    const over_count = try encode(a, .{ @as([]const u8, &.{}), @as([]const u32, sizes), @as([]const Hash, &.{}) });
    try std.testing.expectError(error.WireItemLimit, intake.announce(a, peer_a, over_count, 1));
    try std.testing.expectEqual(0, intake.pending.count());
}

test "public intake rejects wrong chain invalid signature noncanonical and trailing bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = try fixture(a);
    try std.testing.expectError(error.InvalidChainId, decodeRecord(a, 2, peer_a, bytes, 0, 1));
    const trailing = try std.mem.concat(a, u8, &.{ bytes, &.{0} });
    try std.testing.expectError(error.TrailingTransaction, decodeRecord(a, 1, peer_a, trailing, 0, 1));
    var tx: types.Transaction = undefined;
    _ = try tx.decodeFromRLP(a, bytes);
    tx.legacy.s = 0;
    try std.testing.expectError(error.InvalidSignature, decodeRecord(a, 1, peer_a, try encode(a, tx.legacy), 0, 1));
    tx.legacy.to = null;
    const noncanonical = try a.dupe(u8, try encode(a, tx.legacy));
    var fields: BoundedList(rlp.RawValue, 9) = undefined;
    _ = try fields.decodeFromRLP(a, noncanonical);
    const offset = @intFromPtr(fields.items[3].value.ptr) - @intFromPtr(noncanonical.ptr);
    noncanonical[offset] = 0xc0;
    try std.testing.expectError(error.NonCanonicalTransaction, decodeRecord(a, 1, peer_a, noncanonical, 0, 1));
}

test "public intake invalid response does not partially reach sink" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    const wrong = try a.dupe(u8, bytes);
    wrong[wrong.len - 1] ^= 1;
    const announcement = try encode(a, .{ @as([]const u8, &.{ 0, 0 }), @as([]const u32, &.{ @intCast(bytes.len), @intCast(wrong.len) }), @as([]const Hash, &.{ hash(bytes), @splat(0x99) }) });
    try intake.announce(a, peer_a, announcement, 0);
    _ = intake.nextRequest(1, 1).?;
    const response = try encode(a, .{ @as(u64, 1), @as([]const rlp.RawValue, &.{ .{ .value = bytes }, .{ .value = wrong } }) });
    try std.testing.expectError(error.UnrequestedTransaction, intake.response(a, peer_a, response, .{ .mono_ms = 2 }));
    try std.testing.expectEqual(0, recorder.count);
}

test "public intake broadcast racing a pooled response stays idempotent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    try intake.announce(a, peer_a, try announceOne(a, bytes, 0), 0);
    _ = intake.nextRequest(1, 1).?;
    try intake.broadcast(a, peer_b, try encode(a, @as([]const rlp.RawValue, &.{.{ .value = bytes }})), .{ .mono_ms = 2 });
    try intake.response(a, peer_a, try responseOne(a, 1, bytes), .{ .mono_ms = 3 });
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expectEqual(1, intake.stats.decoded);
}

test "public intake bounds inventories and per-peer request concurrency" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const kinds = try a.alloc(u8, max_announcements);
    const sizes = try a.alloc(u32, max_announcements);
    const hashes = try a.alloc(Hash, max_announcements);
    @memset(kinds, 0);
    @memset(sizes, 100);
    for (hashes, 0..) |*item, i| std.mem.writeInt(u256, item, i, .big);
    const announcement = try encode(a, .{ @as([]const u8, kinds), @as([]const u32, sizes), @as([]const Hash, hashes) });
    try intake.announce(a, peer_a, announcement, 0);
    try std.testing.expectEqual(max_pending_per_peer, intake.pending.count());
    try std.testing.expectEqual(max_announcements - max_pending_per_peer, intake.stats.bounded_drops);
    try std.testing.expectEqual(max_request_hashes, intake.nextRequest(1, 1).?.count);
    // The remaining queued hashes cannot create a second request to this peer.
    try std.testing.expect(intake.nextRequest(2, 1) == null);
    intake.disconnect(peer_a);
    intake.expire(2);
    try std.testing.expectEqual(0, intake.pending.count());
    for (0..max_requests + 1) |i| {
        const peer: Peer = .{ .index = i + 10, .epoch = 1 };
        const one = try encode(a, .{ @as([]const u8, &.{0}), @as([]const u32, &.{100}), @as([]const Hash, hashes[i .. i + 1]) });
        try intake.announce(a, peer, one, 3);
    }
    for (0..max_requests) |i| try std.testing.expect(intake.nextRequest(i + 2, 4) != null);
    try std.testing.expect(intake.nextRequest(100, 4) == null);
    intake.expire(10004);
    try std.testing.expectEqual(0, intake.pending.count());
}

test "public intake accepts canonical typed wire wrappers and rejects bare typed broadcasts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Existing upstream typed transaction vector, with actual sender recovery.
    const typed_hex = "01f89b01800a8301e974943985d8b9eda311b84b1e2fbf91f04e7a6454c0638080f838f7943985d8b9eda311b84b1e2fbf91f04e7a6454bf63e1a0000000000000000000000000000000000000000000000000000000000000000001a005ee32c650fc04868b37df068031089e862bc0544bbbce0f54d5320b764453e8a021700a8028a27f20f344c19cbca030b47c66c011707c889b5808997002202155";
    const bytes = try std.fmt.hexToBytes(try a.alloc(u8, typed_hex.len / 2), typed_hex);
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    try intake.announce(a, peer_a, try announceOne(a, bytes, 1), 0);
    _ = intake.nextRequest(1, 1).?;
    try intake.response(a, peer_a, try responseOne(a, 1, bytes), .{ .mono_ms = 2 });
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expectEqual(hash(bytes), recorder.last_hash);
    try std.testing.expectError(error.InvalidTypedWrapper, canonicalBytes(a, bytes));
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    try intake.announce(a, peer_a, try announceOne(a, bytes, 0), 0);
    const request = intake.nextRequest(1, 1).?;
    _ = try Intake.encodeRequest(a, &request);
    try intake.response(a, peer_a, try responseOne(a, 1, bytes), .{ .mono_ms = 2 });
    try std.testing.expectEqual(1, recorder.count);
}

test "public intake allocation failures release owned inventories and scratch" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

test "public intake dishonest announcement metadata cannot poison a second peer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    const wrong = try encode(a, .{ @as([]const u8, &.{0}), @as([]const u32, &.{@intCast(bytes.len + 1)}), @as([]const Hash, &.{hash(bytes)}) });
    try intake.announce(a, peer_a, wrong, 0);
    try intake.announce(a, peer_b, try announceOne(a, bytes, 0), 1);
    _ = intake.nextRequest(1, 2).?;
    try std.testing.expectError(error.AnnouncementMismatch, intake.response(a, peer_a, try responseOne(a, 1, bytes), .{ .mono_ms = 3 }));
    const retry = intake.nextRequest(2, 4).?;
    try std.testing.expectEqual(peer_b, retry.peer);
    try intake.response(a, peer_b, try responseOne(a, 2, bytes), .{ .mono_ms = 5 });
    try std.testing.expectEqual(1, recorder.count);
}

test "public intake limits work before parsing or signature recovery" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    intake.byte_budget = .{ .last_ms = 0, .milli_tokens = 0 };
    try std.testing.expectError(error.FrameRateLimit, intake.announce(a, peer_a, &.{0xff}, 0));
    try std.testing.expectEqual(0, intake.pending.count());
    intake.byte_budget = .{};
    intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 0 };
    const bytes = try fixture(a);
    const broadcast = try encode(a, @as([]const rlp.RawValue, &.{.{ .value = bytes }}));
    try std.testing.expectError(error.SignatureRateLimit, intake.broadcast(a, peer_a, broadcast, .{ .mono_ms = 0 }));
    try std.testing.expectEqual(0, intake.stats.decoded);
    try std.testing.expectEqual(0, recorder.count);
    try intake.broadcast(a, peer_a, broadcast, .{ .mono_ms = 4 });
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expectEqual(1, intake.stats.frame_rate_drops);
    try std.testing.expectEqual(1, intake.stats.signature_rate_drops);
}

test "public intake signature rate is global and peer scoped across reconnects" {
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    for (0..256) |_| try intake.reserveSignature(peer_a, 0);
    try std.testing.expectError(error.SignatureRateLimit, intake.reserveSignature(peer_b, 0));
    const reconnected: Peer = .{ .index = peer_a.index, .epoch = peer_a.epoch + 1 };
    for (0..64) |_| try intake.reserveSignature(reconnected, 1000);
    try std.testing.expectError(error.SignatureRateLimit, intake.reserveSignature(reconnected, 1000));
    for (0..192) |_| try intake.reserveSignature(peer_b, 1000);
    try std.testing.expectError(error.SignatureRateLimit, intake.reserveSignature(.{ .index = 3, .epoch = 1 }, 1000));
}

test "public intake bounds tiny frame floods before inventory scans" {
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const empty_announcement = &[_]u8{ 0xc3, 0x80, 0xc0, 0xc0 };
    for (0..128) |_| try intake.announce(std.testing.allocator, peer_a, empty_announcement, 0);
    try std.testing.expectError(error.FrameRateLimit, intake.announce(std.testing.allocator, peer_a, empty_announcement, 0));
    for (0..128) |_| try intake.announce(std.testing.allocator, peer_b, empty_announcement, 0);
    try std.testing.expectError(error.FrameRateLimit, intake.announce(std.testing.allocator, .{ .index = 3, .epoch = 1 }, empty_announcement, 0));
    try intake.announce(std.testing.allocator, peer_a, empty_announcement, 1000);
    try std.testing.expectEqual(2, intake.stats.frame_rate_drops);
    try std.testing.expectEqual(0, intake.pending.count());
}

test "public intake peer inventory cannot monopolize pending capacity or renew its expiry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const kinds = try a.alloc(u8, max_pending_per_peer + 1);
    const sizes = try a.alloc(u32, kinds.len);
    const hashes = try a.alloc(Hash, kinds.len);
    @memset(kinds, 0);
    @memset(sizes, 100);
    for (hashes, 0..) |*item, i| std.mem.writeInt(u256, item, i, .big);
    const announcement = try encode(a, .{ @as([]const u8, kinds), @as([]const u32, sizes), @as([]const Hash, hashes) });
    try intake.announce(a, peer_a, announcement, 0);
    try intake.announce(a, peer_a, announcement, 100);
    try std.testing.expectEqual(max_pending_per_peer, intake.pending.count());
    try std.testing.expectEqual(pending_lifetime_ms, intake.pending.values()[0].expires_ms);
    const other = try encode(a, .{ @as([]const u8, &.{0}), @as([]const u32, &.{100}), @as([]const Hash, &.{@splat(0xee)}) });
    try intake.announce(a, peer_b, other, 101);
    try std.testing.expectEqual(max_pending_per_peer + 1, intake.pending.count());
    try std.testing.expectEqual(2, intake.stats.peer_pending_drops);
}

test "public intake timed out sources back off while an alternate can supply the transaction" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    const announcement = try announceOne(a, bytes, 0);
    try intake.announce(a, peer_a, announcement, 0);
    _ = intake.nextRequest(1, 1).?;
    intake.expire(1501);
    try intake.announce(a, peer_a, announcement, 1502);
    try std.testing.expect(intake.nextRequest(2, 1502) == null);
    try intake.announce(a, peer_b, announcement, 1503);
    try std.testing.expectEqual(peer_b, intake.nextRequest(3, 1504).?.peer);
    try intake.response(a, peer_b, try responseOne(a, 3, bytes), .{ .mono_ms = 1505 });
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expect(intake.stats.backoff_skips > 0);
}

// Generated independently with eth-account, fixed public test key 0x...01.
const typed2_hex = "02f8630180020a830186a09411111111111111111111111111111111111111118080c080a05f03a658ba564255214fbb83eb0145422acd9b711cd72f241491730e9fecae78a07a6381b231454cfa93bfe68dfde6f7eaa3dfb46a0b1871288c6942a49fbfe63f";
const typed4_hex = "04f8c10180020a830186a09411111111111111111111111111111111111111118080c0f85cf85a019422222222222222222222222222222222222222228001a0c27c1249fd3d7ee36517d19114c6c8e000eeefd0a639151bc23714ce0894ad99a05a9e7f8df557a9d4e251d04d8794a5cbf28d6899143fd2e96513dfb1a7a673b201a01bf6d2026626ce72634289509661c9410e43db01e9b12736a6fcc3387fc5643da07830e757fee7b604ee6f1b4322ccf39c481c460c922a6ff793f7168e864262e8";
const unprotected_hex = "f860800a830186a094111111111111111111111111111111111111111180801ba0fd5ff746b577955f66ff87dc622cb8123360cf1200d603fcf8f450c0fe9d3d6fa06d470bc9178a177c70d69c8ced7d78bd6c789e697de75433059bbb8bb7fb92b7";
const large_chain_hex = "f865800a830186a0941111111111111111111111111111111111111111808085034d519900a0abe4afc7fd9735b72aed8a126c2838fd768e563f6ff1ed2dbbc3664e2672bfaaa00ffbef189d44568bd39d3c92cbe84e1de52e92c02d8f3993894676d93f22ab0a";
const test_sender: u160 = 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf;

fn unhex(a: std.mem.Allocator, value: []const u8) ![]const u8 {
    return std.fmt.hexToBytes(try a.alloc(u8, value.len / 2), value);
}

test "public intake independently signed type2 type4 and legacy variants recover the expected sender" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{ typed2_hex, typed4_hex, unprotected_hex }) |value| {
        const bytes = try unhex(a, value);
        const record = try decodeRecord(a, 1, peer_a, bytes, 0, 1);
        try std.testing.expectEqual(test_sender, record.sender);
        if (bytes[0] < 0x80) try std.testing.expectError(error.InvalidChainId, decodeRecord(a, 11155111, peer_a, bytes, 0, 1));
    }
    const unprotected = try unhex(a, unprotected_hex);
    try std.testing.expectEqual(test_sender, (try decodeRecord(a, 7091047534, peer_a, unprotected, 0, 1)).sender);
    const large_chain = try unhex(a, large_chain_hex);
    try std.testing.expectEqual(test_sender, (try decodeRecord(a, 7091047534, peer_a, large_chain, 0, 1)).sender);
    try std.testing.expectError(error.InvalidChainId, decodeRecord(a, 1, peer_a, large_chain, 0, 1));
    var tx: types.Transaction = undefined;
    _ = try tx.decodeFromRLP(a, unprotected);
    tx.legacy.s = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - tx.legacy.s;
    tx.legacy.v = if (tx.legacy.v == 27) 28 else 27;
    try std.testing.expectError(error.InvalidSignature, decodeRecord(a, 1, peer_a, try encode(a, tx.legacy), 0, 1));
}

fn typedAllocationCase(allocator: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    for ([_][]const u8{ typed2_hex, typed4_hex }, 0..) |value, i| {
        const bytes = try unhex(a, value);
        try intake.announce(a, peer_a, try announceOne(a, bytes, bytes[0]), 0);
        _ = intake.nextRequest(i, 1).?;
        try intake.response(a, peer_a, try responseOne(a, i, bytes), .{ .mono_ms = 2 });
    }
    try std.testing.expectEqual(2, recorder.count);
}

test "public intake typed ownership survives every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, typedAllocationCase, .{});
}
