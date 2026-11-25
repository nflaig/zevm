// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded, receive-only ETH/71 public transaction intake. One owning thread
//! drives this object; it neither serves transactions nor knows private orders.
//! The sink borrows canonical bytes and decoded fields only during accept().
//! State-dependent eligibility, replacement and block selection belong to the
//! builder. Blob requests require an optional prewarmed owning verifier. A copied
//! wrapper is pending, never ready until that verifier authenticates all sidecars.
const std = @import("std");
const rlp = @import("rlp");
const types = @import("../types.zig");
const processor = @import("../processor/processor.zig");
const hash = @import("../evm/crypto/hash.zig").keccak256;
const BlobWire = @import("public_blob.zig");

pub const Hash = [32]u8;
pub const Peer = struct { index: usize, epoch: usize };
pub const max_announcements = 4096;
pub const max_pending = 2048;
pub const max_pending_per_peer = 256;
pub const max_peer_slots = 64;
pub const max_requests = 16;
pub const max_request_hashes = 64;
pub const max_broadcast_transactions = 256;
pub const max_tx_bytes: usize = 128 * 1024;
pub const max_message_bytes: usize = 2 * 1024 * 1024;
pub const max_blob_requests = 2;
pub const max_blob_verifications = 4;
pub const max_pending_blobs = 128;
pub const max_pending_blobs_per_peer = 32;
const verification_timeout_ms = 10000;
const blob_retry_ms = 250;
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
    blob_bytes: Bucket = .{},
    blob_requests: Bucket = .{},
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
    status: ?*const fn (*anyopaque, Hash, i64) Handoff.AdmissionStatus = null,
    blobs: ?Handoff.BlobSink = null,
};
pub const Handoff = @import("public_handoff.zig");
/// Adapt the validated peer sink to engine-independent fields. The Handoff.Sink
/// owner must outlive Intake; no decoded transaction or frame borrow escapes.
pub fn handoffSink(target: *Handoff.Sink) Sink {
    return .{ .context = target, .blobs = target.blobs, .status = if (target.status != null) struct {
        fn status(ctx: *anyopaque, tx_hash: Hash, now: i64) Handoff.AdmissionStatus {
            const sink: *Handoff.Sink = @ptrCast(@alignCast(ctx));
            return sink.status.?(sink.context, tx_hash, now);
        }
    }.status else null, .accept = struct {
        fn accept(ctx: *anyopaque, record: Record) bool {
            const sink: *Handoff.Sink = @ptrCast(@alignCast(ctx));
            return sink.accept(sink.context, .{
                .hash = record.hash,
                .bytes = record.bytes,
                .peer = .{ .index = record.peer.index, .epoch = record.peer.epoch },
                .announced_at_ms = record.announced_at_ms,
                .received_at_ms = record.received_at_ms,
                .frame_received_wall_ms = record.frame_received_wall_ms,
            });
        }
    }.accept };
}
pub const Request = struct {
    id: u64,
    peer: Peer,
    hashes: [max_request_hashes]Hash = undefined,
    announced: [max_request_hashes]struct { kind: u8, size: u32, at_ms: i64 } = undefined,
    count: usize = 0,
    deadline_ms: i64,
    blob: bool = false,
};
const Advertisement = struct { peer: Peer, kind: u8, size: u32 };
const Pending = struct {
    owner_index: usize,
    first_seen_ms: i64,
    expires_ms: i64,
    peers: [2]?Advertisement = .{ null, null },
    requested: ?u64 = null,
    blob: bool = false,
    blob_owner_index: usize = 0,
    verifying: bool = false,
    retry_after_ms: i64 = 0,
    retry_advertisement: ?Advertisement = null,
};
const Verification = struct { hash: Hash, deadline_ms: i64 };
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
    frame_refused_requests: u64 = 0,
    signature_rate_drops: u64 = 0,
    signature_preserved_decoded: u64 = 0,
    signature_discarded_decoded: u64 = 0,
    signature_unprocessed_items: u64 = 0,
    peer_pending_drops: u64 = 0,
    backoff_skips: u64 = 0,
    blob_inventory_drops: u64 = 0,
    blob_requested: u64 = 0,
    blob_queued: u64 = 0,
    blob_ready: u64 = 0,
    blob_failed: u64 = 0,
    blob_sink_full: u64 = 0,
    blob_request_rate_drops: u64 = 0,
    blob_frame_rate_drops: u64 = 0,
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
    blob_byte_budget: Bucket = .{},
    blob_request_budget: Bucket = .{},
    verifications: [max_blob_verifications]?Verification = @splat(null),
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
        var blob_owned: usize = 0;
        var blob_total: usize = 0;
        for (self.pending.values()) |entry| {
            if (entry.owner_index == peer.index) owned += 1;
            if (entry.blob) {
                blob_total += 1;
                if (entry.blob_owner_index == peer.index) blob_owned += 1;
            }
        }
        const blobs_available = self.blobsAvailable();
        for (msg.kinds, msg.sizes.slice(), msg.hashes.slice()) |kind, size, tx_hash| {
            self.stats.announced += 1;
            if (kind == 3 and !blobs_available) {
                self.stats.deferred_blobs += 1;
                continue;
            }
            if (kind > 4 or size > (if (kind == 3) BlobWire.max_wrapper_bytes else max_tx_bytes)) {
                self.stats.unsupported += 1;
                continue;
            }
            if (self.known(tx_hash, now)) {
                self.stats.duplicate += 1;
                continue;
            }
            if (self.pending.getPtr(tx_hash)) |entry| {
                // Bind metadata to its advertiser: a dishonest first peer must
                // not poison a correct announcement from another peer.
                // A first ordinary claim cannot bypass blob inventory quotas
                // when another peer subsequently announces that hash as type 3.
                if (kind == 3 and !entry.blob) {
                    if (blob_total >= max_pending_blobs or blob_owned >= max_pending_blobs_per_peer) {
                        self.stats.blob_inventory_drops += 1;
                        self.stats.bounded_drops += 1;
                        continue;
                    }
                    entry.blob = true;
                    entry.blob_owner_index = peer.index;
                    blob_owned += 1;
                    blob_total += 1;
                }
                addPeer(entry, .{ .peer = peer, .kind = kind, .size = size });
                self.stats.duplicate += 1;
                continue;
            }
            if (kind == 3 and (blob_total >= max_pending_blobs or blob_owned >= max_pending_blobs_per_peer)) {
                self.stats.blob_inventory_drops += 1;
                self.stats.bounded_drops += 1;
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
                .blob = kind == 3,
                .blob_owner_index = peer.index,
                .first_seen_ms = now,
                .expires_ms = now +| pending_lifetime_ms,
                .peers = .{ .{ .peer = peer, .kind = kind, .size = size }, null },
            });
            owned += 1;
            if (kind == 3) {
                blob_owned += 1;
                blob_total += 1;
            }
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
        var blob_outstanding: usize = 0;
        var verifying: usize = 0;
        for (self.requests) |request| if (request) |req| {
            if (req.blob) blob_outstanding += 1;
        };
        for (self.verifications) |item| if (item != null) {
            verifying += 1;
        };
        // Ordinary inventory is always considered first. Blob requests reserve
        // their own two slots/work credits and never batch with ordinary txs.
        for ([_]bool{ false, true }) |blob| {
            if (blob and (!self.blobsAvailable() or blob_outstanding >= max_blob_requests or
                verifying + blob_outstanding >= max_blob_verifications)) continue;
            for (self.pending.values()) |entry| {
                if (entry.requested != null or entry.verifying or now >= entry.expires_ms or now < entry.retry_after_ms) continue;
                for (entry.peers) |optional_peer| {
                    const advertisement = optional_peer orelse continue;
                    if ((advertisement.kind == 3) != blob) continue;
                    const peer = advertisement.peer;
                    if (now < self.peer_work[peer.index].retry_after_ms) {
                        self.stats.backoff_skips += 1;
                        continue;
                    }
                    if (self.peerBusy(peer)) continue;
                    if (blob and !self.reserveBlobRequest(peer, now)) continue;
                    var request: Request = .{ .id = id, .peer = peer, .deadline_ms = now +| request_timeout_ms, .blob = blob };
                    var bytes: usize = 0;
                    for (self.pending.keys(), self.pending.values()) |tx_hash, *candidate| {
                        if (candidate.requested != null or candidate.verifying or now >= candidate.expires_ms or now < candidate.retry_after_ms) continue;
                        const item = getAdvertisement(candidate, peer) orelse continue;
                        if ((item.kind == 3) != blob) continue;
                        if (request.count == (if (blob) @as(usize, 1) else max_request_hashes) or bytes + item.size > max_message_bytes) break;
                        request.hashes[request.count] = tx_hash;
                        request.announced[request.count] = .{ .kind = item.kind, .size = item.size, .at_ms = candidate.first_seen_ms };
                        request.count += 1;
                        bytes += item.size;
                        candidate.requested = id;
                        removePeer(candidate, peer);
                    }
                    std.debug.assert(request.count != 0);
                    self.requests[slot] = request;
                    self.stats.requested += request.count;
                    if (blob) self.stats.blob_requested += 1;
                    return request;
                }
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

    /// Validate the complete bounded response structure before admission. A
    /// local signature limit can admit its already-verified prefix only after
    /// checking the refused suffix structure, without verifying/delivering it.
    /// Missing hashes are normal (peer eviction/response limits); alternatives
    /// remain eligible after this request releases its reservation.
    pub fn response(self: *Intake, a: std.mem.Allocator, peer: Peer, raw: []const u8, receipt: ReceiptTime) !void {
        const now = receipt.mono_ms;
        const expected_blob = if (self.peerRequest(peer)) |slot| self.requests[slot].?.blob else false;
        self.reserveFrameClass(peer, raw.len, now, expected_blob) catch |err| {
            if (err == error.FrameRateLimit) {
                // We deliberately shed this reply. Do not later charge its
                // responder a timeout/backoff for our local admission refusal.
                // At most 16 slots and 64 hashes are touched, without parsing
                // the frame or scanning the unrelated pending inventory.
                for (self.requests, 0..) |request, i| if (request) |req| {
                    if (samePeer(peer, req.peer)) {
                        self.release(i);
                        self.stats.frame_refused_requests += 1;
                        break;
                    }
                };
            }
            return err;
        };
        if (raw.len > max_message_bytes + 1024) return error.ResponseByteLimit;
        const Response = struct { id: u64, transactions: BoundedList(rlp.RawValue, max_request_hashes) };
        var msg: Response = undefined;
        if (try rlp.deserialize(Response, a, raw, &msg) != raw.len) return error.TrailingRlp;
        const slot = self.findRequest(peer, msg.id) orelse return error.UnsolicitedResponse;
        const request = self.requests[slot].?;
        defer self.release(slot);
        if (now >= request.deadline_ms) return error.ExpiredResponse;
        if (msg.transactions.count > request.count) return error.ResponseCountLimit;
        if (request.blob) return self.blobResponse(a, request, msg.transactions.slice(), receipt);
        var records: [max_request_hashes]Record = undefined;
        var record_count: usize = 0;
        var cursor: ResponseCursor = .{ .request = &request };
        for (msg.transactions.slice(), 0..) |raw_tx, item_index| {
            const bytes = try canonicalBytes(a, raw_tx.value);
            const tx_hash = hash(bytes);
            const announced_at_ms = try cursor.validate(bytes, tx_hash);
            if (self.known(tx_hash, now)) {
                self.stats.duplicate += 1;
                continue;
            }
            self.reserveSignature(peer, now) catch return self.deliverLimitedPrefix(a, records[0..record_count], .{
                .first = bytes,
                .remaining = msg.transactions.slice()[item_index + 1 ..],
                .response = cursor,
            }, now);
            records[record_count] = try decodeRecord(a, self.chain_id, peer, bytes, announced_at_ms, now);
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
        for (txs, 0..) |tx, item_index| {
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
            self.reserveSignature(peer, now) catch return self.deliverLimitedPrefix(a, records[0..count], .{
                .first = bytes,
                .remaining = txs[item_index + 1 ..],
            }, now);
            records[count] = try decodeRecord(a, self.chain_id, peer, bytes, now, now);
            records[count].frame_received_wall_ms = receipt.wall_ms;
            count += 1;
            self.stats.decoded += 1;
        }
        for (records[0..count]) |record| try self.deliver(record, now);
    }

    fn deliverLimitedPrefix(self: *Intake, a: std.mem.Allocator, records: []const Record, suffix: LimitedSuffix, now: i64) !void {
        self.stats.signature_unprocessed_items += 1 + suffix.remaining.len;
        const accepted_before = self.stats.accepted;
        defer {
            const preserved = self.stats.accepted - accepted_before;
            self.stats.signature_preserved_decoded += preserved;
            self.stats.signature_discarded_decoded += records.len - preserved;
        }
        // With nothing to deliver, retain the original cheap local refusal.
        // A nonempty prefix requires validating every remaining envelope,
        // response binding and transaction structure before any callback. The
        // first refused item was already canonicalized/hashed/bound by the
        // sequential scan; reuse it and continue at its advanced request cursor.
        if (records.len != 0) {
            try validateOrdinaryStructure(a, suffix.first);
            var binding = suffix.response;
            for (suffix.remaining) |raw_tx| {
                const bytes = try canonicalBytes(a, raw_tx.value);
                if (binding) |*cursor| _ = try cursor.validate(bytes, hash(bytes));
                try validateOrdinaryStructure(a, bytes);
            }
            for (records) |record| try self.deliver(record, now);
        }
        // The driver treats this as local refusal: no peer fault, no outgoing
        // drain, and response's defer releases the remaining reservation.
        return error.SignatureRateLimit;
    }

    fn known(self: *Intake, tx_hash: Hash, now: i64) bool {
        const until = self.seen.get(tx_hash) orelse return false;
        if (now < until) {
            // Query only this previously delivered hash. Never walk the seen
            // table or run validation on the peer/sync thread. Observers without
            // an owning status callback retain the existing suppression policy.
            const status = self.sink.status orelse return true;
            if (status(self.sink.context, tx_hash, now) != .missing) return true;
        }
        _ = self.seen.swapRemove(tx_hash);
        return false;
    }

    fn blobsAvailable(self: *const Intake) bool {
        const sink = self.sink.blobs orelse return false;
        return sink.available(sink.context);
    }

    fn reserveBlobRequest(self: *Intake, peer: Peer, now: i64) bool {
        const local = &self.peer_work[peer.index].blob_requests;
        self.blob_request_budget.replenish(now, 2, 2);
        local.replenish(now, 1, 1);
        if (self.blob_request_budget.milli_tokens < 1000 or local.milli_tokens < 1000) {
            self.stats.blob_request_rate_drops += 1;
            return false;
        }
        self.blob_request_budget.milli_tokens -= 1000;
        local.milli_tokens -= 1000;
        return true;
    }

    fn blobResponse(self: *Intake, a: std.mem.Allocator, request: Request, items: []const rlp.RawValue, receipt: ReceiptTime) !void {
        std.debug.assert(request.count == 1);
        // Empty responses are normal evictions. release() retains another peer.
        if (items.len == 0) return;
        const bytes = try pooledBytes(a, items[0].value, BlobWire.max_wrapper_bytes);
        const frame = try BlobWire.parse(bytes);
        if (!std.mem.eql(u8, &frame.hash, &request.hashes[0])) return error.UnrequestedTransaction;
        if (bytes.len != request.announced[0].size) return error.AnnouncementMismatch;
        if (self.known(frame.hash, receipt.mono_ms)) {
            self.stats.duplicate += 1;
            return;
        }
        // Hash/shape/size are checked before signature work or owning copies.
        try self.reserveSignature(request.peer, receipt.mono_ms);
        const canonical = try frame.canonical(a);
        _ = try decodeSigned(a, self.chain_id, request.peer, canonical, request.announced[0].at_ms, receipt.mono_ms);
        self.stats.decoded += 1;
        const sink = self.sink.blobs orelse return error.BlobSinkUnavailable;
        var free: ?usize = null;
        for (self.verifications, 0..) |item, i| if (item == null) {
            free = i;
            break;
        };
        if (free == null or !sink.available(sink.context) or !sink.accept(sink.context, .{
            .hash = frame.hash,
            .bytes = bytes,
            .peer = .{ .index = request.peer.index, .epoch = request.peer.epoch },
            .announced_at_ms = request.announced[0].at_ms,
            .received_at_ms = receipt.mono_ms,
            .frame_received_wall_ms = receipt.wall_ms,
        })) {
            self.stats.blob_sink_full += 1;
            // The peer supplied its response correctly; preserve its metadata
            // after request release and pace a bounded retry under local load.
            if (self.pending.getPtr(frame.hash)) |entry| {
                entry.retry_after_ms = receipt.mono_ms +| blob_retry_ms;
                entry.retry_advertisement = .{ .peer = request.peer, .kind = 3, .size = request.announced[0].size };
            }
            return;
        }
        self.verifications[free.?] = .{ .hash = frame.hash, .deadline_ms = receipt.mono_ms +| verification_timeout_ms };
        if (self.pending.getPtr(frame.hash)) |entry| entry.verifying = true;
        self.stats.blob_queued += 1;
        self.peer_work[request.peer.index].timeouts = 0;
        self.peer_work[request.peer.index].retry_after_ms = 0;
    }

    /// Poll only four copied jobs, never run signature/KZG work here. A failed
    /// job does not enter seen, so another advertiser can supply the same hash.
    pub fn pollBlobResults(self: *Intake, now: i64) void {
        const sink = self.sink.blobs orelse return;
        for (&self.verifications) |*optional| {
            const item = optional.* orelse continue;
            const status = sink.status(sink.context, item.hash, now);
            if (status == .pending and now < item.deadline_ms) continue;
            if (status == .ready) {
                self.seen.ensureUnusedCapacity(self.allocator, 1) catch {
                    self.stats.bounded_drops += 1;
                    continue;
                };
                if (self.seen.count() == max_seen) self.seen.swapRemoveAt(0);
                self.seen.putAssumeCapacity(item.hash, now +| seen_lifetime_ms);
                _ = self.pending.swapRemove(item.hash);
                self.stats.blob_ready += 1;
            } else {
                if (self.pending.getPtr(item.hash)) |entry| {
                    entry.verifying = false;
                    entry.retry_after_ms = now +| blob_retry_ms;
                }
                self.stats.blob_failed += 1;
            }
            optional.* = null;
        }
    }

    fn reserveFrame(self: *Intake, peer: Peer, bytes: usize, now: i64) !void {
        return self.reserveFrameClass(peer, bytes, now, false);
    }
    fn reserveFrameClass(self: *Intake, peer: Peer, bytes: usize, now: i64, blob: bool) !void {
        if (peer.index >= max_peer_slots) return error.PeerSlotLimit;
        const local = if (blob) &self.peer_work[peer.index].blob_bytes else &self.peer_work[peer.index].bytes;
        const global = if (blob) &self.blob_byte_budget else &self.byte_budget;
        const local_frames = &self.peer_work[peer.index].frames;
        global.replenish(now, if (blob) 2 * 1024 * 1024 else 4 * 1024 * 1024, if (blob) max_message_bytes + 1024 else 4 * 1024 * 1024);
        local.replenish(now, 1024 * 1024, max_message_bytes + 1024);
        self.frame_budget.replenish(now, 512, 256);
        local_frames.replenish(now, 128, 128);
        const cost: u64 = @as(u64, @intCast(bytes)) *| 1000;
        if (self.frame_budget.milli_tokens < 1000 or local_frames.milli_tokens < 1000 or global.milli_tokens < cost or local.milli_tokens < cost) {
            self.stats.frame_rate_drops += 1;
            if (blob) self.stats.blob_frame_rate_drops += 1;
            return error.FrameRateLimit;
        }
        global.milli_tokens -= cost;
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
        if (self.known(record.hash, now)) {
            self.stats.duplicate += 1;
            return;
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
        self.pollBlobResults(now);
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
            if (!entry.verifying and entry.requested == null and (now >= entry.expires_ms or (entry.peers[0] == null and entry.peers[1] == null))) {
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
                    if (entry.retry_advertisement) |retry| {
                        addPeer(entry, retry);
                        entry.retry_advertisement = null;
                    }
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
    fn peerRequest(self: *const Intake, peer: Peer) ?usize {
        for (self.requests, 0..) |request, i| if (request) |req| {
            if (samePeer(peer, req.peer)) return i;
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

const ResponseCursor = struct {
    request: *const Request,
    next: usize = 0,
    fn validate(self: *@This(), bytes: []const u8, tx_hash: Hash) !i64 {
        while (self.next < self.request.count and !std.mem.eql(u8, &self.request.hashes[self.next], &tx_hash)) : (self.next += 1) {}
        if (self.next == self.request.count) return error.UnrequestedTransaction;
        const entry = self.request.announced[self.next];
        self.next += 1;
        if (bytes.len != entry.size or transactionKind(bytes) != entry.kind) return error.AnnouncementMismatch;
        return entry.at_ms;
    }
};

const LimitedSuffix = struct {
    first: []const u8,
    remaining: []const rlp.RawValue,
    response: ?ResponseCursor = null,
};

fn transactionKind(bytes: []const u8) u8 {
    return if (bytes[0] >= 0xc0) 0 else bytes[0];
}
fn canonicalBytes(a: std.mem.Allocator, raw: []const u8) ![]const u8 {
    return pooledBytes(a, raw, max_tx_bytes);
}
fn pooledBytes(a: std.mem.Allocator, raw: []const u8, maximum: usize) ![]const u8 {
    if (raw.len == 0) return error.EmptyTransaction;
    if (raw[0] >= 0xc0) {
        if (raw.len > maximum) return error.TransactionByteLimit;
        return raw;
    }
    // Typed transactions are byte strings in the ETH message's RLP list.
    if (raw[0] < 0x80) return error.InvalidTypedWrapper;
    var bytes: []const u8 = undefined;
    if (try rlp.deserialize([]const u8, a, raw, &bytes) != raw.len) return error.TrailingRlp;
    if (bytes.len == 0) return error.EmptyTransaction;
    if (bytes.len > maximum) return error.TransactionByteLimit;
    if (bytes[0] == 0 or bytes[0] >= 0x80) return error.InvalidTypedWrapper;
    return bytes;
}

fn decodeRecord(a: std.mem.Allocator, chain_id: u64, peer: Peer, bytes: []const u8, announced: i64, now: i64) !Record {
    if (transactionKind(bytes) == 3) return error.BlobSidecarRequired;
    return decodeSigned(a, chain_id, peer, bytes, announced, now);
}

fn validateOrdinaryStructure(a: std.mem.Allocator, bytes: []const u8) !void {
    if (transactionKind(bytes) == 3) return error.BlobSidecarRequired;
    _ = try decodeTransaction(a, bytes);
}
fn decodeSigned(a: std.mem.Allocator, chain_id: u64, peer: Peer, bytes: []const u8, announced: i64, now: i64) !Record {
    const tx = try decodeTransaction(a, bytes);
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

/// Canonical transaction structure and basic fee shape only. Signature and
/// chain validation remain in the separately budgeted recoverTxSender call.
fn decodeTransaction(a: std.mem.Allocator, bytes: []const u8) !types.Transaction {
    const kind = transactionKind(bytes);
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
    return tx;
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

test "public intake primitive handoff owns bytes and preserves backpressure semantics" {
    const Owner = struct {
        bytes: [256]u8 = undefined,
        count: usize = 0,
        full: bool = true,
        record: ?Handoff.Transaction = null,
        fn accept(ctx: *anyopaque, record: Handoff.Transaction) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.full or record.bytes.len > self.bytes.len) return false;
            @memcpy(self.bytes[0..record.bytes.len], record.bytes);
            self.record = record;
            self.record.?.bytes = self.bytes[0..record.bytes.len];
            self.count += 1;
            return true;
        }
    };
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    const a = arena.allocator();
    var owner: Owner = .{};
    var handoff: Handoff.Sink = .{ .context = &owner, .accept = Owner.accept };
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = handoffSink(&handoff) };
    defer intake.deinit();
    const bytes = try fixture(a);
    const tx_hash = hash(bytes);
    const broadcast = try encode(a, @as([]const rlp.RawValue, &.{.{ .value = bytes }}));
    try intake.broadcast(a, peer_a, broadcast, .{ .mono_ms = 100, .wall_ms = 200 });
    try std.testing.expectEqual(0, intake.seen.count());
    try std.testing.expectEqual(1, intake.stats.sink_full);
    owner.full = false;
    try intake.broadcast(a, peer_a, broadcast, .{ .mono_ms = 101, .wall_ms = 201 });
    arena.deinit();
    try std.testing.expectEqual(1, owner.count);
    try std.testing.expectEqual(tx_hash, hash(owner.record.?.bytes));
    try std.testing.expectEqual(101, owner.record.?.received_at_ms);
    try std.testing.expectEqual(201, owner.record.?.frame_received_wall_ms.?);
    try std.testing.expectEqual(peer_a.epoch, owner.record.?.peer.epoch);
    try std.testing.expectEqual(1, intake.stats.accepted);
}

test "public intake owning status retries failed ordinary admission on announcement broadcast and delivery" {
    const Owner = struct {
        admission: Handoff.AdmissionStatus = .pending,
        accepted: usize = 0,
        queried: usize = 0,
        queried_hash: Hash = undefined,
        queried_at: i64 = 0,
        fn accept(ctx: *anyopaque, _: Handoff.Transaction) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.accepted += 1;
            self.admission = .pending;
            return true;
        }
        fn status(ctx: *anyopaque, tx_hash: Hash, now: i64) Handoff.AdmissionStatus {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.queried += 1;
            self.queried_hash = tx_hash;
            self.queried_at = now;
            return self.admission;
        }
    };
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var owner: Owner = .{};
    var handoff: Handoff.Sink = .{ .context = &owner, .accept = Owner.accept, .status = Owner.status };
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = handoffSink(&handoff) };
    defer intake.deinit();
    const bytes = try fixture(a);
    const tx_hash = hash(bytes);
    const announcement = try announceOne(a, bytes, 0);
    const broadcast = try encode(a, @as([]const rlp.RawValue, &.{.{ .value = bytes }}));
    try intake.broadcast(a, peer_a, broadcast, .{ .mono_ms = 100 });
    try std.testing.expectEqual(0, owner.queried);
    try intake.announce(a, peer_b, announcement, 101);
    try intake.broadcast(a, peer_b, broadcast, .{ .mono_ms = 102 });
    try std.testing.expectEqual(1, owner.accepted);
    try std.testing.expect(intake.nextRequest(1, 102) == null);
    owner.admission = .ready;
    try intake.announce(a, peer_b, announcement, 103);
    try std.testing.expectEqual(1, owner.accepted);
    try std.testing.expectEqual(tx_hash, owner.queried_hash);
    try std.testing.expectEqual(103, owner.queried_at);

    owner.admission = .missing;
    try intake.announce(a, peer_b, announcement, 104);
    try std.testing.expectEqual(0, intake.seen.count());
    const request = intake.nextRequest(2, 105).?;
    try std.testing.expectEqual(peer_b, request.peer);
    try intake.response(a, peer_b, try responseOne(a, 2, bytes), .{ .mono_ms = 106 });
    try std.testing.expectEqual(2, owner.accepted);
    owner.admission = .missing;
    try intake.broadcast(a, peer_a, broadcast, .{ .mono_ms = 107 });
    try std.testing.expectEqual(3, owner.accepted);
    // Delivery can follow decoding in a batch. It must also recheck ownership,
    // independently of the earlier broadcast/request duplicate filter.
    owner.admission = .missing;
    try intake.deliver(try decodeRecord(a, 1, peer_a, bytes, 107, 108), 108);
    try std.testing.expectEqual(4, owner.accepted);
    try std.testing.expectEqual(1, intake.seen.count());
}

test "public intake status probes only the queried seen hash and preserves observer suppression" {
    const Owner = struct {
        calls: usize = 0,
        fn accept(_: *anyopaque, _: Record) bool {
            return true;
        }
        fn status(ctx: *anyopaque, _: Hash, _: i64) Handoff.AdmissionStatus {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            return .missing;
        }
    };
    var owner: Owner = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = .{ .context = &owner, .accept = Owner.accept, .status = Owner.status } };
    defer intake.deinit();
    for (0..max_seen) |i| {
        var tx_hash: Hash = @splat(0);
        std.mem.writeInt(u64, tx_hash[0..8], @intCast(i), .big);
        try intake.seen.put(std.testing.allocator, tx_hash, 30000);
    }
    const queried: Hash = @splat(0);
    try std.testing.expect(!intake.known(@splat(0xff), 10));
    try std.testing.expectEqual(0, owner.calls);
    try std.testing.expect(!intake.known(queried, 11));
    try std.testing.expectEqual(1, owner.calls);
    try std.testing.expectEqual(max_seen - 1, intake.seen.count());
    intake.expire(12);
    try std.testing.expectEqual(1, owner.calls);
    try std.testing.expectEqual(max_seen - 1, intake.seen.count());
    intake.sink.status = null;
    try intake.seen.put(std.testing.allocator, queried, 30000);
    try std.testing.expect(intake.known(queried, 13));
    try std.testing.expect(!intake.known(queried, 30000));
    try std.testing.expectEqual(1, owner.calls);
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

test "public intake local response refusal releases only the matching epoch without timeout penalty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    const bytes = try fixture(a);
    try intake.announce(a, peer_a, try announceOne(a, bytes, 0), 0);
    try intake.announce(a, peer_b, try announceOne(a, bytes, 0), 0);
    _ = intake.nextRequest(1, 0).?;
    intake.frame_budget = .{ .last_ms = 0, .milli_tokens = 0 };
    const response = try responseOne(a, 1, bytes);
    const old_epoch: Peer = .{ .index = peer_a.index, .epoch = peer_a.epoch - 1 };
    try std.testing.expectError(error.FrameRateLimit, intake.response(a, old_epoch, response, .{ .mono_ms = 0 }));
    try std.testing.expect(intake.findRequest(peer_a, 1) != null);
    try std.testing.expectError(error.FrameRateLimit, intake.response(a, peer_a, response, .{ .mono_ms = 0 }));
    try std.testing.expect(intake.findRequest(peer_a, 1) == null);
    try std.testing.expectEqual(1, intake.stats.frame_refused_requests);
    intake.expire(request_timeout_ms + 1000);
    try std.testing.expectEqual(0, intake.stats.expired_requests);
    try std.testing.expectEqual(0, intake.peer_work[peer_a.index].timeouts);
    try std.testing.expectEqual(0, intake.peer_work[peer_a.index].retry_after_ms);
    const alternative = intake.nextRequest(2, request_timeout_ms + 1000).?;
    try std.testing.expect(samePeer(peer_b, alternative.peer));
    try intake.response(a, peer_b, try responseOne(a, 2, bytes), .{ .mono_ms = request_timeout_ms + 1001 });
    try std.testing.expectEqual(1, recorder.count);
}

test "public intake preserves verified batch prefix at local signature limit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try fixture(a);
    const second = try std.fmt.hexToBytes(try a.alloc(u8, typed2_hex.len / 2), typed2_hex);
    const raw_items = [_]rlp.RawValue{ .{ .value = first }, .{ .value = try encode(a, second) } };
    for ([_]bool{ false, true }) |is_response| {
        var recorder: Recorder = .{};
        var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
        defer intake.deinit();
        intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 1000 };
        if (is_response) {
            const announcement = try encode(a, .{ @as([]const u8, &.{ 0, 2 }), @as([]const u32, &.{ @intCast(first.len), @intCast(second.len) }), @as([]const Hash, &.{ hash(first), hash(second) }) });
            try intake.announce(a, peer_a, announcement, 0);
            _ = intake.nextRequest(1, 0).?;
            const response = try encode(a, .{ @as(u64, 1), @as([]const rlp.RawValue, &raw_items) });
            try std.testing.expectError(error.SignatureRateLimit, intake.response(a, peer_a, response, .{ .mono_ms = 0 }));
            try std.testing.expect(intake.findRequest(peer_a, 1) == null);
            intake.expire(request_timeout_ms + 1000);
            try std.testing.expectEqual(0, intake.stats.expired_requests);
        } else {
            const broadcast = try encode(a, @as([]const rlp.RawValue, &raw_items));
            try std.testing.expectError(error.SignatureRateLimit, intake.broadcast(a, peer_a, broadcast, .{ .mono_ms = 0 }));
        }
        try std.testing.expectEqual(1, intake.stats.decoded);
        try std.testing.expectEqual(1, intake.stats.signature_preserved_decoded);
        try std.testing.expectEqual(0, intake.stats.signature_discarded_decoded);
        try std.testing.expectEqual(1, intake.stats.signature_unprocessed_items);
        try std.testing.expectEqual(1, recorder.count);
        try std.testing.expectEqual(1, intake.stats.accepted);
    }
}

fn batchWire(a: std.mem.Allocator, transactions: []const []const u8, id: ?u64) ![]const u8 {
    var items: [max_broadcast_transactions]rlp.RawValue = undefined;
    for (transactions, 0..) |bytes, i| items[i] = .{ .value = if (transactionKind(bytes) == 0) bytes else try encode(a, bytes) };
    const slice: []const rlp.RawValue = items[0..transactions.len];
    return if (id) |request_id| encode(a, .{ request_id, slice }) else encode(a, slice);
}

fn batchAnnouncement(a: std.mem.Allocator, transactions: []const []const u8) ![]const u8 {
    var kinds: [max_broadcast_transactions]u8 = undefined;
    var sizes: [max_broadcast_transactions]u32 = undefined;
    var hashes: [max_broadcast_transactions]Hash = undefined;
    for (transactions, 0..) |bytes, i| {
        kinds[i] = transactionKind(bytes);
        sizes[i] = @intCast(bytes.len);
        hashes[i] = hash(bytes);
    }
    return encode(a, .{ @as([]const u8, kinds[0..transactions.len]), @as([]const u32, sizes[0..transactions.len]), @as([]const Hash, hashes[0..transactions.len]) });
}

fn submitTestBatch(intake: *Intake, a: std.mem.Allocator, transactions: []const []const u8, is_response: bool) !void {
    if (is_response) {
        try intake.announce(a, peer_a, try batchAnnouncement(a, transactions), 0);
        const request = intake.nextRequest(1, 0).?;
        try std.testing.expectEqual(transactions.len, request.count);
        return intake.response(a, peer_a, try batchWire(a, transactions, 1), .{ .mono_ms = 0, .wall_ms = 12345 });
    }
    return intake.broadcast(a, peer_a, try batchWire(a, transactions, null), .{ .mono_ms = 0, .wall_ms = 12345 });
}

test "public intake prefix preservation respects empty partial and full global and peer budgets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const txs = [_][]const u8{ try fixture(a), try unhex(a, typed2_hex) };
    for ([_]bool{ false, true }) |is_response| {
        for ([_]bool{ false, true }) |peer_limited| {
            for (0..3) |tokens| {
                var recorder: Recorder = .{};
                var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
                defer intake.deinit();
                const limited = if (peer_limited) &intake.peer_work[peer_a.index].signatures else &intake.signature_budget;
                limited.* = .{ .last_ms = 0, .milli_tokens = tokens * 1000 };
                const result = submitTestBatch(&intake, a, &txs, is_response);
                if (tokens == 2) try result else try std.testing.expectError(error.SignatureRateLimit, result);
                try std.testing.expectEqual(tokens, intake.stats.decoded);
                try std.testing.expectEqual(tokens, intake.stats.accepted);
                try std.testing.expectEqual(tokens, recorder.count);
                try std.testing.expectEqual(0, limited.milli_tokens);
                const other = if (peer_limited) intake.signature_budget else intake.peer_work[peer_a.index].signatures;
                try std.testing.expectEqual(256000 - tokens * 1000, other.milli_tokens);
                try std.testing.expectEqual(@intFromBool(tokens < 2), intake.stats.signature_rate_drops);
                try std.testing.expectEqual(@intFromBool(tokens == 1), intake.stats.signature_preserved_decoded);
                try std.testing.expectEqual(0, intake.stats.signature_discarded_decoded);
                try std.testing.expectEqual(2 - tokens, intake.stats.signature_unprocessed_items);
                if (tokens != 0) try std.testing.expectEqual(12345, recorder.last_received_wall.?);
                for (intake.requests) |request| try std.testing.expect(request == null);
            }
        }
    }
}

test "public intake limited prefix keeps sink refusals retryable and releases only remaining response work" {
    const Receiver = struct {
        calls: usize = 0,
        accepted: usize = 0,
        refuse_first: bool = true,
        fn accept(ctx: *anyopaque, _: Record) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            if (self.refuse_first and self.calls == 1) return false;
            self.accepted += 1;
            return true;
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const txs = [_][]const u8{ try fixture(a), try unhex(a, typed2_hex), try unhex(a, typed4_hex) };
    for ([_]bool{ false, true }) |is_response| {
        var receiver: Receiver = .{};
        var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = .{ .context = &receiver, .accept = Receiver.accept } };
        defer intake.deinit();
        intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 2000 };
        const announcement = try batchAnnouncement(a, &txs);
        try intake.announce(a, peer_a, announcement, 0);
        try intake.announce(a, peer_b, announcement, 0);
        const request = intake.nextRequest(1, 0).?;
        try std.testing.expectEqual(peer_a, request.peer);
        const raw = try batchWire(a, &txs, if (is_response) 1 else null);
        if (is_response) {
            try std.testing.expectError(error.SignatureRateLimit, intake.response(a, peer_a, raw, .{ .mono_ms = 0 }));
        } else {
            try std.testing.expectError(error.SignatureRateLimit, intake.broadcast(a, peer_a, raw, .{ .mono_ms = 0 }));
            // An unsolicited broadcast must not release the outstanding request.
            try std.testing.expect(intake.findRequest(peer_a, 1) != null);
            intake.release(intake.findRequest(peer_a, 1).?);
        }
        try std.testing.expectEqual(2, receiver.calls);
        try std.testing.expectEqual(1, receiver.accepted);
        try std.testing.expectEqual(1, intake.stats.sink_full);
        try std.testing.expectEqual(1, intake.stats.signature_preserved_decoded);
        try std.testing.expectEqual(1, intake.stats.signature_discarded_decoded);
        try std.testing.expect(!intake.known(hash(txs[0]), 0));
        try std.testing.expect(intake.known(hash(txs[1]), 0));
        try std.testing.expect(!intake.known(hash(txs[2]), 0));
        try std.testing.expectEqual(2, intake.pending.count());
        // No timeout/backoff penalty; the alternate supplies exactly the refused
        // verified item and the unverified suffix after ordinary bucket refill.
        const retry = intake.nextRequest(2, 32).?;
        try std.testing.expectEqual(peer_b, retry.peer);
        try std.testing.expectEqual(2, retry.count);
        var retry_txs: [2][]const u8 = undefined;
        for (retry.hashes[0..retry.count], 0..) |tx_hash, i| {
            try std.testing.expect(!std.mem.eql(u8, &tx_hash, &hash(txs[1])));
            retry_txs[i] = if (std.mem.eql(u8, &tx_hash, &hash(txs[0]))) txs[0] else txs[2];
        }
        receiver.refuse_first = false;
        try intake.response(a, peer_b, try batchWire(a, &retry_txs, 2), .{ .mono_ms = 33 });
        try std.testing.expectEqual(3, receiver.accepted);
        try std.testing.expectEqual(3, intake.stats.accepted);
        try std.testing.expectEqual(0, intake.pending.count());
        intake.expire(2500);
        try std.testing.expectEqual(0, intake.stats.expired_requests);
        try std.testing.expectEqual(0, intake.peer_work[peer_a.index].timeouts);
        try std.testing.expectEqual(0, intake.peer_work[peer_a.index].retry_after_ms);
    }
}

test "public intake limited prefix still rejects structurally invalid suffix before delivery" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try fixture(a);
    const second = try unhex(a, typed2_hex);
    var tx: types.Transaction = undefined;
    _ = try tx.decodeFromRLP(a, first);
    tx.legacy.gas_limit = 0;
    const zero_gas = try encode(a, tx.legacy);
    tx.legacy.gas_limit = 100000;
    tx.legacy.to = null;
    const noncanonical = try a.dupe(u8, try encode(a, tx.legacy));
    var fields: BoundedList(rlp.RawValue, 9) = undefined;
    _ = try fields.decodeFromRLP(a, noncanonical);
    const offset = @intFromPtr(fields.items[3].value.ptr) - @intFromPtr(noncanonical.ptr);
    noncanonical[offset] = 0xc0;
    for ([_]bool{ false, true }) |is_response| {
        for ([_]bool{ false, true }) |late| {
            for ([_][]const u8{ &.{0xc0}, zero_gas, noncanonical }) |suffix| {
                var recorder: Recorder = .{};
                var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
                defer intake.deinit();
                intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 1000 };
                if (submitTestBatch(&intake, a, if (late) &.{ first, second, suffix } else &.{ first, suffix }, is_response)) |_| {
                    return error.ExpectedInvalidSuffix;
                } else |err| {
                    try std.testing.expect(err != error.SignatureRateLimit);
                    try std.testing.expect(err != error.OutOfMemory);
                }
                try std.testing.expectEqual(0, recorder.count);
                try std.testing.expectEqual(1, intake.stats.decoded);
                try std.testing.expectEqual(0, intake.stats.signature_preserved_decoded);
                try std.testing.expectEqual(1, intake.stats.signature_discarded_decoded);
                try std.testing.expectEqual(if (late) @as(u64, 2) else 1, intake.stats.signature_unprocessed_items);
                try std.testing.expectEqual(0, intake.seen.count());
                for (intake.requests) |request| try std.testing.expect(request == null);
            }
        }
    }
    // Bare blobs and future typed envelopes cannot hide behind the local quota.
    for ([_]struct { bytes: []const u8, err: anyerror }{
        .{ .bytes = &.{ 3, 0xc0 }, .err = error.BlobSidecarRequired },
        .{ .bytes = &.{ 5, 0xc0 }, .err = error.UnsupportedTransaction },
    }) |case| {
        var recorder: Recorder = .{};
        var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
        defer intake.deinit();
        intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 1000 };
        try std.testing.expectError(case.err, submitTestBatch(&intake, a, &.{ first, case.bytes }, false));
        try std.testing.expectEqual(0, recorder.count);
    }
}

test "public intake quota suffix never bypasses verification and full invalid batches stay atomic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try fixture(a);
    var tx: types.Transaction = undefined;
    _ = try tx.decodeFromRLP(a, first);
    tx.legacy.s = 0;
    const invalid_signature = try encode(a, tx.legacy);
    const wrong_chain = try unhex(a, large_chain_hex);
    for ([_]bool{ false, true }) |is_response| {
        for ([_]struct { bytes: []const u8, err: anyerror }{
            .{ .bytes = invalid_signature, .err = error.InvalidSignature },
            .{ .bytes = wrong_chain, .err = error.InvalidChainId },
        }) |case| {
            for ([_]u64{ 1000, 2000 }) |budget| {
                var recorder: Recorder = .{};
                var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
                defer intake.deinit();
                intake.signature_budget = .{ .last_ms = 0, .milli_tokens = budget };
                const limited = budget == 1000;
                try std.testing.expectError(if (limited) error.SignatureRateLimit else case.err, submitTestBatch(&intake, a, &.{ first, case.bytes }, is_response));
                try std.testing.expectEqual(@intFromBool(limited), recorder.count);
                try std.testing.expectEqual(@intFromBool(limited), intake.stats.signature_preserved_decoded);
                try std.testing.expect(!intake.known(hash(case.bytes), 0));
                if (limited) {
                    try std.testing.expectEqual(hash(first), recorder.last_hash);
                    // A fresh budget verifies the previously skipped suffix and
                    // rejects it; the accepted prefix is not redelivered.
                    const suffix = try batchWire(a, &.{case.bytes}, null);
                    try std.testing.expectError(case.err, intake.broadcast(a, peer_b, suffix, .{ .mono_ms = 32 }));
                    try std.testing.expectEqual(1, recorder.count);
                }
            }
        }
    }
}

test "public intake checks late response bindings and broadcast framing before prefix delivery" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try fixture(a);
    const second = try unhex(a, typed2_hex);
    const third = try unhex(a, typed4_hex);
    for (0..3) |case| {
        var recorder: Recorder = .{};
        var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
        defer intake.deinit();
        intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 1000 };
        const announced = if (case == 0) [_][]const u8{ first, third, second } else [_][]const u8{ first, second, third };
        try intake.announce(a, peer_a, try batchAnnouncement(a, &announced), 0);
        _ = intake.nextRequest(1, 0).?;
        if (case == 1) intake.requests[intake.findRequest(peer_a, 1).?].?.announced[2].size += 1;
        const raw = try batchWire(a, if (case == 2) &.{ first, second, second } else &.{ first, second, third }, 1);
        try std.testing.expectError(if (case == 1) error.AnnouncementMismatch else error.UnrequestedTransaction, intake.response(a, peer_a, raw, .{ .mono_ms = 0 }));
        try std.testing.expectEqual(0, recorder.count);
        try std.testing.expectEqual(1, intake.stats.decoded);
        try std.testing.expectEqual(0, intake.signature_budget.milli_tokens);
        try std.testing.expectEqual(1, intake.stats.signature_discarded_decoded);
    }
    const valid = try batchWire(a, &.{ first, second }, null);
    const trailing = try std.mem.concat(a, u8, &.{ valid, &.{0} });
    const invalid_wrapper = try encode(a, @as([]const rlp.RawValue, &.{ .{ .value = first }, .{ .value = try encode(a, second) }, .{ .value = &.{0} } }));
    for ([_]struct { raw: []const u8, err: anyerror }{
        .{ .raw = trailing, .err = error.TrailingRlp },
        .{ .raw = invalid_wrapper, .err = error.InvalidTypedWrapper },
    }) |case| {
        var recorder: Recorder = .{};
        var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
        defer intake.deinit();
        intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 1000 };
        try std.testing.expectError(case.err, intake.broadcast(a, peer_a, case.raw, .{ .mono_ms = 0 }));
        try std.testing.expectEqual(0, recorder.count);
        try std.testing.expectEqual(@intFromBool(case.err == error.InvalidTypedWrapper), intake.stats.decoded);
    }
}

test "public intake zero prefix refuses without inspecting later transaction envelopes or bindings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try fixture(a);
    const second = try unhex(a, typed2_hex);
    for ([_]bool{ false, true }) |is_response| {
        var recorder: Recorder = .{};
        var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
        defer intake.deinit();
        intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 0 };
        if (is_response) {
            try intake.announce(a, peer_a, try batchAnnouncement(a, &.{ first, second }), 0);
            _ = intake.nextRequest(1, 0).?;
            // The later hash is not requested. No record can be admitted, so
            // the existing local refusal does not inspect or fault this suffix.
            try std.testing.expectError(error.SignatureRateLimit, intake.response(a, peer_a, try batchWire(a, &.{ first, &.{0xc0} }, 1), .{ .mono_ms = 0 }));
        } else {
            const raw = try encode(a, @as([]const rlp.RawValue, &.{ .{ .value = first }, .{ .value = &.{0} } }));
            try std.testing.expectError(error.SignatureRateLimit, intake.broadcast(a, peer_a, raw, .{ .mono_ms = 0 }));
        }
        try std.testing.expectEqual(0, recorder.count);
        try std.testing.expectEqual(0, intake.stats.decoded);
        try std.testing.expectEqual(0, intake.stats.signature_preserved_decoded);
        try std.testing.expectEqual(0, intake.stats.signature_discarded_decoded);
        try std.testing.expectEqual(2, intake.stats.signature_unprocessed_items);
        for (intake.requests) |request| try std.testing.expect(request == null);
    }
}

test "public intake limited broadcasts deduplicate without spending more signature tokens" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try fixture(a);
    const second = try unhex(a, typed2_hex);
    var recorder: Recorder = .{};
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 1000 };
    const raw = try batchWire(a, &.{ first, first, second, first }, null);
    try std.testing.expectError(error.SignatureRateLimit, intake.broadcast(a, peer_a, raw, .{ .mono_ms = 0 }));
    try std.testing.expectEqual(1, recorder.count);
    try std.testing.expectEqual(1, intake.stats.decoded);
    try std.testing.expectEqual(1, intake.stats.duplicate);
    try std.testing.expectEqual(2, intake.stats.signature_unprocessed_items);
    try std.testing.expectEqual(0, intake.signature_budget.milli_tokens);
    try intake.broadcast(a, peer_a, raw, .{ .mono_ms = 32 });
    try std.testing.expectEqual(2, recorder.count);
    try std.testing.expectEqual(2, intake.stats.decoded);
    try std.testing.expectEqual(4, intake.stats.duplicate);
    try std.testing.expectEqual(7192, intake.signature_budget.milli_tokens);
}

const PrefixOwner = struct {
    count: usize = 0,
    bodies: [3][256]u8 = undefined,
    lengths: [3]usize = undefined,
    hashes: [3]Hash = undefined,
    fn accept(ctx: *anyopaque, record: Record) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.count < self.bodies.len and record.bytes.len <= self.bodies[0].len);
        @memcpy(self.bodies[self.count][0..record.bytes.len], record.bytes);
        self.lengths[self.count] = record.bytes.len;
        self.hashes[self.count] = record.hash;
        self.count += 1;
        return true;
    }
    fn sink(self: *@This()) Sink {
        return .{ .context = self, .accept = accept };
    }
};

fn prefixAllocationCase(allocator: std.mem.Allocator, is_response: bool) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var owner: PrefixOwner = .{};
    var intake: Intake = .{ .allocator = allocator, .chain_id = 1, .sink = owner.sink() };
    defer intake.deinit();
    const txs = [_][]const u8{ try unhex(a, typed2_hex), try unhex(a, typed4_hex), try fixture(a) };
    intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 2000 };
    const result = submitTestBatch(&intake, a, &txs, is_response);
    // Check ownership/accounting on every injected failure, including failures
    // during suffix structural parsing and before sink bookkeeping reservation.
    try std.testing.expectEqual(owner.count, intake.stats.accepted);
    try std.testing.expectEqual(owner.count, intake.seen.count());
    if (intake.stats.signature_rate_drops != 0) {
        try std.testing.expectEqual(owner.count, intake.stats.signature_preserved_decoded);
        try std.testing.expectEqual(intake.stats.decoded, intake.stats.signature_preserved_decoded + intake.stats.signature_discarded_decoded);
    }
    for (owner.hashes[0..owner.count]) |tx_hash| try std.testing.expect(intake.seen.contains(tx_hash));
    if (result) |_| {
        return error.ExpectedSignatureLimit;
    } else |err| if (err != error.SignatureRateLimit) return err;
    try std.testing.expectEqual(2, owner.count);
}

test "public intake limited prefix ownership survives every allocation failure" {
    // Arena growth may resize in place depending on allocator layout, which
    // changes the number of allocation calls between failure-injection runs.
    // Force growth through alloc/free so every allocation index is exercised
    // deterministically, with the same leak-checking backing allocator.
    var vtable = std.testing.allocator.vtable.*;
    vtable.resize = std.mem.Allocator.noResize;
    vtable.remap = std.mem.Allocator.noRemap;
    const allocator: std.mem.Allocator = .{ .ptr = std.testing.allocator.ptr, .vtable = &vtable };
    try std.testing.checkAllAllocationFailures(allocator, prefixAllocationCase, .{false});
    try std.testing.checkAllAllocationFailures(allocator, prefixAllocationCase, .{true});
}

test "public intake prefix delivery OOM preserves admitted ownership and truthful counters" {
    for ([_]bool{ false, true }) |is_response| {
        for ([_]bool{ false, true }) |allow_first| {
            var owner: PrefixOwner = .{};
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var intake: Intake = .{ .allocator = failing.allocator(), .chain_id = 1, .sink = owner.sink() };
            defer intake.deinit();
            {
                var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
                defer arena.deinit();
                const a = arena.allocator();
                const txs = [_][]const u8{ try fixture(a), try unhex(a, typed2_hex), try unhex(a, typed4_hex) };
                if (is_response) {
                    try intake.announce(a, peer_a, try batchAnnouncement(a, &txs), 0);
                    _ = intake.nextRequest(1, 0).?;
                }
                if (allow_first) {
                    try intake.seen.ensureTotalCapacity(intake.allocator, 1);
                    for (0..intake.seen.capacity() - 1) |i| {
                        var tx_hash: Hash = @splat(0xaa);
                        std.mem.writeInt(u64, tx_hash[0..8], i, .big);
                        intake.seen.putAssumeCapacity(tx_hash, 30000);
                    }
                }
                failing.fail_index = failing.alloc_index;
                failing.resize_fail_index = failing.resize_index;
                intake.signature_budget = .{ .last_ms = 0, .milli_tokens = 2000 };
                const raw = try batchWire(a, &txs, if (is_response) 1 else null);
                const result = if (is_response) intake.response(a, peer_a, raw, .{ .mono_ms = 0 }) else intake.broadcast(a, peer_a, raw, .{ .mono_ms = 0 });
                try std.testing.expectError(error.OutOfMemory, result);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(@intFromBool(allow_first), owner.count);
                try std.testing.expectEqual(owner.count, intake.stats.accepted);
                try std.testing.expectEqual(owner.count, intake.stats.signature_preserved_decoded);
                try std.testing.expectEqual(2 - owner.count, intake.stats.signature_discarded_decoded);
                try std.testing.expectEqual(1, intake.stats.signature_unprocessed_items);
                try std.testing.expectEqual(2, intake.stats.decoded);
                try std.testing.expect(!intake.known(hash(txs[1]), 0));
                try std.testing.expect(!intake.known(hash(txs[2]), 0));
                if (allow_first) try std.testing.expect(intake.known(hash(txs[0]), 0));
                for (intake.requests) |request| try std.testing.expect(request == null);
            }
            // Callback-owned bytes remain intact after all borrowed frame and
            // decoded-transaction allocations have been released.
            for (owner.hashes[0..owner.count], 0..) |tx_hash, i| {
                try std.testing.expectEqual(tx_hash, hash(owner.bodies[i][0..owner.lengths[i]]));
                try std.testing.expect(intake.known(tx_hash, 1));
            }
        }
    }
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

const BlobTestVector = struct { canonical: []const u8, wrapper: []const u8, hash: Hash };
fn blobTestVector(a: std.mem.Allocator, nonce: u64, count: usize, version: u8, proof_count: usize) !BlobTestVector {
    const secp = @import("zig-eth-secp256k1");
    const C = struct {
        extern fn secp256k1_context_destroy(context: *anyopaque) void;
    };
    const signer = try secp.Secp256k1.init();
    defer C.secp256k1_context_destroy(signer.context);
    const commitment: [48]u8 = .{0xc0} ++ @as([47]u8, @splat(0));
    var versioned: Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &versioned, .{});
    versioned[0] = 1;
    const hashes = try a.alloc(Hash, count);
    @memset(hashes, versioned);
    var tx: types.Transaction = .{ .blob = .{
        .chain_id = 1,
        .nonce = nonce,
        .gas_priority_fee = 2,
        .gas_price = 10,
        .gas_limit = 100000,
        .to = @splat(0x11),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .max_fee_per_blob_gas = 2,
        .blob_hashes = hashes,
        .v = 0,
        .r = 0,
        .s = 0,
    } };
    const signature = try signer.sign(try tx.signingHash(a, 1), @as([31]u8, @splat(0)) ++ [_]u8{1});
    tx.blob.r = std.mem.readInt(u256, signature[0..32], .big);
    tx.blob.s = std.mem.readInt(u256, signature[32..64], .big);
    tx.blob.v = signature[64];
    const body = try encode(a, tx.blob);
    const canonical = try std.mem.concat(a, u8, &.{ &.{3}, body });
    const blob = try a.alloc(u8, BlobWire.bytes_per_blob);
    @memset(blob, 0);
    const blobs = try a.alloc([]const u8, count);
    @memset(blobs, blob);
    const commitments = try a.alloc([48]u8, count);
    @memset(commitments, commitment);
    const proofs = try a.alloc([48]u8, proof_count);
    @memset(proofs, commitment);
    const outer = try encode(a, .{ rlp.RawValue{ .value = body }, version, @as([]const []const u8, blobs), @as([]const [48]u8, commitments), @as([]const [48]u8, proofs) });
    return .{ .canonical = canonical, .hash = hash(canonical), .wrapper = try std.mem.concat(a, u8, &.{ &.{3}, outer }) };
}
fn announceBlob(a: std.mem.Allocator, vector: BlobTestVector) ![]const u8 {
    return encode(a, .{ @as([]const u8, &.{3}), @as([]const u32, &.{@intCast(vector.wrapper.len)}), @as([]const Hash, &.{vector.hash}) });
}
const BlobQueue = struct {
    allocator: std.mem.Allocator,
    warm: bool = true,
    full: bool = false,
    state: Handoff.BlobStatus = .pending,
    bytes: ?[]u8 = null,
    hash: ?Hash = null,
    calls: usize = 0,
    fn available(ctx: *anyopaque) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.warm;
    }
    fn accept(ctx: *anyopaque, tx: Handoff.Transaction) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.full or !self.warm) return false;
        const bytes = self.allocator.dupe(u8, tx.bytes) catch return false;
        if (self.bytes) |previous| self.allocator.free(previous);
        self.bytes = bytes;
        self.hash = tx.hash;
        self.calls += 1;
        return true;
    }
    fn status(ctx: *anyopaque, _: Hash, _: i64) Handoff.BlobStatus {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.state;
    }
    fn sink(self: *@This()) Handoff.BlobSink {
        return .{ .context = self, .available = available, .accept = accept, .status = status };
    }
    fn deinit(self: *@This()) void {
        if (self.bytes) |bytes| self.allocator.free(bytes);
    }
};

test "ETH71 blob handoff retains full wrapper and awaits verifier readiness" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var queue: BlobQueue = .{ .allocator = std.testing.allocator, .warm = false };
    defer queue.deinit();
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    intake.sink.blobs = queue.sink();
    const vector = try blobTestVector(a, 0, 6, 1, 768);
    const expected = vector.hash;
    const ann = try announceBlob(a, vector);
    try intake.announce(a, peer_a, ann, 0);
    try std.testing.expectEqual(1, intake.stats.deferred_blobs);
    try std.testing.expect(intake.nextRequest(1, 0) == null);
    queue.warm = true;
    try intake.announce(a, peer_a, ann, 1);
    const request = intake.nextRequest(2, 1).?;
    try std.testing.expect(request.blob);
    try std.testing.expectEqual(1, request.count);
    try intake.response(a, peer_a, try responseOne(a, 2, vector.wrapper), .{ .mono_ms = 2, .wall_ms = 1234 });
    arena.deinit();
    try std.testing.expectEqual(expected, (try BlobWire.parse(queue.bytes.?)).hash);
    try std.testing.expectEqual(1, intake.stats.blob_queued);
    try std.testing.expectEqual(0, intake.stats.blob_ready);
    try std.testing.expectEqual(0, intake.seen.count());
    try std.testing.expectEqual(0, recorder.count);
    intake.pollBlobResults(3);
    try std.testing.expectEqual(0, intake.seen.count());
    queue.state = .ready;
    intake.pollBlobResults(4);
    try std.testing.expectEqual(1, intake.stats.blob_ready);
    try std.testing.expect(intake.known(expected, 5));
    try std.testing.expectEqual(0, intake.pending.count());
}

test "ETH71 blob failed asynchronous verification retries another peer without hash poisoning" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var queue: BlobQueue = .{ .allocator = std.testing.allocator };
    defer queue.deinit();
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    intake.sink.blobs = queue.sink();
    const vector = try blobTestVector(a, 0, 1, 1, 128);
    const ann = try announceBlob(a, vector);
    try intake.announce(a, peer_a, ann, 0);
    try intake.announce(a, peer_b, ann, 0);
    _ = intake.nextRequest(1, 0).?;
    try intake.response(a, peer_a, try responseOne(a, 1, vector.wrapper), .{ .mono_ms = 1 });
    // Queue state is mocked here; native integration separately runs real KZG.
    queue.state = .missing;
    intake.expire(2);
    try std.testing.expectEqual(1, intake.stats.blob_failed);
    try std.testing.expect(!intake.known(vector.hash, 2));
    try std.testing.expect(intake.nextRequest(2, 3) == null);
    const alternate = intake.nextRequest(3, 502).?;
    try std.testing.expectEqual(peer_b, alternate.peer);
    try intake.response(a, peer_b, try responseOne(a, 3, vector.wrapper), .{ .mono_ms = 503 });
    queue.state = .ready;
    intake.expire(504);
    try std.testing.expectEqual(1, intake.stats.blob_ready);
    try std.testing.expectEqual(2, queue.calls);
}

test "ETH71 blob backpressure preserves retry metadata and ordinary traffic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var queue: BlobQueue = .{ .allocator = std.testing.allocator, .full = true };
    defer queue.deinit();
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    intake.sink.blobs = queue.sink();
    const vector = try blobTestVector(a, 0, 1, 1, 128);
    try intake.announce(a, peer_a, try announceBlob(a, vector), 0);
    _ = intake.nextRequest(1, 0).?;
    try intake.response(a, peer_a, try responseOne(a, 1, vector.wrapper), .{ .mono_ms = 1 });
    try std.testing.expectEqual(1, intake.stats.blob_sink_full);
    try std.testing.expect(getAdvertisement(intake.pending.getPtr(vector.hash).?, peer_a) != null);
    try std.testing.expect(intake.nextRequest(2, 2) == null);
    const ordinary = try fixture(a);
    try intake.announce(a, peer_b, try announceOne(a, ordinary, 0), 2);
    const request = intake.nextRequest(3, 2).?;
    try std.testing.expect(!request.blob);
    try intake.response(a, peer_b, try responseOne(a, 3, ordinary), .{ .mono_ms = 3 });
    try std.testing.expectEqual(1, recorder.count);
    queue.full = false;
    _ = intake.nextRequest(4, 1001).?;
    try intake.response(a, peer_a, try responseOne(a, 4, vector.wrapper), .{ .mono_ms = 1002 });
    try std.testing.expectEqual(1, intake.stats.blob_queued);
}

test "ETH71 blob parser rejects missing version sidecars wrong cardinality and noncanonical framing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const good = try blobTestVector(a, 0, 1, 1, 128);
    const unknown = try blobTestVector(a, 0, 1, 2, 128);
    const missing = try blobTestVector(a, 0, 1, 1, 127);
    const extra = try blobTestVector(a, 0, 1, 1, 129);
    const too_many = try blobTestVector(a, 0, 7, 1, 896);
    try std.testing.expectError(error.BlobSidecarRequired, BlobWire.parse(good.canonical));
    try std.testing.expectError(error.UnsupportedBlobSidecarVersion, BlobWire.parse(unknown.wrapper));
    try std.testing.expectError(error.InvalidBlobWrapper, BlobWire.parse(missing.wrapper));
    try std.testing.expectError(error.InvalidBlobSidecar, BlobWire.parse(extra.wrapper));
    try std.testing.expectError(error.TooManyBlobs, BlobWire.parse(too_many.wrapper));
    try std.testing.expectError(error.InvalidBlobWrapper, BlobWire.parse(try std.mem.concat(a, u8, &.{ good.wrapper, &.{0} })));
    try std.testing.expectError(error.InvalidBlobWrapper, BlobWire.parse(good.wrapper[0 .. good.wrapper.len - 1]));
    try std.testing.expectError(error.NonCanonicalTransaction, BlobWire.parse(&.{ 3, 0xf8, 1, 0xc0 }));
    for (0..@min(good.wrapper.len, 256)) |end| {
        if (BlobWire.parse(good.wrapper[0..end])) |_| return error.AcceptedTruncatedBlob else |_| {}
    }
}

test "ETH71 blob response binds peer epoch id signed hash type and exact pooled size atomically" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vector = try blobTestVector(a, 0, 1, 1, 128);
    const other = try blobTestVector(a, 1, 1, 1, 128);
    const ordinary = try fixture(a);
    for (0..6) |scenario| {
        var recorder: Recorder = .{};
        var queue: BlobQueue = .{ .allocator = std.testing.allocator };
        defer queue.deinit();
        var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
        defer intake.deinit();
        intake.sink.blobs = queue.sink();
        const ann = if (scenario == 4)
            try encode(a, .{ @as([]const u8, &.{3}), @as([]const u32, &.{@intCast(vector.canonical.len)}), @as([]const Hash, &.{vector.hash}) })
        else
            try announceBlob(a, vector);
        try intake.announce(a, peer_a, ann, 0);
        try intake.announce(a, peer_b, try announceBlob(a, vector), 0);
        _ = intake.nextRequest(1, 0).?;
        switch (scenario) {
            0 => try std.testing.expectError(error.UnsolicitedResponse, intake.response(a, .{ .index = peer_a.index, .epoch = peer_a.epoch + 1 }, try responseOne(a, 1, vector.wrapper), .{ .mono_ms = 1 })),
            1 => try std.testing.expectError(error.UnsolicitedResponse, intake.response(a, peer_a, try responseOne(a, 2, vector.wrapper), .{ .mono_ms = 1 })),
            2 => try std.testing.expectError(error.UnrequestedTransaction, intake.response(a, peer_a, try responseOne(a, 1, other.wrapper), .{ .mono_ms = 1 })),
            3 => try std.testing.expectError(error.InvalidBlobWrapper, intake.response(a, peer_a, try responseOne(a, 1, ordinary), .{ .mono_ms = 1 })),
            4 => try std.testing.expectError(error.AnnouncementMismatch, intake.response(a, peer_a, try responseOne(a, 1, vector.wrapper), .{ .mono_ms = 1 })),
            5 => {
                const wrapped = try encode(a, vector.wrapper);
                const response = try encode(a, .{ @as(u64, 1), @as([]const rlp.RawValue, &.{ .{ .value = wrapped }, .{ .value = wrapped } }) });
                try std.testing.expectError(error.ResponseCountLimit, intake.response(a, peer_a, response, .{ .mono_ms = 1 }));
            },
            else => unreachable,
        }
        try std.testing.expectEqual(0, queue.calls);
        try std.testing.expectEqual(0, intake.seen.count());
        intake.disconnect(peer_a);
        const alternate = intake.nextRequest(3, 1001).?;
        try std.testing.expectEqual(peer_b, alternate.peer);
        try intake.response(a, peer_b, try responseOne(a, 3, vector.wrapper), .{ .mono_ms = 1002 });
        try std.testing.expectEqual(1, queue.calls);
    }
}

test "ETH71 blob acquisition bounds inventory concurrent requests and independent byte rates" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var queue: BlobQueue = .{ .allocator = std.testing.allocator };
    defer queue.deinit();
    var intake: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer intake.deinit();
    intake.sink.blobs = queue.sink();
    const kinds = try a.alloc(u8, max_pending_blobs_per_peer + 1);
    const sizes = try a.alloc(u32, kinds.len);
    const hashes = try a.alloc(Hash, kinds.len);
    @memset(kinds, 3);
    @memset(sizes, 150000);
    for (0..5) |index| {
        for (hashes, 0..) |*item, i| std.mem.writeInt(u256, item, index * 1000 + i, .big);
        try intake.announce(a, .{ .index = index, .epoch = 1 }, try encode(a, .{ @as([]const u8, kinds), @as([]const u32, sizes), @as([]const Hash, hashes) }), 0);
    }
    try std.testing.expectEqual(max_pending_blobs, intake.pending.count());
    try std.testing.expectEqual(37, intake.stats.blob_inventory_drops);
    try std.testing.expect(intake.nextRequest(1, 0).?.blob);
    try std.testing.expect(intake.nextRequest(2, 0).?.blob);
    try std.testing.expect(intake.nextRequest(3, 0) == null);
    // Blob traffic consumes its own bytes; exhausting it preserves ordinary
    // frame admission on both the same peer and unrelated peers.
    try intake.reserveFrameClass(peer_a, max_message_bytes, 1, true);
    try std.testing.expectError(error.FrameRateLimit, intake.reserveFrameClass(peer_b, 2048, 1, true));
    try intake.reserveFrame(peer_a, max_message_bytes / 2, 1);
    try std.testing.expectEqual(1, intake.stats.blob_frame_rate_drops);
    intake.expire(1501);
    try std.testing.expectEqual(2, intake.stats.expired_requests);
    try std.testing.expect(intake.nextRequest(4, 1502) != null);
}

test "ETH71 blob signature and chain validation precede queue delivery" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vector = try blobTestVector(a, 0, 1, 1, 128);
    const Fields = struct { body: rlp.RawValue, version: u8, blobs: rlp.RawValue, commitments: rlp.RawValue, proofs: rlp.RawValue };
    var fields: Fields = undefined;
    _ = try rlp.deserialize(Fields, a, vector.wrapper[1..], &fields);
    for (0..3) |scenario| {
        var recorder: Recorder = .{};
        var queue: BlobQueue = .{ .allocator = std.testing.allocator };
        defer queue.deinit();
        var source: Intake = .{ .allocator = std.testing.allocator, .chain_id = if (scenario == 0) 2 else 1, .sink = recorder.sink() };
        defer source.deinit();
        source.sink.blobs = queue.sink();
        var changed = vector;
        if (scenario != 0) {
            var tx: types.Transaction = undefined;
            _ = try tx.decodeFromRLP(a, vector.canonical);
            tx.blob.s = if (scenario == 1) 0 else 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - tx.blob.s;
            fields.body.value = try encode(a, tx.blob);
            changed.canonical = try std.mem.concat(a, u8, &.{ &.{3}, fields.body.value });
            changed.hash = hash(changed.canonical);
            changed.wrapper = try std.mem.concat(a, u8, &.{ &.{3}, try encode(a, fields) });
        }
        try source.announce(a, peer_a, try announceBlob(a, changed), 0);
        _ = source.nextRequest(1, 0).?;
        const reply = try responseOne(a, 1, changed.wrapper);
        if (scenario == 0)
            try std.testing.expectError(error.InvalidChainId, source.response(a, peer_a, reply, .{ .mono_ms = 1 }))
        else
            try std.testing.expectError(error.InvalidSignature, source.response(a, peer_a, reply, .{ .mono_ms = 1 }));
        try std.testing.expectEqual(0, queue.calls);
        try std.testing.expectEqual(0, source.seen.count());
    }
}

fn blobAllocationCase(allocator: std.mem.Allocator, ann: []const u8, response: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var recorder: Recorder = .{};
    var queue: BlobQueue = .{ .allocator = std.testing.allocator };
    defer queue.deinit();
    var source: Intake = .{ .allocator = allocator, .chain_id = 1, .sink = recorder.sink() };
    defer source.deinit();
    source.sink.blobs = queue.sink();
    try source.announce(arena.allocator(), peer_a, ann, 0);
    _ = source.nextRequest(1, 0).?;
    try source.response(arena.allocator(), peer_a, response, .{ .mono_ms = 1 });
    try std.testing.expectEqual(1, queue.calls);
    try std.testing.expectEqual(0, source.seen.count());
}

test "ETH71 blob request decode ownership survives allocation failures and bounded verifier timeout" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vector = try blobTestVector(a, 0, 1, 1, 128);
    const ann = try announceBlob(a, vector);
    const response = try responseOne(a, 1, vector.wrapper);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, blobAllocationCase, .{ ann, response });
    var recorder: Recorder = .{};
    var queue: BlobQueue = .{ .allocator = std.testing.allocator };
    defer queue.deinit();
    var source: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer source.deinit();
    source.sink.blobs = queue.sink();
    try source.announce(a, peer_a, ann, 0);
    _ = source.nextRequest(1, 0).?;
    try source.response(a, peer_a, response, .{ .mono_ms = 1 });
    source.expire(verification_timeout_ms);
    try std.testing.expectEqual(1, source.pending.count());
    source.expire(verification_timeout_ms + 1);
    try std.testing.expectEqual(1, source.stats.blob_failed);
    try std.testing.expectEqual(0, source.pending.count());
    try std.testing.expectEqual(0, source.seen.count());
    for (source.verifications) |verification| try std.testing.expect(verification == null);
}

test "ETH71 blob inventory quota cannot be bypassed by an earlier ordinary type claim" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var recorder: Recorder = .{};
    var queue: BlobQueue = .{ .allocator = std.testing.allocator };
    defer queue.deinit();
    var source: Intake = .{ .allocator = std.testing.allocator, .chain_id = 1, .sink = recorder.sink() };
    defer source.deinit();
    source.sink.blobs = queue.sink();
    const kinds = try a.alloc(u8, max_pending_blobs_per_peer + 1);
    const sizes = try a.alloc(u32, kinds.len);
    const hashes = try a.alloc(Hash, kinds.len);
    @memset(kinds, 2);
    @memset(sizes, 100);
    for (hashes, 0..) |*item, i| std.mem.writeInt(u256, item, i, .big);
    try source.announce(a, peer_a, try encode(a, .{ @as([]const u8, kinds), @as([]const u32, sizes), @as([]const Hash, hashes) }), 0);
    @memset(kinds, 3);
    @memset(sizes, 150000);
    try source.announce(a, peer_b, try encode(a, .{ @as([]const u8, kinds), @as([]const u32, sizes), @as([]const Hash, hashes) }), 0);
    var blob_count: usize = 0;
    for (source.pending.values()) |entry| if (entry.blob) {
        blob_count += 1;
        try std.testing.expectEqual(peer_b.index, entry.blob_owner_index);
    };
    try std.testing.expectEqual(max_pending_blobs_per_peer, blob_count);
    try std.testing.expectEqual(1, source.stats.blob_inventory_drops);
    source.disconnect(peer_a);
    try std.testing.expect(source.nextRequest(1, 1).?.blob);
}
