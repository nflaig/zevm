// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const rlpx = @import("../devp2p/rlpx.zig");
const eth = @import("../devp2p/eth.zig");
const snap = @import("../devp2p/snap.zig");
const types = @import("../types.zig");
const rlp = @import("rlp");
const trie = @import("../trie/trie.zig");
const kv = @import("../db/kv.zig");
const lmdbx = @import("lmdbx");
const prom = @import("metrics");
const branches = @import("../db/branches.zig");
const undo = @import("../db/undo.zig");
const snapshots_db = @import("../db/snapshot.zig");
const bootstrap_db = @import("../db/bootstrap.zig");
const consensus = @import("consensus.zig");
const PublicIntake = @import("public_intake_peer.zig").Driver;

const RangeProofVerifier = @import("../trie/range_proof.zig").Verifier;
const EthDb = @import("../db/eth.zig").Eth;
const List = @import("../free_list.zig").List;
const Blockchain = @import("blockchain.zig").Blockchain;
const max_inflight_requests = 100;
const max_inflight_requests_per_peer = 2;
const header_persist_chunk = 1024;
const batch_storage_code_req_size = 256;
const min_split_range = std.math.maxInt(u256) / (1 << 16);
const progress_log_interval: std.Io.Duration = .fromSeconds(8);
const arena_retain_limit = (32 << 20) - 64;
const max_snap_flush_queue_bytes = 2048 << 20;
const max_snap_flush_seconds = 0.5;
const expected_code_count = 20_000_000;
const hash_window_size = 32 << 10;
const hash_window_nodes = 2 * hash_window_size + 128;
const bootstrap_drain_timeout_seconds = 30;
const state_unavailable_backoff_ms = 10_000;
// Only CL-managed, verified-state, single-block healing gets an early retry.
// The existing one-second tick makes this a 1-2s acquisition budget, not a
// promise about validation, database writes or total state readiness.
// Geth broadcasts its ETH range every 32 blocks; an announced head is a
// lower bound on peer progress, not proof it cannot serve a newer block.
const bal_announced_height_gap = 32;
const near_head_bal_retry_after: std.Io.Duration = .fromSeconds(1);

const log = std.log.scoped(.downloader);

pub const Downloader = struct {
    const Self = @This();

    io: std.Io,
    allocator: std.mem.Allocator,
    bc: *Blockchain,
    eth_db: *EthDb,
    shadow_snapshots: ?*@import("../db/snapshot.zig").Snapshots = null,
    public_intake: ?*PublicIntake = null,
    pending_bootstrap: ?types.BlockHeader = null,
    consensus_updates: ?*std.Io.Queue(consensus.Update) = null,
    consensus_update: ?consensus.Update = null,
    consensus_anchor: ?consensus.Anchor = null,
    bootstrap_target: ?consensus.Anchor = null,
    consensus_probe: ?[32]u8 = null,
    consensus_reported: ?[32]u8 = null,
    ancestor_probe: ?[32]u8 = null,
    ancestors_ready: ?[32]u8 = null,
    header_generation: u64 = 0,

    peer_ranges: []?PeerRange,
    unavailable_state: [rlpx.Server.max_peers]?struct {
        peer: rlpx.Server.PeerId,
        root: [32]u8,
        until_ms: i64,
    } = @splat(null),

    eth_arena: std.heap.ArenaAllocator,
    eth_provider: *eth.Provider,
    free_eth_requests: List(Request(eth.Message)),
    inflight_eth_requests: List(Request(eth.Message)) = .{},
    pending_eth_requests: List(Request(eth.Message)) = .{},
    validating_eth_requests: List(Request(eth.Message)) = .{},

    snap_arena: std.heap.ArenaAllocator,
    snap_provider: *snap.Provider,
    free_snap_requests: List(Request(snap.Message)),
    inflight_snap_requests: List(Request(snap.Message)) = .{},
    pending_snap_requests: List(Request(snap.Message)) = .{},
    stashed_snap_requests: []Request(snap.Message),
    validating_snap_requests: List(Request(snap.Message)) = .{},
    snap_flush_queue: List(QueuedSnapFlush) = .{},
    snap_flush_queue_bytes: usize = 0,

    validated_responses: std.Io.Queue(ValidatedResponse),
    task_group: std.Io.Group = .init,

    sync_target: SyncTarget,
    sync_target_mutex: std.Io.Mutex = .init,
    header: ?struct {
        requested_header_head: u64,
        requested_header_tail: u64,
    } = null,
    state: ?struct {
        pivot: types.BlockHeader,

        phase: enum {
            accounts,
            storage,
            codes,
            hashing,
            catchup,
        } = .accounts,

        account_fetch_head: u256 = 0,
        account_fetch_step: u256 = 0,
        storage_fetch_head: [32]u8 = @splat(0),
        code_hashes: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
        code_fetch_head: usize = 0,
        hash_head: [32]u8 = @splat(0),
    } = null,
    state_heal: ?struct {
        next_pivot: types.BlockHeader,
        target_pivot: types.BlockHeader,
        start_number: u64,
        started_at: std.Io.Timestamp,
        drain_started_at: ?std.Io.Timestamp = null,

        bal_requested: bool = false,
        bal_applied: bool = false,
        // Per logical block, not per wire request: malformed/empty responses,
        // generic timeouts and CL target changes must not replenish this budget.
        bal_early_retry_hash: ?[32]u8 = null,
        // A second wire identity for the SAME pooled request. Only inflight
        // source ownership can claim it; it never owns a validation buffer.
        bal_hedge: ?BalHedge = null,
        bal_hedge_winner: ?u64 = null,
        bal_hashes: [128][32]u8 = undefined,
        stale_storage_roots: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    } = null,
    metrics: Metrics,
    progress: struct {
        headers: u64 = 0,
        account_keyspace: u256 = 0,
        storage_keyspace: u256 = 0,
        code_keyspace: u256 = 0,
        last_log: ?std.Io.Timestamp = null,
    } = .{},

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        bc: *Blockchain,
        eth_db: *EthDb,
        eth_provider: *eth.Provider,
        snap_provider: *snap.Provider,
    ) !Self {
        const peer_ranges = try allocator.alloc(?PeerRange, eth_provider.peers.len);
        @memset(peer_ranges, null);

        var stashed_snap_requests = try allocator.alloc(Request(snap.Message), max_inflight_requests);
        stashed_snap_requests.len = 0;

        const head = try bc.head();

        return .{
            .io = io,
            .allocator = allocator,
            .bc = bc,
            .eth_db = eth_db,
            .eth_arena = .init(allocator),
            .eth_provider = eth_provider,
            .free_eth_requests = try .init(allocator, max_inflight_requests),
            .snap_arena = .init(allocator),
            .snap_provider = snap_provider,
            .free_snap_requests = try .init(allocator, max_inflight_requests),
            .stashed_snap_requests = stashed_snap_requests,
            .peer_ranges = peer_ranges,
            .metrics = try .init(allocator, io),
            .sync_target = .{
                .number = head.number,
                .hash = head.hash,
                .cutoff_number = head.number,
                .cutoff_hash = head.hash,
            },
            .validated_responses = .init(try allocator.alloc(ValidatedResponse, 2 * max_inflight_requests)),
        };
    }

    pub fn run(self: *Self) !void {
        const tag = enum(u8) { eth, snap, validated, tick, target };
        const msg = union(tag) {
            eth: @typeInfo(@TypeOf(eth.Provider.next)).@"fn".return_type.?,
            snap: @typeInfo(@TypeOf(snap.Provider.next)).@"fn".return_type.?,
            validated: @typeInfo(@TypeOf(std.Io.Queue(ValidatedResponse).getOne)).@"fn".return_type.?,
            tick: @typeInfo(@TypeOf(std.Io.sleep)).@"fn".return_type.?,
            target: @typeInfo(@TypeOf(std.Io.Queue(consensus.Update).getOne)).@"fn".return_type.?,
        };

        var buf: [5]msg = undefined;
        var select: std.Io.Select(msg) = .init(self.io, &buf);
        defer self.task_group.cancel(self.io);
        defer select.cancelDiscard();

        try select.concurrent(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator });
        try select.concurrent(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator });
        try select.concurrent(.validated, std.Io.Queue(ValidatedResponse).getOne, .{ &self.validated_responses, self.io });
        try select.concurrent(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real });
        if (self.consensus_updates) |updates|
            try select.concurrent(.target, std.Io.Queue(consensus.Update).getOne, .{ updates, self.io });

        var busy_start = std.Io.Timestamp.now(self.io, .awake);
        while (true) {
            const wait_start = std.Io.Timestamp.now(self.io, .awake);
            self.metrics.loop_busy_seconds.incrBy(secondsSince(self.io, busy_start));
            const event = try select.await();
            const cancel_protection = self.io.swapCancelProtection(.blocked);
            defer _ = self.io.swapCancelProtection(cancel_protection);
            busy_start = std.Io.Timestamp.now(self.io, .awake);
            self.metrics.loop_wait_seconds.incrBy(secondsSince(self.io, wait_start));

            switch (event) {
                .eth => |res| {
                    defer select.concurrent(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    const received_message = res catch {
                        _ = self.eth_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                        continue;
                    };
                    if (!try self.handleEth(received_message)) {
                        self.allocator.free(received_message.read.payload);
                        _ = self.eth_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                    }
                    self.observeHandle(@tagName(received_message.msg), busy_start);
                },
                .snap => |res| {
                    defer select.concurrent(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    const received_message = res catch {
                        _ = self.snap_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                        continue;
                    };
                    if (!try self.handleSnap(received_message)) {
                        self.allocator.free(received_message.read.payload);
                        _ = self.snap_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                    }
                    self.observeHandle(@tagName(received_message.msg), busy_start);
                },
                .validated => |res| {
                    defer select.concurrent(.validated, std.Io.Queue(ValidatedResponse).getOne, .{ &self.validated_responses, self.io }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    const validated = try res;
                    try self.handleValidated(validated);
                    self.observeHandle(validated.resp.msgName(), busy_start);
                },
                .tick => {
                    defer select.concurrent(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    try self.handleTick();
                    self.observeHandle("tick", busy_start);
                },
                .target => |res| {
                    defer select.concurrent(.target, std.Io.Queue(consensus.Update).getOne, .{ self.consensus_updates.?, self.io }) catch |e| std.debug.panic("downloader: target task: {}", .{e});
                    self.consensus_update = try res;
                    try self.advanceConsensusTarget();
                    self.observeHandle("consensus_target", busy_start);
                },
            }
            // In CL-managed shadow mode, don't wait for the one-second recovery
            // tick between a target, its headers, its BAL and the next checkpoint.
            if (self.consensus_updates != null) try self.advanceShadowWork();
        }
    }

    fn handleTick(self: *Self) !void {
        if (self.public_intake) |intake| {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            intake.tick(arena.allocator(), std.Io.Timestamp.now(self.io, .awake).toMilliseconds());
        }
        self.updateMetrics();
        self.logProgress();
        if (self.consensus_updates != null) try self.advanceConsensusTarget();
        if (self.shadow_snapshots != null) try self.advanceAncestorDownload();
        if (self.header != null) {
            try self.advanceHeaderDownload();
            if (self.bc.shadow_branches.load(.acquire)) try self.checkHeaderDownloadComplete();
        }
        try self.drainSnapFlushQueue();
        if (self.state != null) {
            try self.updatePivot();
            try self.advanceStateDownload();
        }
        if (self.state_heal != null) {
            try self.advanceStateHeal();
        }
        try self.checkEthRequestTimeouts();
        try self.checkSnapRequestTimeouts();
        self.drainPendingEthRequests();
        self.drainPendingSnapRequests();
    }

    fn handleEth(self: *Self, received: eth.Provider.ParsedMessage) !bool {
        const peer = received.read.peer;
        if (self.public_intake) |intake| {
            // A Status for this connection epoch must precede public intake.
            if (self.peer_ranges[peer.peer_index]) |range| {
                if (range.id.peer_epoch == peer.peer_epoch)
                    intake.handle(self.eth_arena.allocator(), received, .{
                        .mono_ms = std.Io.Timestamp.now(self.io, .awake).toMilliseconds(),
                        .wall_ms = std.Io.Timestamp.now(self.io, .real).toMilliseconds(),
                    });
            }
        }
        var matched: ?*Request(eth.Message) = null;
        switch (received.msg) {
            .status => |status| {
                if (self.consensus_updates == null) try self.updateTarget(status.latest_block, status.latest_block_hash);
                self.peer_ranges[peer.peer_index] = .{ .id = peer, .range = .{
                    .earliest_block = status.earliest_block,
                    .latest_block = status.latest_block,
                    .latest_block_hash = status.latest_block_hash,
                } };
            },
            .block_range_update => |update| {
                if (self.consensus_updates == null) try self.updateTarget(update.latest_block, update.latest_block_hash);
                self.peer_ranges[peer.peer_index] = .{ .id = peer, .range = update };
            },
            .block_headers => |headers| matched = self.matchRequest(eth.Message, self.eth_provider, &self.inflight_eth_requests, peer, headers.request_id, .get_block_headers),
            .block_access_list => |access_lists| {
                // ETH uses RLP's empty string for an unavailable BAL. The
                // empty list (0xc0) is a real BAL and must still be validated.
                const unavailable = access_lists.rlps.len == 0 or
                    std.mem.eql(u8, access_lists.rlps[0].value, &.{0x80});
                matched = self.matchBalRequest(peer, access_lists.request_id, unavailable);
            },
            else => {},
        }
        if (matched) |req| {
            self.validating_eth_requests.push(req);
            try self.startValidation(&self.eth_arena, .{ .eth = .{ .msg = received, .req = req } });
        }
        self.drainPendingEthRequests();
        return matched != null;
    }

    fn handleSnap(self: *Self, received: snap.Provider.ParsedMessage) !bool {
        const peer = received.read.peer;
        const matched = switch (received.msg) {
            .account_range => |account_range| self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, account_range.id, .get_account_range),
            .storage_ranges => |storage_ranges| self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, storage_ranges.id, .get_storage_ranges),
            .byte_codes => |byte_codes| self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, byte_codes.id, .get_byte_codes),
            else => null,
        };
        if (matched) |req| {
            insertRequest(&self.validating_snap_requests, req, .back);
            try self.startValidation(&self.snap_arena, .{ .snap = .{ .msg = received, .req = req } });
        }
        self.drainPendingSnapRequests();
        return matched != null;
    }

    fn startValidation(self: *Self, arena: *std.heap.ArenaAllocator, response: @FieldType(ValidatedResponse, "resp")) !void {
        defer arena.* = .init(self.allocator);
        self.task_group.concurrent(
            self.io,
            validate,
            .{ self, arena.*, response },
        ) catch validate(self, arena.*, response);
    }

    fn validate(self: *Self, arena: std.heap.ArenaAllocator, response: @FieldType(ValidatedResponse, "resp")) void {
        const start = std.Io.Timestamp.now(self.io, .awake);
        var gpa = arena;
        const allocator = gpa.allocator();
        const outcome = switch (response) {
            .eth => |*resp| switch (resp.msg.msg) {
                .block_headers => |headers| validateHeaders(allocator, resp.req.msg.get_block_headers, headers),
                .block_access_list => |access_lists| validateBal(allocator, access_lists),
                else => unreachable,
            },
            .snap => |*resp| switch (resp.msg.msg) {
                .account_range => |*account_range| self.verifyAccounts(allocator, resp.req.msg.get_account_range, account_range),
                .storage_ranges => |*storage_ranges| self.verifyStorage(allocator, resp.req.msg.get_storage_ranges, resp.req.storage_roots, storage_ranges),
                .byte_codes => |byte_codes| hashCodes(allocator, byte_codes),
                else => unreachable,
            },
        };

        self.metrics.verify_seconds.observe(.{ .msg = response.msgName() }, secondsSince(self.io, start)) catch {};
        self.validated_responses.putOneUncancelable(self.io, .{ .arena = gpa, .resp = response, .outcome = outcome }) catch unreachable;
    }

    fn handleValidated(self: *Self, validated: ValidatedResponse) !void {
        if (validated.outcome) |_| {} else |err| switch (validated.resp) {
            inline else => |resp, proto| {
                if (proto == .snap and (err == error.EmptyAccountRange or err == error.EmptyStorageRanges)) {
                    self.markUnavailableState(resp.req);
                } else {
                    log.debug("dropping peer {} for an invalid {s}: {}", .{ resp.req.peer.peer_index, validated.resp.msgName(), err });
                    const provider = if (proto == .eth) self.eth_provider else self.snap_provider;
                    provider.disconnect(resp.req.peer, err);
                }
            },
        }

        switch (validated.resp) {
            .eth => |*resp| {
                defer validated.deinit(self.allocator);

                self.validating_eth_requests.remove(resp.req);
                switch (resp.msg.msg) {
                    .block_headers => try self.handleHeaders(resp.req, validated.outcome),
                    .block_access_list => try self.handleBals(resp.req, validated.outcome),
                    else => unreachable,
                }
                self.drainPendingEthRequests();
            },
            .snap => |*resp| {
                {
                    errdefer validated.deinit(self.allocator);
                    self.validating_snap_requests.remove(resp.req);
                    switch (resp.msg.msg) {
                        .account_range => try self.handleAccounts(resp.req, validated.outcome),
                        .storage_ranges => try self.handleStorage(resp.req, validated.outcome),
                        .byte_codes => try self.handleCodes(resp.req, validated.outcome),
                        else => unreachable,
                    }
                }
                try self.queueSnapFlush(validated);
                try self.drainSnapFlushQueue();

                self.drainPendingSnapRequests();
                if (self.state != null)
                    try self.advanceStateDownload();
                if (self.state_heal != null)
                    try self.advanceStateHeal();
            },
        }
    }

    fn markUnavailableState(self: *Self, req: *const Request(snap.Message)) void {
        const root = switch (req.msg) {
            .get_account_range => |request| request.root,
            .get_storage_ranges => |request| request.root_hash,
            else => return,
        };
        self.unavailable_state[req.peer.peer_index] = .{
            .peer = req.peer,
            .root = root,
            .until_ms = @as(i64, @intCast(std.Io.Clock.awake.now(self.io).toMilliseconds())) +| state_unavailable_backoff_ms,
        };
        log.debug("peer {} cannot serve state {x}; retaining connection with root-scoped backoff", .{ req.peer.peer_index, root });
    }

    fn queueSnapFlush(self: *Self, validated: ValidatedResponse) !void {
        const outcome = validated.outcome catch return validated.deinit(self.allocator);
        var flush: QueuedSnapFlush = .{ .arena = validated.arena, .response = validated.resp.snap.msg, .validation_outcome = outcome };
        const node = flush.arena.allocator().create(List(QueuedSnapFlush).Node) catch |err| {
            flush.deinit(self.allocator);
            return err;
        };
        node.elem = flush;
        self.snap_flush_queue.insertSorted(&node.elem, QueuedSnapFlush.lessThan);
        self.snap_flush_queue_bytes += node.elem.size();
    }

    fn drainSnapFlushQueue(self: *Self) !void {
        const start = std.Io.Timestamp.now(self.io, .awake);
        var current_node = self.snap_flush_queue.inner.first;
        while (current_node) |list_node| {
            if (secondsSince(self.io, start) > max_snap_flush_seconds) return;
            current_node = list_node.next;
            const flush = &@as(*List(QueuedSnapFlush).Node, @alignCast(@fieldParentPtr("node", list_node))).elem;
            if (self.hasPrecedingSnapRequest(flush)) continue;

            self.snap_flush_queue.remove(flush);
            self.snap_flush_queue_bytes -= flush.size();
            self.metrics.snap_flushed_bytes.incrBy(flush.size());
            defer flush.deinit(self.allocator);
            switch (flush.response.msg) {
                .account_range => |*account_range| try self.persistAccounts(flush.validation_outcome.accounts, account_range),
                .storage_ranges => try self.persistStorage(flush.validation_outcome.storage),
                .byte_codes => |byte_codes| try self.persistCodes(flush.validation_outcome.codes, byte_codes.bytecodes),
                else => unreachable,
            }
        }
    }

    fn hasPrecedingSnapRequest(self: *Self, flush: *const QueuedSnapFlush) bool {
        for ([_]*List(Request(snap.Message)){ &self.pending_snap_requests, &self.inflight_snap_requests, &self.validating_snap_requests }) |list| {
            var current_node = list.inner.first;
            while (current_node) |list_node| : (current_node = list_node.next) {
                const request: *List(Request(snap.Message)).Node = @alignCast(@fieldParentPtr("node", list_node));
                if (flush.isPrecededBy(request.elem.msg, false)) return true;
            }
        }
        return false;
    }

    fn validateHeaders(allocator: std.mem.Allocator, request: eth.GetBlockHeaders, response: eth.BlockHeaders) !ValidationOutcome {
        if (response.rlps.len > request.range.amount) return error.TooManyHeaders;
        if (response.rlps.len == 0) return .{ .headers = .{ .hashes = &.{}, .headers = &.{} } };

        var headers: []types.BlockHeader = try allocator.alloc(types.BlockHeader, response.rlps.len);
        var hashes: [][32]u8 = try allocator.alloc([32]u8, response.rlps.len);
        for (response.rlps, 0..) |header_rlp, index| {
            const canon_index = if (request.range.reverse) response.rlps.len - index - 1 else index;
            if (try rlp.deserialize(types.BlockHeader, allocator, header_rlp.value, &headers[canon_index]) != header_rlp.value.len)
                return error.InvalidHeaderEncoding;
            std.crypto.hash.sha3.Keccak256.hash(header_rlp.value, &hashes[canon_index], .{});
        }

        for (1..headers.len) |i| {
            if (headers[i - 1].number == std.math.maxInt(u64) or headers[i].number != headers[i - 1].number + 1 or
                !std.meta.eql(hashes[i - 1], headers[i].parent_hash))
            {
                return error.InvalidHeaderChain;
            }
        }

        switch (request.range.origin) {
            .hash => |expected_hash| {
                if (!std.meta.eql(hashes[hashes.len - 1], expected_hash)) return error.UnexpectedOriginHeader;
            },
            .number => |expected_number| {
                if (expected_number != headers[hashes.len - 1].number) return error.UnexpectedOriginHeader;
            },
        }

        return .{ .headers = .{ .hashes = hashes, .headers = headers } };
    }

    fn validateBal(allocator: std.mem.Allocator, response: eth.BlockAccessLists) !ValidationOutcome {
        if (response.rlps.len == 0) return error.EmptyResponse;
        const bals = try allocator.alloc(VerifiedBal, response.rlps.len);
        for (response.rlps, bals, 0..) |bal_rlp, *bal, index| {
            std.crypto.hash.sha3.Keccak256.hash(bal_rlp.value, &bal.hash, .{});
            // keep the ones before an access list the peer couldn't serve
            _ = rlp.deserialize(types.BlockAccessLists, allocator, bal_rlp.value, &bal.parsed) catch |err| {
                if (index == 0) return err;
                return .{ .bals = bals[0..index] };
            };
        }
        return .{ .bals = bals };
    }

    fn verifyAccounts(self: *Self, allocator: std.mem.Allocator, request: snap.GetAccountRange, response: *const snap.AccountRange) !ValidationOutcome {
        if (response.accounts.len == 0 and response.proof.len == 0) return error.EmptyAccountRange;
        var scratch_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch_arena.deinit();
        const scratch = scratch_arena.allocator();
        const hashes = try allocator.alloc([32]u8, response.accounts.len);
        const accounts = try scratch.alloc([]const u8, response.accounts.len);
        var code_hashes = try allocator.alloc([32]u8, response.accounts.len);
        code_hashes.len = 0;
        for (response.accounts, 0..) |elem, index| {
            hashes[index] = elem.hash;

            var slim_account: snap.SlimAccount = undefined;
            _ = try rlp.deserialize(snap.SlimAccount, scratch, elem.account.value, &slim_account);
            if (slim_account.code_hash.len == 32 and !std.mem.eql(u8, slim_account.code_hash, &types.empty_code_hash) and
                std.mem.order(u8, &elem.hash, &request.limit) != .gt)
            {
                code_hashes.len += 1;
                code_hashes[code_hashes.len - 1] = slim_account.code_hash[0..32].*;
            }

            var list = std.array_list.Managed(u8).init(scratch);
            try rlp.serialize(types.Account, scratch, slimToFullAccount(slim_account), &list);
            accounts[index] = try list.toOwnedSlice();
        }

        const verifier = try RangeProofVerifier.init(scratch);
        const proof = try proofNodes(scratch, response.proof);
        const has_more = try verifier.verify(
            scratch,
            request.root,
            request.origin,
            hashes,
            accounts,
            if (response.proof.len > 0) &proof else null,
        );
        const served = countBelowLimit(hashes, request.limit);
        return .{ .accounts = .{
            .origin = request.origin,
            .limit = request.limit,
            .hashes = hashes[0..served],
            .code_hashes = code_hashes,
            .has_more = has_more and served == hashes.len,
        } };
    }

    fn verifyStorage(
        self: *Self,
        response_arena: std.mem.Allocator,
        request: snap.GetStorageRanges,
        storage_roots: []const [32]u8,
        response: *const snap.StorageRanges,
    ) !ValidationOutcome {
        if (response.slots.len == 0 and response.proof.len == 0) return error.EmptyStorageRanges;

        const verifier = try RangeProofVerifier.init(self.allocator);
        defer verifier.deinit(self.allocator);

        const proof = try proofNodes(response_arena, response.proof);
        const served = response.slots[0..@min(response.slots.len, request.account_hashes.len)];
        var result: VerifiedStorage = .{
            .chunk = isStorageChunk(request),
            .keys = try response_arena.alloc([][32]u8, @max(served.len, 1)),
            .values = try response_arena.alloc([][]const u8, @max(served.len, 1)),
            .nodes = try response_arena.alloc([]trie.NodeCollector.Node, @max(served.len, 1)),
        };
        var verified: usize = 0;
        if (served.len == 0 and request.account_hashes.len > 0) {
            // without slots, the proof has to show the first account has none from the starting to u256.max
            _ = try verifier.verify(response_arena, storage_roots[0], request.starting_hash, &.{}, &.{}, &proof);
            result.keys[0] = &.{};
            result.values[0] = &.{};
            result.nodes[0] = &.{};
            verified = 1;
        }
        for (served, 0..) |slots, index| {
            const origin: [32]u8 = if (index == 0) request.starting_hash else @splat(0);
            const is_last = index + 1 == response.slots.len;

            const keys = try response_arena.alloc([32]u8, slots.len);
            const values = try response_arena.alloc([]const u8, slots.len);
            var node_collector = try trie.NodeCollector.init(response_arena, slots.len * 2);
            for (slots, 0..) |slot, slot_index| {
                keys[slot_index] = slot.hash;
                values[slot_index] = slot.data;
            }

            const has_more = try verifier.withCollector(&node_collector).verify(
                response_arena,
                storage_roots[index],
                origin,
                keys,
                values,
                if (is_last and response.proof.len > 0) &proof else null,
            );

            const served_slots = if (index + 1 == request.account_hashes.len)
                countBelowLimit(keys, request.limit_hash)
            else
                keys.len;
            result.keys[index] = keys[0..served_slots];
            result.values[index] = values[0..served_slots];
            result.nodes[index] = node_collector.collected();
            verified = index + 1;
            if (has_more and served_slots == keys.len) {
                result.continue_from_slot = origin;
                if (keys.len > 0)
                    std.mem.writeInt(
                        u256,
                        &result.continue_from_slot.?,
                        std.mem.readInt(u256, &keys[keys.len - 1], .big) + 1,
                        .big,
                    );
                break;
            }
        }
        result.account_hashes = try response_arena.dupe([32]u8, request.account_hashes[0..verified]);
        result.keys = result.keys[0..verified];
        result.values = result.values[0..verified];
        result.nodes = result.nodes[0..verified];
        return .{ .storage = result };
    }

    fn countBelowLimit(keys: []const [32]u8, limit: [32]u8) usize {
        for (keys, 0..) |key, index| {
            if (std.mem.order(u8, &key, &limit) == .gt) return index;
        }
        return keys.len;
    }

    fn hashCodes(allocator: std.mem.Allocator, response: snap.ByteCodes) !ValidationOutcome {
        const hashes = try allocator.alloc([32]u8, response.bytecodes.len);
        for (response.bytecodes, hashes) |code, *hash|
            std.crypto.hash.sha3.Keccak256.hash(code, hash, .{});
        return .{ .codes = hashes };
    }

    fn proofNodes(allocator: std.mem.Allocator, nodes: []const []const u8) !trie.NodesHashMap {
        var proof: trie.NodesHashMap = .empty;
        if (nodes.len > 0) {
            try proof.ensureTotalCapacity(allocator, @intCast(nodes.len));
            for (nodes) |node| {
                var h: [32]u8 align(8) = undefined;
                std.crypto.hash.sha3.Keccak256.hash(node, &h, .{});
                try proof.put(allocator, h, node);
            }
        }
        return proof;
    }

    pub fn syncTarget(self: *Self) SyncTarget {
        self.sync_target_mutex.lockUncancelable(self.io);
        defer self.sync_target_mutex.unlock(self.io);
        return self.sync_target;
    }

    /// Shadow mode resumes the committed state checkpoint, never the header
    /// head. Only a persisted finalized consensus anchor authorizes restarting an
    /// incomplete bootstrap's clear. Its new scan waits for a fresh trusted CL
    /// anchor; partial flat tables never become readable views.
    pub fn enableShadow(self: *Self, snapshots: *@import("../db/snapshot.zig").Snapshots, restart_bootstrap: bool) !void {
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const checkpoint = try snapshots_db.readCheckpoint(self.eth_db.kv_store, txn, arena.allocator());
        if (checkpoint) |header| {
            // Existing transactional branch metadata supersedes the old append-only
            // header files. Old prototypes can initialize only at their checkpoint;
            // they cannot invent undo history preceding it.
            self.bc.shadow_branches.store(try branches.state(self.eth_db.kv_store, txn) != null, .release);
            const saved = try self.bc.readHeader(header.number) orelse return error.StateCheckpointHeaderUnavailable;
            if (!std.meta.eql(saved.hash(), header.hash())) return error.StateCheckpointBranchMismatch;
            try branches.initialize(self.eth_db.kv_store, txn, arena.allocator(), header);
            try owned.commit();
            self.bc.shadow_branches.store(true, .release);
            self.state = .{ .pivot = header, .phase = .catchup };
            try snapshots.publish(self.allocator);
            const head = try self.bc.head();
            self.sync_target = .{ .number = head.number, .hash = head.hash, .cutoff_number = head.number, .cutoff_hash = head.hash };
        } else if (try branches.state(self.eth_db.kv_store, txn) != null) {
            if (!restart_bootstrap) return error.IncompleteStateCheckpoint;
            const anchor = try self.readConsensusAnchor(txn, arena.allocator()) orelse return error.IncompleteStateCheckpoint;
            const header = try bootstrap_db.restart(self.eth_db.kv_store, txn, arena.allocator(), anchor.execution_hash);
            if (header.slot_number.? > anchor.slot) return error.BootstrapBranchMismatch;
            try owned.commit();
            self.pending_bootstrap = header;
            log.info("shadow cleared incomplete bootstrap at authorized anchor {} hash {x}; awaiting fresh finalized anchor, no state view published", .{ header.number, header.hash() });
        } else if ((try self.bc.head()).number != 0) return error.IncompleteStateCheckpoint;
        self.shadow_snapshots = snapshots;
    }

    fn readConsensusAnchor(self: *Self, txn: kv.Transaction, allocator: std.mem.Allocator) !?consensus.Anchor {
        const encoded = try self.eth_db.kv_store.table(txn, .state_meta).get("consensus-anchor-v1") orelse return null;
        var anchor: consensus.Anchor = undefined;
        if (encoded.len > 256 or try rlp.deserialize(consensus.Anchor, allocator, encoded, &anchor) != encoded.len)
            return error.InvalidConsensusAnchor;
        return anchor;
    }

    pub fn enableConsensus(self: *Self, updates: *std.Io.Queue(consensus.Update)) !void {
        const snapshots = self.shadow_snapshots orelse return error.ShadowStateRequired;
        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        if (try self.readConsensusAnchor(txn, arena.allocator())) |anchor| {
            if (snapshots.status().count == 0) {
                const header = self.pending_bootstrap orelse return error.IncompleteStateCheckpoint;
                if (!std.meta.eql(header.hash(), anchor.execution_hash)) return error.BootstrapBranchMismatch;
            }
            self.consensus_anchor = anchor;
        } else if (snapshots.status().count != 0) return error.UnanchoredStateCheckpoint;
        self.consensus_updates = updates;
        // A long shutdown or clear can outlast the rolling bootstrap window.
        // Keep the completed clear fenced from all state requests until a new
        // finalized CL update authenticates the exact bootstrap header.
    }

    fn startBootstrap(self: *Self, header: types.BlockHeader) !void {
        self.bc.shadow_branches.store(true, .release);
        self.sync_target_mutex.lockUncancelable(self.io);
        self.sync_target = .{ .number = header.number, .hash = header.hash(), .cutoff_number = header.number, .cutoff_hash = header.hash() };
        self.sync_target_mutex.unlock(self.io);
        self.state = .{ .pivot = header };
        try self.state.?.code_hashes.ensureTotalCapacity(std.heap.page_allocator, expected_code_count);
        self.requestAccountRange(self.free_snap_requests.pop() orelse return error.NoFreeRequest, header.state_root, 0, std.math.maxInt(u256));
    }

    fn desiredConsensusHash(self: *Self) ?[32]u8 {
        const update = self.consensus_update orelse return null;
        if (self.consensus_anchor == null) return update.anchor.execution_hash;
        if (self.pending_bootstrap != null) {
            if (update.anchor.slot < self.consensus_anchor.?.slot) return null;
            return update.anchor.execution_hash;
        }
        if (self.shadow_snapshots.?.status().count == 0) {
            // Freeze an admitted transition until its old-root work drains and
            // every intervening authenticated BAL has been applied. Live FULL
            // and EMPTY hints never select an incomplete bootstrap pivot.
            if (self.header != null or self.state_heal != null) return self.syncTarget().hash;
            const state = self.state orelse return null;
            if (state.phase != .accounts and state.phase != .storage) return null;
            if (update.anchor.slot <= self.consensus_anchor.?.slot) return null;
            return update.anchor.execution_hash;
        }
        return update.head.hash;
    }

    fn cancelHeaderRequests(self: *Self, purpose: HeaderPurpose) void {
        for ([_]*List(Request(eth.Message)){ &self.inflight_eth_requests, &self.pending_eth_requests }) |list| {
            var current = list.inner.first;
            while (current) |node| {
                current = node.next;
                const request = &@as(*List(Request(eth.Message)).Node, @alignCast(@fieldParentPtr("node", node))).elem;
                if (request.msg == .get_block_headers and request.header_purpose == purpose) {
                    list.remove(request);
                    self.free_eth_requests.push(request);
                }
            }
        }
        // Validating requests belong to worker tasks until their result arrives.
        // Their generation/hash is checked before touching the staging file.
    }

    fn advanceConsensusTarget(self: *Self) !void {
        const desired = self.desiredConsensusHash() orelse return;
        // A builder can ask for EMPTY while the writer has warmed FULL. The
        // immutable parent view already serves that request: do not rewind it.
        const already_selected = self.pending_bootstrap == null and self.consensus_anchor != null and
            (std.meta.eql(self.syncTarget().hash, desired) or self.shadow_snapshots.?.status().find(desired) != null);
        if (self.consensus_probe) |pending| {
            if (!already_selected and std.meta.eql(pending, desired)) return;
            self.cancelHeaderRequests(.consensus);
            self.consensus_probe = null;
        }
        if (already_selected) return;
        const req = self.free_eth_requests.pop() orelse return;
        self.consensus_probe = desired;
        self.requestHeadersFor(req, .{ .hash = desired }, 1, .consensus);
    }

    fn handleConsensusHeader(self: *Self, req: *Request(eth.Message), outcome: anyerror!ValidationOutcome) !void {
        const expected = req.msg.get_block_headers.range.origin.hash;
        const desired = self.desiredConsensusHash();
        if (desired == null or !std.meta.eql(desired.?, expected)) {
            if (self.consensus_probe) |probe| if (std.meta.eql(probe, expected)) {
                self.consensus_probe = null;
            };
            self.free_eth_requests.push(req);
            return;
        }
        const headers = if (outcome) |result| result.headers.headers else |_| &.{};
        if (headers.len != 1) {
            self.requestHeadersFor(req, .{ .hash = expected }, 1, .consensus);
            return;
        }
        const header = headers[0];
        if (!std.meta.eql(header.hash(), expected)) return error.ConsensusHeaderHashMismatch;
        if (header.block_access_list_hash == null or header.slot_number == null) return error.PostGloasRequired;
        self.free_eth_requests.push(req);
        self.consensus_probe = null;
        if (self.consensus_anchor != null and self.shadow_snapshots.?.status().find(expected) != null) return;

        if (self.consensus_anchor == null or self.pending_bootstrap != null) {
            const anchor = self.consensus_update.?.anchor;
            if (!std.meta.eql(anchor.execution_hash, expected) or header.slot_number.? > anchor.slot)
                return error.BootstrapBranchMismatch;
            if (self.consensus_anchor) |previous| {
                if (anchor.slot < previous.slot or (anchor.slot == previous.slot and !std.meta.eql(anchor, previous)))
                    return error.ConflictingConsensusAnchor;
            }
            if (self.pending_bootstrap != null and (self.state != null or self.header != null or self.state_heal != null or
                !self.pending_snap_requests.empty() or !self.inflight_snap_requests.empty() or !self.validating_snap_requests.empty() or
                self.stashed_snap_requests.len != 0 or !self.snap_flush_queue.empty()))
                return error.BootstrapRestartBusy;
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            const store = self.eth_db.kv_store;
            var owned: kv.OwnedTransaction = .{ .txn = try store.transaction_rw() };
            defer owned.deinit();
            const txn = owned.txn;
            var encoded = std.array_list.Managed(u8).init(allocator);
            try rlp.serialize(consensus.Anchor, allocator, anchor, &encoded);
            if (self.pending_bootstrap) |cleared| {
                try branches.reanchorClearedUnverified(store, txn, allocator, cleared.hash(), header);
                try store.table(txn, .state_meta).set("consensus-anchor-v1", encoded.items, .Upsert);
            } else {
                try store.table(txn, .state_meta).set("consensus-anchor-v1", encoded.items, .Create);
                try branches.initialize(store, txn, allocator, header);
            }
            try owned.commit();
            self.consensus_anchor = anchor;
            self.pending_bootstrap = null;
            try self.startBootstrap(header);
            log.info("shadow anchored bootstrap: beacon slot {}, execution {} hash {x}", .{ anchor.slot, header.number, expected });
        } else {
            if (self.shadow_snapshots.?.status().count == 0) {
                const anchor = self.consensus_update.?.anchor;
                if (!std.meta.eql(anchor.execution_hash, expected) or header.slot_number.? > anchor.slot)
                    return error.BootstrapBranchMismatch;
                const pivot = self.state.?.pivot;
                if (header.number <= pivot.number or header.number - pivot.number > branches.extension_limit)
                    return error.BootstrapAnchorGapTooLarge;
                self.bootstrap_target = anchor;
            }
            try self.selectConsensusTarget(header);
        }
    }

    fn selectConsensusTarget(self: *Self, header: types.BlockHeader) !void {
        const hash = header.hash();
        const head = try self.bc.head();
        if (std.meta.eql(self.syncTarget().hash, hash)) return;
        self.cancelHeaderRequests(.chain);
        self.header_generation = std.math.add(u64, self.header_generation, 1) catch return error.HeaderGenerationExhausted;
        try self.clearDownloadedHeaders();
        self.sync_target_mutex.lockUncancelable(self.io);
        self.sync_target = .{ .number = header.number, .hash = hash, .cutoff_number = @min(head.number, header.number), .cutoff_hash = head.hash };
        self.sync_target_mutex.unlock(self.io);
        self.header = .{ .requested_header_head = 0, .requested_header_tail = std.math.maxInt(u64) };
        self.progress.headers = 0;
        if (self.state == null) {
            const status = self.shadow_snapshots.?.status();
            if (status.count == 0) return error.StateNotReady;
            self.state = .{ .pivot = status.headers[0], .phase = .catchup };
        }
        log.info("shadow consensus target: slot {} execution {} hash {x}", .{ self.consensus_update.?.head.slot, header.number, hash });
        // The CL-bound lookup already authenticated this exact target header.
        // For a direct extension of the CURRENT verified checkpoint, its parent
        // is also local. Reuse both instead of fetching the pair from a peer
        // again. Keep the normal branch-selection and BAL/root-validation path;
        // storing a header must never publish unexecuted state as ready.
        if (self.bc.shadow_branches.load(.acquire) and self.state_heal == null and
            header.number > 0 and header.number - 1 == head.number and
            std.meta.eql(header.parent_hash, head.hash))
        {
            const checkpoint = blk: {
                const store = self.eth_db.kv_store;
                const txn = try store.transaction_ro();
                defer txn.abort() catch unreachable;
                var scratch: [8192]u8 = undefined;
                var a = std.heap.FixedBufferAllocator.init(&scratch);
                // BlockHeader owns all fields, including ExtraData.buf. The
                // decoder copies bytes; no transaction/scratch view escapes.
                break :blk try snapshots_db.readCheckpoint(store, txn, a.allocator());
            };
            if (checkpoint) |parent| if (std.meta.eql(parent.hash(), head.hash)) {
                var headers = [_]types.BlockHeader{ parent, header };
                var hashes = [_][32]u8{ head.hash, hash };
                if (try self.persistDownloadedHeaderChain(&headers, &hashes, 2) != null)
                    return error.InconsistentConsensusHeaderSeed;
                self.header = .{ .requested_header_head = header.number, .requested_header_tail = parent.number };
                self.progress.headers = 2;
                try self.checkHeaderDownloadComplete();
                return;
            };
        }
        try self.advanceHeaderDownload();
    }

    fn advanceShadowWork(self: *Self) !void {
        try self.advanceConsensusTarget();
        if (self.header != null) {
            try self.advanceHeaderDownload();
            try self.checkHeaderDownloadComplete();
        }
        if (self.state != null) try self.advanceStateDownload();
        if (self.state_heal != null) try self.advanceStateHeal();
        try self.advanceAncestorDownload();
        const update = self.consensus_update orelse return;
        const status = self.shadow_snapshots.?.status();
        const ready = status.find(update.head.hash) orelse return;
        if (self.consensus_reported) |reported| if (std.meta.eql(reported, update.head.hash)) return;
        self.consensus_reported = update.head.hash;
        log.info("shadow consensus ready: slot {} execution {} hash {x} observed_age_ms {}", .{
            update.head.slot,                                                        ready.number, update.head.hash,
            std.Io.Clock.real.now(self.io).toMilliseconds() - update.observed_at_ms,
        });
    }

    fn advanceAncestorDownload(self: *Self) !void {
        if (self.ancestor_probe != null) return;
        const status = self.shadow_snapshots.?.status();
        if (status.count == 0) return;
        const parent = status.headers[0];
        if (self.ancestors_ready) |hash| if (std.meta.eql(hash, parent.hash())) return;
        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;
        const gap = try branches.missingAncestor(self.eth_db.kv_store, txn, parent) orelse {
            self.ancestors_ready = parent.hash();
            return;
        };
        const req = self.free_eth_requests.pop() orelse return;
        self.ancestor_probe = gap.hash;
        self.requestHeadersFor(req, .{ .hash = gap.hash }, gap.count, .ancestors);
    }

    fn handleAncestorHeaders(self: *Self, req: *Request(eth.Message), outcome: anyerror!ValidationOutcome) !void {
        const request = req.msg.get_block_headers.range;
        const headers = if (outcome) |result| result.headers.headers else |_| &.{};
        if (headers.len == 0) {
            self.requestHeadersFor(req, request.origin, request.amount, .ancestors);
            return;
        }
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;
        try branches.rememberAncestors(self.eth_db.kv_store, txn, arena.allocator(), request.origin.hash, headers);
        try owned.commit();
        self.free_eth_requests.push(req);
        self.ancestor_probe = null;
        log.debug("shadow cached {} hash-linked ancestors", .{headers.len});
    }

    fn publishHashedState(self: *Self, header: types.BlockHeader) !void {
        const snapshots = self.shadow_snapshots orelse return;
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        try snapshots_db.writeCheckpoint(self.eth_db.kv_store, txn, arena.allocator(), header);
        try branches.initialize(self.eth_db.kv_store, txn, arena.allocator(), header);
        try owned.commit();
        self.bc.shadow_branches.store(true, .release);
        try snapshots.publish(self.allocator);
        self.sync_target_mutex.lockUncancelable(self.io);
        self.sync_target.cutoff_number = header.number;
        self.sync_target.cutoff_hash = header.hash();
        const target_number = self.sync_target.number;
        self.sync_target_mutex.unlock(self.io);
        if (self.header == null and target_number > header.number)
            self.header = .{ .requested_header_head = 0, .requested_header_tail = std.math.maxInt(u64) };
    }

    fn updateTarget(self: *Self, number: u64, hash: [32]u8) !void {
        const head = try self.bc.head();
        if (head.number >= number) return;

        {
            self.sync_target_mutex.lockUncancelable(self.io);
            defer self.sync_target_mutex.unlock(self.io);

            if (self.sync_target.paused) return;
            if (self.sync_target.number >= number) return;
            if (self.sync_target.number <= head.number) self.progress.headers = 0;

            self.sync_target = .{
                .hash = hash,
                .number = number,
                .cutoff_number = head.number,
                .cutoff_hash = head.hash,
            };
        }

        if (self.header == null) self.header = .{
            .requested_header_head = 0,
            .requested_header_tail = std.math.maxInt(u64),
        };
        if (self.state == null) {
            if (head.number == 0) {
                self.state = .{ .pivot = try self.bc.readHeader(0) orelse unreachable };
                try self.state.?.code_hashes.ensureTotalCapacity(std.heap.page_allocator, expected_code_count);
            } else {
                const pivot = if (self.shadow_snapshots) |snapshots| blk: {
                    const status = snapshots.status();
                    if (status.count == 0) return error.StateNotReady;
                    break :blk status.headers[0];
                } else try self.bc.headHeader();
                self.state = .{ .pivot = pivot, .phase = .catchup };
            }
        }

        try self.updatePivot();
    }

    fn sendRequest(self: *Self, provider: anytype, pick_peer_fn: anytype, req: anytype) !void {
        const sent_at = std.Io.Clock.now(.real, self.io);
        errdefer {
            req.peer = invalid_peer;
            req.deadline = sent_at;
        }

        req.id = provider.nextRequestId();
        switch (req.msg) {
            inline else => |*msg| if (@hasField(@TypeOf(msg.*), "id")) {
                msg.id = req.id;
            },
        }
        req.sent_at = sent_at;
        req.peer = try pick_peer_fn(self, req.msg);
        try provider.send(req.peer, req.msg);
        self.metrics.requests_sent.incr(.{ .msg = @tagName(req.msg) }) catch {};
        req.deadline = sent_at.addDuration(try provider.timeoutFor(req.peer, std.meta.activeTag(req.msg)));
    }

    fn matchRequest(
        self: *Self,
        comptime Message: type,
        provider: anytype,
        list: *List(Request(Message)),
        peer: rlpx.Server.PeerId,
        id: u64,
        request_tag: std.meta.Tag(Message),
    ) ?*Request(Message) {
        var current_node = list.inner.first;

        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(Message)).Node = @alignCast(@fieldParentPtr("node", node));

            if (request.elem.id == id and std.meta.eql(peer, request.elem.peer) and std.meta.eql(request_tag, request.elem.msg)) {
                const delay = request.elem.sent_at.untilNow(self.io, .real);
                provider.observeDelay(peer, request_tag, delay);
                self.metrics.response_seconds.observe(
                    .{ .msg = @tagName(request_tag) },
                    @as(f64, @floatFromInt(delay.toNanoseconds())) / std.time.ns_per_s,
                ) catch {};
                list.inner.remove(node);
                node.next = null;
                node.prev = null;
                return &request.elem;
            }

            current_node = next_node;
        }
        return null;
    }

    fn drainPendingRequests(self: *Self, pending: anytype, inflight: anytype, send_fn: anytype) void {
        while (pending.pop()) |req| {
            send_fn(self, req) catch return insertRequest(pending, req, .front);
            insertRequest(inflight, req, .back);
        }
    }

    fn insertRequest(list: anytype, req: anytype, comptime at: enum { front, back }) void {
        if (@TypeOf(list) == *List(Request(snap.Message))) return list.insertSorted(req, Request(snap.Message).lessThan);
        switch (at) {
            .front => list.prepend(req),
            .back => list.push(req),
        }
    }

    fn checkRequestTimeouts(
        self: *Self,
        comptime Message: type,
        list: *List(Request(Message)),
        pending: *List(Request(Message)),
        provider: anytype,
    ) void {
        var current_node = list.inner.first;

        const now = std.Io.Clock.now(.real, self.io);
        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(Message)).Node = @alignCast(@fieldParentPtr("node", node));

            if (request.elem.deadline.toMilliseconds() < now.toMilliseconds()) {
                if (!std.meta.eql(request.elem.peer, invalid_peer)) {
                    self.metrics.request_timeouts.incr(.{ .msg = @tagName(request.elem.msg) }) catch {};
                    log.debug("{t} request {} to {} timed out after {}ms (timeout {}ms)", .{
                        std.meta.activeTag(request.elem.msg),
                        request.elem.id,
                        request.elem.peer,
                        request.elem.sent_at.durationTo(now).toMilliseconds(),
                        request.elem.sent_at.durationTo(request.elem.deadline).toMilliseconds(),
                    });
                }
                const assumed_rtt: std.Io.Duration = .fromNanoseconds(request.elem.sent_at.durationTo(now).nanoseconds * 2);
                provider.observeDelay(request.elem.peer, std.meta.activeTag(request.elem.msg), assumed_rtt);
                if (Message == eth.Message) if (self.state_heal) |*heal| {
                    if (heal.bal_hedge) |hedge| if (hedge.matchesSource(&request.elem)) {
                        self.metrics.bal_early_retry_expired.incr();
                        log.info("BAL retry exhausted: block {}, original_request {}, alternate_request {}; original deadline retained", .{
                            heal.next_pivot.number, request.elem.id, hedge.id,
                        });
                        heal.bal_hedge = null;
                    };
                    if (heal.bal_hedge_winner == request.elem.id) heal.bal_hedge_winner = null;
                };
                list.inner.remove(node);
                insertRequest(pending, &request.elem, .front);
            }

            current_node = next_node;
        }
    }

    fn pickEthPeer(self: *Self, msg: eth.Message) !rlpx.Server.PeerId {
        switch (msg) {
            .get_block_headers => |header_req| {
                const allowed_height_gap = 16;
                const height = switch (header_req.range.origin) {
                    .number => |number| number -| allowed_height_gap,
                    .hash => self.syncTarget().number -| allowed_height_gap,
                };
                return self.eth_provider.pickRandomPeer(PeerFilter(eth.Message).init(self, &self.inflight_eth_requests, height));
            },
            else => {},
        }
        return self.eth_provider.pickRandomPeer(PeerFilter(eth.Message).init(self, &self.inflight_eth_requests, null));
    }

    fn sendEthRequest(self: *Self, req: *Request(eth.Message), urgent: bool) void {
        if (urgent) self.pending_eth_requests.prepend(req) else self.pending_eth_requests.push(req);
        self.drainPendingEthRequests();
    }

    fn reissueEthRequest(self: *Self, req: *Request(eth.Message)) !void {
        return self.sendRequest(self.eth_provider, Self.pickEthPeer, req);
    }

    fn popFreeEthRequest(self: *Self) ?*Request(eth.Message) {
        if (!self.pending_eth_requests.empty()) return null;
        return self.free_eth_requests.pop();
    }

    fn drainPendingEthRequests(self: *Self) void {
        drainPendingRequests(self, &self.pending_eth_requests, &self.inflight_eth_requests, Self.reissueEthRequest);
    }

    fn checkEthRequestTimeouts(self: *Self) !void {
        self.retryNearHeadBal(self.eth_provider, std.Io.Clock.now(.real, self.io));
        self.checkRequestTimeouts(eth.Message, &self.inflight_eth_requests, &self.pending_eth_requests, self.eth_provider);
        self.drainPendingEthRequests();
    }

    fn retryNearHeadBal(self: *Self, provider: anytype, now: std.Io.Timestamp) void {
        const snapshots = self.shadow_snapshots orelse return;
        if (self.consensus_updates == null or snapshots.status().count == 0) return;
        const heal = if (self.state_heal) |*h| h else return;
        if (!heal.bal_requested or heal.bal_applied or heal.next_pivot.number != heal.target_pivot.number) return;
        const hash = heal.next_pivot.hash();
        if (!std.meta.eql(hash, heal.target_pivot.hash())) return;
        if (heal.bal_early_retry_hash) |used| if (std.meta.eql(hash, used)) return;

        // Validation owns another list; never reclaim or alias its request.
        var node = self.inflight_eth_requests.inner.first;
        while (node) |n| : (node = n.next) {
            const entry: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", n));
            const req = &entry.elem;
            if (req.msg != .get_block_access_list) continue;
            const hashes = req.msg.get_block_access_list.hashes;
            if (hashes.len != 1 or !std.meta.eql(hashes[0], hash)) continue;
            if (req.sent_at.durationTo(now).nanoseconds < near_head_bal_retry_after.nanoseconds) return;
            if (now.nanoseconds >= req.deadline.nanoseconds) return;

            // ETH range announcements can lag head by a broadcast interval.
            // Still exclude peers far behind or known to have pruned the block.
            var filter = PeerFilter(eth.Message).init(self, &self.inflight_eth_requests, heal.next_pivot.number -| bal_announced_height_gap);
            filter.excluded_peer = req.peer;
            filter.max_earliest = heal.next_pivot.number;
            const peer = provider.pickRandomPeer(filter) catch {
                self.metrics.bal_early_retry_no_peer.incr();
                return;
            };
            heal.bal_early_retry_hash = hash;
            self.metrics.bal_early_retry_attempts.incr();
            const id = provider.nextRequestId();
            var msg = req.msg;
            msg.get_block_access_list.id = id;
            provider.send(peer, msg) catch |err| {
                log.info("BAL early retry send failed: block {}, request {}, peer {}, error {t}; original retained", .{
                    heal.next_pivot.number, id, peer, err,
                });
                return;
            };
            // queueMsg copies wire bytes. Store the alias only after enqueue;
            // the cancel-protected owner cannot match any reply mid-transition.
            // Keep the original identity AND deadline, including an original
            // reply already waiting in the queue. Neither timeout is extended.
            heal.bal_hedge = .{ .hash = hash, .source_peer = req.peer, .source_id = req.id, .peer = peer, .id = id, .sent_at = now };
            log.info("BAL early retry: block {}, original_request {}, original_peer {}, request {}, peer {}, waited {}ms", .{
                heal.next_pivot.number, req.id, req.peer, id, peer, req.sent_at.durationTo(now).toMilliseconds(),
            });
            self.metrics.requests_sent.incr(.{ .msg = "get_block_access_list" }) catch {};
            self.metrics.bal_early_retries.incr();
            return;
        }
    }

    fn matchBalRequest(self: *Self, peer: rlpx.Server.PeerId, id: u64, unavailable: bool) ?*Request(eth.Message) {
        const hedge = if (self.state_heal) |*h| h.bal_hedge else null;
        if (hedge) |h| {
            const original = id == h.source_id and std.meta.eql(peer, h.source_peer);
            const alternate = id == h.id and std.meta.eql(peer, h.peer);
            if (unavailable and (original or alternate)) {
                // An unavailable peer supplies no BAL. An empty block's BAL
                // still has one RLP entry. Preserve the other wire identity
                // without extending the original deadline or validating twice.
                const req = self.findBalHedgeSource(h) orelse return null;
                if (original) {
                    req.id = h.id;
                    req.msg.get_block_access_list.id = h.id;
                    req.peer = h.peer;
                    req.sent_at = h.sent_at;
                    self.state_heal.?.bal_hedge_winner = h.id;
                }
                self.state_heal.?.bal_hedge = null;
                self.metrics.bal_early_retry_empty.incr();
                log.info("BAL retry empty response: block {}, request {}, peer {}; {s} retained", .{
                    self.state_heal.?.next_pivot.number, id, peer, if (original) "alternate" else "original",
                });
                return null;
            }
        }
        if (self.matchRequest(eth.Message, self.eth_provider, &self.inflight_eth_requests, peer, id, .get_block_access_list)) |req| {
            if (hedge) |h| if (h.matchesSource(req)) self.finishBalHedge(req, "original");
            if (hedge == null) if (self.state_heal) |*heal| if (heal.bal_hedge_winner == id) self.finishBalHedge(req, "remaining_alternate");
            return req;
        }
        const h = hedge orelse return null;
        if (id != h.id or !std.meta.eql(peer, h.peer)) return null;
        const req = self.findBalHedgeSource(h) orelse return null;
        // Claim the SAME list node. After removal, the other reply cannot
        // match or create a second validation job. The alias cannot revive
        // a timed-out/reissued source: both source id and peer epoch bind it.
        req.id = h.id;
        req.msg.get_block_access_list.id = h.id;
        req.peer = h.peer;
        req.sent_at = h.sent_at;
        const matched = self.matchRequest(eth.Message, self.eth_provider, &self.inflight_eth_requests, peer, id, .get_block_access_list).?;
        self.finishBalHedge(matched, "alternate");
        return matched;
    }

    fn findBalHedgeSource(self: *Self, h: BalHedge) ?*Request(eth.Message) {
        var node = self.inflight_eth_requests.inner.first;
        while (node) |n| : (node = n.next) {
            const entry: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", n));
            const req = &entry.elem;
            if (h.matchesSource(req)) return req;
        }
        // Defensive cleanup if the owning source vanished: never retain a
        // stale peer-capacity charge or attach the alias to a newer request.
        self.state_heal.?.bal_hedge = null;
        log.info("BAL retry source retired: block {}, original_request {}, alternate_request {}", .{
            self.state_heal.?.next_pivot.number, h.source_id, h.id,
        });
        return null;
    }

    fn finishBalHedge(self: *Self, req: *const Request(eth.Message), winner: []const u8) void {
        const heal = &self.state_heal.?;
        heal.bal_hedge = null;
        heal.bal_hedge_winner = req.id;
        log.info("BAL retry response: block {}, request {}, peer {}, winner {s}, elapsed {}ms", .{
            heal.next_pivot.number, req.id, req.peer, winner, req.sent_at.untilNow(self.io, .real).toMilliseconds(),
        });
    }

    fn pickSnapPeer(self: *Self, msg: snap.Message) !rlpx.Server.PeerId {
        var filter = PeerFilter(snap.Message).init(
            self,
            &self.inflight_snap_requests,
            self.state.?.pivot.number,
        );
        filter.state_root = switch (msg) {
            .get_account_range => |request| request.root,
            .get_storage_ranges => |request| request.root_hash,
            else => null,
        };
        return self.snap_provider.pickFastestPeer(std.meta.activeTag(msg), filter);
    }

    fn sendSnapRequest(self: *Self, req: *Request(snap.Message)) !void {
        insertRequest(&self.pending_snap_requests, req, .back);
        self.drainPendingSnapRequests();
    }

    fn reissueSnapRequest(self: *Self, req: *Request(snap.Message)) !void {
        if (self.snapFlushQueueFull()) {
            const draining_for_heal = if (self.state_heal) |state_heal| !state_heal.bal_requested else false;
            const blocked_node = (if (draining_for_heal) self.snap_flush_queue.inner.last else self.snap_flush_queue.inner.first) orelse return error.SnapFlushQueueFull;
            const blocked = &@as(*List(QueuedSnapFlush).Node, @alignCast(@fieldParentPtr("node", blocked_node))).elem;
            if (!blocked.isPrecededBy(req.msg, true)) return error.SnapFlushQueueFull;
        }
        return self.sendRequest(self.snap_provider, Self.pickSnapPeer, req);
    }

    fn snapFlushQueueFull(self: *Self) bool {
        if (self.state_heal) |state_heal| if (!state_heal.bal_requested) return true;
        return self.snap_flush_queue_bytes > max_snap_flush_queue_bytes;
    }

    fn popFreeSnapRequest(self: *Self) ?*Request(snap.Message) {
        if (!self.pending_snap_requests.empty()) return null;
        return self.free_snap_requests.pop();
    }

    fn drainPendingSnapRequests(self: *Self) void {
        drainPendingRequests(self, &self.pending_snap_requests, &self.inflight_snap_requests, Self.reissueSnapRequest);
    }

    fn checkSnapRequestTimeouts(self: *Self) !void {
        self.checkRequestTimeouts(snap.Message, &self.inflight_snap_requests, &self.pending_snap_requests, self.snap_provider);
        self.drainPendingSnapRequests();
    }

    fn stashSnapRequests(self: *Self) void {
        while (self.inflight_snap_requests.pop() orelse self.pending_snap_requests.pop()) |node| {
            self.stashed_snap_requests.len += 1;
            self.stashed_snap_requests[self.stashed_snap_requests.len - 1] = node.*;
            self.free_snap_requests.push(node);
        }
    }

    fn popSnapRequests(self: *Self) !void {
        std.debug.assert(self.inflight_snap_requests.empty() and self.pending_snap_requests.empty());

        const pivot_root = self.state.?.pivot.state_root;
        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;

        for (self.stashed_snap_requests) |stashed_req| {
            const req = self.free_snap_requests.pop() orelse unreachable;
            req.* = stashed_req;
            switch (req.msg) {
                .get_account_range => |*account_range_req| account_range_req.root = pivot_root,
                .get_storage_ranges => |*storage_ranges_req| {
                    storage_ranges_req.root_hash = pivot_root;
                    // These were previously downloaded accounts. BAL healing
                    // and any required new-root account proofs have completed
                    // before resuming: absence/empty storage is authenticated,
                    // unlike an empty network response for a nonempty root.
                    // SNAP servers may omit empty storage lists entirely, so
                    // keeping one here can stall or misalign the whole batch.
                    const accounts = storage_ranges_req.account_hashes;
                    const roots = req.storage_roots;
                    var kept: usize = 0;
                    var first_kept: usize = 0;
                    var last_kept: usize = 0;
                    for (accounts, 0..) |account_hash, index| {
                        const account = try self.eth_db.readAccount(txn, account_hash);
                        const root = if (account) |acc| acc.storage_hash else types.empty_root_hash;
                        if (std.meta.eql(root, types.empty_root_hash)) continue;
                        if (kept == 0) first_kept = index;
                        last_kept = index;
                        accounts[kept] = account_hash;
                        roots[kept] = root;
                        kept += 1;
                    }
                    if (kept == 0) {
                        self.allocator.free(@as([][32]u8, accounts.ptr[0..batch_storage_code_req_size]));
                        self.allocator.free(@as([][32]u8, roots.ptr[0..batch_storage_code_req_size]));
                        self.progress.storage_keyspace +|= req.keyspace[1] - req.keyspace[0];
                        self.free_snap_requests.push(req);
                        continue;
                    }
                    // Origin/limit belong to the original edge accounts, not
                    // whichever accounts become the edges after compaction.
                    if (first_kept != 0) storage_ranges_req.starting_hash = @splat(0);
                    if (last_kept != accounts.len - 1) storage_ranges_req.limit_hash = @splat(0xff);
                    storage_ranges_req.account_hashes = accounts[0..kept];
                    req.storage_roots = roots[0..kept];
                },
                else => {},
            }

            self.sendSnapRequest(req) catch {};
        }
        self.stashed_snap_requests.len = 0;
    }

    fn advanceHeaderDownload(self: *Self) !void {
        const target = self.syncTarget();

        var status = &self.header.?;
        if (status.requested_header_tail != std.math.maxInt(u64) and status.requested_header_head < target.number) {
            // target moved, fill the gap from new head to old head
            requestHeaders(
                self,
                self.popFreeEthRequest() orelse return,
                .{ .hash = target.hash },
                target.number - status.requested_header_head,
            );
            status.requested_header_head = target.number;
        }

        while (status.requested_header_tail > target.cutoff_number) {
            const origin: eth.HashOrNumber, const origin_num = if (status.requested_header_tail == std.math.maxInt(u64))
                .{ .{ .hash = target.hash }, target.number }
            else if (self.bc.shadow_branches.load(.acquire) and try self.readDownladedHeader(status.requested_header_tail) != null)
                .{ .{ .hash = (try self.readDownladedHeader(status.requested_header_tail)).?.hash() }, status.requested_header_tail }
            else
                .{ .{ .number = status.requested_header_tail }, status.requested_header_tail };
            const batch_size = @as(u64, @min(1023, origin_num - target.cutoff_number)) + 1;
            requestHeaders(
                self,
                self.popFreeEthRequest() orelse return,
                origin,
                batch_size,
            );
            status.requested_header_tail = (origin_num + 1) - batch_size;
            if (status.requested_header_head < origin_num)
                status.requested_header_head = origin_num;
        }
    }

    fn requestHeaders(self: *Self, req: *Request(eth.Message), origin: eth.HashOrNumber, amount: u64) void {
        self.requestHeadersFor(req, origin, amount, .chain);
    }

    fn requestHeadersFor(self: *Self, req: *Request(eth.Message), origin: eth.HashOrNumber, amount: u64, purpose: HeaderPurpose) void {
        req.header_generation = self.header_generation;
        req.header_purpose = purpose;
        req.msg = .{ .get_block_headers = .{ .range = .{
            .origin = origin,
            .amount = amount,
            .skip = 0,
            .reverse = true,
        } } };
        self.sendEthRequest(req, origin == .hash);
        log.debug("requesting headers origin {} amount {}", .{ origin, amount });
    }

    fn handleHeaders(self: *Self, matched_request: *Request(eth.Message), outcome: anyerror!ValidationOutcome) !void {
        if (matched_request.header_purpose == .consensus) return self.handleConsensusHeader(matched_request, outcome);
        if (matched_request.header_purpose == .ancestors) return self.handleAncestorHeaders(matched_request, outcome);
        if (matched_request.header_generation != self.header_generation) {
            self.free_eth_requests.push(matched_request);
            return;
        }
        const headers_request = matched_request.msg.get_block_headers;

        const hashes, const headers = if (outcome) |result| .{ result.headers.hashes, result.headers.headers } else |e| {
            log.debug("header validation failed for origin {} amount {}: {t}", .{ headers_request.range.origin, headers_request.range.amount, e });
            self.requestHeaders(matched_request, headers_request.range.origin, headers_request.range.amount);
            return;
        };

        var followup_request: ?@TypeOf(headers_request.range) = null;
        if (headers.len > 0) {
            const invalidated_range = try self.persistDownloadedHeaderChain(
                headers,
                hashes,
                headers_request.range.amount,
            );
            if (invalidated_range) |range| {
                followup_request = .{
                    .origin = .{ .hash = range.origin },
                    .amount = range.amount,
                };
            } else if (headers_request.range.amount > headers.len and headers[0].number > 0) {
                followup_request = .{
                    .origin = .{ .hash = headers[0].parent_hash },
                    .amount = headers_request.range.amount - headers.len,
                };
            }
            self.progress.headers += headers.len;
            log.debug("validated header range start {} end {} invalidated {any}", .{ headers[0].number, headers[0].number + headers.len - 1, invalidated_range });
        } else followup_request = headers_request.range;

        if (followup_request) |followup| {
            self.requestHeaders(matched_request, followup.origin, followup.amount);
        } else {
            self.free_eth_requests.push(matched_request);
            try self.advanceHeaderDownload();
        }

        try self.checkHeaderDownloadComplete();
    }

    fn hasHeaderRequest(list: *List(Request(eth.Message))) bool {
        var current_node = list.inner.first;
        while (current_node) |node| : (current_node = node.next) {
            const request: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", node));
            if (request.elem.msg == .get_block_headers and request.elem.header_purpose == .chain) return true;
        }
        return false;
    }

    fn checkHeaderDownloadComplete(self: *Self) !void {
        if (self.header == null) return;
        const target = self.syncTarget();
        if (self.header.?.requested_header_head < target.number or
            self.header.?.requested_header_tail > target.cutoff_number)
            return;

        if (!self.pending_eth_requests.empty()) return;
        if (hasHeaderRequest(&self.inflight_eth_requests) or hasHeaderRequest(&self.validating_eth_requests)) return;

        if (self.bc.shadow_branches.load(.acquire)) return self.selectDownloadedBranch(target);

        const head = try self.bc.head();
        if (self.shadow_snapshots != null) {
            const cutoff = try self.readDownladedHeader(head.number) orelse return error.MissingDownloadedHeader;
            if (!std.meta.eql(cutoff.hash(), head.hash)) return error.ShadowInitialSyncReorg;
        }
        log.debug("persisting headers start {} end {}", .{
            head.number + 1,
            target.number,
        });

        const first = head.number + 1;
        const total = target.number - head.number;
        var persisted: u64 = 0;
        while (persisted < total) {
            const count = @min(header_persist_chunk, total - persisted);
            const headers = try self.readDownladedHeaders(self.allocator, first + persisted, count);
            defer self.allocator.free(headers);
            try self.bc.appendHeaders(headers);
            persisted += count;
        }

        try self.clearDownloadedHeaders();
        self.header = null;
    }

    fn selectDownloadedBranch(self: *Self, target: SyncTarget) !void {
        // An in-flight BAL is bound to the selected branch. Finish it before
        // changing the writer's branch; read leases are independent MDBX views.
        if (self.state_heal != null) return;
        if (self.shadow_snapshots.?.status().count == 0) return self.selectBootstrapBranch(target);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const store = self.eth_db.kv_store;
        var owned: kv.OwnedTransaction = .{ .txn = try store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;
        const selected = try branches.state(store, txn) orelse return error.StateNotReady;
        var checkpoint = try snapshots_db.readCheckpoint(store, txn, allocator) orelse return error.StateNotReady;
        // Limit selected-header lead so all catch-up parents stay in the bounded
        // selected window, even after a long offline period.
        if (checkpoint.number < selected.head.number) return;
        const tip = try self.readDownladedHeader(target.number) orelse return error.MissingDownloadedHeader;
        if (!std.meta.eql(tip.hash(), target.hash)) return error.BranchTargetMismatch;
        var number = @min(selected.head.number, target.number);
        const ancestor = while (true) : (number -= 1) {
            const downloaded = try self.readDownladedHeader(number) orelse {
                self.sync_target_mutex.lockUncancelable(self.io);
                self.sync_target.cutoff_number = number;
                self.sync_target_mutex.unlock(self.io);
                return;
            };
            const known = try branches.read(store, txn, number) orelse return error.BranchAncestorUnavailable;
            if (std.meta.eql(downloaded.hash(), known.hash())) break known;
            if (number == selected.base.number or selected.head.number - number >= undo.depth_limit)
                return error.StateHistoryUnavailable;
        };
        const end = @min(target.number, ancestor.number + branches.extension_limit);
        const headers = try self.readDownladedHeaders(allocator, ancestor.number + 1, end - ancestor.number);
        // Rewind, selected headers and verified checkpoint commit together.
        if (checkpoint.number > ancestor.number) checkpoint = try undo.rewind(self.eth_db, txn, allocator, ancestor.hash());
        try branches.select(store, txn, allocator, ancestor, headers);
        try owned.commit();
        const rewound = selected.head.number - ancestor.number;
        if (rewound > 0) {
            log.info("shadow reorg recovered: old head {}, ancestor {}, selected {}, depth {}", .{ selected.head.number, ancestor.number, end, rewound });
            try self.shadow_snapshots.?.publish(self.allocator);
        }
        self.state = .{ .pivot = checkpoint, .phase = .catchup };
        if (end == target.number) {
            try self.clearDownloadedHeaders();
            self.header = null;
        }
    }

    fn selectBootstrapBranch(self: *Self, target: SyncTarget) !void {
        const anchor = self.bootstrap_target orelse return error.BootstrapBranchMismatch;
        if (self.state.?.phase != .accounts and self.state.?.phase != .storage)
            return error.BootstrapBranchMismatch;
        const current = self.state.?.pivot;
        if (!std.meta.eql(target.hash, anchor.execution_hash) or target.number <= current.number or
            target.number - current.number > branches.extension_limit) return error.BootstrapAnchorGapTooLarge;
        const old = try self.readDownladedHeader(current.number) orelse return error.MissingDownloadedHeader;
        if (!std.meta.eql(old.hash(), current.hash())) return error.BootstrapBranchMismatch;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const headers = try self.readDownladedHeaders(a, current.number + 1, target.number - current.number);
        const next = headers[headers.len - 1];
        if (next.slot_number == null or next.slot_number.? > anchor.slot) return error.BootstrapBranchMismatch;
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        try bootstrap_db.advance(self.eth_db.kv_store, owned.txn, a, current.hash(), anchor.execution_hash, headers);
        var encoded = std.array_list.Managed(u8).init(a);
        try rlp.serialize(consensus.Anchor, a, anchor, &encoded);
        try self.eth_db.kv_store.table(owned.txn, .state_meta).set("consensus-anchor-v1", encoded.items, .Upsert);
        try owned.commit();
        self.consensus_anchor = anchor;
        self.bootstrap_target = null;
        try self.clearDownloadedHeaders();
        self.header = null;
        if (!try self.startStateHeal(current, next)) return error.MissingDownloadedHeader;
        self.state.?.pivot = next;
        log.info("shadow bootstrap advancing finalized anchor {} -> {}; partial state remains unavailable", .{ current.number, next.number });
    }

    fn persistDownloadedHeaderChain(
        self: *Self,
        headers: []types.BlockHeader,
        hashes: [][32]u8,
        original_requested_amount: u64,
    ) !?struct { origin: [32]u8, amount: u64 } {
        if (try self.readDownladedHeader(headers[headers.len - 1].number + 1)) |child_header| {
            if (!std.meta.eql(child_header.parent_hash, hashes[headers.len - 1])) {
                return .{ .origin = child_header.parent_hash, .amount = original_requested_amount };
            }
        }

        const offset = headers[0].number * @sizeOf(types.BlockHeader);
        const bytes: [*]u8 = @ptrCast(headers.ptr);
        const size = @sizeOf(types.BlockHeader) * headers.len;

        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();
        try file.value.file.writePositionalAll(self.io, bytes[0..size], offset);

        if (headers[0].number > 0) {
            if (try self.readDownladedHeader(headers[0].number - 1)) |parent_header| {
                if (!std.meta.eql(headers[0].parent_hash, parent_header.hash())) {
                    var invalidated_count: usize = 1;
                    while (try self.readDownladedHeader(headers[0].number - 1 - invalidated_count)) |invalidated_header| {
                        invalidated_count += 1;
                        if (invalidated_header.number == 0 or invalidated_count == header_persist_chunk) break;
                    }
                    try self.clearDownloadedHeader(headers[0].number - 1);
                    try self.clearDownloadedHeader(headers[0].number - invalidated_count);
                    return .{ .origin = headers[0].parent_hash, .amount = invalidated_count };
                }
            }
        }

        return null;
    }

    fn readDownladedHeader(self: *Self, number: u64) !?types.BlockHeader {
        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();

        const offset = number * @sizeOf(types.BlockHeader);
        var header: types.BlockHeader = undefined;
        const buf: [*]u8 = @ptrCast(&header);

        if (try file.value.file.readPositionalAll(self.io, buf[0..@sizeOf(types.BlockHeader)], offset) == @sizeOf(types.BlockHeader)) {
            if (!std.meta.eql(header, std.mem.zeroes(types.BlockHeader))) {
                return header;
            }
        }
        return null;
    }

    fn readDownladedHeaders(self: *Self, allocator: std.mem.Allocator, start: u64, count: u64) ![]types.BlockHeader {
        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();

        const headers = try allocator.alloc(types.BlockHeader, count);
        errdefer allocator.free(headers);

        const offset = start * @sizeOf(types.BlockHeader);
        const bytes: [*]u8 = @ptrCast(headers.ptr);
        const size = count * @sizeOf(types.BlockHeader);

        if (try file.value.file.readPositionalAll(self.io, bytes[0..size], offset) != size) return error.MissingDownloadedHeader;
        for (headers) |*header| {
            if (std.meta.eql(header.*, std.mem.zeroes(types.BlockHeader))) return error.MissingDownloadedHeader;
        }

        return headers;
    }

    fn clearDownloadedHeader(self: *Self, number: u64) !void {
        const offset = number * @sizeOf(types.BlockHeader);
        var header: types.BlockHeader = std.mem.zeroes(types.BlockHeader);
        const bytes: [*]u8 = @ptrCast(&header);

        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();
        try file.value.file.writePositionalAll(self.io, bytes[0..@sizeOf(types.BlockHeader)], offset);
    }

    fn clearDownloadedHeaders(self: *Self) !void {
        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();
        try file.value.file.setLength(self.io, 0);
    }

    fn readHeader(self: *Self, number: u64) !?types.BlockHeader {
        return try self.readDownladedHeader(number) orelse self.bc.readHeader(number);
    }

    fn updatePivot(self: *Self) !void {
        if (self.consensus_updates != null) return; // finalized advances use selectBootstrapBranch
        switch ((self.state orelse return).phase) {
            .accounts, .storage => {},
            .codes, .hashing, .catchup => return,
        }

        const head_height = self.syncTarget().number;
        const new_pivot_height = if (head_height > 32) head_height - 32 else 0;

        const cur_pivot = self.state.?.pivot;
        if (new_pivot_height - cur_pivot.number >= 64) {
            const new_pivot = try self.readHeader(new_pivot_height) orelse return;

            if (cur_pivot.number != 0) {
                if (!try self.startStateHeal(cur_pivot, new_pivot)) return;
            }

            log.debug("new pivot {}, old {}", .{ new_pivot, cur_pivot });
            self.state.?.pivot = new_pivot;
            if (cur_pivot.number == 0) self.requestAccountRange(
                self.free_snap_requests.pop() orelse unreachable,
                new_pivot.state_root,
                0,
                std.math.maxInt(u256),
            );
        }
    }

    // false while headers up to the target are still missing
    fn startStateHeal(self: *Self, cur_pivot: types.BlockHeader, target_pivot: types.BlockHeader) !bool {
        if (try self.bc.readHeader(target_pivot.number) == null) return false;

        if (self.state_heal) |*state_heal| {
            state_heal.target_pivot = target_pivot;
            log.info("state heal: target moved to {}", .{target_pivot.number});
        } else {
            const next_pivot = try self.bc.readHeader(cur_pivot.number + 1) orelse unreachable;
            if (!std.mem.eql(u8, &next_pivot.parent_hash, &cur_pivot.hash())) return error.Reorg;
            self.state_heal = .{
                .target_pivot = target_pivot,
                .next_pivot = next_pivot,
                .start_number = cur_pivot.number,
                .started_at = std.Io.Clock.now(.real, self.io),
                .drain_started_at = std.Io.Clock.now(.awake, self.io),
            };
            log.info("state heal: started, pivot {} -> {} ({} blocks)", .{
                cur_pivot.number,
                target_pivot.number,
                target_pivot.number - cur_pivot.number,
            });
        }
        return true;
    }

    fn advanceStateDownload(self: *Self) !void {
        if (self.state_heal != null) return; // state download is paused

        const state = &self.state.?;

        switch (state.phase) {
            .accounts => {},
            .storage => try self.advanceStorageDownload(),
            .codes => try self.advanceCodesDownload(),
            .hashing => {
                if (self.task_group.token.load(.acquire) != null) return;
                try self.publishHashedState(state.pivot);
                log.info("hashing done", .{});
                state.phase = .catchup;
                return;
            },
            .catchup => {
                const target = self.syncTarget();
                if (state.pivot.number < target.number) {
                    const target_number = if (self.bc.shadow_branches.load(.acquire)) @min(target.number, (try self.bc.head()).number) else target.number;
                    if (target_number <= state.pivot.number) return;
                    const new_pivot = try self.bc.readHeader(target_number) orelse return;
                    if (!try self.startStateHeal(state.pivot, new_pivot)) return;
                    state.pivot = new_pivot;
                    return;
                }

                self.state = null;
                log.info("state download done", .{});
                return;
            },
        }

        if (self.state.?.pivot.number > 0 and self.inflight_snap_requests.empty() and
            self.pending_snap_requests.empty() and self.validating_snap_requests.empty() and
            self.stashed_snap_requests.len == 0 and self.snap_flush_queue.empty())
        {
            // A selected finalized tip may still be downloading its header
            // ancestry. Do not launch code/account hashing of the old pivot
            // while that admitted transition is waiting to heal the flat state.
            if (self.bootstrap_target != null) return;
            log.info("{t} download done", .{state.phase});
            switch (state.phase) {
                .accounts => state.phase = .storage,
                .storage => {
                    state.code_hashes.sortUnstable(CodeHashOrder{ .keys = state.code_hashes.keys() });
                    state.phase = .codes;
                    try self.task_group.concurrent(self.io, hashTrieTask, .{ self, null, state.pivot.state_root });
                },
                .codes => {
                    state.code_hashes.deinit(std.heap.page_allocator);
                    state.phase = .hashing;
                },
                .hashing, .catchup => unreachable,
            }
        }
    }

    fn hashTrieTask(self: *Self, owner: ?[32]u8, expected_root: [32]u8) void {
        self.hashTrie(owner, expected_root) catch |err| {
            if (err == error.Canceled) return self.io.recancel();
            if (owner) |account| std.debug.panic("downloader: hashing storage trie of {x} failed: {}", .{ account, err });
            std.debug.panic("downloader: hashing account trie failed: {}", .{err});
        };
    }

    fn hashTrie(self: *Self, owner: ?[32]u8, expected_root: [32]u8) !void {
        var root = types.empty_root_hash;
        var from: ?[32]u8 = @splat(0);
        while (from) |start| {
            try self.io.checkCancel();
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            var storage_jobs = std.array_list.Managed([2][32]u8).init(allocator);

            from, root, const nodes = if (owner) |account|
                try self.updateStorageWindow(allocator, account, start, root)
            else
                try self.updateAccountWindow(allocator, start, root, &storage_jobs);
            if (owner == null) if (from) |head| {
                self.state.?.hash_head = head;
            };
            if (from == null and !std.meta.eql(root, expected_root)) return error.RootMismatch;
            if (nodes.len > 0) {
                var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
                defer owned.deinit();
                const txn = owned.txn;
                if (owner) |account| {
                    try self.eth_db.deleteStorageTrieFrom(txn, account, nodes[0].path);
                    try self.eth_db.appendStorageTrie(txn, account, nodes, false);
                } else {
                    try self.eth_db.deleteAccountTrieFrom(txn, nodes[0].path);
                    try self.eth_db.appendAccountTrie(txn, nodes);
                }
                try owned.commit();
            }

            for (storage_jobs.items) |job| self.task_group.async(self.io, hashTrieTask, .{ self, job[0], job[1] });
        }
    }

    fn updateStorageWindow(
        self: *Self,
        allocator: std.mem.Allocator,
        account_hash: [32]u8,
        start: [32]u8,
        root: [32]u8,
    ) !struct { ?[32]u8, [32]u8, []trie.NodeCollector.Node } {
        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;
        if (!try self.isStorageTrieAvailable(txn, account_hash, root)) return error.MissingTrieRoot;

        const keys = try allocator.alloc([32]u8, hash_window_size);
        const values = try allocator.alloc(u256, hash_window_size);
        const count = try self.eth_db.readStorageRange(txn, account_hash, start, keys, values);

        const collector = try allocator.create(trie.NodeCollector);
        collector.* = try .init(allocator, hash_window_nodes);
        var storage_trie = (try self.eth_db.openStorageTrie(allocator, txn, account_hash, root))
            .withCollector(collector);
        defer self.eth_db.closeStorageTrie(&storage_trie);
        if (count > 0) try storage_trie.updateNoDeletions(keys[0..count], values[0..count]);
        return .{ if (count < keys.len) null else nextKey(keys[count - 1]), try storage_trie.rootHash(), collector.collected() };
    }

    fn updateAccountWindow(
        self: *Self,
        allocator: std.mem.Allocator,
        start: [32]u8,
        root: [32]u8,
        storage_jobs: *std.array_list.Managed([2][32]u8),
    ) !struct { ?[32]u8, [32]u8, []trie.NodeCollector.Node } {
        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;
        if (!try self.isAccountTrieAvailable(txn, root)) return error.MissingTrieRoot;

        const keys = try allocator.alloc([32]u8, hash_window_size);
        const accounts = try allocator.alloc(types.Account, hash_window_size);
        const count = try self.eth_db.readAccountRange(txn, start, keys, accounts);
        try self.queueStorageJobs(txn, keys[0..count], accounts[0..count], storage_jobs);

        const collector = try allocator.create(trie.NodeCollector);
        collector.* = try .init(allocator, hash_window_nodes);
        var account_trie = (try self.eth_db.openAccountTrie(allocator, txn, root))
            .withCollector(collector);
        defer self.eth_db.closeAccountTrie(&account_trie);
        if (count > 0) try account_trie.updateNoDeletions(keys[0..count], accounts[0..count]);
        return .{ if (count < keys.len) null else nextKey(keys[count - 1]), try account_trie.rootHash(), collector.collected() };
    }

    fn queueStorageJobs(
        self: *Self,
        txn: kv.Transaction,
        hashes: []const [32]u8,
        accounts: []const types.Account,
        storage_jobs: *std.array_list.Managed([2][32]u8),
    ) !void {
        if (hashes.len == 0) return;
        const tries = try self.eth_db.kv_store.table(txn, .storage_tries).cursor();
        defer tries.deinit();
        const storage = try self.eth_db.kv_store.table(txn, .storage).cursor();
        defer storage.deinit();

        var trie_head: ?[32]u8 = if (try tries.seekLowerBound(&hashes[0])) |res| res.entry.key[0..32].* else null;
        for (hashes, accounts) |hash, account| {
            if (std.meta.eql(account.storage_hash, types.empty_root_hash)) continue;
            if (try hasStorageTrie(tries, &trie_head, hash)) continue;
            if (try storage.seekLowerBound(&hash)) |res|
                if (std.mem.eql(u8, res.entry.key, &hash) and try storage.count() == 1) continue;
            try storage_jobs.append(.{ hash, account.storage_hash });
        }
    }

    fn hasStorageTrie(tries: kv.Cursor, head: *?[32]u8, account_hash: [32]u8) !bool {
        while (head.*) |trie_account| {
            if (std.mem.order(u8, &trie_account, &account_hash) != .lt) return std.meta.eql(trie_account, account_hash);
            head.* = if (try tries.nextNoDup()) |next| next.key[0..32].* else null;
        }
        return false;
    }

    fn nextKey(key: [32]u8) ?[32]u8 {
        const value = std.mem.readInt(u256, &key, .big);
        if (value == std.math.maxInt(u256)) return null;
        var next: [32]u8 = undefined;
        std.mem.writeInt(u256, &next, value + 1, .big);
        return next;
    }

    fn requestAccountRange(self: *Self, req: *Request(snap.Message), state_root: [32]u8, origin: u256, limit: u256) void {
        log.debug("requesting account range origin: {x} limit: {x}", .{ origin, limit });
        var origin_bytes: [32]u8 = undefined;
        var limit_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &origin_bytes, origin, .big);
        std.mem.writeInt(u256, &limit_bytes, limit, .big);

        req.msg = .{ .get_account_range = .{
            .root = state_root,
            .origin = origin_bytes,
            .limit = limit_bytes,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn handleAccounts(self: *Self, request: *Request(snap.Message), outcome: anyerror!ValidationOutcome) !void {
        const get_accounts_range = request.msg.get_account_range;

        var continue_from_account: ?[32]u8 = null;
        if (outcome) |result| {
            const accounts = result.accounts;
            const hashes = accounts.hashes;
            const last = if (hashes.len > 0) hashes[hashes.len - 1] else get_accounts_range.limit;
            log.debug("verified account range {x}-{x}", .{ get_accounts_range.origin, last });
            if (accounts.has_more and std.mem.order(u8, &last, &get_accounts_range.limit) == .lt) {
                var next: [32]u8 = undefined;
                std.mem.writeInt(u256, &next, std.mem.readInt(u256, &last, .big) + 1, .big);
                continue_from_account = next;
            }
            const covered_until = if (accounts.has_more) last else get_accounts_range.limit;
            self.progress.account_keyspace +|= std.mem.readInt(u256, &covered_until, .big) - std.mem.readInt(u256, &get_accounts_range.origin, .big);
            for (accounts.code_hashes) |code_hash|
                try self.state.?.code_hashes.put(std.heap.page_allocator, code_hash, {});
        } else |_| {
            continue_from_account = get_accounts_range.origin;
        }

        const state = &self.state.?;
        const prev_origin = std.mem.readInt(u256, &get_accounts_range.origin, .big);
        const limit = std.mem.readInt(u256, &get_accounts_range.limit, .big);
        if (continue_from_account) |origin_bytes| {
            log.debug("remaining account range {x}-{x}", .{ origin_bytes, get_accounts_range.limit });

            const origin = std.mem.readInt(u256, &origin_bytes, .big);
            if (state.account_fetch_step == 0 and origin != prev_origin) {
                // first response of the initial full range request sizes the chunks
                state.account_fetch_step = origin - prev_origin;
                state.account_fetch_head = origin;
                self.requestAccountChunks(request);
            } else {
                self.requestAccountRange(request, state.pivot.state_root, origin, limit);
            }
        } else if (prev_origin != limit and limit < std.math.maxInt(u256)) {
            self.requestAccountChunks(request);
        } else {
            self.free_snap_requests.push(request);
        }
    }

    fn requestAccountChunks(self: *Self, request: *Request(snap.Message)) void {
        const state = &self.state.?;
        const max = std.math.maxInt(u256);

        var req = request;
        while (state.account_fetch_head < max) {
            const origin = state.account_fetch_head;
            const limit = if (max - origin > state.account_fetch_step +| 1) origin + state.account_fetch_step else max;
            self.requestAccountRange(req, state.pivot.state_root, origin, limit);
            state.account_fetch_head = limit +| 1;
            req = self.popFreeSnapRequest() orelse return;
        }
        self.free_snap_requests.push(req);
    }

    fn persistAccounts(self: *Self, accounts: VerifiedAccounts, response: *const snap.AccountRange) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;

        const write_op: lmdbx.Database.SetFlag = if (std.meta.eql(accounts.origin, accounts.limit)) .Upsert else .Append;
        const table = self.eth_db.kv_store.table(txn, .accounts);
        for (accounts.hashes, 0..) |hash, index| {
            try table.set(&hash, response.accounts[index].account.value, write_op);
        }
        // a proven single account query that doesn't return the account means it no longer exists
        if (std.meta.eql(accounts.origin, accounts.limit) and (accounts.hashes.len == 0 or !std.meta.eql(accounts.hashes[0], accounts.origin))) {
            try self.eth_db.deleteAccount(txn, accounts.origin);
        }

        try self.commitTxn(&owned, "accounts", txn_start);
    }

    fn advanceStorageDownload(self: *Self) !void {
        const state = &self.state.?;

        if (self.free_snap_requests.empty()) return;

        const build_start = std.Io.Timestamp.now(self.io, .awake);
        var scanned: u64 = 0;
        defer if (scanned > 0) {
            self.metrics.batch_build_seconds.observe(secondsSince(self.io, build_start));
            self.metrics.batch_accounts_scanned.incrBy(scanned);
        };

        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;
        const accounts_table = self.eth_db.kv_store.table(txn, .accounts);
        const account_iterator = try accounts_table.cursor();
        defer account_iterator.deinit();

        if (try account_iterator.seekLowerBound(&state.storage_fetch_head) == null)
            return;

        while (true) {
            const storage_request = self.popFreeSnapRequest();
            if (storage_request == null) {
                return;
            }
            errdefer {
                self.free_snap_requests.push(storage_request.?);
            }

            var account_hashes = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            account_hashes.len = 0;
            errdefer {
                account_hashes.len = batch_storage_code_req_size;
                self.allocator.free(account_hashes);
            }
            var storage_roots = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            storage_roots.len = 0;
            errdefer {
                storage_roots.len = batch_storage_code_req_size;
                self.allocator.free(storage_roots);
            }

            const batch_start = std.mem.readInt(u256, &state.storage_fetch_head, .big);
            const accounts_exhausted = while (true) {
                scanned += 1;
                const cur = try account_iterator.getCurrentEntry();
                state.storage_fetch_head = cur.key[0..32].*;

                const acc = EthDb.decodeAccount(cur.value) catch unreachable;
                const has_storage = !std.meta.eql(acc.storage_hash, types.empty_root_hash);

                if (has_storage and account_hashes.len == batch_storage_code_req_size)
                    break false;

                if (has_storage) {
                    account_hashes.len += 1;
                    account_hashes[account_hashes.len - 1] = cur.key[0..32].*;
                    storage_roots.len += 1;
                    storage_roots[storage_roots.len - 1] = acc.storage_hash;
                }

                if (try account_iterator.goToNext() == null) break true;
            };

            const batch_end = if (accounts_exhausted) std.math.maxInt(u256) else std.mem.readInt(
                u256,
                &state.storage_fetch_head,
                .big,
            );
            storage_request.?.keyspace = .{ batch_start, batch_end };
            storage_request.?.storage_roots = storage_roots;
            self.requestStorageRanges(storage_request.?, state.pivot.state_root, account_hashes);

            if (accounts_exhausted) {
                std.mem.writeInt(u256, &state.storage_fetch_head, std.mem.readInt(u256, &state.storage_fetch_head, .big) +| 1, .big);
                return;
            }
        }
    }

    fn requestStorageRanges(self: *Self, req: *Request(snap.Message), state_root: [32]u8, accounts: [][32]u8) void {
        log.debug("requesting storage ranges accounts: {}", .{accounts.len});
        req.msg = .{ .get_storage_ranges = .{
            .account_hashes = accounts,
            .root_hash = state_root,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn handleStorage(self: *Self, req: *Request(snap.Message), outcome: anyerror!ValidationOutcome) !void {
        const result: VerifiedStorage = if (outcome) |verified| verified.storage else |_| .{};
        const request = &req.msg.get_storage_ranges;
        const requested_accounts = request.account_hashes;
        const storage_roots = req.storage_roots;
        const verified = result.keys.len;

        var next = verified;
        var starting_hash: [32]u8 = if (verified > 0) @splat(0) else request.starting_hash;
        if (result.continue_from_slot) |from| {
            const origin = std.mem.readInt(u256, &from, .big);
            const limit = std.mem.readInt(u256, &request.limit_hash, .big);
            if (verified < requested_accounts.len) {
                if (self.free_snap_requests.pop()) |new_req| {
                    try self.requestSlots(new_req, req, verified - 1, origin, std.math.maxInt(u256));
                } else {
                    next = verified - 1;
                    starting_hash = from;
                }
            } else if (origin <= limit) {
                const received_from: [32]u8 = if (verified == 1) request.starting_hash else @splat(0);
                const step = @max(origin - std.mem.readInt(u256, &received_from, .big), min_split_range);
                if (limit - origin > step and !self.free_snap_requests.empty()) {
                    std.mem.writeInt(u256, &request.limit_hash, origin + step, .big);
                    var start = origin + step + 1;
                    while (self.free_snap_requests.pop()) |new_req| : (start += step + 1) {
                        const end = if (self.free_snap_requests.empty() or limit - start <= step) limit else start + step;
                        try self.requestSlots(new_req, req, verified - 1, start, end);
                        if (end == limit) break;
                    }
                }
                next = verified - 1;
                starting_hash = from;
            }
        }

        const remaining = requested_accounts.len - next;
        if (remaining > 0) {
            std.mem.copyForwards([32]u8, requested_accounts[0..remaining], requested_accounts[next..]);
            std.mem.copyForwards([32]u8, storage_roots[0..remaining], storage_roots[next..]);
            request.account_hashes = requested_accounts[0..remaining];
            req.storage_roots = storage_roots[0..remaining];
            request.starting_hash = starting_hash;
            self.sendSnapRequest(req) catch {};
        } else {
            self.allocator.free(@as([][32]u8, requested_accounts.ptr[0..batch_storage_code_req_size]));
            self.allocator.free(@as([][32]u8, storage_roots.ptr[0..batch_storage_code_req_size]));
            self.progress.storage_keyspace +|= req.keyspace[1] - req.keyspace[0];
            self.free_snap_requests.push(req);
        }
    }

    fn persistStorage(self: *Self, storage: VerifiedStorage) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;
        for (storage.account_hashes, storage.keys, storage.values, storage.nodes) |account_hash, keys, values, nodes| {
            try self.eth_db.appendStorage(txn, account_hash, keys, values, !storage.chunk);
            if (nodes.len > 0)
                try self.eth_db.appendStorageTrie(txn, account_hash, nodes, true);
        }
        try self.commitTxn(&owned, "storage", txn_start);
    }

    fn requestSlots(self: *Self, new_req: *Request(snap.Message), req: *const Request(snap.Message), account: usize, start: u256, end: u256) !void {
        log.debug("requesting slots of account {x} start: {x} end: {x}", .{ req.msg.get_storage_ranges.account_hashes[account], start, end });
        const hashes = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
        errdefer self.allocator.free(hashes);
        const roots = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
        hashes[0] = req.msg.get_storage_ranges.account_hashes[account];
        roots[0] = req.storage_roots[account];
        new_req.keyspace = .{ 0, 0 };
        new_req.storage_roots = roots[0..1];
        new_req.msg = .{ .get_storage_ranges = .{
            .account_hashes = hashes[0..1],
            .root_hash = req.msg.get_storage_ranges.root_hash,
        } };
        std.mem.writeInt(u256, &new_req.msg.get_storage_ranges.starting_hash, start, .big);
        std.mem.writeInt(u256, &new_req.msg.get_storage_ranges.limit_hash, end, .big);
        self.sendSnapRequest(new_req) catch {};
    }

    fn advanceCodesDownload(self: *Self) !void {
        const state = &self.state.?;
        const code_hashes = state.code_hashes.keys();

        while (state.code_fetch_head < code_hashes.len) {
            const code_request = self.popFreeSnapRequest() orelse return;
            errdefer self.free_snap_requests.push(code_request);

            const batch = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            const count = @min(code_hashes.len - state.code_fetch_head, batch_storage_code_req_size);
            @memcpy(batch[0..count], code_hashes[state.code_fetch_head..][0..count]);

            const batch_start = if (state.code_fetch_head == 0) 0 else std.mem.readInt(u256, &code_hashes[state.code_fetch_head], .big);
            state.code_fetch_head += count;
            const batch_end = if (state.code_fetch_head == code_hashes.len) std.math.maxInt(u256) else std.mem.readInt(u256, &code_hashes[state.code_fetch_head], .big);
            code_request.keyspace = .{ batch_start, batch_end };
            self.requestCodes(code_request, batch[0..count]);
        }
    }

    fn requestCodes(self: *Self, req: *Request(snap.Message), code_hashes: [][32]u8) void {
        log.debug("requesting codes: {}", .{code_hashes.len});
        req.msg = .{ .get_byte_codes = .{
            .hashes = code_hashes,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn handleCodes(self: *Self, req: *Request(snap.Message), outcome: anyerror!ValidationOutcome) !void {
        const code_hashes: [][32]u8 = if (outcome) |result| result.codes else |_| &.{};

        const requested_hashes = req.msg.get_byte_codes.hashes;

        var retry_count: usize = 0;
        var next_hash_index: usize = 0;
        for (code_hashes) |code_hash| {
            while (next_hash_index < requested_hashes.len and !std.meta.eql(requested_hashes[next_hash_index], code_hash)) : (next_hash_index += 1) {
                requested_hashes[retry_count] = requested_hashes[next_hash_index];
                retry_count += 1;
            }
            if (next_hash_index == requested_hashes.len) break;
            next_hash_index += 1;
        }

        const unserved = requested_hashes[next_hash_index..];
        std.mem.copyForwards([32]u8, requested_hashes[retry_count..][0..unserved.len], unserved);
        retry_count += unserved.len;

        if (retry_count > 0) {
            self.requestCodes(req, requested_hashes[0..retry_count]);
        } else {
            self.allocator.free(@as([][32]u8, requested_hashes.ptr[0..batch_storage_code_req_size]));
            self.progress.code_keyspace +|= req.keyspace[1] - req.keyspace[0];
            self.free_snap_requests.push(req);
        }
    }

    fn persistCodes(self: *Self, hashes: []const [32]u8, codes: []const []const u8) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;
        const table = self.eth_db.kv_store.table(txn, .codes);
        for (hashes, codes) |hash, code| {
            table.set(&hash, code, .Create) catch |e| {
                if (e != lmdbx.Error.MDBX_KEYEXIST) return e;
            };
        }
        try self.commitTxn(&owned, "codes", txn_start);
    }

    fn advanceStateHeal(self: *Self) !void {
        const state_heal = &self.state_heal.?;

        if (state_heal.bal_applied) {
            if (state_heal.next_pivot.number + 1 > state_heal.target_pivot.number) {
                if (self.fetchStaleStorageRoots()) return;
            }
            if (self.inflight_snap_requests.empty() and self.pending_snap_requests.empty() and
                self.validating_snap_requests.empty() and self.snap_flush_queue.empty())
            {
                if (state_heal.next_pivot.number + 1 > state_heal.target_pivot.number) {
                    log.info("state heal: done, healed {} blocks in {}s", .{
                        state_heal.target_pivot.number - state_heal.start_number,
                        state_heal.started_at.durationTo(std.Io.Clock.now(.real, self.io)).toSeconds(),
                    });
                    if (self.bootstrapIncomplete()) {
                        var arena = std.heap.ArenaAllocator.init(self.allocator);
                        defer arena.deinit();
                        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
                        defer owned.deinit();
                        try bootstrap_db.completeAdvance(self.eth_db.kv_store, owned.txn, arena.allocator(), self.state.?.pivot.hash());
                        try owned.commit();
                    }
                    state_heal.stale_storage_roots.deinit(self.allocator);
                    self.state_heal = null;
                    try self.popSnapRequests();
                    return;
                }

                try self.advanceNextPivot();
                state_heal.bal_requested = false;
                state_heal.bal_applied = false;
            }
        }

        if (state_heal.bal_requested == false) {
            if (!self.validating_snap_requests.empty() or !self.snap_flush_queue.empty()) {
                if (self.bootstrapIncomplete()) if (state_heal.drain_started_at) |started| {
                    if (started.durationTo(std.Io.Clock.now(.awake, self.io)).toSeconds() >= bootstrap_drain_timeout_seconds)
                        return error.BootstrapDrainUnavailable;
                };
                return;
            }
            self.stashSnapRequests();
            const bal_req = self.free_eth_requests.pop() orelse return;
            try self.requestRemainingBals(bal_req);
            state_heal.bal_requested = true;
        }
    }

    fn bootstrapIncomplete(self: *const Self) bool {
        const snapshots = self.shadow_snapshots orelse return false;
        return self.consensus_anchor != null and snapshots.status().count == 0;
    }

    // the next block must build on the one just applied, otherwise the header chain reorged under us
    fn advanceNextPivot(self: *Self) !void {
        const state_heal = &self.state_heal.?;
        const next = try self.bc.readHeader(state_heal.next_pivot.number + 1) orelse unreachable;
        if (!std.mem.eql(u8, &next.parent_hash, &state_heal.next_pivot.hash())) return error.Reorg;
        state_heal.next_pivot = next;
    }

    fn requestRemainingBals(self: *Self, req: *Request(eth.Message)) !void {
        const state_heal = &self.state_heal.?;
        var header = state_heal.next_pivot;
        var count: usize = 0;
        while (count < state_heal.bal_hashes.len) {
            state_heal.bal_hashes[count] = header.hash();
            count += 1;
            if (header.number >= state_heal.target_pivot.number) break;
            header = try self.bc.readHeader(header.number + 1) orelse unreachable;
        }
        self.requestBals(req, state_heal.bal_hashes[0..count]);
    }

    fn requestBals(self: *Self, req: *Request(eth.Message), hashes: [][32]u8) void {
        req.msg = .{ .get_block_access_list = .{ .hashes = hashes } };
        self.sendEthRequest(req, true);
    }

    fn handleBals(self: *Self, req: *Request(eth.Message), outcome: anyerror!ValidationOutcome) !void {
        if (self.state_heal) |*state_heal| {
            const bals: []VerifiedBal = if (outcome) |result| result.bals else |_| &.{};
            const hedged = state_heal.bal_hedge_winner == req.id;
            if (hedged) log.info("BAL retry decoded: block {}, request {}, lists {}, outcome {s}", .{
                state_heal.next_pivot.number, req.id, bals.len, if (outcome) |_| "decoded" else |err| @errorName(err),
            });
            state_heal.bal_hedge_winner = null;
            for (bals) |bal| {
                if (!std.meta.eql(bal.hash, state_heal.next_pivot.block_access_list_hash.?)) break;
                std.debug.assert(!state_heal.bal_applied);
                try self.applyBal(bal.parsed);
                if (hedged) log.info("BAL retry applied: block {}, request {}, heal_elapsed {}ms", .{
                    state_heal.next_pivot.number, req.id, state_heal.started_at.untilNow(self.io, .real).toMilliseconds(),
                });
                if (state_heal.next_pivot.number >= state_heal.target_pivot.number) {
                    state_heal.bal_applied = true;
                    break;
                }
                try self.advanceNextPivot();
            }
            if (state_heal.bal_applied) {
                self.free_eth_requests.push(req);
                try self.advanceStateHeal();
                return;
            }
            try self.requestRemainingBals(req);
        } else unreachable;
    }

    fn applyBal(self: *Self, bal: types.BlockAccessLists) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        var owned: kv.OwnedTransaction = .{ .txn = try self.eth_db.kv_store.transaction_rw() };
        defer owned.deinit();
        const txn = owned.txn;

        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const allocator = scratch.allocator();

        const parent = try self.bc.readHeader(self.state_heal.?.next_pivot.number - 1) orelse unreachable;
        const publish_shadow = self.shadow_snapshots != null and self.state.?.phase == .catchup;
        if (publish_shadow) {
            const checkpoint = try @import("../db/snapshot.zig").readCheckpoint(self.eth_db.kv_store, txn, allocator) orelse return error.StateNotReady;
            if (!std.meta.eql(checkpoint.hash(), self.state_heal.?.next_pivot.parent_hash) or
                !std.meta.eql(checkpoint.hash(), parent.hash())) return error.StateCheckpointBranchMismatch;
        }
        var account_collector = try trie.NodeCollector.init(allocator, bal.len * 66);
        var account_trie = if (try self.isAccountTrieAvailable(txn, parent.state_root))
            (try self.eth_db.openAccountTrie(allocator, txn, parent.state_root)).withCollector(&account_collector)
        else
            null;
        defer if (account_trie) |*at| self.eth_db.closeAccountTrie(at);

        const hashed = try types.HashedBlockAccessLists.init(allocator, bal);
        const previous = if (publish_shadow) try undo.capture(self.eth_db, txn, allocator, parent, hashed) else null;
        for (hashed.changes, hashed.account_hashes, hashed.slot_hashes) |changes, addr_hash, slot_hashes| {
            if (changes.readOnly()) continue;
            if (!self.isAccountFetched(addr_hash)) continue;

            const values = try allocator.alloc(u256, changes.storage_changes.len);
            for (changes.storage_changes, values) |slot, *value| value.* = slot.lastValue();

            const diff = try changes.accountDiff();
            const new_code_hash = if (diff.code) |code| try self.eth_db.writeCode(txn, code) else null;
            var account = (try self.eth_db.readAccount(txn, addr_hash)) orelse types.EmptyAccount;
            const storage_root = if (slot_hashes.len > 0 and self.isStorageFetched(addr_hash, null))
                try self.updateStorageTrie(allocator, txn, addr_hash, account.storage_hash, slot_hashes, values)
            else
                null;

            for (slot_hashes, values) |slot, value| {
                if (self.isStorageFetched(addr_hash, slot)) try self.eth_db.writeStorage(txn, addr_hash, slot, value);
            }
            if (slot_hashes.len > 0 and storage_root == null) {
                try self.state_heal.?.stale_storage_roots.put(self.allocator, addr_hash, {});
                continue;
            }

            if (diff.balance) |balance| account.balance = balance;
            if (diff.nonce) |nonce| account.nonce = nonce;
            if (new_code_hash) |code_hash| account.code_hash = code_hash;
            if (storage_root) |root| account.storage_hash = root;

            // the account trie resolves leaves from the accounts table, so update it before persisting
            const updated: ?types.Account = if (account.isEmpty()) null else account;
            if (account_trie) |*at| try at.updateUnsorted(&.{addr_hash}, &.{updated});
            if (updated) |acc| {
                try self.eth_db.writeAccount(allocator, txn, addr_hash, acc);
            } else try self.eth_db.deleteAccount(txn, addr_hash);
        }

        if (account_trie) |*at| {
            const root = try at.rootHash();
            const expected_root = self.state_heal.?.next_pivot.state_root;
            std.debug.assert(self.state_heal.?.stale_storage_roots.count() == 0);
            if (!std.meta.eql(root, expected_root)) {
                log.err("state heal: account trie root {x} mismatch, expected {x} at block {}", .{
                    root,
                    expected_root,
                    self.state_heal.?.next_pivot.number,
                });
                return error.RootMismatch;
            }
            try self.eth_db.commitAccountTrieNodes(txn, &account_collector);
        } else if (publish_shadow) return error.StateNotReady;

        if (previous) |record| try undo.save(self.eth_db.kv_store, txn, allocator, self.state_heal.?.next_pivot, record);
        if (publish_shadow) try snapshots_db.writeCheckpoint(
            self.eth_db.kv_store,
            txn,
            allocator,
            self.state_heal.?.next_pivot,
        );

        try self.commitTxn(&owned, "bal", txn_start);
        if (publish_shadow) try self.shadow_snapshots.?.publish(self.allocator);
    }

    fn isAccountFetched(self: *Self, account_hash: [32]u8) bool {
        std.debug.assert(self.state_heal != null);
        const state = &self.state.?;
        if (state.phase != .accounts) return true;

        var fetched_until: [32]u8 = undefined;
        std.mem.writeInt(u256, &fetched_until, state.account_fetch_head, .big);
        for (self.stashed_snap_requests) |request| {
            if (request.msg != .get_account_range) continue;
            const origin = request.msg.get_account_range.origin;
            if (std.mem.order(u8, &origin, &fetched_until) == .lt) fetched_until = origin;
        }
        return std.mem.order(u8, &account_hash, &fetched_until) == .lt;
    }

    fn storageFetchPassed(self: *Self, account_hash: [32]u8) bool {
        const state = &self.state.?;
        return switch (state.phase) {
            .accounts => false,
            .storage => std.mem.order(u8, &account_hash, &state.storage_fetch_head) == .lt,
            .codes, .hashing, .catchup => true,
        };
    }

    fn updateStorageTrie(
        self: *Self,
        allocator: std.mem.Allocator,
        txn: kv.Transaction,
        addr_hash: [32]u8,
        root: [32]u8,
        slots: []const [32]u8,
        values: []const u256,
    ) !?[32]u8 {
        if (!try self.isStorageTrieAvailable(txn, addr_hash, root)) return null;
        const st = try self.eth_db.openStorageTrie(allocator, txn, addr_hash, root);
        // per key: up to 64 inner nodes on its path plus removals from collapses
        var collector = try trie.NodeCollector.init(allocator, slots.len * 66);
        var storage_trie = st.withCollector(&collector);
        defer self.eth_db.closeStorageTrie(&storage_trie);
        try storage_trie.update(slots, values);
        const new_root = try storage_trie.rootHash();
        try self.eth_db.commitStorageTrieNodes(txn, addr_hash, &collector);
        return new_root;
    }

    fn isAccountTrieAvailable(self: *Self, txn: kv.Transaction, root: [32]u8) !bool {
        return std.meta.eql(types.empty_root_hash, root) or try self.eth_db.hasAccountTrie(txn);
    }

    fn isStorageTrieAvailable(self: *Self, txn: kv.Transaction, addr_hash: [32]u8, root: [32]u8) !bool {
        return std.meta.eql(types.empty_root_hash, root) or try self.eth_db.hasStorageTrie(txn, addr_hash);
    }

    fn isStorageFetched(self: *Self, account_hash: [32]u8, slot_hash: ?[32]u8) bool {
        std.debug.assert(self.state_heal != null);
        if (!self.storageFetchPassed(account_hash)) return false;

        for (self.stashed_snap_requests) |request| {
            if (request.msg != .get_storage_ranges) continue;
            const storage_request = request.msg.get_storage_ranges;
            for (storage_request.account_hashes, 0..) |requested_account, index| {
                if (!std.meta.eql(requested_account, account_hash)) continue;
                const slot = slot_hash orelse return false;
                if (index > 0) return false;
                if (std.mem.order(u8, &slot, &storage_request.starting_hash) != .lt and
                    std.mem.order(u8, &slot, &storage_request.limit_hash) != .gt) return false;
            }
        }
        return true;
    }

    fn fetchStaleStorageRoots(self: *Self) bool {
        const stale_storage_roots = &self.state_heal.?.stale_storage_roots;
        const idle = self.inflight_snap_requests.empty() and self.pending_snap_requests.empty() and
            self.validating_snap_requests.empty();
        if (idle) {
            if (stale_storage_roots.count() == 0) return false;
            log.info("state heal: fetching {} accounts with stale storage roots", .{stale_storage_roots.count()});
        }

        while (stale_storage_roots.count() > 0) {
            const req = self.free_snap_requests.pop() orelse break;
            const account_hash = stale_storage_roots.pop().?.key;
            const account = std.mem.readInt(u256, &account_hash, .big);
            self.requestAccountRange(req, self.state.?.pivot.state_root, account, account);
        }
        return true;
    }

    fn commitTxn(self: *Self, owned: *kv.OwnedTransaction, op: []const u8, started_at: std.Io.Timestamp) !void {
        const commit_start = std.Io.Timestamp.now(self.io, .awake);
        try owned.commit();
        self.metrics.db_commit_seconds.observe(.{ .op = op }, secondsSince(self.io, commit_start)) catch {};
        self.metrics.db_txn_seconds.observe(.{ .op = op }, secondsSince(self.io, started_at)) catch {};
    }

    fn observeHandle(self: *Self, msg: []const u8, started_at: std.Io.Timestamp) void {
        self.metrics.handle_seconds.observe(.{ .msg = msg }, secondsSince(self.io, started_at)) catch {};
    }

    pub fn writeMetrics(self: *Self, writer: *std.Io.Writer) !void {
        return prom.write(&self.metrics, writer);
    }

    fn updateMetrics(self: *Self) void {
        const m = &self.metrics;
        const request_counts = [_]struct { []const u8, []const u8, usize }{
            .{ "eth", "inflight", self.inflight_eth_requests.inner.len() },
            .{ "eth", "pending", self.pending_eth_requests.inner.len() },
            .{ "eth", "validating", self.validating_eth_requests.inner.len() },
            .{ "snap", "inflight", self.inflight_snap_requests.inner.len() },
            .{ "snap", "pending", self.pending_snap_requests.inner.len() },
            .{ "snap", "validating", self.validating_snap_requests.inner.len() },
            .{ "snap", "stashed", self.stashed_snap_requests.len },
            .{ "eth", "free", self.free_eth_requests.inner.len() },
            .{ "snap", "free", self.free_snap_requests.inner.len() },
        };
        for (request_counts) |c| m.requests.set(.{ .proto = c[0], .state = c[1] }, c[2]) catch {};

        m.sync_target.set(self.syncTarget().number);
        if (self.bc.head()) |head| m.chain_head.set(head.number) else |_| {}
        m.headers_downloaded.set(self.progress.headers);
        if (self.state) |state| m.pivot.set(state.pivot.number);
        m.state_progress.set(.{ .kind = "accounts" }, keyspacePercent(self.progress.account_keyspace)) catch {};
        m.state_progress.set(.{ .kind = "storage" }, keyspacePercent(self.progress.storage_keyspace)) catch {};
        m.state_progress.set(.{ .kind = "codes" }, keyspacePercent(self.progress.code_keyspace)) catch {};
        if (self.eth_db.kv_store.env.info()) |info| m.db_size_bytes.set(info.geo.current) else |_| {}
        m.heal_blocks_remaining.set(if (self.state_heal) |heal| heal.target_pivot.number -| (heal.next_pivot.number - 1) else 0);
        m.snap_flush_queue_entries.set(self.snap_flush_queue.inner.len());
        m.snap_flush_queue_bytes.set(self.snap_flush_queue_bytes);
        const flush_head = if (self.snap_flush_queue.inner.first) |list_node|
            &@as(*List(QueuedSnapFlush).Node, @alignCast(@fieldParentPtr("node", list_node))).elem
        else
            null;
        m.snap_flush_queue_blocked.set(if (flush_head) |head| @intFromBool(self.hasPrecedingSnapRequest(head)) else 0);
    }

    fn logProgress(self: *Self) void {
        const now = std.Io.Clock.now(.real, self.io);
        if (self.progress.last_log) |last| {
            if (last.durationTo(now).nanoseconds < progress_log_interval.nanoseconds) return;
        }
        self.progress.last_log = now;

        if (self.eth_provider.server) |server| {
            log.info("peers: {}/{} connections, eth {}, snap {}; dials {} (failed {}), inbound {}, handshakes {}, disconnects {}", .{
                server.connectionCount(),
                rlpx.Server.max_peers,
                self.eth_provider.peerCount(),
                self.snap_provider.peerCount(),
                server.stats.dials.load(.monotonic),
                server.stats.failed_dials.load(.monotonic),
                server.stats.inbound.load(.monotonic),
                server.stats.handshakes.load(.monotonic),
                server.stats.disconnects.load(.monotonic),
            });
        }

        const target = self.syncTarget();
        if (self.header != null) {
            const total_headers = target.number - target.cutoff_number + 1;
            log.info("header download: {d:.2}% ({}/{} headers), target {}, inflight requests {}", .{
                @as(f64, @floatFromInt(self.progress.headers)) / @as(f64, @floatFromInt(total_headers)) * 100,
                self.progress.headers,
                total_headers,
                target.number,
                self.inflight_eth_requests.inner.len(),
            });
        }
        if (self.state) |state| if (state.phase != .catchup) {
            var hashing_buf: [32]u8 = undefined;
            log.info("state download: pivot {}, {t} {d:.2}%{s}, inflight requests {}, healing {}", .{
                state.pivot.number,
                state.phase,
                keyspacePercent(switch (state.phase) {
                    .accounts => self.progress.account_keyspace,
                    .storage => self.progress.storage_keyspace,
                    .codes => self.progress.code_keyspace,
                    .hashing => std.mem.readInt(u256, &state.hash_head, .big),
                    .catchup => unreachable,
                }),
                if (state.phase == .codes)
                    std.fmt.bufPrint(
                        &hashing_buf,
                        ", hashing {d:.2}%",
                        .{keyspacePercent(std.mem.readInt(u256, &state.hash_head, .big))},
                    ) catch ""
                else
                    "",
                self.inflight_snap_requests.inner.len(),
                self.state_heal != null,
            });
        };
        if (self.state_heal) |state_heal| {
            const healed = state_heal.next_pivot.number - 1 - state_heal.start_number;
            const total = state_heal.target_pivot.number - state_heal.start_number;
            const bal_status = if (state_heal.bal_applied) "applied" else if (state_heal.bal_requested) "requested" else "not requested";
            log.info("state heal: block {} ({}/{} healed, {}s elapsed), bal {s}, inflight snap {}, pending snap {}, inflight eth {}", .{
                state_heal.next_pivot.number,
                healed,
                total,
                state_heal.started_at.durationTo(now).toSeconds(),
                bal_status,
                self.inflight_snap_requests.inner.len(),
                self.pending_snap_requests.inner.len(),
                self.inflight_eth_requests.inner.len(),
            });
        }
    }

    fn keyspacePercent(covered: u256) f64 {
        return @as(f64, @floatFromInt(@as(u64, @truncate(covered >> 192)))) / std.math.pow(f64, 2, 64) * 100;
    }
};

const HeaderPurpose = enum { chain, consensus, ancestors };

fn Request(comptime msg: type) type {
    return struct {
        id: u64,
        peer: rlpx.Server.PeerId,
        msg: msg,
        sent_at: std.Io.Timestamp,
        deadline: std.Io.Timestamp,
        keyspace: [2]u256 = .{ 0, 0 },
        storage_roots: [][32]u8 = &.{},
        header_purpose: HeaderPurpose = .chain,
        header_generation: u64 = 0,

        fn lessThan(ctx: void, left: @This(), right: @This()) bool {
            return msg.lessThan(ctx, left.msg, right.msg);
        }
    };
}

test "shadow old generation header replies are freed without touching downloaded headers" {
    const a = std.testing.allocator;
    var pool = try List(Request(eth.Message)).init(a, 1);
    defer pool.deinit(a);
    const req = pool.pop().?;
    req.header_generation = 1;
    req.header_purpose = .chain;
    // All state/files deliberately absent: a stale validation must be discarded
    // before decoding, retrying or writing to the new branch's staging file.
    var downloader: Downloader = undefined;
    downloader.header_generation = 2;
    downloader.free_eth_requests = .{};
    try downloader.handleHeaders(req, error.StaleResponseMustNotBeConsumed);
    try std.testing.expectEqual(req, downloader.free_eth_requests.pop().?);
}

test "shadow superseded consensus lookup cannot replace the newly selected target" {
    const a = std.testing.allocator;
    var pool = try List(Request(eth.Message)).init(a, 1);
    defer pool.deinit(a);
    const req = pool.pop().?;
    req.header_purpose = .consensus;
    req.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = @splat(1) }, .amount = 1, .skip = 0, .reverse = true } } };
    var downloader: Downloader = undefined;
    downloader.consensus_anchor = null;
    downloader.consensus_probe = @splat(1);
    downloader.consensus_update = .{
        .anchor = .{ .beacon_root = @splat(9), .execution_hash = @splat(2), .slot = 100 },
        .head = .{ .hash = @splat(3), .slot = 101 },
        .observed_at_ms = 0,
    };
    downloader.free_eth_requests = .{};
    try downloader.handleHeaders(req, error.StaleResponseMustNotBeConsumed);
    try std.testing.expectEqual(req, downloader.free_eth_requests.pop().?);
    try std.testing.expectEqual(null, downloader.consensus_probe);
}

test "retained EMPTY parent cancels obsolete probes without rewinding warmed FULL state" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(io, "db", &path);
    var store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20);
    defer store.deinit() catch unreachable;
    var snapshots: snapshots_db.Snapshots = .{ .io = io, .store = &store };
    defer snapshots.deinit();
    var parent = @import("blockchain.zig").glamsterdam_devnet8_config.genesis_header;
    parent.number = 1;
    var full = parent;
    full.number = 2;
    full.parent_hash = parent.hash();
    for ([_]types.BlockHeader{ parent, full }) |header| {
        const txn = try store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        try snapshots_db.writeCheckpoint(&store, txn, a, header);
        try txn.commit();
        try snapshots.publish(a);
    }
    var pool = try List(Request(eth.Message)).init(a, 1);
    defer pool.deinit(a);
    const obsolete = pool.pop().?;
    obsolete.header_purpose = .consensus;
    obsolete.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = @splat(9) }, .amount = 1, .skip = 0, .reverse = true } } };
    // No peer provider or writable blockchain is installed. Serving a retained
    // parent must neither request a header nor touch the active writer branch.
    var downloader: Downloader = undefined;
    downloader.io = io;
    downloader.shadow_snapshots = &snapshots;
    downloader.pending_bootstrap = null;
    downloader.consensus_anchor = .{ .beacon_root = @splat(8), .execution_hash = parent.hash(), .slot = 100 };
    downloader.consensus_update = .{ .anchor = downloader.consensus_anchor.?, .head = .{ .hash = parent.hash(), .slot = 101 }, .observed_at_ms = 0 };
    downloader.consensus_probe = @splat(9);
    downloader.sync_target_mutex = .init;
    downloader.sync_target = .{ .number = full.number, .hash = full.hash(), .cutoff_number = full.number, .cutoff_hash = full.hash() };
    downloader.header_generation = 42;
    downloader.inflight_eth_requests = .{};
    downloader.pending_eth_requests = .{};
    downloader.free_eth_requests = .{};
    downloader.inflight_eth_requests.push(obsolete);
    try downloader.advanceConsensusTarget();
    try std.testing.expectEqual(null, downloader.consensus_probe);
    try std.testing.expectEqual(obsolete, downloader.free_eth_requests.pop().?);
    try std.testing.expectEqual(@as(u64, 42), downloader.header_generation);
    try std.testing.expectEqual(full.hash(), downloader.sync_target.hash);
    try std.testing.expectEqual(full.hash(), snapshots.status().headers[0].hash());
    const old = try snapshots.acquire(parent.hash(), parent.state_root);
    defer old.deinit();
    try std.testing.expectEqual(parent.hash(), old.header.hash());
}

test "consensus direct extension reuses verified target and checkpoint without a second header request" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(io, "db", &path);
    var store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20);
    defer store.deinit() catch unreachable;
    var files = try @import("../db/file.zig").Storage.init(io, a, path[0..length]);
    defer files.deinit(io, a) catch unreachable;
    var db = EthDb.init(&store);
    var bc: Blockchain = .{
        .cfg = @import("blockchain.zig").glamsterdam_devnet8_config,
        .io = io,
        .allocator = a,
        .eth_db = &db,
        .file_storage = &files,
        .shadow_branches = .init(true),
    };
    var parent = bc.cfg.genesis_header;
    parent.number = 10;
    parent.block_access_list_hash = @splat(0x44);
    parent.slot_number = 20;
    parent.state_root = types.empty_root_hash;
    {
        const txn = try store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        try branches.initialize(&store, txn, arena.allocator(), parent);
        try snapshots_db.writeCheckpoint(&store, txn, a, parent);
        try txn.commit();
    }
    var snapshots: snapshots_db.Snapshots = .{ .io = io, .store = &store };
    defer snapshots.deinit();
    try snapshots.publish(a);
    const lease = try snapshots.acquire(parent.hash(), parent.state_root);
    defer lease.deinit();
    var child = parent;
    child.number += 1;
    child.parent_hash = parent.hash();
    child.slot_number = 21;
    std.crypto.hash.sha3.Keccak256.hash(&.{0xc0}, &child.block_access_list_hash.?, .{});

    // Fully initialized providers have no connected peers. The authenticated
    // child and immutable checkpoint must advance without queuing another fetch.
    // State is NOT marked ready before the normal BAL/root validation finishes.
    var eth_provider = try eth.Provider.init(arena.allocator());
    var snap_provider = try snap.Provider.init(arena.allocator());
    var downloader = try Downloader.init(io, arena.allocator(), &bc, &db, &eth_provider, &snap_provider);
    downloader.shadow_snapshots = &snapshots;
    downloader.consensus_anchor = .{ .beacon_root = @splat(8), .execution_hash = parent.hash(), .slot = 20 };
    downloader.consensus_update = .{
        .anchor = downloader.consensus_anchor.?,
        .head = .{ .hash = child.hash(), .slot = 21 },
        .observed_at_ms = 0,
    };
    downloader.free_eth_requests = .{};
    var request_pool = try List(Request(eth.Message)).init(arena.allocator(), 4);
    const lookup = request_pool.pop().?;
    lookup.header_purpose = .consensus;
    lookup.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = child.hash() }, .amount = 1, .skip = 0, .reverse = true } } };
    var lookup_headers = [_]types.BlockHeader{child};
    var lookup_hashes = [_][32]u8{child.hash()};
    const lookup_result: ValidationOutcome = .{ .headers = .{ .headers = &lookup_headers, .hashes = &lookup_hashes } };

    // A worker result's claimed hash is not authority: bind the decoded header
    // itself to the current trusted CL target before altering any branch state.
    lookup_headers[0].beneficiary = @splat(0x77);
    try std.testing.expectError(error.ConsensusHeaderHashMismatch, downloader.handleConsensusHeader(lookup, lookup_result));
    try std.testing.expectEqual(parent.hash(), downloader.sync_target.hash);
    try std.testing.expectEqual(null, downloader.header);
    lookup_headers[0] = child;
    lookup_headers[0].block_access_list_hash = null;
    lookup.msg.get_block_headers.range.origin.hash = lookup_headers[0].hash();
    downloader.consensus_update.?.head.hash = lookup_headers[0].hash();
    try std.testing.expectError(error.PostGloasRequired, downloader.handleConsensusHeader(lookup, lookup_result));
    try std.testing.expectEqual(parent.hash(), downloader.sync_target.hash);
    lookup_headers[0] = child;
    lookup.msg.get_block_headers.range.origin.hash = child.hash();
    downloader.consensus_update.?.head.hash = child.hash();
    try downloader.handleConsensusHeader(lookup, lookup_result);
    try std.testing.expectEqual(null, downloader.header);
    try std.testing.expectEqual(child.hash(), (try bc.head()).hash);
    try std.testing.expectEqual(parent.hash(), downloader.state.?.pivot.hash());
    try std.testing.expectEqual(parent.hash(), snapshots.status().headers[0].hash());
    try std.testing.expectError(error.StateViewUnavailable, snapshots.acquire(child.hash(), child.state_root));
    try std.testing.expectEqual(parent.hash(), lease.header.hash());
    try std.testing.expectEqual(2, downloader.progress.headers);
    try std.testing.expect(downloader.pending_eth_requests.empty() and downloader.inflight_eth_requests.empty());
    const generation = downloader.header_generation;
    try downloader.selectConsensusTarget(child);
    try std.testing.expectEqual(generation, downloader.header_generation);
    try std.testing.expectEqual(null, downloader.header);

    // A true same-height sibling has the same verified parent but a different
    // hash. Child A is already selected: child B must follow normal branch
    // discovery while A's state is still being completed, not seed a conflict.
    var sibling = child;
    sibling.beneficiary = @splat(0xbb);
    try downloader.selectConsensusTarget(sibling);
    try std.testing.expectEqual(child.number, sibling.number);
    try std.testing.expectEqual(child.parent_hash, sibling.parent_hash);
    try std.testing.expectEqual(sibling.hash(), downloader.sync_target.hash);
    try std.testing.expect(downloader.header != null);
    try std.testing.expectEqual(child.hash(), (try bc.head()).hash);
    try std.testing.expectEqual(0, downloader.progress.headers);
    try std.testing.expectError(error.StateViewUnavailable, snapshots.acquire(sibling.hash(), sibling.state_root));

    // A known header without its verified state must not authorize this path.
    // The old parent lease remains usable while the next target waits on peers.
    var next = child;
    next.number += 1;
    next.parent_hash = child.hash();
    next.slot_number = 22;
    try downloader.selectConsensusTarget(next);
    try std.testing.expect(downloader.header != null);
    try std.testing.expectEqual(child.hash(), (try bc.head()).hash);
    try std.testing.expectEqual(parent.hash(), lease.header.hash());

    // Height gaps and broken parent links use the normal
    // authenticated range-download path rather than inventing an ancestor.
    inline for (.{ "gap", "wrong_parent", "healing" }) |case| {
        {
            const reset = try store.transaction_rw();
            errdefer reset.abort() catch unreachable;
            try branches.select(&store, reset, arena.allocator(), parent, &.{});
            try reset.commit();
        }
        downloader.sync_target = .{ .number = parent.number, .hash = parent.hash(), .cutoff_number = parent.number, .cutoff_hash = parent.hash() };
        downloader.state_heal = null;
        var other = child;
        if (comptime std.mem.eql(u8, case, "gap")) other.number += 1;
        if (comptime std.mem.eql(u8, case, "wrong_parent")) other.parent_hash = @splat(0xaa);
        if (comptime std.mem.eql(u8, case, "healing")) downloader.state_heal = .{
            .next_pivot = child,
            .target_pivot = child,
            .start_number = parent.number,
            .started_at = .now(io, .awake),
        };
        try downloader.selectConsensusTarget(other);
        try std.testing.expect(downloader.header != null);
        try std.testing.expectEqual(parent.hash(), (try bc.head()).hash);
        try std.testing.expectEqual(parent.hash(), snapshots.status().headers[0].hash());
        try std.testing.expectEqual(0, downloader.progress.headers);
    }

    // Switching a live download cancels requests owned by the loop, but leaves
    // a worker's request alive until its result arrives. Old staged descendants
    // must also be removed before seeding the new sibling of that old target.
    downloader.state_heal = null;
    downloader.cancelHeaderRequests(.chain);
    downloader.free_eth_requests = .{};
    downloader.sync_target = .{ .number = parent.number, .hash = parent.hash(), .cutoff_number = parent.number, .cutoff_hash = parent.hash() };
    var old_descendant = sibling;
    old_descendant.number += 1;
    old_descendant.parent_hash = sibling.hash();
    var old_headers = [_]types.BlockHeader{ parent, sibling, old_descendant };
    var old_hashes = [_][32]u8{ parent.hash(), sibling.hash(), old_descendant.hash() };
    try std.testing.expectEqual(null, try downloader.persistDownloadedHeaderChain(&old_headers, &old_hashes, 3));
    const inflight = request_pool.pop().?;
    const pending = request_pool.pop().?;
    const validating = request_pool.pop().?;
    const old_generation = downloader.header_generation;
    for ([_]*Request(eth.Message){ inflight, pending, validating }) |req| req.* = .{
        .id = 1,
        .peer = .{ .peer_index = 0, .peer_epoch = 0 },
        .msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = sibling.hash() }, .amount = 2 } } },
        .sent_at = .now(io, .awake),
        .deadline = .now(io, .awake),
        .header_generation = old_generation,
    };
    downloader.inflight_eth_requests.push(inflight);
    downloader.pending_eth_requests.push(pending);
    downloader.validating_eth_requests.push(validating);
    try downloader.selectConsensusTarget(child);
    try std.testing.expectEqual(old_generation + 1, downloader.header_generation);
    try std.testing.expect(downloader.inflight_eth_requests.empty() and downloader.pending_eth_requests.empty());
    try std.testing.expectEqual(2, downloader.free_eth_requests.inner.len());
    try std.testing.expectEqual(1, downloader.validating_eth_requests.inner.len());
    try std.testing.expect(downloader.header != null);
    try std.testing.expectEqual(parent.hash(), (try bc.head()).hash);
    try std.testing.expectEqual(child.hash(), (try downloader.readDownladedHeader(child.number)).?.hash());
    try std.testing.expectEqual(null, try downloader.readDownladedHeader(old_descendant.number));
    try downloader.handleValidated(.{
        .arena = .init(arena.allocator()),
        .resp = .{ .eth = .{
            .req = validating,
            .msg = .{
                .msg = .{ .block_headers = .{ .request_id = 1, .rlps = &.{} } },
                .read = .{ .peer = validating.peer, .id = 4, .payload = try arena.allocator().alloc(u8, 0) },
            },
        } },
        .outcome = .{ .headers = .{ .headers = old_headers[0..2], .hashes = old_hashes[0..2] } },
    });
    try std.testing.expect(downloader.validating_eth_requests.empty());
    try std.testing.expectEqual(3, downloader.free_eth_requests.inner.len());
    try std.testing.expectEqual(child.hash(), (try downloader.readDownladedHeader(child.number)).?.hash());
    try std.testing.expectEqual(2, downloader.progress.headers);
    try downloader.checkHeaderDownloadComplete();
    try std.testing.expectEqual(null, downloader.header);
    try std.testing.expectEqual(child.hash(), (try bc.head()).hash);
    try std.testing.expectError(error.StateViewUnavailable, snapshots.acquire(child.hash(), child.state_root));

    // Header reuse still goes through BAL hash gating, state-root calculation
    // and atomic checkpoint publication. A wrong BAL cannot make the child
    // ready; the matching empty BAL advances the real empty trie checkpoint.
    downloader.state_heal = .{
        .next_pivot = child,
        .target_pivot = child,
        .start_number = parent.number,
        .started_at = .now(io, .real),
        .bal_requested = true,
    };
    const bal_req = downloader.free_eth_requests.pop().?;
    var bals = [_]VerifiedBal{.{ .hash = @splat(0x99), .parsed = &.{} }};
    try downloader.handleBals(bal_req, .{ .bals = &bals });
    try std.testing.expect(!downloader.state_heal.?.bal_applied);
    try std.testing.expectError(error.StateViewUnavailable, snapshots.acquire(child.hash(), child.state_root));
    try std.testing.expectEqual(parent.hash(), snapshots.status().headers[0].hash());
    try std.testing.expectEqual(bal_req, downloader.pending_eth_requests.pop().?);
    bals[0].hash = child.block_access_list_hash.?;
    try downloader.handleBals(bal_req, .{ .bals = &bals });
    try std.testing.expectEqual(null, downloader.state_heal);
    const child_lease = try snapshots.acquire(child.hash(), child.state_root);
    defer child_lease.deinit();
    try std.testing.expectEqual(child.hash(), child_lease.header.hash());
    try std.testing.expectError(error.StateRootMismatch, snapshots.acquire(child.hash(), @splat(0xff)));
    try std.testing.expectEqual(parent.hash(), lease.header.hash());

    // Once A is fully verified, a same-height CL switch to B still downloads
    // its ancestry, rewinds to the common parent and verifies B's own BAL.
    // The retained FULL-A lease stays valid while the writer follows FULL-B.
    downloader.consensus_update.?.head.hash = sibling.hash();
    const sibling_lookup = downloader.free_eth_requests.pop().?;
    sibling_lookup.header_purpose = .consensus;
    sibling_lookup.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = sibling.hash() }, .amount = 1 } } };
    lookup_headers[0] = sibling;
    lookup_hashes[0] = sibling.hash();
    try downloader.handleConsensusHeader(sibling_lookup, lookup_result);
    try std.testing.expectEqual(child.hash(), (try bc.head()).hash);
    const sibling_range = downloader.pending_eth_requests.pop().?;
    try downloader.handleHeaders(sibling_range, lookup_result);
    try std.testing.expectEqual(child.hash(), (try bc.head()).hash);
    try downloader.advanceHeaderDownload();
    const ancestry_range = downloader.pending_eth_requests.pop().?;
    try std.testing.expectEqual(2, ancestry_range.msg.get_block_headers.range.amount);
    try downloader.handleHeaders(ancestry_range, .{ .headers = .{ .headers = old_headers[0..2], .hashes = old_hashes[0..2] } });
    try std.testing.expectEqual(null, downloader.header);
    try std.testing.expectEqual(sibling.hash(), (try bc.head()).hash);
    try std.testing.expectEqual(parent.hash(), downloader.state.?.pivot.hash());
    try std.testing.expectError(error.StateViewUnavailable, snapshots.acquire(sibling.hash(), sibling.state_root));
    downloader.state_heal = .{
        .next_pivot = sibling,
        .target_pivot = sibling,
        .start_number = parent.number,
        .started_at = .now(io, .real),
        .bal_requested = true,
    };
    try downloader.handleBals(downloader.free_eth_requests.pop().?, .{ .bals = &bals });
    const sibling_lease = try snapshots.acquire(sibling.hash(), sibling.state_root);
    defer sibling_lease.deinit();
    try std.testing.expectEqual(sibling.hash(), sibling_lease.header.hash());
    try std.testing.expectEqual(child.hash(), child_lease.header.hash());
    try std.testing.expectEqual(parent.hash(), lease.header.hash());
}

test "shadow cancellation preserves in-validation ownership and BAL requests" {
    const a = std.testing.allocator;
    var pool = try List(Request(eth.Message)).init(a, 4);
    defer pool.deinit(a);
    var downloader: Downloader = undefined;
    downloader.inflight_eth_requests = .{};
    downloader.pending_eth_requests = .{};
    downloader.validating_eth_requests = .{};
    downloader.free_eth_requests = .{};
    const inflight = pool.pop().?;
    const pending = pool.pop().?;
    const validating = pool.pop().?;
    const bal = pool.pop().?;
    for ([_]*Request(eth.Message){ inflight, pending, validating }) |req| {
        req.header_purpose = .chain;
        req.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = @splat(1) }, .amount = 1, .skip = 0, .reverse = true } } };
    }
    bal.msg = .{ .get_block_access_list = .{ .hashes = &.{} } };
    downloader.inflight_eth_requests.push(inflight);
    downloader.inflight_eth_requests.push(bal);
    downloader.pending_eth_requests.push(pending);
    downloader.validating_eth_requests.push(validating);
    downloader.cancelHeaderRequests(.chain);
    try std.testing.expectEqual(validating, downloader.validating_eth_requests.pop().?);
    try std.testing.expectEqual(bal, downloader.inflight_eth_requests.pop().?);
    try std.testing.expect(downloader.inflight_eth_requests.empty());
    try std.testing.expect(downloader.pending_eth_requests.empty());
    try std.testing.expectEqual(inflight, downloader.free_eth_requests.pop().?);
    try std.testing.expectEqual(pending, downloader.free_eth_requests.pop().?);
    try std.testing.expect(downloader.free_eth_requests.empty());
}

test "cleared unverified startup awaits a fresh finalized anchor beyond the rolling window" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(io, "db", &path);
    var store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20);
    defer store.deinit() catch unreachable;
    var files = try @import("../db/file.zig").Storage.init(io, a, path[0..length]);
    defer files.deinit(io, a) catch unreachable;
    var db = EthDb.init(&store);
    var bc: Blockchain = .{ .cfg = @import("blockchain.zig").glamsterdam_devnet8_config, .io = io, .allocator = alloc, .eth_db = &db, .file_storage = &files, .shadow_branches = .init(true) };
    var previous = bc.cfg.genesis_header;
    previous.number = 10;
    previous.slot_number = 20;
    previous.block_access_list_hash = @splat(1);
    const old_anchor: consensus.Anchor = .{ .beacon_root = @splat(1), .execution_hash = previous.hash(), .slot = 20 };
    {
        var owned: kv.OwnedTransaction = .{ .txn = try store.transaction_rw() };
        defer owned.deinit();
        try db.writeAccount(alloc, owned.txn, types.keccakOfU160(1), types.EmptyAccount);
        try branches.initialize(&store, owned.txn, alloc, previous);
        var encoded = std.array_list.Managed(u8).init(alloc);
        try rlp.serialize(consensus.Anchor, alloc, old_anchor, &encoded);
        try store.table(owned.txn, .state_meta).set("consensus-anchor-v1", encoded.items, .Upsert);
        try owned.commit();
    }
    var views: snapshots_db.Snapshots = .{ .io = io, .store = &store };
    defer views.deinit();
    var eth_provider = try eth.Provider.init(alloc);
    var snap_provider = try snap.Provider.init(alloc);
    var d = try Downloader.init(io, alloc, &bc, &db, &eth_provider, &snap_provider);
    defer d.task_group.cancel(io);
    defer if (d.state) |*state| state.code_hashes.deinit(std.heap.page_allocator);
    try d.enableShadow(&views, true);
    var queue_buffer: [4]consensus.Update = undefined;
    var queue: std.Io.Queue(consensus.Update) = .init(&queue_buffer);
    try d.enableConsensus(&queue);
    // No old-root request may race the freshly cleared startup admission.
    try std.testing.expectEqual(null, d.state);
    try std.testing.expect(d.pending_bootstrap != null);
    try std.testing.expect(d.pending_snap_requests.empty());
    try std.testing.expectEqual(0, views.status().count);

    var regressed = old_anchor;
    regressed.slot -= 1;
    d.consensus_update = .{ .anchor = regressed, .head = .{ .hash = @splat(0xee), .slot = 600 }, .observed_at_ms = 0 };
    try std.testing.expectEqual(null, d.desiredConsensusHash());
    var conflicting = old_anchor;
    conflicting.beacon_root = @splat(0x33);
    d.consensus_update = .{ .anchor = conflicting, .head = .{ .hash = @splat(0xee), .slot = 600 }, .observed_at_ms = 0 };
    // Even an unchanged execution hash must be freshly admitted; a same-slot
    // beacon conflict cannot be hidden by the already-selected fast path.
    try d.advanceConsensusTarget();
    const conflict_lookup = d.pending_eth_requests.pop().?;
    var old_headers = [_]types.BlockHeader{previous};
    var old_hashes = [_][32]u8{previous.hash()};
    try std.testing.expectError(error.ConflictingConsensusAnchor, d.handleConsensusHeader(conflict_lookup, .{ .headers = .{ .headers = &old_headers, .hashes = &old_hashes } }));
    try std.testing.expectEqual(null, d.state);
    try std.testing.expectEqual(old_anchor, d.consensus_anchor.?);
    try std.testing.expect(d.pending_bootstrap != null);
    try std.testing.expect(d.pending_snap_requests.empty());

    var fresh = previous;
    fresh.number += branches.extension_limit + 50;
    fresh.slot_number = 500;
    fresh.parent_hash = @splat(0x99); // No claim of retained ancestry to old partial state.
    fresh.state_root = types.empty_root_hash;
    const new_anchor: consensus.Anchor = .{ .beacon_root = @splat(2), .execution_hash = fresh.hash(), .slot = 501 };
    d.consensus_update = .{ .anchor = new_anchor, .head = .{ .hash = @splat(0xee), .slot = 600 }, .observed_at_ms = 0 };
    try std.testing.expectEqual(fresh.hash(), d.desiredConsensusHash().?);
    try d.advanceConsensusTarget();
    const lookup = d.pending_eth_requests.pop().?;
    var headers = [_]types.BlockHeader{fresh};
    var hashes = [_][32]u8{fresh.hash()};
    try d.handleConsensusHeader(lookup, .{ .headers = .{ .headers = &headers, .hashes = &hashes } });
    try std.testing.expectEqual(null, d.pending_bootstrap);
    try std.testing.expectEqual(fresh.hash(), d.state.?.pivot.hash());
    try std.testing.expectEqual(new_anchor, d.consensus_anchor.?);
    try std.testing.expectEqual(0, views.status().count);
    const range = d.pending_snap_requests.pop().?;
    try std.testing.expectEqual(fresh.state_root, range.msg.get_account_range.root);
    d.free_snap_requests.push(range);
    {
        const txn = try store.transaction_ro();
        defer txn.abort() catch unreachable;
        try std.testing.expectEqual(null, try snapshots_db.readCheckpoint(&store, txn, alloc));
        try std.testing.expectEqual(fresh.hash(), (try branches.state(&store, txn)).?.base.hash());
        try std.testing.expectEqual(new_anchor, (try d.readConsensusAnchor(txn, alloc)).?);
        try std.testing.expectEqual(null, try db.readAccount(txn, types.keccakOfU160(1)));
    }
    try std.testing.expectError(error.StateViewUnavailable, views.acquire(fresh.hash(), fresh.state_root));
    try std.testing.expectError(error.RootMismatch, d.hashTrie(null, @splat(0x77)));
    try std.testing.expectEqual(0, views.status().count);
    try d.hashTrie(null, fresh.state_root);
    try d.publishHashedState(fresh);
    const lease = try views.acquire(fresh.hash(), fresh.state_root);
    defer lease.deinit();
    try std.testing.expectEqual(fresh.hash(), lease.header.hash());
}

test "incomplete bootstrap advances only a finalized linked root and publishes after full hashing" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(io, "db", &path);
    var store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20);
    defer store.deinit() catch unreachable;
    var files = try @import("../db/file.zig").Storage.init(io, a, path[0..length]);
    defer files.deinit(io, a) catch unreachable;
    var db = EthDb.init(&store);
    var bc: Blockchain = .{ .cfg = @import("blockchain.zig").glamsterdam_devnet8_config, .io = io, .allocator = alloc, .eth_db = &db, .file_storage = &files, .shadow_branches = .init(true) };
    const address: u160 = 1;
    const key = types.keccakOfU160(address);
    var account = types.EmptyAccount;
    account.balance = 10;
    var account_trie = @import("../trie/account_trie.zig").AccountTrie.init(alloc);
    try account_trie.updateUnsorted(&.{key}, &.{account});
    var parent = bc.cfg.genesis_header;
    parent.number = 10;
    parent.slot_number = 20;
    parent.block_access_list_hash = @splat(1);
    parent.state_root = try account_trie.rootHash();
    {
        var owned: kv.OwnedTransaction = .{ .txn = try store.transaction_rw() };
        defer owned.deinit();
        try db.writeAccount(alloc, owned.txn, key, account);
        try branches.initialize(&store, owned.txn, alloc, parent);
        try owned.commit();
    }
    account.balance = 20;
    var child_trie = @import("../trie/account_trie.zig").AccountTrie.init(alloc);
    try child_trie.updateUnsorted(&.{key}, &.{account});
    var changes = [_]types.BalanceChange{.{ .index = 1, .balance = 20 }};
    var bal = [_]types.AccountChanges{.{ .addr = address, .storage_changes = &.{}, .storage_reads = &.{}, .balance_changes = &changes, .nonce_changes = &.{}, .code_changes = &.{} }};
    var encoded = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(types.BlockAccessLists, alloc, &bal, &encoded);
    var child = parent;
    child.number += 1;
    child.slot_number = 21;
    child.parent_hash = parent.hash();
    child.state_root = try child_trie.rootHash();
    std.crypto.hash.sha3.Keccak256.hash(encoded.items, &child.block_access_list_hash.?, .{});
    var views: snapshots_db.Snapshots = .{ .io = io, .store = &store };
    defer views.deinit();
    var eth_provider = try eth.Provider.init(alloc);
    var snap_provider = try snap.Provider.init(alloc);
    var d = try Downloader.init(io, alloc, &bc, &db, &eth_provider, &snap_provider);
    defer d.task_group.cancel(io);
    d.shadow_snapshots = &views;
    d.consensus_anchor = .{ .beacon_root = @splat(1), .execution_hash = parent.hash(), .slot = 20 };
    d.consensus_update = .{
        .anchor = .{ .beacon_root = @splat(2), .execution_hash = child.hash(), .slot = 52 },
        .head = .{ .hash = @splat(0xee), .slot = 100 },
        .observed_at_ms = 0,
    };
    d.state = .{ .pivot = parent, .account_fetch_head = std.math.maxInt(u256) };
    // An empty state response is ordinary unavailability. Keep the live peer
    // and pending range, with no write or immediate repeated request. There is
    // deliberately no socket/server: disconnect or send would fail this test.
    const peer: rlpx.Server.PeerId = .{ .peer_index = 0, .peer_epoch = 1 };
    snap_provider.peers[0].info.store(.{ .epoch = 1, .offset = 32 }, .release);
    d.peer_ranges[0] = .{ .id = peer, .range = .{ .earliest_block = 0, .latest_block = child.number, .latest_block_hash = child.hash() } };
    const snap_req = d.free_snap_requests.pop().?;
    snap_req.* = .{ .id = 1, .peer = peer, .sent_at = .now(io, .real), .deadline = .now(io, .real), .msg = .{
        .get_account_range = .{ .root = parent.state_root, .origin = @splat(0), .limit = @splat(0xff) },
    } };
    d.validating_snap_requests.push(snap_req);
    try d.handleValidated(.{
        .arena = .init(alloc),
        .resp = .{ .snap = .{ .req = snap_req, .msg = .{
            .msg = .{ .account_range = .{ .id = 1, .accounts = &.{}, .proof = &.{} } },
            .read = .{ .peer = peer, .id = 1, .payload = try alloc.alloc(u8, 0) },
        } } },
        .outcome = error.EmptyAccountRange,
    });
    try std.testing.expectEqual(32, snap_provider.peers[0].info.load(.acquire).offset);
    try std.testing.expectEqual(snap_req, d.pending_snap_requests.pop().?);
    try std.testing.expect(d.snap_flush_queue.empty() and d.validating_snap_requests.empty());
    d.free_snap_requests.push(snap_req);
    snap_provider.peers[0].info.store(.{ .epoch = 0, .offset = 0 }, .release);
    // An unrelated live execution head must never select bootstrap work.
    try std.testing.expectEqual(child.hash(), d.desiredConsensusHash().?);
    const lookup = d.free_eth_requests.pop().?;
    lookup.header_purpose = .consensus;
    lookup.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = child.hash() }, .amount = 1 } } };
    var child_headers = [_]types.BlockHeader{child};
    var child_hashes = [_][32]u8{child.hash()};
    try d.handleConsensusHeader(lookup, .{ .headers = .{ .headers = &child_headers, .hashes = &child_hashes } });
    // Finishing the old-root storage scan while its new header range is in
    // flight must not start asynchronous hashing against the soon-to-move root.
    d.state.?.phase = .storage;
    d.state.?.storage_fetch_head = @splat(0xff);
    try d.advanceStateDownload();
    try std.testing.expectEqual(.storage, d.state.?.phase);
    try std.testing.expectEqual(null, d.task_group.token.load(.acquire));
    d.state.?.phase = .accounts;
    const range = d.pending_eth_requests.pop().?;
    var chain = [_]types.BlockHeader{ parent, child };
    var hashes = [_][32]u8{ parent.hash(), child.hash() };
    try d.handleHeaders(range, .{ .headers = .{ .headers = &chain, .hashes = &hashes } });
    try std.testing.expectEqual(child.hash(), d.state.?.pivot.hash());
    try std.testing.expectEqual(child.hash(), d.consensus_anchor.?.execution_hash);
    try std.testing.expectEqual(0, views.status().count);
    try std.testing.expectError(error.StateViewUnavailable, views.acquire(child.hash(), child.state_root));

    // Preserve the old-root queue barrier and fail within a fixed interval;
    // never flush later ranges around an unavailable predecessor.
    const validating = d.free_snap_requests.pop().?;
    d.validating_snap_requests.push(validating);
    d.state_heal.?.drain_started_at = .fromNanoseconds(0);
    try std.testing.expectError(error.BootstrapDrainUnavailable, d.advanceStateHeal());
    try std.testing.expect(!d.state_heal.?.bal_requested);
    try std.testing.expectEqual(validating, d.validating_snap_requests.pop().?);
    d.free_snap_requests.push(validating);
    d.state_heal.?.drain_started_at = .now(io, .awake);
    try d.advanceStateHeal();
    const request = d.pending_eth_requests.pop().?;
    var wrong = [_]VerifiedBal{.{ .hash = @splat(0xff), .parsed = &bal }};
    try d.handleBals(request, .{ .bals = &wrong });
    {
        const txn = try store.transaction_ro();
        defer txn.abort() catch unreachable;
        try std.testing.expectEqual(10, (try db.readAccount(txn, key)).?.balance);
    }
    try std.testing.expectEqual(request, d.pending_eth_requests.pop().?);
    wrong[0].hash = child.block_access_list_hash.?;
    try d.handleBals(request, .{ .bals = &wrong });
    try std.testing.expectEqual(null, d.state_heal);
    try std.testing.expectEqual(0, views.status().count);
    {
        const txn = try store.transaction_ro();
        defer txn.abort() catch unreachable;
        try std.testing.expectEqual(20, (try db.readAccount(txn, key)).?.balance);
        try std.testing.expectEqual(child.hash(), (try branches.state(&store, txn)).?.base.hash());
        try std.testing.expectEqual(null, try snapshots_db.readCheckpoint(&store, txn, alloc));
    }
    try std.testing.expectError(error.RootMismatch, d.hashTrie(null, @splat(0x77)));
    try std.testing.expectEqual(0, views.status().count);
    try d.hashTrie(null, child.state_root);
    try d.publishHashedState(child);
    const lease = try views.acquire(child.hash(), child.state_root);
    defer lease.deinit();
    try std.testing.expectEqual(child.hash(), lease.header.hash());
}

test "unavailable SNAP state backs off only one connection and exact requested root" {
    const io = std.testing.io;
    var d: Downloader = undefined;
    d.io = io;
    d.unavailable_state = @splat(null);
    var inflight: List(Request(snap.Message)) = .{};
    var filter = PeerFilter(snap.Message).init(&d, &inflight, null);
    filter.state_root = @splat(1);
    var req: Request(snap.Message) = .{
        .id = 1,
        .sent_at = .now(io, .real),
        .deadline = .now(io, .real),
        .peer = .{ .peer_index = 0, .peer_epoch = 10 },
        .msg = .{ .get_account_range = .{ .root = @splat(1), .origin = @splat(0), .limit = @splat(0xff) } },
    };
    d.markUnavailableState(&req);
    try std.testing.expect(!filter.validPeer(req.peer));
    try std.testing.expect(filter.validPeer(.{ .peer_index = 0, .peer_epoch = 11 }));
    try std.testing.expect(filter.validPeer(.{ .peer_index = 1, .peer_epoch = 10 }));
    filter.state_root = @splat(2);
    try std.testing.expect(filter.validPeer(req.peer));
    filter.state_root = @splat(1);
    d.unavailable_state[0].?.until_ms = 0;
    try std.testing.expect(filter.validPeer(req.peer));
}

test "bootstrap healing refreshes changed incomplete storage account before retargeting pending ranges" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(io, "db", &path);
    var store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20);
    defer store.deinit() catch unreachable;
    var files = try @import("../db/file.zig").Storage.init(io, a, path[0..length]);
    defer files.deinit(io, a) catch unreachable;
    var db = EthDb.init(&store);
    var bc: Blockchain = .{ .cfg = @import("blockchain.zig").glamsterdam_devnet8_config, .io = io, .allocator = alloc, .eth_db = &db, .file_storage = &files, .shadow_branches = .init(true) };
    const address: u160 = 1;
    const key = types.keccakOfU160(address);
    var slots = [_]u256{ 1, 2 };
    var slot_hashes = [_][32]u8{ types.keccakOfU256(1), types.keccakOfU256(2) };
    if (std.mem.order(u8, &slot_hashes[0], &slot_hashes[1]) == .gt) {
        std.mem.swap(u256, &slots[0], &slots[1]);
        std.mem.swap([32]u8, &slot_hashes[0], &slot_hashes[1]);
    }
    var old_storage = @import("../trie/storage_trie.zig").StorageTrie.init(alloc);
    try old_storage.update(&slot_hashes, &.{ 7, 11 });
    var account = types.EmptyAccount;
    account.balance = 10;
    account.storage_hash = try old_storage.rootHash();
    var old_accounts = @import("../trie/account_trie.zig").AccountTrie.init(alloc);
    try old_accounts.updateUnsorted(&.{key}, &.{account});
    var parent_header = bc.cfg.genesis_header;
    parent_header.number = 10;
    parent_header.slot_number = 20;
    parent_header.block_access_list_hash = @splat(1);
    parent_header.state_root = try old_accounts.rootHash();
    {
        var owned: kv.OwnedTransaction = .{ .txn = try store.transaction_rw() };
        defer owned.deinit();
        try db.writeAccount(alloc, owned.txn, key, account);
        // Only the first storage chunk has arrived; the second is outstanding.
        try db.writeStorage(owned.txn, key, slot_hashes[0], 7);
        try branches.initialize(&store, owned.txn, alloc, parent_header);
        try owned.commit();
    }
    var new_storage = @import("../trie/storage_trie.zig").StorageTrie.init(alloc);
    try new_storage.update(&slot_hashes, &.{ 17, 21 });
    var updated = account;
    updated.balance = 20;
    updated.nonce = 1;
    updated.storage_hash = try new_storage.rootHash();
    var new_accounts = @import("../trie/account_trie.zig").AccountTrie.init(alloc);
    try new_accounts.updateUnsorted(&.{key}, &.{updated});
    var child = parent_header;
    child.number += 1;
    child.slot_number = 21;
    child.parent_hash = parent_header.hash();
    child.state_root = try new_accounts.rootHash();
    var changes = [_]types.StorageChange{ .{ .index = 1, .value = 17 }, .{ .index = 1, .value = 21 } };
    var storage_changes = [_]types.SlotChanges{ .{ .key = slots[0], .changes = changes[0..1] }, .{ .key = slots[1], .changes = changes[1..2] } };
    var balances = [_]types.BalanceChange{.{ .index = 1, .balance = 20 }};
    var nonces = [_]types.NonceChange{.{ .index = 1, .nonce = 1 }};
    var bal = [_]types.AccountChanges{.{ .addr = address, .storage_changes = &storage_changes, .storage_reads = &.{}, .balance_changes = &balances, .nonce_changes = &nonces, .code_changes = &.{} }};
    var encoded = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(types.BlockAccessLists, alloc, &bal, &encoded);
    std.crypto.hash.sha3.Keccak256.hash(encoded.items, &child.block_access_list_hash.?, .{});
    {
        var owned: kv.OwnedTransaction = .{ .txn = try store.transaction_rw() };
        defer owned.deinit();
        try bootstrap_db.advance(&store, owned.txn, alloc, parent_header.hash(), child.hash(), &.{child});
        try owned.commit();
    }
    var views: snapshots_db.Snapshots = .{ .io = io, .store = &store };
    defer views.deinit();
    var eth_provider = try eth.Provider.init(alloc);
    var snap_provider = try snap.Provider.init(alloc);
    var d = try Downloader.init(io, alloc, &bc, &db, &eth_provider, &snap_provider);
    defer d.task_group.cancel(io);
    d.shadow_snapshots = &views;
    d.consensus_anchor = .{ .beacon_root = @splat(1), .execution_hash = child.hash(), .slot = 52 };
    d.state = .{ .pivot = child, .phase = .storage, .storage_fetch_head = @splat(0xff) };
    var pending_accounts = [_][32]u8{key};
    var pending_roots = [_][32]u8{account.storage_hash};
    d.stashed_snap_requests.len = 1;
    d.stashed_snap_requests[0] = .{
        .id = 10,
        .peer = invalid_peer,
        .sent_at = .now(io, .real),
        .deadline = .now(io, .real),
        .storage_roots = &pending_roots,
        .msg = .{ .get_storage_ranges = .{ .root_hash = parent_header.state_root, .account_hashes = &pending_accounts, .starting_hash = slot_hashes[1] } },
    };
    try std.testing.expect(try d.startStateHeal(parent_header, child));
    d.state_heal.?.bal_requested = true;
    var verified = [_]VerifiedBal{.{ .hash = child.block_access_list_hash.?, .parsed = &bal }};
    try d.handleBals(d.free_eth_requests.pop().?, .{ .bals = &verified });
    const refresh = d.pending_snap_requests.pop().?;
    try std.testing.expectEqual(key, refresh.msg.get_account_range.origin);
    try std.testing.expectEqual(key, refresh.msg.get_account_range.limit);
    try std.testing.expectEqual(child.state_root, refresh.msg.get_account_range.root);
    {
        const txn = try store.transaction_ro();
        defer txn.abort() catch unreachable;
        try std.testing.expectEqual(account.storage_hash, (try db.readAccount(txn, key)).?.storage_hash);
        var keys: [2][32]u8 = undefined;
        var values: [2]u256 = undefined;
        try std.testing.expectEqual(1, try db.readStorageRange(txn, key, @splat(0), &keys, &values));
        try std.testing.expectEqual(17, values[0]);
    }
    var slim = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(snap.SlimAccount, alloc, .{ .nonce = 1, .balance = 20, .root = &updated.storage_hash, .code_hash = &.{} }, &slim);
    const accounts = try alloc.alloc(@typeInfo(@FieldType(snap.AccountRange, "accounts")).pointer.child, 1);
    accounts[0] = .{ .hash = key, .account = .{ .value = slim.items } };
    var response: snap.AccountRange = .{ .id = 1, .accounts = accounts, .proof = &.{} };
    var bad_request = refresh.msg.get_account_range;
    bad_request.root = parent_header.state_root;
    if (d.verifyAccounts(alloc, bad_request, &response)) |_| return error.TestExpectedError else |_| {}
    const outcome = try d.verifyAccounts(alloc, refresh.msg.get_account_range, &response);
    d.validating_snap_requests.push(refresh);
    try d.handleValidated(.{
        .arena = .init(alloc),
        .resp = .{ .snap = .{ .req = refresh, .msg = .{
            .msg = .{ .account_range = response },
            .read = .{ .peer = invalid_peer, .id = 1, .payload = try alloc.alloc(u8, 0) },
        } } },
        .outcome = outcome,
    });
    try std.testing.expectEqual(null, d.state_heal);
    try std.testing.expectEqual(0, views.status().count);
    const retargeted = d.pending_snap_requests.pop().?;
    try std.testing.expectEqual(child.state_root, retargeted.msg.get_storage_ranges.root_hash);
    try std.testing.expectEqual(updated.storage_hash, retargeted.storage_roots[0]);
    try std.testing.expectEqual(slot_hashes[1], retargeted.msg.get_storage_ranges.starting_hash);
    const txn = try store.transaction_ro();
    defer txn.abort() catch unreachable;
    try std.testing.expectEqual(updated, (try db.readAccount(txn, key)).?);
    try std.testing.expectEqual(null, try snapshots_db.readCheckpoint(&store, txn, alloc));
}

test "healed storage resumes only authenticated nonempty accounts and preserves survivor bounds" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(io, "db", &path);
    var store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20);
    defer store.deinit() catch unreachable;
    var files = try @import("../db/file.zig").Storage.init(io, a, path[0..length]);
    defer files.deinit(io, a) catch unreachable;
    var db = EthDb.init(&store);
    var bc: Blockchain = .{ .cfg = @import("blockchain.zig").glamsterdam_devnet8_config, .io = io, .allocator = alloc, .eth_db = &db, .file_storage = &files };
    const keys = [_][32]u8{ @splat(0x11), @splat(0x22), @splat(0x33), @splat(0x44), @splat(0x55) };
    var storage_trie = @import("../trie/storage_trie.zig").StorageTrie.init(alloc);
    try storage_trie.update(&.{types.keccakOfU256(1)}, &.{7});
    const storage_root = try storage_trie.rootHash();
    var empty_account = types.EmptyAccount;
    empty_account.balance = 10;
    var nonempty_account = empty_account;
    nonempty_account.storage_hash = storage_root;
    // A complete account-range proof authenticates two empty roots, two
    // nonempty roots and absence of the middle account. No peer response may
    // make an unknown storage root look empty merely by returning no slots.
    const present_keys = [_][32]u8{ keys[0], keys[1], keys[3], keys[4] };
    const present_accounts = [_]types.Account{ empty_account, nonempty_account, nonempty_account, empty_account };
    var account_trie = @import("../trie/account_trie.zig").AccountTrie.init(alloc);
    try account_trie.updateUnsorted(&present_keys, &.{ empty_account, nonempty_account, nonempty_account, empty_account });
    var header = bc.cfg.genesis_header;
    header.state_root = try account_trie.rootHash();
    {
        var owned: kv.OwnedTransaction = .{ .txn = try store.transaction_rw() };
        defer owned.deinit();
        try branches.initialize(&store, owned.txn, alloc, header);
        try owned.commit();
    }
    bc.shadow_branches.store(true, .release);
    var eth_provider = try eth.Provider.init(alloc);
    var snap_provider = try snap.Provider.init(alloc);
    var d = try Downloader.init(io, alloc, &bc, &db, &eth_provider, &snap_provider);
    defer d.task_group.cancel(io);
    d.state = .{ .pivot = header, .phase = .storage };
    const accounts = try alloc.alloc(@typeInfo(@FieldType(snap.AccountRange, "accounts")).pointer.child, present_keys.len);
    for (present_keys, present_accounts, accounts) |key, account, *encoded_account| {
        var slim = std.array_list.Managed(u8).init(alloc);
        try rlp.serialize(snap.SlimAccount, alloc, .{
            .nonce = 0,
            .balance = 10,
            .root = if (std.meta.eql(account.storage_hash, types.empty_root_hash)) &.{} else &account.storage_hash,
            .code_hash = &.{},
        }, &slim);
        encoded_account.* = .{ .hash = key, .account = .{ .value = slim.items } };
    }
    var response: snap.AccountRange = .{ .id = 1, .accounts = accounts, .proof = &.{} };
    const authenticated = try d.verifyAccounts(alloc, .{ .root = header.state_root, .origin = @splat(0), .limit = @splat(0xff) }, &response);
    try d.persistAccounts(authenticated.accounts, &response);
    const query = try store.transaction_ro();
    defer query.abort() catch unreachable;
    try std.testing.expectEqual(null, try db.readAccount(query, keys[2]));

    // Use the testing allocator for the request-owned buffers, so dropped
    // requests must really free both allocations and surviving ones remain live.
    d.allocator = a;
    // Bounded limits in production belong to single-account requestSlots;
    // multi-account non-max limits here additionally distinguish each edge.
    const cases = [_]struct { indices: []const usize, survivors: []const usize, trim_start: bool, trim_limit: bool }{
        .{ .indices = &.{ 0, 1, 2, 3, 4 }, .survivors = &.{ 1, 3 }, .trim_start = true, .trim_limit = true },
        .{ .indices = &.{ 1, 2, 3 }, .survivors = &.{ 1, 3 }, .trim_start = false, .trim_limit = false },
        .{ .indices = &.{ 0, 2, 4 }, .survivors = &.{}, .trim_start = true, .trim_limit = true },
        .{ .indices = &.{ 0, 1, 3 }, .survivors = &.{ 1, 3 }, .trim_start = true, .trim_limit = false },
        .{ .indices = &.{ 1, 3, 4 }, .survivors = &.{ 1, 3 }, .trim_start = false, .trim_limit = true },
    };
    for (cases) |case| {
        const request_accounts = try a.alloc([32]u8, batch_storage_code_req_size);
        const request_roots = try a.alloc([32]u8, batch_storage_code_req_size);
        var caller_owns_buffers = true;
        defer if (caller_owns_buffers) {
            a.free(request_accounts);
            a.free(request_roots);
        };
        for (case.indices, 0..) |index, i| {
            request_accounts[i] = keys[index];
            request_roots[i] = @splat(0xaa); // the previously authenticated old root
        }
        const free_before = d.free_snap_requests.inner.len();
        const progress_before = d.progress.storage_keyspace;
        d.stashed_snap_requests.len = 1;
        d.stashed_snap_requests[0] = .{
            .id = 10,
            .peer = invalid_peer,
            .sent_at = .now(io, .real),
            .deadline = .now(io, .real),
            .keyspace = .{ 100, 200 },
            .storage_roots = request_roots[0..case.indices.len],
            .msg = .{ .get_storage_ranges = .{
                .root_hash = @splat(0xbb),
                .account_hashes = request_accounts[0..case.indices.len],
                .starting_hash = @splat(0x66),
                .limit_hash = @splat(0x99),
            } },
        };
        try d.popSnapRequests();
        try std.testing.expectEqual(0, d.stashed_snap_requests.len);
        if (case.survivors.len == 0) {
            caller_owns_buffers = false; // popSnapRequests completed and freed it
            try std.testing.expect(d.pending_snap_requests.empty());
            try std.testing.expectEqual(free_before, d.free_snap_requests.inner.len());
            try std.testing.expectEqual(progress_before + 100, d.progress.storage_keyspace);
        } else {
            const request = d.pending_snap_requests.pop().?;
            defer d.free_snap_requests.push(request);
            const storage_request = request.msg.get_storage_ranges;
            try std.testing.expectEqual(case.survivors.len, storage_request.account_hashes.len);
            try std.testing.expectEqual(case.survivors.len, request.storage_roots.len);
            for (case.survivors, storage_request.account_hashes, request.storage_roots) |index, key, root| {
                try std.testing.expectEqual(keys[index], key);
                try std.testing.expectEqual(storage_root, root);
            }
            try std.testing.expectEqual(header.state_root, storage_request.root_hash);
            try std.testing.expectEqual(@as([32]u8, @splat(if (case.trim_start) 0 else 0x66)), storage_request.starting_hash);
            try std.testing.expectEqual(@as([32]u8, @splat(if (case.trim_limit) 0xff else 0x99)), storage_request.limit_hash);
            try std.testing.expectEqual(progress_before, d.progress.storage_keyspace);
            const unavailable: snap.StorageRanges = .{ .id = 10, .slots = &.{}, .proof = &.{} };
            try std.testing.expectError(error.EmptyStorageRanges, d.verifyStorage(alloc, storage_request, request.storage_roots, &unavailable));
        }
    }
}

pub const SyncTarget = struct {
    paused: bool = false,

    number: u64,
    hash: [32]u8,

    cutoff_number: u64, // last header to fetch, inclusive
    cutoff_hash: [32]u8,
};

const PeerRange = struct {
    id: rlpx.Server.PeerId,
    range: eth.BlockRangeUpdate,
};

const ValidatedResponse = struct {
    arena: std.heap.ArenaAllocator,
    resp: union(enum) {
        eth: struct { msg: eth.Provider.ParsedMessage, req: *Request(eth.Message) },
        snap: struct { msg: snap.Provider.ParsedMessage, req: *Request(snap.Message) },

        fn msgName(self: *const @This()) []const u8 {
            return switch (self.*) {
                inline else => |resp| @tagName(resp.msg.msg),
            };
        }
    },
    outcome: anyerror!ValidationOutcome = error.NotValidated,

    fn deinit(self: *const ValidatedResponse, allocator: std.mem.Allocator) void {
        switch (self.resp) {
            inline else => |resp| allocator.free(resp.msg.read.payload),
        }
        self.arena.deinit();
    }
};

const ValidationOutcome = union(enum) {
    headers: struct { hashes: [][32]u8, headers: []types.BlockHeader },
    bals: []VerifiedBal,
    accounts: VerifiedAccounts,
    storage: VerifiedStorage,
    codes: [][32]u8,
};

const VerifiedBal = struct {
    hash: [32]u8,
    parsed: types.BlockAccessLists,
};

const VerifiedAccounts = struct {
    origin: [32]u8,
    limit: [32]u8,
    hashes: [][32]u8,
    code_hashes: [][32]u8,
    has_more: bool,
};

const CodeHashOrder = struct {
    keys: []const [32]u8,

    pub fn lessThan(self: CodeHashOrder, a: usize, b: usize) bool {
        return std.mem.order(u8, &self.keys[a], &self.keys[b]) == .lt;
    }
};

fn isStorageChunk(request: snap.GetStorageRanges) bool {
    return request.account_hashes.len == 1 and !std.mem.allEqual(u8, &request.starting_hash, 0);
}

const VerifiedStorage = struct {
    chunk: bool = false,
    account_hashes: [][32]u8 = &.{},
    keys: [][][32]u8 = &.{},
    values: [][][]const u8 = &.{},
    nodes: [][]trie.NodeCollector.Node = &.{},
    continue_from_slot: ?[32]u8 = null,
};

const QueuedSnapFlush = struct {
    arena: std.heap.ArenaAllocator,
    response: snap.Provider.ParsedMessage,
    validation_outcome: ValidationOutcome,

    fn deinit(self: *const QueuedSnapFlush, allocator: std.mem.Allocator) void {
        allocator.free(self.response.read.payload);
        self.arena.deinit();
    }

    fn size(self: *const QueuedSnapFlush) usize {
        return self.arena.queryCapacity() + self.response.read.payload.len;
    }

    fn lessThan(_: void, left: QueuedSnapFlush, right: QueuedSnapFlush) bool {
        const left_tag = std.meta.activeTag(left.validation_outcome);
        const right_tag = std.meta.activeTag(right.validation_outcome);
        if (left_tag != right_tag) return @backingInt(left_tag) < @backingInt(right_tag);
        return switch (std.mem.order(u8, &left.firstKey(), &right.firstKey())) {
            .lt => true,
            .gt => false,
            .eq => left_tag == .storage and std.mem.order(u8, &firstSlot(left.validation_outcome.storage), &firstSlot(right.validation_outcome.storage)) == .lt,
        };
    }

    fn firstSlot(storage: VerifiedStorage) [32]u8 {
        return if (storage.keys.len > 0 and storage.keys[0].len > 0) storage.keys[0][0] else @splat(0);
    }

    fn firstKey(self: *const QueuedSnapFlush) [32]u8 {
        const keys: []const [32]u8 = switch (self.validation_outcome) {
            .accounts => |accounts| return accounts.origin,
            .storage => |storage| storage.account_hashes,
            .codes => |hashes| hashes,
            else => unreachable,
        };
        return if (keys.len > 0) keys[0] else @splat(0);
    }

    fn isPrecededBy(self: *const QueuedSnapFlush, msg: snap.Message, chunks_precede_later_accounts: bool) bool {
        switch (msg) {
            .get_account_range => |request| return self.validation_outcome == .accounts and
                std.mem.order(u8, &request.origin, &self.firstKey()) == .lt,
            .get_storage_ranges => |request| {
                if (self.validation_outcome != .storage or request.account_hashes.len == 0) return false;
                return switch (std.mem.order(u8, &request.account_hashes[0], &self.firstKey())) {
                    .lt => chunks_precede_later_accounts or !isStorageChunk(request),
                    .gt => false,
                    .eq => std.mem.order(u8, &request.starting_hash, &firstSlot(self.validation_outcome.storage)) == .lt,
                };
            },
            else => return false,
        }
    }
};

const BalHedge = struct {
    hash: [32]u8,
    source_peer: rlpx.Server.PeerId,
    source_id: u64,
    peer: rlpx.Server.PeerId,
    id: u64,
    sent_at: std.Io.Timestamp,

    fn matchesSource(self: BalHedge, req: *const Request(eth.Message)) bool {
        return req.id == self.source_id and std.meta.eql(req.peer, self.source_peer) and
            req.msg == .get_block_access_list and req.msg.get_block_access_list.hashes.len == 1 and
            std.meta.eql(req.msg.get_block_access_list.hashes[0], self.hash);
    }
};

const invalid_peer: rlpx.Server.PeerId = .{
    .peer_index = std.math.maxInt(usize),
    .peer_epoch = std.math.maxInt(usize),
};

fn PeerFilter(comptime Message: type) type {
    return struct {
        downloader: *Downloader,
        min_height: ?u64,
        excluded_peer: ?rlpx.Server.PeerId = null,
        max_earliest: ?u64 = null,
        state_root: ?[32]u8 = null,
        inflight: [rlpx.Server.max_peers]struct { epoch: usize = 0, count: usize = 0 } = @splat(.{}),

        fn init(downloader: *Downloader, inflight: *List(Request(Message)), min_height: ?u64) @This() {
            var self: @This() = .{ .downloader = downloader, .min_height = min_height };
            const hedge: ?BalHedge = if (Message == eth.Message)
                (if (downloader.state_heal) |*heal| heal.bal_hedge else null)
            else
                null;
            var hedge_live = false;
            var current_node = inflight.inner.first;
            while (current_node) |node| : (current_node = node.next) {
                const request: *List(Request(Message)).Node = @alignCast(@fieldParentPtr("node", node));
                if (Message == eth.Message) if (hedge) |h| {
                    if (h.matchesSource(&request.elem)) hedge_live = true;
                };
                const peer = request.elem.peer;
                const slot = &self.inflight[peer.peer_index];
                if (peer.peer_epoch > slot.epoch) slot.* = .{ .epoch = peer.peer_epoch };
                if (peer.peer_epoch == slot.epoch) slot.count += 1;
            }
            // A defensive stale alias must not charge an unrelated connection.
            if (Message == eth.Message) if (hedge_live) {
                const peer = hedge.?.peer;
                const slot = &self.inflight[peer.peer_index];
                if (peer.peer_epoch > slot.epoch) slot.* = .{ .epoch = peer.peer_epoch };
                if (peer.peer_epoch == slot.epoch) slot.count += 1;
            };
            return self;
        }

        pub fn validPeer(self: *const @This(), peer_id: rlpx.Server.PeerId) bool {
            if (self.excluded_peer) |excluded| if (std.meta.eql(excluded, peer_id)) return false;
            if (self.state_root) |root| if (self.downloader.unavailable_state[peer_id.peer_index]) |unavailable| {
                if (std.meta.eql(unavailable.peer, peer_id) and std.meta.eql(unavailable.root, root) and
                    std.Io.Clock.awake.now(self.downloader.io).toMilliseconds() < unavailable.until_ms) return false;
            };
            if (self.min_height) |min_height| {
                const peer_range = self.downloader.peer_ranges[peer_id.peer_index] orelse return false;
                if (peer_range.id.peer_epoch != peer_id.peer_epoch or min_height > peer_range.range.latest_block) return false;
                if (self.max_earliest) |limit| if (peer_range.range.earliest_block > limit) return false;
            }

            const slot = self.inflight[peer_id.peer_index];
            return slot.epoch != peer_id.peer_epoch or slot.count < max_inflight_requests_per_peer;
        }
    };
}

fn slimToFullAccount(slim: snap.SlimAccount) types.Account {
    return .{
        .balance = slim.balance,
        .nonce = slim.nonce,
        .code_hash = if (slim.code_hash.len == 32)
            slim.code_hash[0..32].*
        else
            types.empty_code_hash,
        .storage_hash = if (slim.root.len == 32)
            slim.root[0..32].*
        else
            types.empty_root_hash,
    };
}

const Metrics = struct {
    const duration_buckets: []const f64 = &.{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 };
    const MsgLabels = struct { msg: []const u8 };
    const RequestLabels = struct { proto: []const u8, state: []const u8 };
    const KindLabels = struct { kind: []const u8 };
    const OpLabels = struct { op: []const u8 };

    loop_busy_seconds: prom.Counter(f64),
    loop_wait_seconds: prom.Counter(f64),
    handle_seconds: prom.HistogramVec(f64, MsgLabels, duration_buckets),
    requests_sent: prom.CounterVec(u64, MsgLabels),
    request_timeouts: prom.CounterVec(u64, MsgLabels),
    bal_early_retry_attempts: prom.Counter(u64),
    bal_early_retries: prom.Counter(u64),
    bal_early_retry_no_peer: prom.Counter(u64),
    bal_early_retry_empty: prom.Counter(u64),
    bal_early_retry_expired: prom.Counter(u64),
    response_seconds: prom.HistogramVec(f64, MsgLabels, duration_buckets),
    verify_seconds: prom.HistogramVec(f64, MsgLabels, duration_buckets),
    requests: prom.GaugeVec(u64, RequestLabels),
    sync_target: prom.Gauge(u64),
    chain_head: prom.Gauge(u64),
    headers_downloaded: prom.Gauge(u64),
    pivot: prom.Gauge(u64),
    state_progress: prom.GaugeVec(f64, KindLabels),
    heal_blocks_remaining: prom.Gauge(u64),
    db_txn_seconds: prom.HistogramVec(f64, OpLabels, duration_buckets),
    db_commit_seconds: prom.HistogramVec(f64, OpLabels, duration_buckets),
    db_size_bytes: prom.Gauge(u64),
    batch_build_seconds: prom.Histogram(f64, duration_buckets),
    batch_accounts_scanned: prom.Counter(u64),
    snap_flush_queue_entries: prom.Gauge(u64),
    snap_flush_queue_bytes: prom.Gauge(u64),
    snap_flush_queue_blocked: prom.Gauge(u64),
    snap_flushed_bytes: prom.Counter(u64),

    fn init(allocator: std.mem.Allocator, io: std.Io) !Metrics {
        const opts: prom.RegistryOpts = .{};
        var handle_seconds: @FieldType(Metrics, "handle_seconds") = try .init(allocator, io, "downloader_handle_seconds", .{ .help = "Time the downloader loop spent handling a message or tick" }, opts);
        errdefer handle_seconds.deinit();
        var requests_sent: @FieldType(Metrics, "requests_sent") = try .init(allocator, io, "downloader_requests_sent_total", .{ .help = "Requests sent to peers" }, opts);
        errdefer requests_sent.deinit();
        var request_timeouts: @FieldType(Metrics, "request_timeouts") = try .init(allocator, io, "downloader_request_timeouts_total", .{ .help = "Requests that timed out" }, opts);
        errdefer request_timeouts.deinit();
        var response_seconds: @FieldType(Metrics, "response_seconds") = try .init(allocator, io, "downloader_response_seconds", .{ .help = "Time from sending a request to matching its response" }, opts);
        errdefer response_seconds.deinit();
        var verify_seconds: @FieldType(Metrics, "verify_seconds") = try .init(allocator, io, "downloader_verify_seconds", .{ .help = "Time spent verifying a snap response off the downloader loop" }, opts);
        errdefer verify_seconds.deinit();
        var requests: @FieldType(Metrics, "requests") = try .init(allocator, io, "downloader_requests", .{ .help = "Requests by protocol and state" }, opts);
        errdefer requests.deinit();
        var state_progress: @FieldType(Metrics, "state_progress") = try .init(allocator, io, "downloader_state_progress", .{ .help = "State download progress in percent of the keyspace" }, opts);
        errdefer state_progress.deinit();
        var db_txn_seconds: @FieldType(Metrics, "db_txn_seconds") = try .init(allocator, io, "downloader_db_txn_seconds", .{ .help = "Write transaction duration from begin to commit, by operation" }, opts);
        errdefer db_txn_seconds.deinit();
        const db_commit_seconds: @FieldType(Metrics, "db_commit_seconds") = try .init(allocator, io, "downloader_db_commit_seconds", .{ .help = "Write transaction commit duration, by operation" }, opts);

        return .{
            .loop_busy_seconds = .init("downloader_loop_busy_seconds_total", .{ .help = "Time the downloader loop spent processing" }, opts),
            .loop_wait_seconds = .init("downloader_loop_wait_seconds_total", .{ .help = "Time the downloader loop spent waiting for messages" }, opts),
            .handle_seconds = handle_seconds,
            .requests_sent = requests_sent,
            .request_timeouts = request_timeouts,
            .bal_early_retry_attempts = .init("downloader_bal_early_retry_attempts_total", .{ .help = "Bounded near-head BAL alternate-peer send attempts" }, opts),
            .bal_early_retries = .init("downloader_bal_early_retries_total", .{ .help = "Near-head BAL alternate-peer hedges enqueued" }, opts),
            .bal_early_retry_no_peer = .init("downloader_bal_early_retry_no_peer_total", .{ .help = "Eligible near-head BAL ticks with no alternate peer" }, opts),
            .bal_early_retry_empty = .init("downloader_bal_early_retry_empty_total", .{ .help = "Empty hedged BAL responses ignored while retaining the other peer" }, opts),
            .bal_early_retry_expired = .init("downloader_bal_early_retry_expired_total", .{ .help = "BAL hedges retired at the original request deadline" }, opts),
            .response_seconds = response_seconds,
            .verify_seconds = verify_seconds,
            .requests = requests,
            .sync_target = .init("downloader_sync_target", .{ .help = "Block number the downloader is syncing towards" }, opts),
            .chain_head = .init("downloader_chain_head", .{ .help = "Last header persisted in the chain" }, opts),
            .headers_downloaded = .init("downloader_headers_downloaded", .{ .help = "Headers downloaded towards the current target" }, opts),
            .pivot = .init("downloader_pivot", .{ .help = "State download pivot block" }, opts),
            .state_progress = state_progress,
            .heal_blocks_remaining = .init("downloader_heal_blocks_remaining", .{ .help = "Blocks left to heal, 0 when not healing" }, opts),
            .db_txn_seconds = db_txn_seconds,
            .db_commit_seconds = db_commit_seconds,
            .db_size_bytes = .init("downloader_db_size_bytes", .{ .help = "Current size of the state database file" }, opts),
            .batch_build_seconds = .init("downloader_batch_build_seconds", .{ .help = "Time spent building storage and code request batches" }, opts),
            .batch_accounts_scanned = .init("downloader_batch_accounts_scanned_total", .{ .help = "Accounts scanned while building storage and code request batches" }, opts),
            .snap_flush_queue_entries = .init("downloader_snap_flush_queue_entries", .{ .help = "Snap responses waiting to be written to the database" }, opts),
            .snap_flush_queue_bytes = .init("downloader_snap_flush_queue_bytes", .{ .help = "Memory held by the snap responses waiting to be written" }, opts),
            .snap_flush_queue_blocked = .init("downloader_snap_flush_queue_blocked", .{ .help = "1 when the first snap response waiting to be written is waiting on a request" }, opts),
            .snap_flushed_bytes = .init("downloader_snap_flushed_bytes_total", .{ .help = "Memory of the snap responses written to the database" }, opts),
        };
    }
};

fn secondsSince(io: std.Io, start: std.Io.Timestamp) f64 {
    const ns = start.durationTo(std.Io.Timestamp.now(io, .awake)).toNanoseconds();
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}
// Append to src/node/downloader.zig. Test-only; no production hooks or sockets.
// Uses real ETH provider framing, bounded RLPx queueing, asynchronous BAL
// validation, MDBX checkpoints, and retained state-reader leases.

const BalRetryTestWrite = @typeInfo(@FieldType(rlpx.Server, "write_queue_buf")).pointer.child;
const BalRetryTestSlot = @typeInfo(@FieldType(rlpx.Server, "slots")).pointer.child;

// Production frees incoming frames through Downloader.allocator. Route only
// those frames to an independent checked allocator; long-lived fixture state
// stays in its arena. The checked allocator detects leaks and double frees.
const BalRetryTestMemory = struct {
    backing: std.mem.Allocator,
    frames: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{ .canary = 0xb041f12e }),
    addresses: [128][*]u8 = undefined,
    count: std.atomic.Value(usize) = .init(0),

    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn frame(self: *@This(), bytes: []const u8) ![]u8 {
        const count = self.count.load(.monotonic);
        std.debug.assert(bytes.len > 0 and count < self.addresses.len);
        const result = try self.frames.allocator().dupe(u8, bytes);
        self.addresses[count] = result.ptr;
        self.count.store(count + 1, .release);
        return result;
    }

    fn owner(self: *@This(), ptr: [*]u8) std.mem.Allocator {
        for (self.addresses[0..self.count.load(.acquire)]) |address| if (address == ptr) return self.frames.allocator();
        return self.backing;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.owner(bytes.ptr).rawResize(bytes, alignment, len, ra);
    }

    fn remap(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.owner(bytes.ptr).rawRemap(bytes, alignment, len, ra);
    }

    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.owner(bytes.ptr).rawFree(bytes, alignment, ra);
    }

    fn deinit(self: *@This()) void {
        std.testing.expectEqual(@as(usize, 0), self.frames.deinit()) catch @panic("incoming frame leak");
    }
};

const BalRetryTestFixture = struct {
    allocator: std.mem.Allocator,
    memory: BalRetryTestMemory,
    store: kv.Store,
    files: @import("../db/file.zig").Storage,
    db: EthDb,
    bc: Blockchain,
    snapshots: snapshots_db.Snapshots,
    eth_provider: eth.Provider,
    snap_provider: snap.Provider,
    downloader: Downloader,
    server: rlpx.Server,
    writes: [8]BalRetryTestWrite,
    write_slots: [rlpx.Server.max_peers]std.atomic.Value(usize),
    peer_slots: [rlpx.Server.max_peers]BalRetryTestSlot,
    updates_storage: [2]consensus.Update,
    updates: std.Io.Queue(consensus.Update),
    parent: types.BlockHeader,
    child: types.BlockHeader,
    hashes: [1][32]u8,
    bal_bytes: []const u8,
    request: *Request(eth.Message),
    sent_at: std.Io.Timestamp,

    const old_peer: rlpx.Server.PeerId = .{ .peer_index = 0, .peer_epoch = 10 };
    const alternate: rlpx.Server.PeerId = .{ .peer_index = 1, .peer_epoch = 20 };

    fn init(self: *@This(), allocator: std.mem.Allocator, path: []const u8) !void {
        return self.initWithEmptyBal(allocator, path, false);
    }

    fn initWithEmptyBal(self: *@This(), backing: std.mem.Allocator, path: []const u8, empty_bal: bool) !void {
        const io = std.testing.io;
        self.memory = .{ .backing = backing };
        errdefer self.memory.deinit();
        const allocator = self.memory.allocator();
        self.allocator = allocator;
        self.store = try kv.Store.initBounded(std.testing.allocator, path, 64 << 20, 1 << 20);
        errdefer self.store.deinit() catch unreachable;
        self.files = try @import("../db/file.zig").Storage.init(io, std.testing.allocator, path);
        errdefer self.files.deinit(io, std.testing.allocator) catch unreachable;
        self.db = EthDb.init(&self.store);
        self.bc = .{
            .cfg = @import("blockchain.zig").glamsterdam_devnet8_config,
            .io = io,
            .allocator = allocator,
            .eth_db = &self.db,
            .file_storage = &self.files,
            .shadow_branches = .init(true),
        };
        self.parent = self.bc.cfg.genesis_header;
        self.parent.number = 100;
        self.parent.slot_number = 20;
        self.parent.block_access_list_hash = @splat(0x44);
        self.parent.state_root = types.empty_root_hash;
        {
            var owned: kv.OwnedTransaction = .{ .txn = try self.store.transaction_rw() };
            defer owned.deinit();
            try branches.initialize(&self.store, owned.txn, allocator, self.parent);
            try snapshots_db.writeCheckpoint(&self.store, owned.txn, allocator, self.parent);
            try owned.commit();
        }
        self.snapshots = .{ .io = io, .store = &self.store };
        errdefer self.snapshots.deinit();
        try self.snapshots.publish(allocator);

        // The BAL creates a real account; parity is not merely an empty root.
        var account = types.EmptyAccount;
        account.balance = 20;
        account.nonce = 1;
        var accounts = @import("../trie/account_trie.zig").AccountTrie.init(allocator);
        try accounts.updateUnsorted(&.{types.keccakOfU160(1)}, &.{account});
        var balances = [_]types.BalanceChange{.{ .index = 1, .balance = 20 }};
        var nonces = [_]types.NonceChange{.{ .index = 1, .nonce = 1 }};
        var bal = [_]types.AccountChanges{.{
            .addr = 1,
            .storage_changes = &.{},
            .storage_reads = &.{},
            .balance_changes = &balances,
            .nonce_changes = &nonces,
            .code_changes = &.{},
        }};
        var encoded = std.array_list.Managed(u8).init(allocator);
        try rlp.serialize(types.BlockAccessLists, allocator, &bal, &encoded);
        self.bal_bytes = if (empty_bal) &.{0xc0} else encoded.items;
        self.child = self.parent;
        self.child.number += 1;
        self.child.slot_number = 21;
        self.child.parent_hash = self.parent.hash();
        self.child.state_root = if (empty_bal) types.empty_root_hash else try accounts.rootHash();
        std.crypto.hash.sha3.Keccak256.hash(self.bal_bytes, &self.child.block_access_list_hash.?, .{});

        self.eth_provider = try eth.Provider.init(allocator);
        self.snap_provider = try snap.Provider.init(allocator);
        self.downloader = try Downloader.init(io, allocator, &self.bc, &self.db, &self.eth_provider, &self.snap_provider);
        self.downloader.shadow_snapshots = &self.snapshots;
        self.downloader.consensus_anchor = .{ .beacon_root = @splat(8), .execution_hash = self.parent.hash(), .slot = 20 };
        self.downloader.consensus_update = .{
            .anchor = self.downloader.consensus_anchor.?,
            .head = .{ .hash = self.child.hash(), .slot = 21 },
            .observed_at_ms = 0,
        };
        self.updates = .init(&self.updates_storage);
        self.downloader.consensus_updates = &self.updates;
        try self.downloader.selectConsensusTarget(self.child);
        try std.testing.expectEqual(self.child.hash(), (try self.bc.head()).hash);
        try std.testing.expectEqual(self.parent.hash(), self.snapshots.status().headers[0].hash());
        try std.testing.expect(self.downloader.inflight_eth_requests.empty());

        self.server = undefined;
        self.server.allocator = allocator;
        self.server.io = io;
        self.server.write_queue_buf = &self.writes;
        self.server.write_queue = .init(&self.writes);
        self.write_slots = @splat(.init(32));
        self.server.free_write_queue_slots = &self.write_slots;
        self.peer_slots = @splat(.{});
        self.server.slots = &self.peer_slots;
        self.eth_provider.server = &self.server;
        self.enablePeer(old_peer, 0, self.child.number);
        self.enablePeer(alternate, 0, self.child.number);
        // Deterministic synthetic tick times remain in the recent past, so
        // real response RTT observation never receives a future sent_at.
        self.sent_at = .fromNanoseconds(std.Io.Clock.now(.real, io).nanoseconds - 10 * std.time.ns_per_s);
        self.hashes = .{self.child.hash()};
        self.downloader.state_heal = .{
            .next_pivot = self.child,
            .target_pivot = self.child,
            .start_number = self.parent.number,
            .started_at = self.sent_at,
            .bal_requested = true,
        };
        self.request = self.downloader.free_eth_requests.pop().?;
        self.request.* = .{
            .id = 700,
            .peer = old_peer,
            .msg = .{ .get_block_access_list = .{ .id = 700, .hashes = &self.hashes } },
            .sent_at = self.sent_at,
            .deadline = self.sent_at.addDuration(.fromSeconds(60)),
        };
        self.downloader.inflight_eth_requests.push(self.request);
    }

    fn deinit(self: *@This()) void {
        self.downloader.task_group.cancel(std.testing.io);
        // A failed assertion may leave a completed worker result unconsumed.
        var result: ValidatedResponse = undefined;
        while ((self.downloader.validated_responses.get(std.testing.io, (&result)[0..1], 0) catch unreachable) != 0)
            result.deinit(self.allocator);
        _ = self.drainWrites() catch unreachable;
        self.snapshots.deinit();
        self.files.deinit(std.testing.io, std.testing.allocator) catch unreachable;
        self.store.deinit() catch unreachable;
        self.memory.deinit();
    }

    fn enablePeer(self: *@This(), peer: rlpx.Server.PeerId, earliest: u64, latest: u64) void {
        self.eth_provider.peers[peer.peer_index].info.store(.{ .epoch = peer.peer_epoch, .offset = 16 }, .release);
        self.downloader.peer_ranges[peer.peer_index] = .{
            .id = peer,
            .range = .{ .earliest_block = earliest, .latest_block = latest, .latest_block_hash = self.child.hash() },
        };
    }

    fn tick(self: *@This(), elapsed_ns: i96) void {
        self.downloader.retryNearHeadBal(&self.eth_provider, .fromNanoseconds(self.sent_at.nanoseconds + elapsed_ns));
    }

    fn takeWrite(self: *@This()) !?BalRetryTestWrite {
        var write: BalRetryTestWrite = undefined;
        return if (try self.server.write_queue.get(std.testing.io, (&write)[0..1], 0) == 0) null else write;
    }

    fn releaseWrite(self: *@This(), write: BalRetryTestWrite) void {
        self.allocator.free(write.payload);
        self.server.releaseWriteQueueSlot(write.peer_id.peer_index);
    }

    fn drainWrites(self: *@This()) !usize {
        var count: usize = 0;
        while (try self.takeWrite()) |write| {
            self.releaseWrite(write);
            count += 1;
        }
        return count;
    }

    fn expectOriginal(self: *@This(), original: Request(eth.Message)) !void {
        try std.testing.expectEqualDeep(original, self.request.*);
        try std.testing.expectEqual(1, self.downloader.inflight_eth_requests.inner.len());
        try std.testing.expect(self.downloader.pending_eth_requests.empty());
        try std.testing.expect(self.downloader.validating_eth_requests.empty());
    }

    fn deliver(self: *@This(), peer: rlpx.Server.PeerId, id: u64, values: []const []const u8) !bool {
        const values_rlp = try self.allocator.alloc(rlp.RawValue, values.len);
        defer self.allocator.free(values_rlp);
        for (values_rlp, values) |*value, bytes| value.* = .{ .value = bytes };
        var encoded = std.array_list.Managed(u8).init(self.allocator);
        defer encoded.deinit();
        try rlp.serialize(eth.BlockAccessLists, self.allocator, .{ .request_id = id, .rlps = values_rlp }, &encoded);
        return self.deliverFrame(peer, @backingInt(eth.MessageId.block_access_list), encoded.items);
    }

    fn deliverFrame(self: *@This(), peer: rlpx.Server.PeerId, message_id: u8, bytes: []const u8) !bool {
        const payload = try self.memory.frame(bytes);
        try self.eth_provider.queue.putOne(std.testing.io, .{ .peer = peer, .id = message_id, .payload = payload });
        const received = self.eth_provider.next(std.testing.io, self.downloader.eth_arena.allocator(), self.allocator) catch |err| {
            _ = self.downloader.eth_arena.reset(.{ .retain_with_limit = arena_retain_limit });
            return err; // Provider.next already freed the failed frame.
        };
        if (received.msg == .block_access_list) for (received.msg.block_access_list.rlps) |raw| {
            // The real decoder returns borrowed slices into this owned frame.
            try std.testing.expect(@intFromPtr(raw.value.ptr) >= @intFromPtr(payload.ptr));
            try std.testing.expect(@intFromPtr(raw.value.ptr) + raw.value.len <= @intFromPtr(payload.ptr) + payload.len);
        };
        const matched = try self.downloader.handleEth(received);
        if (!matched) {
            self.allocator.free(payload);
            _ = self.downloader.eth_arena.reset(.{ .retain_with_limit = arena_retain_limit });
        }
        return matched;
    }

    fn finishValidation(self: *@This()) !void {
        const result = try self.downloader.validated_responses.getOne(std.testing.io);
        try self.downloader.handleValidated(result);
        try self.downloader.task_group.await(std.testing.io);
        var extra: ValidatedResponse = undefined;
        if (try self.downloader.validated_responses.get(std.testing.io, (&extra)[0..1], 0) != 0) {
            extra.deinit(self.allocator);
            return error.UnexpectedExtraValidationResult;
        }
        try std.testing.expect(self.downloader.validating_eth_requests.empty());
    }

    fn expectChildState(self: *@This(), old: snapshots_db.View) !void {
        const view = try self.snapshots.acquire(self.child.hash(), self.child.state_root);
        defer view.deinit();
        try std.testing.expectEqual(self.child.hash(), view.header.hash());
        const account = (try self.db.readAccount(view.txn, types.keccakOfU160(1))).?;
        try std.testing.expectEqual(@as(u256, 20), account.balance);
        try std.testing.expectEqual(@as(u64, 1), account.nonce);
        try std.testing.expectEqual(null, try self.db.readAccount(old.txn, types.keccakOfU160(1)));
        try std.testing.expectEqual(self.parent.hash(), old.header.hash());
        try std.testing.expectError(error.StateRootMismatch, self.snapshots.acquire(self.child.hash(), @splat(0xff)));
        try std.testing.expectEqual(null, self.downloader.state_heal);
    }
};

test "near-head BAL retry real queue exact threshold keeps original deadline and once after target changes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(std.testing.io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
    var f: BalRetryTestFixture = undefined;
    try f.init(arena.allocator(), path[0..length]);
    defer f.deinit();
    const original = f.request.*;

    f.tick(std.time.ns_per_s - 1);
    try f.expectOriginal(original);
    try std.testing.expectEqual(null, try f.takeWrite());
    // Normal range announcements may trail head by several blocks.
    f.downloader.peer_ranges[1].?.range.latest_block = f.child.number - 1;
    f.tick(std.time.ns_per_s);
    try f.expectOriginal(original);
    const hedge = f.downloader.state_heal.?.bal_hedge.?;
    try std.testing.expectEqual(BalRetryTestFixture.alternate, hedge.peer);
    try std.testing.expect(hedge.id != original.id);
    try std.testing.expectEqual(original.id, hedge.source_id);
    try std.testing.expectEqual(original.peer, hedge.source_peer);
    try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
    try std.testing.expectEqual(1, f.downloader.inflight_eth_requests.inner.len());
    const write = (try f.takeWrite()).?;
    defer f.releaseWrite(write);
    var hedged_message = original.msg.get_block_access_list;
    hedged_message.id = hedge.id;
    const expected, const expected_len = try rlpx.encodeMsg(arena.allocator(), 16 + 0x12, hedged_message, true);
    defer arena.allocator().free(expected);
    try std.testing.expectEqual(hedge.peer, write.peer_id);
    try std.testing.expectEqualSlices(u8, expected[0..expected_len], write.payload[0..write.payload_len]);
    f.tick(2 * std.time.ns_per_s);
    try std.testing.expectEqual(null, try f.takeWrite());

    // Actual CL retargeting fences the still-healing writer; it must not
    // replenish the old block's one-extra-attempt budget.
    const source_id = f.request.id;
    var sibling = f.child;
    sibling.beneficiary = @splat(0xbb);
    f.downloader.consensus_update.?.head.hash = sibling.hash();
    try f.downloader.selectConsensusTarget(sibling);
    try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.next_pivot.hash());
    try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.target_pivot.hash());
    try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
    while (try f.takeWrite()) |header_write| {
        defer f.releaseWrite(header_write);
        // RLPx message id is the one-byte RLP integer before compressed data.
        try std.testing.expectEqual(@as(u8, 16 + @backingInt(eth.MessageId.get_block_headers)), header_write.payload[0]);
    }
    var bal_requests: usize = 0;
    var current = f.downloader.inflight_eth_requests.inner.first;
    while (current) |node| : (current = node.next) {
        const req = &@as(*List(Request(eth.Message)).Node, @alignCast(@fieldParentPtr("node", node))).elem;
        if (req.msg == .get_block_access_list) {
            try std.testing.expectEqual(1, req.msg.get_block_access_list.hashes.len);
            try std.testing.expectEqual(f.child.hash(), req.msg.get_block_access_list.hashes[0]);
            bal_requests += 1;
        }
    }
    try std.testing.expectEqual(1, bal_requests);
    f.tick(3 * std.time.ns_per_s);
    try std.testing.expectEqual(source_id, f.request.id);
    try std.testing.expectEqual(original.deadline, f.request.deadline);
    try std.testing.expectEqual(hedge, f.downloader.state_heal.?.bal_hedge.?);
    try std.testing.expectEqual(null, try f.takeWrite());
}

test "near-head BAL retry ineligible peers leave original completely intact" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(std.testing.io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
    var f: BalRetryTestFixture = undefined;
    try f.init(arena.allocator(), path[0..length]);
    defer f.deinit();
    const original = f.request.*;
    inline for (.{ "absent", "no_range", "stale_range", "behind", "pruned", "saturated" }) |reason| {
        f.enablePeer(BalRetryTestFixture.alternate, 0, f.child.number);
        var extra: [2]?*Request(eth.Message) = @splat(null);
        defer for (extra) |maybe| if (maybe) |req| {
            f.downloader.inflight_eth_requests.remove(req);
            f.downloader.free_eth_requests.push(req);
        };
        if (comptime std.mem.eql(u8, reason, "absent")) f.eth_provider.peers[1].info.store(.{ .epoch = 0, .offset = 0 }, .release);
        if (comptime std.mem.eql(u8, reason, "no_range")) f.downloader.peer_ranges[1] = null;
        if (comptime std.mem.eql(u8, reason, "stale_range")) f.downloader.peer_ranges[1].?.id.peer_epoch += 1;
        if (comptime std.mem.eql(u8, reason, "behind")) f.downloader.peer_ranges[1].?.range.latest_block = f.child.number - bal_announced_height_gap - 1;
        if (comptime std.mem.eql(u8, reason, "pruned")) f.downloader.peer_ranges[1].?.range.earliest_block = f.child.number + 1;
        if (comptime std.mem.eql(u8, reason, "saturated")) for (&extra) |*entry| {
            const req = f.downloader.free_eth_requests.pop().?;
            req.* = original;
            req.peer = BalRetryTestFixture.alternate;
            req.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .number = 1 }, .amount = 1 } } };
            f.downloader.inflight_eth_requests.push(req);
            entry.* = req;
        };
        f.tick(std.time.ns_per_s);
        try std.testing.expectEqualDeep(original, f.request.*);
        try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_early_retry_hash);
        try std.testing.expectEqual(null, try f.takeWrite());
    }
    // No-candidate observations do not permanently disable a later candidate.
    f.enablePeer(BalRetryTestFixture.alternate, 0, f.child.number);
    f.tick(2 * std.time.ns_per_s);
    try std.testing.expectEqual(1, try f.drainWrites());
}

test "near-head BAL retry bounded queue failure retains original and spends budget" {
    inline for (.{ "peer_slots", "global_queue" }) |reason| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var dir = std.testing.tmpDir(.{});
        defer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
        var f: BalRetryTestFixture = undefined;
        try f.init(arena.allocator(), path[0..length]);
        defer f.deinit();
        const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
        defer old.deinit();
        const original = f.request.*;
        if (comptime std.mem.eql(u8, reason, "peer_slots")) {
            f.write_slots[1].store(8, .release);
        } else {
            for (0..f.writes.len) |_| {
                try f.server.reserveWriteQueueSlot(1, 8);
                const filler: BalRetryTestWrite = .{ .peer_id = BalRetryTestFixture.alternate, .payload = try arena.allocator().alloc(u8, 0), .payload_len = 0 };
                try std.testing.expectEqual(1, try f.server.write_queue.put(std.testing.io, &.{filler}, 0));
            }
        }
        f.tick(std.time.ns_per_s);
        try f.expectOriginal(original);
        try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
        try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_hedge);
        try std.testing.expectEqual(if (comptime std.mem.eql(u8, reason, "peer_slots")) @as(usize, 0) else f.writes.len, try f.drainWrites());
        f.write_slots[1].store(32, .release);
        f.tick(2 * std.time.ns_per_s);
        try f.expectOriginal(original);
        try std.testing.expectEqual(null, try f.takeWrite());
        try std.testing.expect(try f.deliver(original.peer, original.id, &.{f.bal_bytes}));
        try f.finishValidation();
        try f.expectChildState(old);
    }
}

test "near-head BAL retry original and alternate winners claim once with authentic state parity" {
    var final_hashes: [3][32]u8 = undefined;
    inline for (.{ "baseline", "original", "alternate" }, 0..) |winner, index| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var dir = std.testing.tmpDir(.{});
        defer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
        var f: BalRetryTestFixture = undefined;
        try f.init(arena.allocator(), path[0..length]);
        defer f.deinit();
        const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
        defer old.deinit();
        const original = f.request.*;
        var accepted_id = original.id;
        var accepted_peer = original.peer;
        var loser_id: ?u64 = null;
        var loser_peer: rlpx.Server.PeerId = undefined;
        if (comptime !std.mem.eql(u8, winner, "baseline")) {
            f.tick(std.time.ns_per_s);
            try std.testing.expectEqual(1, try f.drainWrites());
            const hedge = f.downloader.state_heal.?.bal_hedge.?;
            try f.expectOriginal(original);
            try std.testing.expect(!try f.deliver(original.peer, hedge.id, &.{f.bal_bytes}));
            try std.testing.expect(!try f.deliver(hedge.peer, original.id, &.{f.bal_bytes}));
            var wrong_epoch = hedge.peer;
            wrong_epoch.peer_epoch += 1;
            try std.testing.expect(!try f.deliver(wrong_epoch, hedge.id, &.{f.bal_bytes}));
            try std.testing.expect(!try f.deliver(f.request.peer, f.request.id + 900, &.{f.bal_bytes}));
            try std.testing.expectEqual(1, f.downloader.inflight_eth_requests.inner.len());
            try std.testing.expect(f.downloader.validating_eth_requests.empty());
            try std.testing.expectError(error.StateViewUnavailable, f.snapshots.acquire(f.child.hash(), f.child.state_root));
            if (comptime std.mem.eql(u8, winner, "alternate")) {
                accepted_id = hedge.id;
                accepted_peer = hedge.peer;
                loser_id = original.id;
                loser_peer = original.peer;
            } else {
                loser_id = hedge.id;
                loser_peer = hedge.peer;
            }
        }
        try std.testing.expect(try f.deliver(accepted_peer, accepted_id, &.{f.bal_bytes}));
        try std.testing.expectEqual(original.deadline, f.request.deadline);
        try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_hedge);
        try std.testing.expectEqual(1, f.downloader.validating_eth_requests.inner.len());
        if (loser_id) |id| try std.testing.expect(!try f.deliver(loser_peer, id, &.{f.bal_bytes}));
        try f.finishValidation();
        try f.expectChildState(old);
        try std.testing.expect(!try f.deliver(accepted_peer, accepted_id, &.{f.bal_bytes}));
        if (loser_id) |id| try std.testing.expect(!try f.deliver(loser_peer, id, &.{f.bal_bytes}));
        try std.testing.expectEqual(16, f.eth_provider.peers[0].info.load(.acquire).offset);
        try std.testing.expectEqual(16, f.eth_provider.peers[1].info.load(.acquire).offset);
        try std.testing.expectEqual(max_inflight_requests, f.downloader.free_eth_requests.inner.len());
        final_hashes[index] = f.snapshots.status().headers[0].hash();
    }
    try std.testing.expectEqual(final_hashes[0], final_hashes[1]);
    try std.testing.expectEqual(final_hashes[0], final_hashes[2]);
}

test "near-head BAL retry cannot reclaim an actual asynchronous validating request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(std.testing.io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
    var f: BalRetryTestFixture = undefined;
    try f.init(arena.allocator(), path[0..length]);
    defer f.deinit();
    const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
    defer old.deinit();
    const original = f.request.*;
    try std.testing.expect(try f.deliver(original.peer, original.id, &.{f.bal_bytes}));
    try std.testing.expect(f.downloader.inflight_eth_requests.empty());
    try std.testing.expectEqual(1, f.downloader.validating_eth_requests.inner.len());
    // Even a completed worker remains validation-owned until the owner takes
    // its queued result. No sleep or production test hook is necessary.
    f.tick(std.time.ns_per_s);
    f.downloader.cancelHeaderRequests(.chain);
    try std.testing.expectEqualDeep(original, f.request.*);
    try std.testing.expectEqual(1, f.downloader.validating_eth_requests.inner.len());
    try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_early_retry_hash);
    try std.testing.expectEqual(null, try f.takeWrite());
    try std.testing.expectError(error.StateViewUnavailable, f.snapshots.acquire(f.child.hash(), f.child.state_root));
    try std.testing.expect(!try f.deliver(original.peer, original.id, &.{f.bal_bytes}));
    try f.finishValidation();
    try f.expectChildState(old);
}

test "near-head BAL retry empty alternate retains original and authentic state" {
    inline for (.{ false, true }) |placeholder| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var dir = std.testing.tmpDir(.{});
        defer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
        var f: BalRetryTestFixture = undefined;
        try f.init(arena.allocator(), path[0..length]);
        defer f.deinit();
        const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
        defer old.deinit();
        const original = f.request.*;
        f.tick(std.time.ns_per_s);
        try std.testing.expectEqual(1, try f.drainWrites());
        const hedge = f.downloader.state_heal.?.bal_hedge.?;

        // A lagging alternate has no BAL yet. Do not consume the original's
        // response ownership or open a validation task for this empty frame.
        try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, if (placeholder) &.{&.{0x80}} else &.{}));
        try f.expectOriginal(original);
        try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_hedge);
        try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
        try std.testing.expectEqual(max_inflight_requests - 1, f.downloader.free_eth_requests.inner.len());
        try std.testing.expectError(error.StateViewUnavailable, f.snapshots.acquire(f.child.hash(), f.child.state_root));
        try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
        f.tick(2 * std.time.ns_per_s);
        try f.expectOriginal(original);
        try std.testing.expectEqual(null, try f.takeWrite());
        try std.testing.expect(try f.deliver(original.peer, original.id, &.{f.bal_bytes}));
        try std.testing.expectEqual(original.deadline, f.request.deadline);
        try f.finishValidation();
        try f.expectChildState(old);
        try std.testing.expectEqual(max_inflight_requests, f.downloader.free_eth_requests.inner.len());
        try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
    }
}

test "near-head BAL retry empty original retains alternate with original deadline and authentic state" {
    inline for (.{ false, true }) |placeholder| {
        inline for (.{ "valid", "timeout" }) |outcome| {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            var dir = std.testing.tmpDir(.{});
            defer dir.cleanup();
            try dir.dir.createDir(std.testing.io, "db", .default_dir);
            var path: [1024]u8 = undefined;
            const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
            var f: BalRetryTestFixture = undefined;
            try f.init(arena.allocator(), path[0..length]);
            defer f.deinit();
            const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
            defer old.deinit();
            if (comptime std.mem.eql(u8, outcome, "timeout")) f.request.deadline = f.sent_at.addDuration(.fromSeconds(5));
            const original = f.request.*;
            f.tick(std.time.ns_per_s);
            try std.testing.expectEqual(1, try f.drainWrites());
            const hedge = f.downloader.state_heal.?.bal_hedge.?;

            // Keep the already-sent alternate on the same pooled node. A new
            // regular reissue would discard useful work and extend the timeout.
            try std.testing.expect(!try f.deliver(original.peer, original.id, if (placeholder) &.{&.{0x80}} else &.{}));
            var promoted = original;
            promoted.id = hedge.id;
            promoted.msg.get_block_access_list.id = hedge.id;
            promoted.peer = hedge.peer;
            promoted.sent_at = hedge.sent_at;
            try f.expectOriginal(promoted);
            try std.testing.expectEqual(original.deadline, f.request.deadline);
            try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_hedge);
            try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
            try std.testing.expectEqual(max_inflight_requests - 1, f.downloader.free_eth_requests.inner.len());
            try std.testing.expectError(error.StateViewUnavailable, f.snapshots.acquire(f.child.hash(), f.child.state_root));
            try std.testing.expect(!try f.deliver(original.peer, original.id, &.{}));
            try std.testing.expect(!try f.deliver(original.peer, original.id, &.{f.bal_bytes}));
            var wrong_epoch = hedge.peer;
            wrong_epoch.peer_epoch += 1;
            try std.testing.expect(!try f.deliver(wrong_epoch, hedge.id, &.{f.bal_bytes}));
            f.tick(2 * std.time.ns_per_s);
            try f.expectOriginal(promoted);
            try std.testing.expectEqual(null, try f.takeWrite());

            if (comptime std.mem.eql(u8, outcome, "timeout")) {
                f.downloader.checkRequestTimeouts(eth.Message, &f.downloader.inflight_eth_requests, &f.downloader.pending_eth_requests, &f.eth_provider);
                try std.testing.expect(f.downloader.inflight_eth_requests.empty());
                try std.testing.expectEqual(1, f.downloader.pending_eth_requests.inner.len());
                try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_hedge);
                // The expired alternate cannot reclaim the pending source; the
                // normal handleEth path drains one ordinary reissue instead.
                try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
                try std.testing.expectEqual(1, try f.drainWrites());
                try std.testing.expect(f.request.id != original.id and f.request.id != hedge.id);
                const reissued = f.request.*;
                try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
                f.downloader.retryNearHeadBal(&f.eth_provider, reissued.sent_at.addDuration(.fromSeconds(2)));
                try f.expectOriginal(reissued);
                try std.testing.expectEqual(null, try f.takeWrite());
            }
            try std.testing.expect(try f.deliver(f.request.peer, f.request.id, &.{f.bal_bytes}));
            try f.finishValidation();
            try f.expectChildState(old);
            try std.testing.expectEqual(max_inflight_requests, f.downloader.free_eth_requests.inner.len());
            try std.testing.expect(!try f.deliver(original.peer, original.id, &.{f.bal_bytes}));
        }
    }
}

test "near-head BAL retry budget survives empty wrong-commitment and normal-timeout reissues" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(std.testing.io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
    var f: BalRetryTestFixture = undefined;
    try f.init(arena.allocator(), path[0..length]);
    defer f.deinit();
    const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
    defer old.deinit();
    f.tick(std.time.ns_per_s);
    try std.testing.expectEqual(1, try f.drainWrites());
    // Both peers can lack the BAL. Once the alternate has answered empty,
    // the original empty response must retain the ordinary reissue behavior.
    const hedge = f.downloader.state_heal.?.bal_hedge.?;
    try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, &.{}));
    inline for (.{ "empty", "wrong_commitment" }) |reason| {
        const id = f.request.id;
        if (comptime std.mem.eql(u8, reason, "empty")) {
            try std.testing.expect(try f.deliver(f.request.peer, id, &.{}));
        } else {
            try std.testing.expect(try f.deliver(f.request.peer, id, &.{&.{0xc0}}));
        }
        try f.finishValidation();
        try std.testing.expect(f.request.id != id);
        try std.testing.expectEqual(1, try f.drainWrites()); // existing regular reissue
        try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
        try std.testing.expectError(error.StateViewUnavailable, f.snapshots.acquire(f.child.hash(), f.child.state_root));
        const current = f.request.*;
        f.downloader.retryNearHeadBal(&f.eth_provider, current.sent_at.addDuration(.fromSeconds(2)));
        try f.expectOriginal(current);
        try std.testing.expectEqual(null, try f.takeWrite());
    }
    const before_timeout = f.request.id;
    f.request.deadline = .fromNanoseconds(std.Io.Clock.now(.real, std.testing.io).nanoseconds - std.time.ns_per_ms);
    f.downloader.checkRequestTimeouts(eth.Message, &f.downloader.inflight_eth_requests, &f.downloader.pending_eth_requests, &f.eth_provider);
    f.downloader.drainPendingEthRequests();
    try std.testing.expect(f.request.id != before_timeout);
    try std.testing.expectEqual(1, try f.drainWrites());
    const after_timeout = f.request.*;
    f.downloader.retryNearHeadBal(&f.eth_provider, after_timeout.sent_at.addDuration(.fromSeconds(2)));
    try f.expectOriginal(after_timeout);
    try std.testing.expectEqual(null, try f.takeWrite());
    try std.testing.expect(try f.deliver(f.request.peer, f.request.id, &.{f.bal_bytes}));
    try f.finishValidation();
    try f.expectChildState(old);
}

test "near-head BAL retry stays out of bootstrap batches non-BAL and expired work" {
    inline for (.{ "no_cl", "no_snapshots", "no_verified_checkpoint", "no_heal", "multi_block", "multi_hash", "sibling_target", "not_requested", "applied", "wrong_hash", "header", "expired" }) |reason| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var dir = std.testing.tmpDir(.{});
        defer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
        var f: BalRetryTestFixture = undefined;
        try f.init(arena.allocator(), path[0..length]);
        defer f.deinit();
        var batch = [_][32]u8{ f.child.hash(), @splat(0xaa) };
        if (comptime std.mem.eql(u8, reason, "no_cl")) f.downloader.consensus_updates = null;
        if (comptime std.mem.eql(u8, reason, "no_snapshots")) f.downloader.shadow_snapshots = null;
        if (comptime std.mem.eql(u8, reason, "no_verified_checkpoint")) f.snapshots.deinit();
        if (comptime std.mem.eql(u8, reason, "no_heal")) f.downloader.state_heal = null;
        if (comptime std.mem.eql(u8, reason, "multi_block")) f.downloader.state_heal.?.target_pivot.number += 1;
        if (comptime std.mem.eql(u8, reason, "multi_hash")) f.request.msg.get_block_access_list.hashes = &batch;
        if (comptime std.mem.eql(u8, reason, "sibling_target")) f.downloader.state_heal.?.target_pivot.beneficiary = @splat(0xdd);
        if (comptime std.mem.eql(u8, reason, "not_requested")) f.downloader.state_heal.?.bal_requested = false;
        if (comptime std.mem.eql(u8, reason, "applied")) f.downloader.state_heal.?.bal_applied = true;
        if (comptime std.mem.eql(u8, reason, "wrong_hash")) f.hashes[0] = @splat(0xaa);
        if (comptime std.mem.eql(u8, reason, "header")) f.request.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .hash = f.child.hash() }, .amount = 1 } } };
        if (comptime std.mem.eql(u8, reason, "expired")) f.request.deadline = f.sent_at.addDuration(.fromSeconds(1));
        const original = f.request.*;
        f.tick(std.time.ns_per_s);
        try f.expectOriginal(original);
        if (f.downloader.state_heal) |heal| try std.testing.expectEqual(null, heal.bal_early_retry_hash);
        try std.testing.expectEqual(null, try f.takeWrite());
    }
}

test "near-head BAL retry accepts bounded stale range announcements" {
    inline for (.{ 1, 16, 31, 32 }) |lag| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var dir = std.testing.tmpDir(.{});
        defer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
        var f: BalRetryTestFixture = undefined;
        try f.init(arena.allocator(), path[0..length]);
        defer f.deinit();
        const original = f.request.*;
        f.downloader.peer_ranges[1].?.range.latest_block = f.child.number - lag;
        f.tick(std.time.ns_per_s);
        try f.expectOriginal(original);
        try std.testing.expectEqual(BalRetryTestFixture.alternate, f.downloader.state_heal.?.bal_hedge.?.peer);
        try std.testing.expectEqual(1, try f.drainWrites());
    }
}

test "near-head BAL retry alias consumes peer capacity and original timeout fences late alternate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(std.testing.io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
    var f: BalRetryTestFixture = undefined;
    try f.init(arena.allocator(), path[0..length]);
    defer f.deinit();
    const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
    defer old.deinit();
    // Hedge at synthetic t+1s; original deadline t+5s is in the real past.
    // The ordinary timeout below must fire at that exact original budget.
    f.request.deadline = f.sent_at.addDuration(.fromSeconds(5));
    const original = f.request.*;
    f.tick(std.time.ns_per_s);
    try f.expectOriginal(original);
    try std.testing.expectEqual(1, try f.drainWrites());
    const hedge = f.downloader.state_heal.?.bal_hedge.?;
    var filter = PeerFilter(eth.Message).init(&f.downloader, &f.downloader.inflight_eth_requests, null);
    try std.testing.expect(filter.validPeer(hedge.peer)); // one of two slots
    const other = f.downloader.free_eth_requests.pop().?;
    other.* = original;
    other.id += 1;
    other.peer = hedge.peer;
    other.msg = .{ .get_block_headers = .{ .range = .{ .origin = .{ .number = 1 }, .amount = 1 } } };
    f.downloader.inflight_eth_requests.push(other);
    filter = PeerFilter(eth.Message).init(&f.downloader, &f.downloader.inflight_eth_requests, null);
    try std.testing.expect(!filter.validPeer(hedge.peer)); // hedge plus ordinary
    var next_epoch = hedge.peer;
    next_epoch.peer_epoch += 1;
    try std.testing.expect(filter.validPeer(next_epoch)); // old connection accounting cannot leak
    f.downloader.inflight_eth_requests.remove(other);
    f.downloader.free_eth_requests.push(other);

    f.downloader.checkRequestTimeouts(eth.Message, &f.downloader.inflight_eth_requests, &f.downloader.pending_eth_requests, &f.eth_provider);
    try std.testing.expect(f.downloader.inflight_eth_requests.empty());
    try std.testing.expectEqual(1, f.downloader.pending_eth_requests.inner.len());
    try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_hedge);
    try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
    // An obsolete alternate cannot revive a pending owner; handleEth then
    // drains the existing normal reissue, as in the real event loop.
    try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
    try std.testing.expectEqual(1, try f.drainWrites());
    try std.testing.expect(f.request.id != original.id and f.request.id != hedge.id);
    const reissued = f.request.*;
    try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
    try std.testing.expect(!try f.deliver(original.peer, original.id, &.{f.bal_bytes}));
    f.downloader.retryNearHeadBal(&f.eth_provider, reissued.sent_at.addDuration(.fromSeconds(2)));
    try f.expectOriginal(reissued);
    try std.testing.expectEqual(null, try f.takeWrite());
    try std.testing.expect(try f.deliver(reissued.peer, reissued.id, &.{f.bal_bytes}));
    try f.finishValidation();
    try f.expectChildState(old);
}

test "near-head BAL retry stale alias cannot attach to a newer request for the same hash" {
    inline for (.{ false, true }) |empty| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var dir = std.testing.tmpDir(.{});
        defer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
        var f: BalRetryTestFixture = undefined;
        try f.init(arena.allocator(), path[0..length]);
        defer f.deinit();
        const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
        defer old.deinit();
        f.tick(std.time.ns_per_s);
        try std.testing.expectEqual(1, try f.drainWrites());
        const hedge = f.downloader.state_heal.?.bal_hedge.?;
        // Deliberately leave an obsolete alias while the same pooled node has
        // a newer request identity. This tests defensive cleanup independently
        // of the normal timeout path, which already clears the alias itself.
        f.request.id += 71;
        f.request.msg.get_block_access_list.id = f.request.id;
        f.request.peer = hedge.peer;
        const current = f.request.*;
        var filter = PeerFilter(eth.Message).init(&f.downloader, &f.downloader.inflight_eth_requests, null);
        try std.testing.expect(filter.validPeer(hedge.peer)); // stale source is already uncharged
        try std.testing.expect(!try f.deliver(hedge.peer, hedge.id, if (empty) &.{} else &.{f.bal_bytes}));
        try f.expectOriginal(current);
        try std.testing.expectEqual(null, f.downloader.state_heal.?.bal_hedge);
        try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.bal_early_retry_hash.?);
        filter = PeerFilter(eth.Message).init(&f.downloader, &f.downloader.inflight_eth_requests, null);
        try std.testing.expect(filter.validPeer(hedge.peer));
        f.tick(2 * std.time.ns_per_s);
        try std.testing.expectEqual(null, try f.takeWrite());
        try std.testing.expect(try f.deliver(current.peer, current.id, &.{f.bal_bytes}));
        try f.finishValidation();
        try f.expectChildState(old);
    }
}

test "near-head BAL retry production heal and timeout driver dispatch a bounded hedge" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(std.testing.io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
    var f: BalRetryTestFixture = undefined;
    try f.init(arena.allocator(), path[0..length]);
    defer f.deinit();
    const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
    defer old.deinit();
    // Keep the real authenticated target/checkpoint selected by the fixture,
    // but discard its synthetic request/heal. The production catch-up driver
    // must create both. Ancestor prefetch is unrelated to this direct child.
    f.downloader.inflight_eth_requests.remove(f.request);
    f.downloader.free_eth_requests.push(f.request);
    f.downloader.state_heal = null;
    f.downloader.ancestors_ready = f.parent.hash();
    try std.testing.expectEqual(f.parent.hash(), f.downloader.state.?.pivot.hash());
    try f.downloader.advanceShadowWork();
    try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.next_pivot.hash());
    try std.testing.expectEqual(f.child.hash(), f.downloader.state_heal.?.target_pivot.hash());
    try std.testing.expect(f.downloader.state_heal.?.bal_requested);
    try std.testing.expectEqual(1, f.downloader.inflight_eth_requests.inner.len());
    const node = f.downloader.inflight_eth_requests.inner.first.?;
    f.request = &@as(*List(Request(eth.Message)).Node, @alignCast(@fieldParentPtr("node", node))).elem;
    try std.testing.expectEqual(1, f.request.msg.get_block_access_list.hashes.len);
    try std.testing.expectEqual(f.child.hash(), f.request.msg.get_block_access_list.hashes[0]);
    const source_write = (try f.takeWrite()).?;
    defer f.releaseWrite(source_write);
    const expected, const expected_len = try rlpx.encodeMsg(arena.allocator(), 16 + 0x12, f.request.msg.get_block_access_list, true);
    defer arena.allocator().free(expected);
    try std.testing.expectEqual(f.request.peer, source_write.peer_id);
    try std.testing.expectEqualSlices(u8, expected[0..expected_len], source_write.payload[0..source_write.payload_len]);
    try std.testing.expectEqual(null, try f.takeWrite());
    // Only the send time is backdated. The actual sendRequest-assigned
    // deadline and real one-second owner callback are preserved.
    f.request.sent_at = std.Io.Clock.now(.real, std.testing.io).addDuration(.fromSeconds(-2));
    const original = f.request.*;
    try f.downloader.checkEthRequestTimeouts();
    // A production BAL request does not initialize unused SNAP-only fields.
    // Compare every field that defines its wire identity and ownership.
    try std.testing.expectEqualDeep(.{ original.id, original.peer, original.msg, original.sent_at, original.deadline }, .{ f.request.id, f.request.peer, f.request.msg, f.request.sent_at, f.request.deadline });
    try std.testing.expectEqual(1, f.downloader.inflight_eth_requests.inner.len());
    try std.testing.expect(f.downloader.pending_eth_requests.empty());
    try std.testing.expect(f.downloader.validating_eth_requests.empty());
    const hedge = f.downloader.state_heal.?.bal_hedge.?;
    try std.testing.expect(!std.meta.eql(original.peer, hedge.peer));
    const retry_write = (try f.takeWrite()).?;
    defer f.releaseWrite(retry_write);
    var retry_message = original.msg.get_block_access_list;
    retry_message.id = hedge.id;
    const retry_expected, const retry_expected_len = try rlpx.encodeMsg(arena.allocator(), 16 + 0x12, retry_message, true);
    defer arena.allocator().free(retry_expected);
    try std.testing.expectEqual(hedge.peer, retry_write.peer_id);
    try std.testing.expectEqualSlices(u8, retry_expected[0..retry_expected_len], retry_write.payload[0..retry_write.payload_len]);
    try f.downloader.checkEthRequestTimeouts();
    try std.testing.expectEqual(null, try f.takeWrite());
    try std.testing.expect(try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
    try f.finishValidation();
    try f.expectChildState(old);
    try std.testing.expectEqual(max_inflight_requests, f.downloader.free_eth_requests.inner.len());
}

test "near-head BAL retry real empty BAL remains available and validates on either identity" {
    inline for (.{ false, true }) |alternate_wins| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var dir = std.testing.tmpDir(.{});
        defer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
        var f: BalRetryTestFixture = undefined;
        try f.initWithEmptyBal(arena.allocator(), path[0..length], true);
        defer f.deinit();
        const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
        defer old.deinit();
        const original = f.request.*;
        f.tick(std.time.ns_per_s);
        try std.testing.expectEqual(1, try f.drainWrites());
        const hedge = f.downloader.state_heal.?.bal_hedge.?;
        try std.testing.expect(try f.deliver(if (alternate_wins) hedge.peer else original.peer, if (alternate_wins) hedge.id else original.id, &.{&.{0xc0}}));
        try std.testing.expectEqual(original.deadline, f.request.deadline);
        try std.testing.expectEqual(1, f.downloader.validating_eth_requests.inner.len());
        try f.finishValidation();
        const view = try f.snapshots.acquire(f.child.hash(), types.empty_root_hash);
        defer view.deinit();
        try std.testing.expectEqual(null, try f.db.readAccount(view.txn, types.keccakOfU160(1)));
        try std.testing.expectEqual(null, try f.db.readAccount(old.txn, types.keccakOfU160(1)));
        try std.testing.expectEqual(null, f.downloader.state_heal);
        try std.testing.expectEqual(max_inflight_requests, f.downloader.free_eth_requests.inner.len());
        try std.testing.expectEqual(null, try f.takeWrite());
    }
}

test "near-head BAL retry provider rejects malformed frames without consuming either request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.createDir(std.testing.io, "db", .default_dir);
    var path: [1024]u8 = undefined;
    const length = try dir.dir.realPathFile(std.testing.io, "db", &path);
    var f: BalRetryTestFixture = undefined;
    try f.init(arena.allocator(), path[0..length]);
    defer f.deinit();
    const old = try f.snapshots.acquire(f.parent.hash(), f.parent.state_root);
    defer old.deinit();
    const original = f.request.*;
    f.tick(std.time.ns_per_s);
    try std.testing.expectEqual(1, try f.drainWrites());
    const hedge = f.downloader.state_heal.?.bal_hedge.?;
    try std.testing.expectError(error.InvalidMessageId, f.deliverFrame(hedge.peer, 0xff, &.{0x80}));
    try std.testing.expectError(error.NotAnRLPList, f.deliverFrame(hedge.peer, @backingInt(eth.MessageId.block_access_list), &.{0x80}));
    try f.expectOriginal(original);
    try std.testing.expectEqual(hedge, f.downloader.state_heal.?.bal_hedge.?);
    try std.testing.expect(try f.deliver(hedge.peer, hedge.id, &.{f.bal_bytes}));
    try f.finishValidation();
    try f.expectChildState(old);
}
