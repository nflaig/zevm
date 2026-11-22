// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Primitive, receive-only public transaction handoff. This module deliberately
//! has no execution-engine types. A sink must copy bytes before returning true;
//! false means local backpressure and must not disconnect a shared sync peer.
pub const Hash = [32]u8;
pub const Peer = struct { index: usize, epoch: usize };
pub const Transaction = struct {
    hash: Hash,
    bytes: []const u8,
    peer: Peer,
    announced_at_ms: i64,
    received_at_ms: i64,
    frame_received_wall_ms: ?i64 = null,
};
pub const Sink = struct {
    context: *anyopaque,
    /// Called only for canonical ordinary transactions after ETH validation.
    /// This trusted in-process callback is not an authenticated wire protocol.
    accept: *const fn (*anyopaque, Transaction) bool,
};
