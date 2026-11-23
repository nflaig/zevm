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
    /// Optional owning admission state. A copied ordinary job can later expire
    /// or fail; missing permits retry instead of retaining a peer-side tombstone.
    /// Query one hash only, with bounded work and no validation or state IO.
    status: ?*const fn (*anyopaque, Hash, i64) AdmissionStatus = null,
    blobs: ?BlobSink = null,
};

/// Queue admission is not availability. Only the owning verifier may report
/// ready after all ordered sidecars have passed KZG. Missing permits another
/// peer's response after a rejected/expired job; pending suppresses duplicate
/// verification work. All callbacks are bounded and must not perform KZG.
pub const AdmissionStatus = enum { missing, pending, ready };
pub const BlobStatus = AdmissionStatus;
pub const BlobSink = struct {
    context: *anyopaque,
    /// True only after trusted KZG settings have been prewarmed and while open.
    available: *const fn (*anyopaque) bool,
    /// bytes is the complete ETH/71 version-1 wrapper, hash is its signed tx hash.
    /// Copy before returning true. False is local backpressure, not peer fault.
    accept: *const fn (*anyopaque, Transaction) bool,
    status: *const fn (*anyopaque, Hash, i64) BlobStatus,
};
