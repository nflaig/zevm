// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded ETH/71 EIP-7594 version-1 framing, not KZG verification. Slices
//! borrow a complete peer frame; only the separately owned verifier can mark
//! the transaction ready. ETH/72 cells and legacy blob-proof wrappers differ.
const std = @import("std");
pub const max_signed_bytes: usize = 128 * 1024;
pub const max_wrapper_bytes: usize = 2 * 1024 * 1024;
pub const max_blobs = 6;
pub const bytes_per_blob = 131072;
pub const proofs_per_blob = 128;

pub const Wrapper = struct {
    signed_body: []const u8,
    hash: [32]u8,
    blob_count: usize,

    pub fn canonical(self: Wrapper, a: std.mem.Allocator) ![]const u8 {
        const bytes = try a.alloc(u8, self.signed_body.len + 1);
        bytes[0] = 3;
        @memcpy(bytes[1..], self.signed_body);
        return bytes;
    }
};

pub fn parse(raw: []const u8) !Wrapper {
    if (raw.len > max_wrapper_bytes) return error.TransactionByteLimit;
    if (raw.len < 2 or raw[0] != 3) return error.InvalidBlobWrapper;
    const outer = try exact(raw[1..], true);
    var fields = outer.payload;
    const signed = try take(&fields);
    if (!signed.list) return error.BlobSidecarRequired;
    if (signed.raw.len + 1 > max_signed_bytes) return error.TransactionByteLimit;
    const version = try take(&fields);
    if (version.list or !std.mem.eql(u8, version.payload, &.{1})) return error.UnsupportedBlobSidecarVersion;
    const blobs = try take(&fields);
    const commitments = try take(&fields);
    const proofs = try take(&fields);
    if (fields.len != 0 or !blobs.list or !commitments.list or !proofs.list) return error.InvalidBlobWrapper;

    // Validate every nested RLP item before the generic signed-body decoder.
    // This bounds access-list depth as well as the blob/hash/proof list arities.
    try tree(signed.raw, 0);
    var body = signed.payload;
    var hashes: View = undefined;
    for (0..14) |i| {
        const field = try take(&body);
        if (i == 8 or i == 10) {
            if (!field.list) return error.InvalidBlobTransaction;
            if (i == 10) hashes = field;
        } else if (field.list) return error.InvalidBlobTransaction;
        if (i == 5 and field.payload.len != 20) return error.InvalidBlobTransaction;
    }
    if (body.len != 0) return error.InvalidBlobTransaction;
    var remaining_hashes = hashes.payload;
    var remaining_blobs = blobs.payload;
    var remaining_commitments = commitments.payload;
    var remaining_proofs = proofs.payload;
    var count: usize = 0;
    while (remaining_hashes.len != 0) : (count += 1) {
        if (count == max_blobs) return error.TooManyBlobs;
        const expected = try take(&remaining_hashes);
        const blob = try take(&remaining_blobs);
        const commitment = try take(&remaining_commitments);
        if (expected.list or expected.payload.len != 32 or expected.payload[0] != 1 or
            blob.list or blob.payload.len != bytes_per_blob or commitment.list or commitment.payload.len != 48)
            return error.InvalidBlobSidecar;
        var versioned: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(commitment.payload, &versioned, .{});
        versioned[0] = 1;
        if (!std.mem.eql(u8, &versioned, expected.payload)) return error.BlobVersionedHashMismatch;
        for (0..proofs_per_blob) |_| {
            const proof = try take(&remaining_proofs);
            if (proof.list or proof.payload.len != 48) return error.InvalidBlobSidecar;
        }
    }
    if (count == 0 or remaining_blobs.len != 0 or remaining_commitments.len != 0 or remaining_proofs.len != 0)
        return error.InvalidBlobSidecar;
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(&.{3});
    hasher.update(signed.raw);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{ .signed_body = signed.raw, .hash = digest, .blob_count = count };
}

const View = struct { raw: []const u8, payload: []const u8, list: bool };
fn exact(bytes: []const u8, list: bool) !View {
    const field = try view(bytes);
    if (field.raw.len != bytes.len or field.list != list) return error.InvalidBlobWrapper;
    return field;
}
fn take(bytes: *[]const u8) !View {
    const field = try view(bytes.*);
    bytes.* = bytes.*[field.raw.len..];
    return field;
}
fn tree(bytes: []const u8, depth: u8) !void {
    if (depth > 8) return error.InvalidBlobTransaction;
    const field = try view(bytes);
    if (field.raw.len != bytes.len) return error.InvalidBlobTransaction;
    if (field.list) {
        var rest = field.payload;
        while (rest.len != 0) try tree((try take(&rest)).raw, depth + 1);
    }
}
fn view(bytes: []const u8) !View {
    if (bytes.len == 0) return error.InvalidBlobWrapper;
    const tag = bytes[0];
    if (tag < 0x80) return .{ .raw = bytes[0..1], .payload = bytes[0..1], .list = false };
    const list = tag >= 0xc0;
    const short: u8 = if (list) 0xc0 else 0x80;
    const long: u8 = if (list) 0xf7 else 0xb7;
    var offset: usize = 1;
    var len: usize = 0;
    if (tag <= long) {
        len = tag - short;
    } else {
        const width: usize = tag - long;
        if (width > @sizeOf(usize) or width >= bytes.len or bytes[1] == 0) return error.InvalidBlobWrapper;
        for (bytes[1 .. 1 + width]) |byte| len = (len << 8) | byte;
        if (len < 56) return error.NonCanonicalTransaction;
        offset += width;
    }
    if (len > bytes.len - offset) return error.InvalidBlobWrapper;
    if (!list and len == 1 and bytes[offset] < 0x80) return error.NonCanonicalTransaction;
    return .{ .raw = bytes[0 .. offset + len], .payload = bytes[offset .. offset + len], .list = list };
}
