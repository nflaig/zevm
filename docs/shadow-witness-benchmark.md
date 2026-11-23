# Local authenticated witness benchmark

`shadow-witness-bench` isolates the allocation, proof and JSON costs of the shadow
witness endpoint. It creates its own temporary MDBX database and deletes that
directory on normal exit. It opens no network connection and accepts no external
database path. The fixture has 16 accounts and a contract with 128 nonzero storage
slots and three bytes of code. The parent hash/root remains fixed throughout.

Build with the pinned Zig 0.17 toolchain. From this checkout:

```sh
zig build test-shadow-witness-bench -Doptimize=debug
zig build test-shadow-witness-bench shadow-witness-bench -Doptimize=safe
./zig-out/bin/shadow-witness-bench --iterations 40 --warmup 3 > witness.jsonl
```

The correctness build step runs two repetitions with no warmup. CLI bounds are
1–1,000 measured repetitions and 0–50 warmups; defaults are 40 and 3. Keep stdout
JSONL and build diagnostics on separate files when capturing a build invocation.

The four request shapes are an absent account, a present account without storage,
one present storage slot, and the protocol maximum of 128 slots in one account.
For each shape, every repetition rotates the order of these modes:

| Mode | Measured work |
|---|---|
| `typed_fresh` | Allocate 16 MiB, direct `Shadow.read`, release backing |
| `typed_reused` | Fresh FBA over existing 16 MiB, direct `Shadow.read` |
| `witness_fresh` | Explicit original allocation/read/JSON-copy/release path |
| `witness_reused` | Same read/JSON-copy using existing bounded backing |
| `rpc_fresh` | `Server.handle`, request parsing and response envelope, original scratch lifetime |
| `rpc_reused` | Same complete JSON handler with reused scratch lifetime |
| `rpc_runtime` | Current `Shadow` handler registered with `Server.handle` |

The explicit fresh handler stays in the benchmark after the runtime changes, so
before/after comparisons do not require different fixture state or binaries.
The benchmark's reused handlers are single-threaded controls; `rpc_runtime`
includes whatever ownership/locking the runtime actually provides. All variants
call the same authenticated `Shadow.read`; none caches account values, proofs,
trie resolvers, DB leases or a mutable candidate. A new `FixedBufferAllocator`
starts at offset zero on each control call. Only its 16 MiB backing is reused.

Before measurement, the reference account and storage proofs are checked against
their roots using independently hashed proof-node maps. Account nonce/balance,
code hash/bytes, nonexistence and every storage value are checked against the
fixture inputs. Every warmup and measured result must then match the reference
JSON byte-for-byte, including the parent stamp and RPC envelope where applicable.
All modes emit the same witness Keccak digest for a given request shape. Any
mismatch exits with an error; there is no timing threshold or timing assertion.

Each measurement row reports min/median/p90/max/mean nanoseconds, request/witness
sizes, used scratch and the correctness digest. `usedScratchBytes` is the maximum
FBA end offset observed after a read, not a transient allocation high-water mark.
The explicit handlers
also time backing allocation, authenticated read, JSON serialization and backing
release. These phase fields are `null` for `rpc_runtime`, which is measured as a
whole without runtime instrumentation. Typed timing excludes JSON serialization
and equality checks, but includes fresh backing release. JSON and RPC modes
include their serialization; equality checks are outside all timing intervals.
The output arena retains capacity between calls, and warmups are excluded.
Phase timestamp calls themselves add overhead, especially for small reads. The
runtime handler has no phase instrumentation, so use the equally instrumented
fresh/reused control pair to isolate backing lifetime; do not subtract separately
measured medians to claim an exact JSON or mutex cost.

This is a warm, small, same-parent fixture. `Server.handle` includes JSON parsing,
dispatch and response construction but excludes HTTP, sockets, scheduling and
live DB/writer contention. It cannot establish live latency, mainnet throughput,
transaction arrival, bid competitiveness or concurrent workspace safety. Compare
the actual runtime mode with its controls, then qualify any change separately
on the isolated shadow process before making a deployment claim.

## Local qualification, 2026-11-21

Pinned Zig 0.17.0, ReleaseSafe, Intel Core i7-1360P, CPU 0 affinity; 40 measured
iterations and three warmups per shape/mode. Modes alternated within each
repetition. Median times below are milliseconds:

| Request | Typed fresh | Typed reused | RPC fresh control | RPC reused control | Current runtime RPC |
|---|---:|---:|---:|---:|---:|
| Absent account | 9.002 | 0.018 | 8.921 | 0.031 | 0.019 |
| Present account | 9.120 | 0.022 | 9.098 | 0.036 | 0.022 |
| One slot | 9.117 | 0.029 | 9.122 | 0.046 | 0.031 |
| 128 slots | 10.174 | 1.077 | 10.518 | 1.470 | 1.459 |

For the fresh absent-account RPC control, median backing allocation was 6.741 ms
and release 2.192 ms; the authenticated read was 0.019 ms. Thus backing lifetime
dominates this small-request fixture. The 128-slot authenticated read still takes
about 1.1 ms and emits a 222,622-byte witness, so large requests retain meaningful
proof and JSON work after reuse. Recorded scratch end offsets were 3,640, 4,032,
8,904 and 760,520 bytes for the four shapes, within the unchanged 16 MiB bound.

Debug and ReleaseSafe correctness runs each passed all 56 mode/repetition
comparisons, with the same four witness digests across build modes. The timing
run also passed all 1,204 comparisons, including warmups. No timing assertion was
used. The timed executable SHA256 was
`c2623f29a78a246b6e4d4bd2e4c152fc36826c9c212b9c745b1ea4f2fec43d26`.
The qualification workspace retains the full JSONL samples and a source manifest
for `shadow.zig`, `jsonrpc.zig`, `http.zig`, this benchmark and `build.zig`; those
sources were unchanged during the measured run. These results measure this local
fixture, independently of any later isolated runtime or production qualification.
Subsequent HTTP socket-cancellation handling is covered by the final node tests;
it does not alter the workspace or typed read implementation measured here.
