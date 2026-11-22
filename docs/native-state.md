# Native exact-parent state reader

`native_state` is an independent Zig module using RLP and MDBX, without the node,
execution engine or JSON-RPC. A constructor can keep its own pinned EVM version
and bridge account/header scalars and raw trie-node bytes explicitly.

The existing sync owner creates `Eth`, `Snapshots` and a stable-address `Reader`:

```zig
var reader: native.Reader = .{ .eth = &eth, .snapshots = &snapshots };
defer reader.deinit();
var lease = try reader.acquire(.{ .block_hash = hash, .state_root = root });
defer lease.deinit();
const account = try lease.readAccount(scratch, address);
const value = try lease.readStorage(scratch, address, slot);
const code = try lease.readCode(scratch, account.code_hash);
```

`acquire` only clones an already published, verified Gloas view. It does not open
the latest transaction under a caller-supplied old label. A lease survives writer
commits, reorgs and eviction from the eight-entry snapshot registry. The reader
admits at most 32 active leases; callers must also bound their duration, since a
long lease retains old database pages. Release every lease before closing its
reader, snapshots or database. Reader/store addresses must remain stable. Leases
are move-only and confined to one worker at a time, including during finalizing
or discarding candidate checkpoints that still need parent state.

Account and storage reads hash-check every resolved trie node, including leaves
reconstructed from flat state. They do not assemble a complete proof response.
Proven absence returns an empty account or zero; missing/corrupt trie data is an
error. Code is limited to 128 KiB and copied only after verifying its hash. The
caller obtains that hash from an authenticated account; an arbitrary valid code
hash does not authenticate an account. `readNode`/`readNodes` authenticate owner,
nibble path and expected hash for the finalizer; nodes are at most 1 KiB, paths
at most 64 nibbles and batches at most 16 nodes.

The traversal cache is explicitly disabled by default. Enable it on a lease
with `try lease.enableNodeCache(allocator, .{})`; that allocator must outlive the
lease. The default permits 4,096 path entries and 4 MiB of retained RLP. Hard
limits are 16,384 entries and 16 MiB of RLP per lease. Metadata is separately
bounded by the reserved hash-table capacity; `nodeCacheStats()` reports both
the occupied entries and reserved entry capacity, plus retained RLP bytes.

Entries authorize an exact `(owner, nibble path, expected hash)` within that
lease. The account root comes from its header, storage roots from authenticated
owner reads, and child edges only from decoded, hash-checked parent nodes.
Authorized edges can read one preimage directly; an unknown path still walks
from the authenticated root. A correct hash at an unreachable DB path grants
no access. Embedded nodes do not become independent hash references. Returned
RLP is always copied into caller scratch, including cache hits. Reorgs, writer
commits and registry eviction cannot change an existing lease's authorizations.

There is no eviction or cross-lease sharing. At either capacity bound, existing
entries remain usable and uncached work uses the original path. Actual allocator
errors propagate, while previously authenticated entries remain valid. Checks
for cancellation precede hits and authorization publication. Use
`.{ .max_bytes = 0 }` for authorization-only qualification: it skips repeated
root walks but fetches and verifies each node's bytes again. Separate counters
report hits, authorized reads, root-walk fallbacks, owner reads and capacity
misses; they count attempted work, not just successful operations. These modes
support matched measurements; enabling the cache alone is not evidence of a
payload or bid improvement.

`header` and `stamp` identify the leased state. `readAncestors` returns up to 256
owned inline headers. Only ancestor lookup may open a fresh read transaction to
use later immutable header backfill: it follows hashes from the leased parent
and verifies every height/hash, never a selected-height or latest-state lookup.

Every call uses caller-owned bounded scratch. Scalar values and headers own
their data; returned code and RLP are copied into the supplied allocator. No MDBX
cursor or borrowed database slice escapes. Reset scratch only after consuming or
retaining those bytes. Allocation/cancellation failures do not modify the parent
or close the lease. Reads check cancellation at operation boundaries and between
bounded batch items; synchronous MDBX access itself is not preempted mid-call.

`kv.Store.openReadOnly` supports an isolated constructor process opening an
existing database with no writer transaction, table creation or geometry/sync
changes. MDBX still updates reader lock bookkeeping. Use one environment per
path per process. Publish the currently committed verified checkpoint into that
process's registry and acquire its exact hash/root before the writer advances.
This cannot retrieve historical views that the process never retained, and is
not a replacement for a shared owner's lease service.

Processes sharing an MDBX lock file must use the same PID namespace. In Docker,
an isolated reader joins the writer with `--pid=container:<writer-id>` while its
network can remain disabled. A successful reconstruction is insufficient if
MDBX reports a lock error: stop the qualification, preserve diagnostics and
recover the isolated environment before retrying. Do not delete or replace a
lock file while an environment is open.

The build explicitly sets `MDBX_CHECKING=0`, retaining mandatory consistency
failure handling even though the dependency uses `MDBX_DEBUG=-1` to silence
routine logs. Without the override, fatal unlock failures can be logged and
execution can continue. The native suite checks the linked C library's actual
build options. See [qualification](mdbx-checking-qualification-20261122.json).

Run `zig build test-native-state -Doptimize=debug` and `-Doptimize=safe` with the
pinned compiler. Tests use a real temporary MDBX with writer changes, sibling
branches, retained leases, eviction, authenticated absence, corruption, bounded
admission, allocation failures, cancellation and read-only opens. No deployment
or performance improvement is implied by these correctness checks.
