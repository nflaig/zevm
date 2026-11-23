# Shadow state qualification

This opt-in prototype supplies authenticated account/storage/code witnesses for
an exact execution parent. It does not implement Engine API, accept private
transactions, or authorize use as a production execution client.

Build with Zig 0.17.0:

```sh
zig build zevm test-shadow-state -Doptimize=safe -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v3
zig build test-shadow-state -Doptimize=debug
zig build shadow-crash-probe -Doptimize=safe
python3 test/shadow_crash_test.py --probe ./zig-out/bin/shadow-crash-probe
```

Start in a fresh, dedicated directory with `--shadow-state`, independent peer
ports and localhost HTTP. The shadow DB defaults to a 16 GiB maximum with 256 MiB
growth. `--shadow-state-max-db-gib <1..128>` admits a larger or smaller explicit
cap only with `--shadow-state`; it never grows automatically beyond that cap.
An existing `mdbx.dat` larger than the requested cap is refused before opening
MDBX. The configured cap and actual geometry are logged on startup. This bounds
the MDBX data file, including trie/code tables and copy-on-write history; it does
not bound process RAM, static header files or logs. A map-full transaction aborts
without publishing a partial checkpoint. A real MDBX regression fills a small
map, preserves its previous root and retained lease, rejects a smaller reopen,
and verifies recovery after a larger explicit cap is admitted.
Lowering a previously configured upper bound is allowed only while the existing
file still fits. An older binary with a fixed 16 GiB cap must use a separate
directory after a shadow database has grown beyond 16 GiB; never assume a binary
rollback also rolls back database geometry. Standalone witness/native benchmarks
open existing state read-only and do not change geometry; temporary fixture and
crash-probe databases are not production state directories.
Apply CPU, memory, PID and log limits to the process/container independently.
Never mount an existing execution client's database into this process.

`zevm_getStateStatusV1` with `[]` returns up to eight retained state snapshots,
newest first. Each binds `blockHash`, `stateRoot`, `blockNumber` and the MDBX
`databaseVersion`. An empty list means no qualified state is available, even if
`eth_syncing` reports false or headers have reached the network head.

`zevm_getStateWitnessV1` takes:

```json
[{"blockHash":"0x<32 bytes>","stateRoot":"0x<32 bytes>"},
 [{"address":"0x<20 bytes>","storageKeys":["0x0","0x1"]}]]
```

It returns `parent` (the same snapshot metadata) and `accounts`, using EIP-1186
proof fields plus inline `code`. Maximum 16 accounts, 128 total storage keys,
128 KiB per code and 16 MiB request scratch. Unknown/evicted parents and wrong
roots fail; there is no latest or block-number fallback. Clients must authenticate
all claims against their independently selected parent root. A header from an
untrusted peer alone is not proof of canonical chain selection.

`zevm_getStateNodesV1` takes the same parent selector followed by 1–16 queries:

```json
[{"blockHash":"0x<32 bytes>","stateRoot":"0x<32 bytes>"},
 [{"owner":"0x<20 bytes>","path":"0x000a","expectedHash":"0x<32 bytes>"}]]
```

`owner: null` selects the account trie; an address selects its authenticated
parent storage trie. `path` encodes **raw nibble bytes** (the example means
nibbles 0, 10), not a compact trie path or storage-key preimage. At most 64
nibbles are accepted. The server walks from the leased root, verifies each hash
reference, and returns `parent` plus `nodes`, in query order, each at most 1024
bytes. Embedded nodes are not separate missing hash references. A client must
independently establish that the expected hash is reachable at that path in its
parent trie before importing it. Both the root binding and node hash matter.
Scratch is limited to 4 MiB; unknown owners, corrupt preimages, wrong paths and
wrong expected hashes fail without a latest-state fallback.

The JSON wrappers retain one lazily allocated 16 MiB scratch buffer per API.
Each request acquires a cancellable exclusive lease and starts a fresh fixed
allocator with its existing limit: 16 MiB for witnesses, 4 MiB for nodes or
ancestors. This reuses allocation capacity, never DB views, state values or
authentication results. Response JSON is copied into caller-owned memory before
the lease is released, including on alternate-parent requests. Direct typed
reads continue to use the caller's allocator. The API must not be copied after
use and must be destroyed only after its RPC callers have joined.

The [matched local benchmark](shadow-witness-benchmark.md) found that allocating
and freeing the whole workspace dominated small reads. Retaining its backing
removed that repeated cost while preserving proof authentication and response
bytes. Allocation-failure, cancelled-waiter, concurrent-parent, response-retention
and actual HTTP cancellation tests cover the new lifetime. Socket cancellation
causes are preserved through generic I/O and RPC error handling so shutdown can
join the server. Debug and ReleaseSafe each pass 192 general/shadow tests;
[qualification](shadow-workspace-qualification-20261121.json) records exact source
and binary hashes. Local witness timings do not establish full construction or
live bidding performance.

`zevm_getStateAncestorsV1` takes `[parent, count]`, where `count` is 1–256 and
includes the exact parent itself. It returns `parent` and RLP `headers`, newest
first, following parent hashes only. The immutable header cache may be backfilled
after a state lease was published, so it uses a fresh read-only header transaction
while retaining the original state lease. The caller checks every hash, number,
and the first header's state root. A missing ancestor returns `AncestorUnavailable`;
state-read readiness alone does not promise construction readiness.

The downloader fills missing ancestors by hash from peers, separately from
selected-height mappings and writable state. Partial responses resume at the
next missing hash. The cache is bounded to 4096 headers / 8 MiB; backfill batches
are at most 256 headers and reuse a 4 MiB insertion workspace. Backfilling never
extends the undo window or changes forkchoice. Tests fill and evict the cache
using the live downloader slab allocator and preserve alternate branch chains.

Only completed account/storage hashing and code acquisition establish the first
checkpoint. Later checked BAL updates write state and checkpoint in one MDBX
transaction. Readers clone retained read-only transactions so concurrent writes
or retention eviction do not relabel old state. Code bytes and proof preimages
are copied before releasing the read transaction. Each resolved proof node,
including flat-state leaves, is hash-checked; missing data never means zero.

Downloader writes and DBI initialization own their MDBX transaction until commit
is attempted. MDBX consumes the handle on both successful and failed commits
(except a wrong-thread rejection), so cleanup never aborts it a second time.
An aborted-commit result is an error, and state publication remains strictly
after a successful commit. Real MDBX regressions preserve the old authenticated
checkpoint/lease across a broken commit and a later error after successful commit.
Write/commit failures propagate out of the downloader; no tight retry is added.

Restart resumes the state checkpoint rather than the header tip. A checkpoint
whose header is unavailable or no longer matches is rejected. A directory from
an interrupted initial sync has no checkpoint and is refused; restart that
experiment with a new directory. After the first verified checkpoint, recent
selected headers live transactionally in MDBX, independently of the initial-sync
header files. Each verified BAL update journals its account/storage preimages in
the same transaction as state and checkpoint. A branch switch rewinds to a common
ancestor, checks every restored root, and atomically selects the new header chain.
Existing cloned read leases remain immutable across that switch.

Undo is bounded to 32 records / 128 MiB, at most 32 MiB per record. Selected
headers retain a 256-height window and install at most 128 headers ahead of the
verified state at a time. Missing history, corrupt preimages or a reorg preceding
the first verified checkpoint fail closed without committing a partial rewind.
Automatic partial-sync recovery and deeper reorg reconstruction remain gaps. The
peer-driven downloader still does not implement CL forkchoice. Retaining views
from different branches is not full multi-branch sync.

## Consensus-selected shadow targets

`--shadow-state --shadow-beacon-url http://127.0.0.1:9596` enables the local
Lodestar target tracker. This is a read-only experimental integration. It never
calls Geth RPC or Engine methods and never changes the beacon's forkchoice.
The beacon remains a trust boundary and may itself still use Geth for execution
validation; this mode does not make the whole stack Geth-independent.

Bootstrap reads a finalized, canonical, non-optimistic beacon header, then the
post-Gloas block at that exact root. It anchors to the bid's **execution parent**:
the block's own advertised payload may be absent. The execution header is fetched
from peers by that exact hash, and the initial SNAP state must hash to its root.
No state is advertised before account, storage and code verification completes.
The anchor is persisted in the same transaction as the branch base. A peer-only
database cannot silently become a consensus-anchored one: use a fresh directory.

During the account/storage scan, five-second reconciliation refreshes that
finalized anchor. This matters on networks whose state download exceeds the
SNAP peers' recent-state retention: a fixed root can become unavailable. The
downloader accepts only a hash-linked finalized extension of at most 128 blocks,
stashes outstanding ranges after the old-root validation/write queue drains,
and applies each header's hash-checked BAL to the fetched portion. Accounts with
incomplete changed storage are refreshed with proofs against the new root before
outstanding ranges are retargeted. Live FULL/EMPTY hints do not move an incomplete
bootstrap. Code download and final hashing keep their existing root/code checks.

The selected old base, new tip, finalized consensus anchor and an authorized-tip
marker are committed together before healing; no verified-state marker is
written. After healing, the selected base and head are rebased to the new anchor.
Empty account/storage SNAP responses are treated as state unavailability, with
a ten-second backoff for that connection and requested root. Invalid proofs still
disconnect the peer. The old-root queue must drain within 30 seconds; otherwise
the downloader fails with `BootstrapDrainUnavailable`, preserving ordering and
keeping state unavailable. This is bounded failure, not automatic recovery of an
arbitrarily expired partial download.

After bootstrap, `head_v2`, `head`, `execution_payload` and `payload_attributes`
SSE events trigger a read of Lodestar's `/eth/v2/debug/fork_choice`. Execution
payload notifications warm their exact FULL hash immediately, before the beacon's
timeliness decision selects FULL. Payload attributes request their exact parent.
Both hints must match a **valid, non-optimistic node with the same beacon root
and execution hash**; payload notifications also bind the slot and FULL status.
The earlier `execution_payload_available` event is deliberately not used: its
payload has not yet passed execution validation.

For head notifications and reconciliation, the selected node is matched by both
beacon root and FULL/EMPTY status. If it is EMPTY but that same beacon block has
a verified FULL variant, warm FULL while retaining the EMPTY parent. This is a
read-only cache policy, not a change to canonical forkchoice. Requests for a
retained parent reuse its immutable view without rewinding the writer. A new
uncached branch still requires header linkage, bounded undo and root checks.
Five-second reconciliation repairs missed events; SSE reconnects after one second. Ordinary
HTTP lookups have a two-second timeout and a 4 MiB body limit. Only explicit
loopback HTTP endpoints are allowed, and redirects are not followed.

The downloader accepts same-height and lower-height targets, fetches the target
header by hash, and fences obsolete header results with a generation. Existing
BAL work completes against its original selected branch before any rewind.
Header/BAL responses advance the pipeline immediately instead of waiting for the
one-second recovery tick. `shadow consensus ready` logs the time from the
tracker's observation, including lookup time, to a verified retained view; this is not transaction
arrival latency or a proposer deadline measurement.

An interrupted bootstrap with a persisted trusted consensus anchor restarts
automatically in the same directory when `--shadow-beacon-url` is supplied.
It clears only unverified account/storage/code/trie tables, in one transaction,
and repeats the full scan of the persisted authorized anchor. If interrupted
between selecting a new finalized tip and completing its heal, the saved tip,
anchor and authorization marker must agree; reset rebases to that tip atomically.
Ordered append ingestion
cannot safely resume into partially populated tables. No state view is published
until full root hashing and code download finish. A verified checkpoint is never
cleared; missing/mismatched anchor metadata still fails closed. The database tests
cover reset commit/abort, wrong anchors, progressed branches and preserving a
verified checkpoint (77 shadow tests and 81 general tests in Debug and safe).

A separate live Plataberget process was killed with SIGKILL after account/storage
download and during initial code/hash work. On restart in the **same** directory,
it kept all state views unavailable until the fixed anchor's root was verified,
then published that anchor after 233.5 seconds. Independent Geth header/root
comparison passed, followed by three complete native payload reconstructions
using only shadow state RPCs. The ten initial connection-refused observations
were during process startup; no partial state was published. Evidence lives in
`bootstrap-recovery-v7` and `full-execution-bootstrap-recovery-v7` in the isolated
qualification workspace. This tests one interruption point, not power loss or
exhausted history recovery.

Current limits: finalized progress must remain within the 128-block extension
bound and peers must serve each old root while its write queue drains. A larger
gap fails with `BootstrapAnchorGapTooLarge` and requires a fresh bootstrap;
there is no automatic state reset loop or unbounded history walk. After a long
interruption, the persisted anchor may already be unservable. The account/storage
phase can advance finalized roots; code download and final hashing do not.
Recovery after the first verified checkpoint is bounded by retained
undo history; only eight recent views are retained and one writer processes
targets at a time, so arbitrary FULL/EMPTY/ancestor coverage is not guaranteed.
It depends on Lodestar's debug V2 API, not
a standardized Engine forkchoice implementation.

Before production adoption, qualify independent live sync, restart/corruption,
reorg recovery, exact-parent availability at builder deadlines, full candidate
root/receipt/value parity, and performance against an independent EL oracle.

The first Plataberget qualification on 2026-11-21 reproduced a downloader reorg
failure: the persisted header at height 627188 was `bd23ae2d…`, while the next
persisted header's parent was the competing `f9b3c70e…` header at the same height.
State application returned `Reorg` and the process exited. The captured headers
are now a regression fixture: a disconnected height extension is rejected before
selection changes. Tests also cover ancestor rewind, an alternate branch, database
reopen, retention limits, corruption, allocation failures and retained read
leases. The repaired downloader subsequently survived a live depth-one reorg and
passed authenticated reads afterward. The first selected-head tracker was slower:
an event capture showed verified execution payloads arriving 4.7–6.2 seconds before
FULL selection. This motivated immediate verified-payload warming. Continuous
exact-parent availability still needs separate qualification; these tests alone
do not authorize production use.

The dedicated crash probe uses a temporary MDBX environment and real account
trie/checkpoint/branch writes. The driver sends SIGKILL while those writes are
uncommitted, then repeats immediately after commit. A fresh process authenticates
the surviving account against the checkpoint root and checks that selected header,
account nonce and balance agree. Both cases pass in Debug and safe mode and run
in CI. This qualifies process-crash boundaries, not host power-loss durability or
all live downloader failure timing.

Full native construction also exercises ancestor and witness requests on the
same retained HTTP arena. A regression reproduced `OutOfMemory` when the 4 MiB
ancestor scratch was followed by the 16 MiB witness scratch: arena growth could
exceed the slab allocator's 32 MiB single-allocation limit. These bounded scratch
buffers now use independent page allocations and are released after copying the
JSON response. The alternating-request regression passes with the real slab
allocator in both Debug and safe mode; the global slab limit is unchanged.

## Direct-extension header readiness qualification

The trusted CL target lookup already returns the exact execution header. When
that header directly extends the **current verified checkpoint**, the downloader
now reuses the header and local checkpoint instead of fetching the pair again
from a peer. This removes one redundant header request on that path. It retains
the normal branch selector, BAL hash check, calculated state-root check and
atomic checkpoint publication. No state becomes available at header selection.
Active BAL work, unverified selected heads, gaps and alternate branches continue
through the existing download path. Target changes cancel loop-owned requests,
advance the generation and discard old staging; worker-owned responses are
discarded by generation after their validation finishes.

The full-source review confirmed that `BlockHeader` owns every field inline,
including the 32-byte `ExtraData` buffer. Reading a checkpoint does not retain
the decoder scratch or database transaction. Header reuse does not introduce
execution-header semantic validation: both paths depend on the trusted,
execution-valid Lodestar selection described above. They bind the fetched header
to its CL hash and require post-Gloas fields; this is not a standalone EL.

The integration regression uses initialized ETH/SNAP providers with no connected
peers. It checks the missing second request, mismatched header hash and absent
Gloas fields, duplicate targets, true same-height siblings, old in-flight and
worker-owned requests, stale staged descendants, unavailable child state before
BAL verification and a wrong BAL hash. A matching BAL passes the existing root
calculation and publishes the child. A later verified A-to-B sibling transition
downloads ancestry, rewinds to the common parent and publishes B while a retained
A lease stays readable. ReleaseSafe qualification passed 95 general and 77 shadow
tests; general totals also include the independent public-intake tests.

The read-only 15-minute baseline from 2026-11-21 contained 68 completed single-block
advances. Median observation-to-ready was 573.5 ms, target-header-known-to-ready
356.863 ms, and target-header-known-to-heal-start 160.7495 ms. The last interval
includes header download, storage and scheduling; it is **not** the expected
gain from this change. No post-change live improvement is claimed by this test.
Use zbuilder's `test/analyze_shadow_readiness.py` on a single chronological process
log for a comparison. It matches slot/number/hash, handles midnight, reports
incomplete/duplicate events and excludes ambiguous sibling heal-start attribution.
Its three parser tests pass, and it reproduces every row and median of the saved
68-block baseline exactly.
