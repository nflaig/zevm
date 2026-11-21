# Shadow state qualification

This opt-in prototype supplies authenticated account/storage/code witnesses for
an exact execution parent. It does not implement Engine API, accept private
transactions, or authorize use as a production execution client.

Build with Zig 0.17.0:

```sh
zig build zevm test-shadow-state -Doptimize=safe -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v3
zig build test-shadow-state -Doptimize=debug
```

Start in a fresh, dedicated directory with `--shadow-state`, independent peer
ports and localhost HTTP. The shadow DB has a 16 GiB maximum with 256 MiB growth.
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

Only completed account/storage hashing and code acquisition establish the first
checkpoint. Later checked BAL updates write state and checkpoint in one MDBX
transaction. Readers clone retained read-only transactions so concurrent writes
or retention eviction do not relabel old state. Code bytes and proof preimages
are copied before releasing the read transaction. Each resolved proof node,
including flat-state leaves, is hash-checked; missing data never means zero.

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

Current limits: the finalized bootstrap pivot stays fixed until complete; an
interrupted initial sync requires a new directory; recovery is bounded by retained
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
