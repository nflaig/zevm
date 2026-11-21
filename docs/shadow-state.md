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
experiment with a new directory. Automatic partial-sync recovery and reorg
reconstruction remain qualification gaps. Retained views can represent different
branches, but the peer-driven downloader does not yet implement CL forkchoice or
reconstruct arbitrary historical branches. This is not full multi-branch sync.

Before production adoption, qualify independent live sync, restart/corruption,
reorg recovery, exact-parent availability at builder deadlines, full candidate
root/receipt/value parity, and performance against an independent EL oracle.

The first Plataberget qualification on 2026-11-21 reproduced a downloader reorg
failure: the persisted header at height 627188 was `bd23ae2d…`, while the next
persisted header's parent was the competing `f9b3c70e…` header at the same height.
State application returned `Reorg` and the process exited. The header downloader
currently appends a height extension without reconciling its cutoff hash against
the existing branch. A fresh initial sync and a clean restart therefore do not
qualify recovery or continuous availability. Do not deploy this as a production
state source until branch-aware sync and recovery have passed the same tests.
