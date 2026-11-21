# Independent public transaction intake qualification

`--public-intake-observer` is a default-off, receive-only ETH/71 experiment. It
requires `--shadow-state`. The node receives public transaction announcements,
requests missing transactions from the announcing peers, and accepts direct
transaction broadcasts. It uses no Geth subscription, transaction RPC or database.
It does **not** feed a production constructor, advertise or serve transactions,
or receive private bundles. The only installed sink emits public hashes, sizes
and receipt timestamps; no transaction bodies or credentials are logged.

The wire adapter uses the ETH/68–71 three-field announcement format, plus
request-ID-wrapped pooled requests/responses. It does not negotiate ETH/72 or
interpret ETH/72 cell announcements. Relevant primary specifications are the
[ETH protocol](https://github.com/ethereum/devp2p/blob/master/caps/eth.md) and
[EIP-5793](https://eips.ethereum.org/EIPS/eip-5793). The upstream protocol document
now describes ETH/72; its four-field announcement must not be copied into the
existing ETH/71 capability.

## Ownership and validation

`node/public_intake.zig` is a native, single-owner component. The downloader's ETH
queue owns every mutation; the optional peer adapter reserves requests before
sending and rolls them back on transport failure. Connections are distinguished
by peer index **and epoch**. Requests use the provider's shared request-ID source.
Transaction intake begins only after a Status message for that connection epoch.

Announcement metadata remains tied to its advertiser. A dishonest first size or
type does not overwrite the independent binding from a second peer. Transactions
must match requested hashes, order and announced sizes/types. Canonical RLP,
chain ID, low-s signature recovery and basic fee shape are checked using zevm's
existing transaction decoder and sender recovery. An entire response is checked
before any of its records reaches the sink. Repeated hashes are deduplicated,
including direct broadcasts that race a requested response. Ordinary missing
items, empty responses, disconnections and timeouts release reservations so a
retained alternate peer can supply them.

The sink receives a `Record` with canonical bytes, decoded transaction fields,
recovered sender, peer and timestamps. These are borrowed **only during the
callback**. A native constructor adapter must copy into an independently bounded
immutable allocation before returning. A false return means backpressure; that
transaction is not recorded as delivered. The callback is not permission to
include a transaction: balance, nonce, intrinsic gas, current fork rules and
candidate-specific eligibility still require builder validation/execution.

## Bounds

| Resource | Limit |
| --- | --- |
| Announcement | 4,096 entries / 192 KiB |
| Pending unique hashes | 2,048 |
| Pending hashes admitted by one peer slot | 256; reconnects do not reset ownership |
| Remembered alternate sources | Two per hash |
| In-flight requests | 16 total; one per peer |
| Request batch | 64 hashes / 2 MiB announced transaction bytes |
| Response frame | 2 MiB plus 1 KiB envelope allowance |
| Direct broadcast | 256 transactions / 2 MiB |
| Individual ordinary transaction | 128 KiB |
| Request timeout | 1.5 s, serviced by the existing recovery tick |
| Pending announcement lifetime | 10 s |
| Delivered-hash deduplication | 8,192 entries / 30 s, capacity eviction allowed |
| Frame bytes before parsing/hash work | 4 MiB/s global, 1 MiB/s per peer slot |
| Frame-byte burst | 4 MiB global, 2 MiB + 1 KiB per peer slot |
| Frames before parsing/hash work | 512/s global (burst 256), 128/s per peer slot (burst 128) |
| Decode/signature attempts | 256/s global, 64/s per peer slot; burst 256 |
| Timeout retry backoff | Exponential 1–10 s, reset after a valid response |

Wire lists enforce their element limit before decoding/allocating further
members. Expiry and disconnected-peer cleanup run on the existing one-second
tick; effective timeout recovery can therefore take up to one additional second.
Oversized/malformed messages are counted; invalid transactions never reach the
sink. These limits are experimental admission policy, not consensus limits.
The observer never disconnects a shared state-sync peer for an intake verdict;
it releases only its own reservations. Token buckets charge incoming bytes before
parsing or hashing and unknown transactions before decoding/signature work.
Denied work spends neither the other bucket's tokens nor any signature attempt.
Denied frames return from the adapter immediately; they do not scan pending
inventory, release requests or drain outgoing work. This prevents a tiny-frame
flood from moving expensive work into the rejection path. Empty announcements
also return before the pending-ownership scan.
Rate-limit loss is expected under overload and must not be mistaken for complete
coverage. A frame rejected during validation contributes no records to the sink.
The bounded work remains on the downloader thread, so this limits additional CPU
work without claiming immunity from transport/decompression load or a real-time
latency guarantee.

`public_intake_stats` records accepted, decoded/signature-verified, announced, requested, duplicate,
deferred-blob, unsupported, invalid, oversized, stale-response, outstanding,
pending, capacity-drop, sink-full and timeout counts every minute.
It also records frame/signature rate drops, per-peer pending drops and backoff
selection skips. Repeated announcements cannot renew the ten-second pending
lifetime, and a stalled peer is bypassed while a remembered alternative is usable.
`public_transaction` records monotonic announcement time, frame-dispatch time in
both clocks, and wall-clock acceptance time after validation. Frame dispatch is
not a first-byte network timestamp. Logs are capped at 512 records per monotonic
second; `public_intake_observer_stats` reports logged and skipped counts. Windows
with skipped records cannot establish complete transaction coverage. Compare
**first** receipt/acceptance per hash with Geth's observations on the same host;
these delays are not transaction-to-bid latency or a win-rate gain.

## Explicit remaining work

Blob announcements are counted and deferred. A bare type-3 transaction is never
emitted as ready input; verified sidecar acquisition/retention and the correct
network version remain separate work. This experiment is not a complete mempool:
native constructor delivery, scheduling by executable nonce chains, fee/replacement
policy, reorg reinsertion, peer-quality qualification and safe long-running
publication are still required. Independent intake must demonstrate better or
equivalent coverage and timing before replacing the existing production feed.

Local tests include real legacy/typed signature recovery, canonical encoding,
wrong-chain/signature failures, malformed and oversized frames, request identity,
empty responses, duplicate delivery races, two-peer metadata poisoning, timeout
and disconnect recovery, sink backpressure, inventory/request bounds and
allocation failures. Run the repository's normal `test` target with the pinned
Zig 0.17 toolchain in Debug and safe modes. Live results must be recorded separately;
passing these tests does not establish real peer coverage or better block value.

## Review closure

The Opus 5.5 xhigh review correctly identified two observer blockers: disconnects
could affect shared sync peers, and per-message limits did not bound sustained
decode/signature throughput. The adapter now has no `provider.disconnect` call;
a connected-provider regression rejects malformed transactions while preserving
the live connection. Global/per-peer byte and decode budgets, per-peer inventory
quotas and retry backoff have adversarial tests, including reconnects. Known
hashes still avoid repeated recovery; invalid or dropped work is never marked
delivered.

The reported ReceiptTime call mismatch came from a stale supplied diff. The
current dispatcher already passes both `.mono_ms` and `.wall_ms`, and node builds
exercise that path. Both clocks are propagated to a sink regression. The adapter
uses the real allocator for canonical typed wrappers. Empty typed wrappers are
classified as invalid rather than oversized.

Exact advertised size remains the consensus encoding's size, per ETH/71's
announcement contract; a recollected wrapper-size tolerance was not used to
weaken the binding. Independent eth-account-generated vectors cover type 2,
type 4 with authorization, unprotected legacy, and the devnet's large legacy chain
ID, recovering the known public test-key sender. Wrong-chain, high-s, typed
allocation-failure and wrapper cases are exercised.

The provider interaction was checked in full source: `send` serializes/copies
request bytes into its transport queue; transport slots are released by transport
writes, not downloader response matching. Pooled responses use a separate intake
request table and the downloader's switch ignores them for state matching. All
public transaction message types remain raw at the provider boundary, so intake
bounds apply before element decoding. `timeoutFor` only resets stale-peer RTT
state when used here; it does not disconnect. The ETH arena/frame is freed after
the synchronous intake callback, and the downloader joins its tasks before its
run method returns and main destroys intake state.
