# Optional ETH/71 blob acquisition

The receive-only public intake can fetch complete PeerDAS wrappers when attached
to an owning verifier. The hash/time observer retains its previous behavior:
without a capable, prewarmed blob sink, type-3 announcements are counted as
`deferred_blobs`. There is no blob gossip, public serving API, private input
source, or execution-client fallback in this path.

The wire contract is pinned to
[ETH/71, devp2p commit 0dfc043](https://github.com/ethereum/devp2p/blob/0dfc043453940de2bec50ec7f0ebddc8741b485d/caps/eth.md#newpooledtransactionhashes-0x08)
and [EIP-7594](https://eips.ethereum.org/EIPS/eip-7594#networking).
The response carries `0x03 || rlp([signed_body, 1, blobs, commitments, cell_proofs])`
inside the ETH typed-transaction byte string. The announcement's size is checked
against those pooled bytes, excluding the enclosing ETH RLP string prefix. The
transaction hash is computed from `0x03 || rlp(signed_body)` only. Geth's
[transaction size implementation](https://github.com/ethereum/go-ethereum/blob/v1.16.7/core/types/transaction.go)
also includes sidecars. ETH/72's cell custody announcements and separate cell
requests are not accepted as ETH/71 messages.

`public_blob.zig` validates canonical framing, the bounded signed body, version 1,
exact list cardinalities, at most six ordered versioned hashes, 131072 bytes per
blob, 48 bytes per commitment and proof, and 128 proofs per blob. Commitments
must hash to the corresponding signed hashes; repeated hashes remain valid and
preserve their positions. The ordinary decoder validates the signed fields,
chain ID and signature. Neither framing nor a signature establishes blob
availability.

`PublicHandoff.Sink.blobs` is optional. Its callbacks use only primitive fields,
so synchronization and construction can retain independent execution-engine
versions. `available` becomes true only after the owning verifier's `prewarm()`.
`accept` copies the complete wrapper into a bounded queue before returning.
`status` is a short, mutex-protected lookup returning `pending`, `missing`, or
`ready`; it performs no signature or KZG work. The separate native owning drain
revalidates signed bytes and all ordered sidecars, computes cells from each exact
blob, and verifies every supplied cell proof before publishing an immutable
ready entry.

The peer owner retains at most four verification records. A queued wrapper does
not enter its seen set. Failed or expired verification permits another retained
advertiser to provide the same hash. Local queue backpressure preserves the
responding peer's announcement, with retry pacing; a malformed response clears
only that peer's intake reservations. These errors never disconnect a shared
state-sync connection. Polling readiness is not delivery to a constructor and
is not permission to sign or offer a bid.

`blob_queued` counts owned handoffs, while `blob_ready` counts successful
verification observations. `blob_failed` also includes local expiry/work
refusal; it is not a cryptographic peer-fault counter. Ordinary `accepted` and
hash/time observer logs remain ordinary-only. Request quotas count transactions,
whereas verification quotas count individual blobs, so admission can exceed
verification capacity for sustained six-blob traffic. Those bounded coverage
losses must be measured before any throughput tuning.

| Bound | Policy |
| --- | --- |
| Pending blob inventory | 128 globally, 32 per first blob advertiser slot, inside the existing 2048 total |
| Requests | Two blob requests within 16 total, one transaction per blob request, one outstanding request per peer |
| Request pacing | Two per second globally, burst two; one per second per peer slot, burst one |
| Message/body | 2 MiB pooled wrapper; 128 KiB canonical signed transaction; existing 2 MiB plus 1024-byte response framing bound |
| Blob response byte admission | Separate 2 MiB/s global and 1 MiB/s per-peer budgets, each with a 2 MiB plus 1024-byte burst |
| Ordinary admission | Existing ordinary byte, frame, signature and inventory bounds remain; requests examine ordinary inventory first |
| Lifetimes | 1500 ms request, 10 s pending inventory, at most 10 s verifier observation, 250 ms local retry delay |
| Native owner | Four waiting blob jobs/8 MiB plus one active wrapper; 64 resident/80 live blobs including leased evictions; 64 MiB retained ownership |
| Verification work | Native signature quota; two blob verifications/s, burst six, failures charged; one prewarmed drain |

The native owner's default queue/job deadline remains 1500 ms. Its C KZG calls
are cooperatively bounded between calls, not forcibly interruptible. Large
crypto regression fixtures explicitly use a 10 s ceiling and do not qualify
production latency. Prewarming occurs before admissions and does not consume a
job deadline. Joining the verifier precedes owner destruction; typed leases and
ready sealed results retain their independent data lifetimes.

Tests cover peer/epoch/request/hash/size binding, extra and malformed responses,
bare bodies, wrong wrapper versions, missing proofs, seven-blob rejection,
noncanonical/truncated RLP, invalid chain/signatures, independent byte quotas,
concurrent request and inventory bounds, allocation failure, local pressure,
verifier timeout, and shared state-peer isolation. The combined native-node
fixture uses real KZG with six repeated zero-polynomial blobs: a valid nonzero
field in the last blob fails verification without partial readiness, ordinary
input progresses, and another peer supplies the valid complete wrapper. A
separate one-blob fixture verifies recovery from owning queue pressure.

This establishes an in-process acquisition/ownership/verification path. Live
peer availability, deadline completion under realistic contention, fee-weighted
blob coverage, constructor selection and Gloas reveal/column publication need
separate qualification. No performance or profitability claim follows from
these fixtures. A peer transaction rejected by an exact-parent candidate is not
removed globally; branch-specific nonce/fee alternatives remain the native
constructor's responsibility.
