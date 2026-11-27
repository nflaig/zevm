# Reuse authenticated owner roots within native leases

The storage-child fallback reuses an owner root already authenticated and
retained by the same immutable lease. It still walks `nodeAtPath` from that root
and verifies the requested path and hash. If the owner authorization is absent,
it performs the ordinary authenticated account read. No cache limit, eviction,
branch policy, return-byte ownership, result lifetime or database schema changes.
`owner_reads` continues to count attempted owner-account reads, and consequently
falls when those attempts are skipped; `fallback_reads` retains its own meaning.
Consumer uses of `owner_reads` are diagnostic logging, not selection policy.

The maintained producer base is `63ab43c84ffa3fb430f386364a35d3607b3887e6`
(`nflaig/shadow-state-base`). Its tree is identical to deployed producer
`1fe7a0efb10bb8534346b5eb4c8aab3cdf9b0dd2`. The only compiled producer
implementation change is in `src/native_state.zig`; its SHA-256 is
`d92defcfa2cb4527d591c9a48e11ae553d744a9565fe01c903964dc776c2046e`.
The 16K-to-32K wording correction in `docs/native-state.md` describes an existing
limit; the experiment does not increase it.

## Correctness and review

The native-state suite passes **57/57 in Debug and Safe**, including sibling
parents, absent owners, missing owner authorization, unreachable valid preimages,
corrupt and missing trie nodes, cancelled saturated reads and injected backing
allocator/arena-refill failures. Lease admission and backing allocations are
released on failure. This does not claim fault injection at every logical
allocation site. The unmodified producer with the exact new test file compiles
and fails exactly five `owner_reads` assertions; the other 52 tests pass.

Two actual Opus 5.5 xhigh reviews, with tools disabled, found no production
correctness, ownership, authentication or cancellation blocker. Their context,
verbatim results and subsequent evidence-gate resolution are in the
[review record](native-owner-root-review-20261127.md). The final timing blocks
completed after the closure review; the review was not an execution of them.

All three production-default-allocator blocks pass literal complete payload
and supplemental receipt-byte comparisons. The state roots, transaction/receipt
roots, block hashes, raw transactions and BAL bytes match. Retained early/final
outputs survive later revisions, Host cancellation, Runtime destruction and
MDBX teardown. The earlier separate strong-poison test-allocator block also
passes these ownership checks; its performance numbers are not mixed into the
production-default-allocator result.

Every fixed-work observation performs **1,244,212 node reads and 130 seals**.
All cache statistics except `owner_reads` are identical. The control performs
**224,148 owner-account reads**, and treatment performs **zero**. Both branches
fill 32,768 entries while remaining within the unchanged 4 MiB RLP budget.
Peak seal scratch remains **42,313,884 bytes**. Complete serialized fixed-work
payload/receipt artifact SHA-256 is
`09dc41d7dc6060964c44ef888750b73e60b5edd48a1456edd98e46a7c4c7356a`.

## Matched timing

Zig 0.17.0 Safe, `x86_64-linux-gnu.2.35`, `baseline+cx16`; Runtime, Host and
Intake use the deployed Safe executable's default `SafeAllocator` options.
Setup, Io and assertion allocations still use the test allocator. Only the
owner-loop interval is used for the CPU figures below. `/usr/bin/time` covers
the larger process and is retained separately. State-read time overlaps
state-root time and is not added to it.

Three blocks run ABBA, BAAB, ABBA. Each process has a discarded warmup and two
measured observations per schedule, balanced by physical primary position.
The independent units are **six matched process pairs**, not the 12 observations
per arm. Each table row compares adjacent processes; negative change is lower.

| Block/pair | Fixed control CPU (s) | Fixed treatment CPU (s) | Fixed CPU change | Owner-schedule CPU change | Owner-schedule late receive→primary publication change |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1: C0/T1 | 22.173 | 20.014 | -9.74% | +2.82% | -16.82% |
| 1: C3/T2 | 21.245 | 19.967 | -6.02% | -2.04% | -1.88% |
| 2: C1/T0 | 20.791 | 20.103 | -3.31% | -2.66% | +0.43% |
| 2: C2/T3 | 21.517 | 20.337 | -5.48% | -7.82% | -18.75% |
| 3: C0/T1 | 20.744 | 19.733 | -4.87% | -3.40% | -2.67% |
| 3: C3/T2 | 21.184 | 19.785 | -6.60% | -3.05% | -0.54% |

For identical fixed work, paired in-loop CPU changes range from
**-9.74% to -3.31%**. Seal CPU per seal changes range
from **-10.15% to -3.96%**. These are descriptive local
paired measurements, not a population percentile or a live latency estimate.

With the existing owner schedule, paired total CPU changes range from
**-7.82% to +2.82%**; late ordinary receive-to-primary
native publication changes range from
**-18.75% to +0.43%**. Intermediate
seal counts can change under the elapsed-time budget, so this is not an
equal-sealing-work comparison. Preserve that variability alongside the fixed-work
benefit; it does not prove a universal end-to-end improvement.

Host load and CPU pressure are retained for every process. Other user workloads,
CPU affinity and governor were not controlled. A warmup runs inside every
process, both process orders are used, and the full paired distributions remain
in the [machine-readable qualification](native-owner-root-reuse-20261127.json).

## Replay and scope

Apply [the fixture patch](native-owner-root-benchmark-20261127.patch) to exactly
zbuilder `6c64b11ec8d277de1cb5b236c5320aa2b9309d13`, then follow the added
`docs/qualification/native-owner-root-benchmark.md`. The fixture-only local
consumer commit is `d416a1c009837823075e527e8811db15b0b2fbdb`; the patch is the portable
artifact and needs no consumer runtime pin change. Patch SHA-256:
`477f3838bc2ba5c29640e7ac0bae1802d574daa4a70f01bca7afa311649610e8`.

The benchmark creates temporary authenticated MDBX state with 65,536 storage
slots and executes 64 transactions making 8,192 writes, then an ordinary
transaction that is already nonce-eligible on the primary. Another task admits
it after the drain phase and before a costly seal, through a bounded test-only
rendezvous. This deliberately stresses one queue phase, not a random arrival
distribution. Fixed work uses two attempts/turn, a one-second append allowance
and no secondary deferral. The other schedule uses the existing 16 attempts,
20 ms allowance and 250 ms secondary deferral; both use 10 ms start-to-start
pacing. Each branch completes the same 65 transactions.

The fixture extends the session allowance to 60 seconds and gas ceiling to
300 million. Its worker/session/result/retained reservations are
512/128/16/128 MiB, so it does not qualify deployed resource headroom. It does
not model network ingress, publisher Prepared time, gossip, proposer delivery,
live deadlines or bid outcomes. No live database was opened.

Recreate the aggregate from the three complete manifests with
`python3 docs/qualification/native-owner-root-summary.py MANIFEST_ABBA MANIFEST_BAAB MANIFEST_ABBA`.
The summarizer verifies byte equality, counter equality, source fixture and
binary identity, excludes warmups, and reports adjacent process differences.
Its hash, exact compiler hash, build flags, logs and source hashes are bound in
the machine-readable record. Native-state tests use
`zig build test-native-state -Doptimize=safe` and the corresponding `debug` run.

This qualifies a narrow reduction in redundant authenticated state work and is
suitable for subsequent pin-only consumer qualification. It is not evidence
of a deployed performance improvement. Preserve each network's existing
consumer variant when changing only its producer dependency.
