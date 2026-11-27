# Current-head header hedge contract

Base: maintained `nflaig/shadow-state-base` commit
`f0fd8e8ced126e4f66303647e9c9106a79be1306`, including owner-root PR6.
This is a separate branch and qualification. The failed Sepolia observation is
retained; it does not identify which header request or CL update caused the miss.

The original pre-implementation contract is retained in the immutable design
review packet. Its lifetime-per-hash ledger was rejected during review: it
unnecessarily exhausted the availability improvement. This revision uses bounded
renewable load, without any pruning or finality assumptions.

## Observed source behavior

The consensus tracker deduplicates by execution hash and finalized anchor, not
beacon root. A verified FULL on the selected beacon root supersedes EMPTY even
before forkchoice's payload-status selection changes. Branch attributes can be
accepted without changing the writer's preferred target.

A current consensus header probe keeps one request until a response or its
ordinary ETH deadline. A fresh peer's header deadline is 15 seconds
(`max(3 seconds, 3 * default RTT 5 seconds)`), longer than one slot. Repeated
notification of the same desired hash does not create another probe. The BAL
hedge cannot run until an authenticated header has started a state heal.

## Production contract

1. Only the current CL-authenticated, single-header, hash-origin consensus probe
   is eligible, after bootstrap has a verified checkpoint. No chain-range,
   ancestor, SNAP, bootstrap, or public transaction request gains a hedge.
2. The owner may send one alternate after the current primary wire attempt has
   waited one second. Tick granularity makes this roughly 1–2 seconds when the
   owner can run. Pick a distinct eligible connection before allocating the
   extra request. Missing peer/pool capacity leaves the primary and allowance
   unchanged and allows a later check.
3. Per active probe generation, at most one extra send attempt. Primary empty,
   invalid and timeout reissues do not reset that flag. A failed send consumes it.
4. Globally, one extra single-header attempt per monotonic awake second, burst
   one: consecutive attempts are separated by at least one second. There is no
   catch-up burst after idle, and no finite lifetime limit. Target changes,
   A→B→A, later EMPTY anchors, finality, responses and primary retries cannot
   reset the cooldown. Backwards time grants no credit. A later generation for
   the same hash may get an attempt only after real allowance replenishment.
   A newly dispatched FULL/reorg probe can get an alternate at its own age
   threshold; the preceding target cannot impose an additional full-slot wait.
5. The alternate comes from the existing 100-entry request pool and inherits
   the primary wire attempt's exact deadline. It is never extended or reissued,
   and expiration adds no artificial peer RTT penalty. The primary's identity,
   deadline and existing normal retry behavior remain intact.
6. Two workers may validate independently. The first valid current-generation
   response wins; an empty or peer-invalid response cannot consume the other's
   response. Exact raw and decoded hash, mandatory fork fields, CL target and
   normal BAL/state-root verification remain mandatory. Header arrival never
   publishes ready state. A hash-authenticated local codec/fork mismatch retains
   the existing fail-stop disposition: no peer eviction/retry storm.
7. Winner/supersession cancels only pending/inflight siblings. Validating workers
   retain their pooled request, arena and response frame until owner completion.
   Their hash/generation fence precedes peer penalties and state mutation.
   Wire matching still requires exact request id, peer index/epoch and tag.
8. INFO records include bounded first primary send/response/empty validation per
   generation, alternate send/failure, timeout, retirement and resolution.
   Repeated primary empty/reissue details are DEBUG. Metadata includes target
   hash, generation, request id, connection epoch, wait and deadline; no peer
   address, transaction, key or private payload. The progress record exposes
   cumulative hedge attempts and configured interval.

## Deliberate limits

This is not a guarantee of readiness inside every slot. A silent primary plus
an unavailable, failed or invalid alternate can still wait the unchanged normal
primary deadline (15 seconds for a fresh peer). Long validation or state work,
no eligible distinct peer, pool pressure, and owner scheduling can delay progress.
The existing 16-block header peer range filter and round-robin selection remain.
No discovery, connection, gossip, builder scheduling or parent-admission policy
changes are included. The failed historical canary is not retrospectively solved
by this fixture.

## Qualification design

Use real ETH provider encoding/decoding, minimal RLPx queues, async workers and a
real temporary MDBX checkpoint with an old retained reader lease. Start with no
selected child or manufactured state heal. Compare the exact final child root
and account state after normal BAL dispatch/application.

Cover threshold, missing peer, send failure, pool/scope exclusions, long-running
allowance and clock regression; A→B→A/EMPTY changes with workers outstanding;
both-valid and invalid-first/valid-second races; wrong hash/id/epoch, empty from
either peer, timeout/ordinary reissue; cancellation and real worker arena/frame
ownership; fatal authenticated fork mismatch without peer eviction; and stale
header metadata on a reused BAL request. Test same-root EMPTY→FULL using real
Tracker.publishForkChoice. Run Debug and ReleaseSafe affected suites and a
compiled negative control disabling only the new header hedge. Actual independent
Opus 5.5 xhigh reviews use frozen packets, tools disabled. No production changes
are authorized from this worktree.

## Reproduce the affected tests

Use the repository-pinned Zig 0.17.0 development toolchain. Run each of
`zig build test -Doptimize=safe -Dtest-filter=downloader -j2`,
`zig build test -Doptimize=debug -Dtest-filter=downloader -j2`, and the same two
commands with `-Dtest-filter=consensus`. The real-provider fixtures are embedded
in `src/node/downloader.zig`; no production test hooks or live database are used.
The [qualification record](qualification/native-header-hedge-20261127.json) binds
source, toolchain and logs; the [independent review](qualification/native-header-hedge-review-20261127.md) records the final verdict and limits.

Final affected suites: downloader39/39 and consensus21/21 in both modes. A
compiled negative control disabling only the header-hedge dispatch fails the
silent-primary test in both modes; Debug identifies the missing-alternate
assertion. To reproduce it, apply the [one-line control patch](qualification/native-header-hedge-negative-20261127.patch) in a separate checkout, then run
`zig build test -Doptimize=debug -Dtest-filter="current head header hedge real owner" -j2`.
The expected result is one failure, not a compile error.

No live performance result is part of this producer qualification.
