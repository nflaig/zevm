# Header hedge independent review record

Actual Claude Opus 5.5, xhigh effort, tools and MCP disabled; no session
persistence. Both calls completed with exit0 and isError=false. This is a static
review, separate from the executed qualification below.

The initial design review found three blockers, all resolved before the final
freeze: header-tag checks on pooled BAL reuse; preserving local fail-stop for
hash-authenticated codec/fork mismatches; and replacing the permanently
exhaustible hash ledger with renewable bounded load. It also requested bounded
INFO output for rapid empty-response retries, which is implemented.

The final review below used exactly the source hashes in the qualification JSON.
It ran concurrently with the final tests, so its references to unfinished tests
reflect packet creation time. The final downloader39/39 and consensus21/21
suites subsequently passed in each mode. Both compiled negative controls failed
at the expected missing-alternate condition; Debug provides its exact trace.
Clock-regression coverage remains a budget-unit test; the authenticated
re-encoding-mismatch branch has the pre-existing direct-owner test, while the
missing-fork-field error is exercised through a real worker/checked allocator.
These limits are not described as broader coverage.

## Final frozen-packet verdict

## Verdict: NO BLOCKERS

This was a static review of the frozen packet only. I did not build or run anything. The unfinished broad Debug/ReleaseSafe suites and the compiled negative control are not counted as passed.

## Checked and holding

**Refill, load and clock**
- The allowance is a single `next_at` on the awake clock, with no burst.
- It is spent only after both a distinct peer and a free node are secured.
- A failed send consumes it. A missing peer or empty pool does not.
- Clock regression and saturation fail closed.
- The cooldown can never delay a fresh FULL/reorg probe beyond its own threshold. A generation's primary is sent only after the previous generation retired, and therefore after that generation's spend. Its 1 s age threshold always falls at or after `next_at` while real and awake time advance together.
- So A→B→A churn stays at most one extra send per second. The cooldown only binds when real and awake time diverge (wall-clock steps, suspend).

**A→B→A and EMPTY**
- Every retirement cancels inflight and pending consensus nodes.
- Validating nodes are fenced by a monotonic generation plus `probe == desired == origin`.
- A retained-EMPTY `already_selected` change retires the probe without starting a new one.
- An anchor-only change with the same hash keeps the generation and its once-flag.

**Tagged-union safety**
- Every `get_block_headers` access on a reused node is guarded by message tag first: hedge scan, timeouts, cancel and `handleEth`.
- `logConsensusHeader` asserts the tag, and all its callers satisfy it.
- `requestHeadersFor` resets the secondary flag, id, peer and timestamps. BAL reuse never reads header metadata.

**Lifetimes**
- Every consensus node exits exactly once:
  - stale → freed
  - local error → freed, then fatal
  - empty or invalid alternate → freed
  - empty or invalid primary → reissued
  - winner → freed, siblings cancelled
  - expired alternate → freed
  - failed alternate send → freed
  - timed-out primary → reissued
- The transferred worker arena and response frame are released by `ValidatedResponse.deinit` on every path.
- The worker reads only the request's message and purpose, which the owner does not mutate while the request is validating.

**Fail-stop**
- Re-encode mismatch and missing Gloas fields can only arise from bytes whose raw keccak equals the CL hash. No peer can trigger or repair them.
- These are intercepted before the disconnect branch, keeping the pre-change fatal disposition.

**Races**
- The owner is serialized, so the first processed valid current result wins.
- A second result sees `probe == null` and is disposed as stale.
- Wire matching still requires id, peer index/epoch and tag.

## Material limits (non-blocking)

1. **Stated residual.** A silent primary plus an empty, invalid, failed or absent alternate still waits the ordinary deadline. That is 15 s for a fresh peer, or as little as about 2 s of alternate window when the primary peer's measured RTT gives a 3 s deadline. A primary reissue after empty, invalid or timeout never gets a second alternate in the same generation.

2. **Wall-clock dependence.** Age and deadline use the real clock.
   - A backward wall step suppresses hedging, as it already does existing timeouts, until wall time catches up.
   - A forward step can hedge early, still under the awake cooldown.
   - The cost is lost benefit, not extra load.

3. **Decode failures stay peer faults.** In `validateHeaders`, deserialization runs before the raw-hash check. If authentic bytes fail to decode (an unknown future field encoding), that is still treated as a peer fault. This is pre-existing; the hedge adds at most one extra eviction per generation.

4. **Dead stale branch in `handleConsensusHeader`.** The new stale check in `handleValidated` makes that function's desired-mismatch branch unreachable for worker results. The old branch also cleared `consensus_probe` when `desired == null`.
   - That case cannot occur in the hedge-eligible regime, because `desired` is the head hash and non-null once a checkpoint exists.
   - In bootstrap (no checkpoint yet, codes/hashing phase), the probe stays set until `desired` changes, and that change always retires it.
   - I found no stall, but it is a behavior divergence.

5. **Older-generation replies are discarded.** In A→B→A, a valid same-hash reply from an older generation is thrown away. The current primary continues, so this is conservative and has no correctness impact.

6. **Some INFO lines are bounded by rate, not by count.**
   - Bounded per generation: first primary send, response and empty validation; alternate send, failure and expiry.
   - Bounded by rate only:
     - primary timeouts (3 s minimum timeout)
     - peer-invalid validations (each disconnects the peer)
     - stale dispositions (one per outstanding request)
     - notice reasons alternating between `no_alternate` and `no_request_slot` (at most one per tick)

7. **Qualification gaps.**
   - `ConsensusHeaderHashMismatch` is not exercised through a real worker; only `PostGloasRequired` is.
   - Clock regression is tested only at the unit (budget) level.
   - The in-file "control" calls `checkRequestTimeouts` directly rather than running the owner with the hedge disabled. The proof that the positive test depends on the hedge rests on the unfinished compiled negative control.

8. **Pool gate bypass.** The hedge pops directly from `free_eth_requests`, bypassing `popFreeEthRequest`'s pending-empty gate. This is bounded to one node per generation.
