# Independent owner-root review records

Both reviews used actual `claude-opus-5-5`, effort `xhigh`, with tools disabled and no persistent session. The production `native_state.zig` bytes remained unchanged across the reviews and final benchmarks (SHA-256 `d92defcfa2cb4527d591c9a48e11ae553d744a9565fe01c903964dc776c2046e`). These are source reviews, not executed tests. The closure review preceded completion of the final timing blocks; its pending evidence gates are resolved in the qualification report, not rewritten here.

The negative control compiles and fails exactly five `owner_reads` assertions, with the other 52 tests passing. The treatment passes all 57 in Debug and Safe. Allocation fault coverage concerns backing allocator/arena-refill failures, not every logical scratch allocation site or lease reuse after every OOM. No new allocation site is introduced by the production change.

The final qualification separates the strong-poison ownership cohort from the production-default Runtime/Host/Intake allocator cohorts, binds binaries to toolchain/flags/source, preserves full byte equality and counter checks, and reports matched process pairs with load and sample-size limits. It makes no live, Prepared, gossip or deadline claim.

## opus-owner-root-r1

Packet SHA-256: `84480c24301505f89dba5557114d9bf18e75272f9e81da0f395b82c83983b456`. Result SHA-256: `1f3ff52607e0689cb33325c746a03f08578ad91cc96f37b04767f950ccd02375`.

# Review: exact-parent owner-root reuse in `readNodeUncached`

I reviewed only the pasted source and ran no tools. I could not see `StorageTrieResolver`, `Trie.withRoot`, or Runtime/Host internals, and I note below where a conclusion depends on them.

## Verdict

**No correctness, ownership, authentication, or cancellation blocker in the production change.** It is fine for the isolated experiment. Any performance claim is gated on the benchmark items below.

## Root-authorization audit

These are all the places that write to `NodeCache.entries`, and what each means for `Key(X, &.{})`.

| Site | What it can install | Owner-root relevance |
|---|---|---|
| `src/native_state.zig:186` `enableNodeCache` | `Key(null, &.{})` = header state root | Account trie only. It never creates an owner-X key. |
| `src/native_state.zig:226` `readAccount` | `Key(X, &.{})` = `storage_hash` from `getAuthenticated` against `view.header.state_root` on this lease's txn | **Primary source of owner roots.** |
| `src/native_state.zig:113` `remember(key, expected)` | `key` itself | For `Key(X, &.{})` this is reached only in two ways. Via `:265`, where the entry already exists, so it is a no-op at `:100-102`. Or via the `:288` fallback. In that case the `:310` lookup uses the same key that just missed at `:265`, so reuse cannot occur. It always goes through `:313` → `:226` first, and `nodeAtPath` at depth 0 forces `expected` to equal that root (`trie.zig:287-289`). |
| `src/native_state.zig:122` child edges | `Key(key.owner, child path)` | The owner is inherited, so account-trie nodes never yield owner-X keys. Leaves yield no references (`trie.zig:251`), so an account leaf is never parsed into a storage root. Branch and ext edges have depth strictly greater than the parent. A top-level `.hashed` would only re-key the parent itself, and `:101` rejects a differing hash. |

**Conclusion:** any `Key(X, &.{})` entry implies a prior successful authenticated `readAccount(X)` in the same immutable txn. `:310` therefore returns exactly the value `:313` would return.

Consequences:
- **Reachability is still authenticated.** `:317` still walks from that root through the path and hash checks (`trie.zig:286-311`). The preimage hash is checked at `trie.zig:211`.
- **The returned bytes are owned.** They are a dupe in the caller's `a` (`trie.zig:212`).
- **No root crosses leases.** The cache lives on the lease and is freed at `:170`.
- **Same-hash view promotion is safe.** When `snapshot.zig:62-77` promotes a view with the same header hash, the new txn goes only to new leases. Your corrupt/missing tests depend on exactly this.
- **Cache evolution is identical to baseline.** In the old code, `:226` on an already-present equal root was a no-op. So `entries`, `capacity_misses`, `hits`, `authorized_reads`, `fallback_reads` and `retained_bytes` evolve identically to baseline for the same request sequence. Only `owner_reads` changes.
- **The `.?` invariant at `:275` is unchanged.**

## Production findings

1. **Low, accepted trade-off — `native_state.zig:310`.** The removed per-fallback `readAccount` also re-ran `:226`. That acted as a self-consistency check: a mismatching cached root would raise `StateRootMismatch`. Since insertion has a single source and the txn is immutable, this check was redundant. No action needed; I'm noting it so the loss is deliberate.

2. **Low — cancellation points on the reuse path drop from 4 to 2.**
   - Remaining: `:261` at entry and `:299` before publication.
   - Removed: `:218` → `:211`, and `:225`. Nothing blocking ran between them except the account walk being skipped.
   - Cancellation still precedes any publication, so this is not a blocker. A test is suggested below.

3. **Nit — `docs/native-state.md:70`.** It says `owner_reads` counts "actual fallback account reads". However, `:311` increments before `:313`, so cancelled or failed reads are counted too. That matches the "attempted work" wording at `docs/native-state.md:61`; say "attempted" here. Also, the counter's meaning changed: before, it roughly equalled the storage fallback count. Any consumer using it as a proxy for fallbacks must be updated.

4. **Info — `docs/native-state.md:40`.** The 16,384 → 32,768 change is a doc correction to match the existing limit at `native_state.zig:81` and the test that rejects 32,769. It is not part of this optimization. Optionally split it out to keep the diff narrow.

## Tests

**Coverage of the new path is good:**
- Cross-parent and cross-lease isolation: `native_state_tests.zig:779`, `:781`
- Absent owner does not borrow another owner's root: `:783-784`
- No reuse when the root was never retained: `:791-792`
- Unreachable valid preimage is still rejected through the walk: `:827`
- Corrupt preimage: `:828`
- Missing node: `:839`
- Strict counter: `:686`

**Optional additions and caveats:**
- **Cancellation on the reuse path.** Use `max_entries = 2`, read the account, then call `readNode(child)` with `fail_at = 2`. Expect `Canceled`, unchanged `entries` and `retained_bytes`, and a usable lease. A follow-up with `fail_at = 3` that succeeds pins that no hidden extra checks exist.
- **Allocation failure on the reuse path.** `cacheAllocationRead` only reaches the authorized path, because the root is cached before `readNode(&.{})`. Add a saturated child read to it.
- **The hash after close at `:794` proves validity, not non-aliasing.** The MDBX map stays mapped, and the `first` view is still held by `Snapshots` and by `control` (`:755`), so its pages cannot be recycled. A slice aliasing mmap would pass too. Non-aliasing is guaranteed structurally by `trie.zig:212`, and `max_bytes = 0` rules out aliasing the cache. Don't cite `:794` as proof of non-aliasing.
- **Status.** The 56/56 result predates the tightening, so the final tree is unverified until you rerun it, as you noted.

## Benchmark false-positive risks (for a performance claim)

1. **Blocker for a claim — the treatment path being exercised is never asserted.** `entries == 32768` and `fallback_reads > 0` hold in both arms. Use the emitted `finalMetrics` in fixed-work mode to gate on:
   - Every cache stat except `owner_reads` is identical across arms. This follows from the audit above.
   - The treatment has `owner_reads ≈ 0`.
   - The control has `owner_reads ≈ fallback_reads` (minus any account-trie fallbacks).

   This also proves build provenance, i.e. that each arm actually linked the intended producer. Emitting a source or build ID would help too.

2. **Blocker for a claim — sample size.** Iteration 0 is warm-up and iteration 2 flips the primary, so each (schedule, primary) cell has n = 1 per process. You need interleaved, multi-process ABAB repetitions, reported as distributions. Keep the CPU governor and load fixed.

3. **Medium — build mode and allocator.** Debug signature checks dominate the run; the code comment already allows 10 s for them. If per-read scratch reaches `std.testing.allocator` in Debug, the per-allocation cost inflates the savings from the allocations the treatment removes (account-trie resolver, decode, RLP). Time in the deployed optimize mode with the production allocator path.

4. **Medium — choice of metric.**
   - In `deployed_owner`, the seal count varies, and completion and publication times are quantized by the 10 ms pacing and the 250 ms secondary interval. A small per-seal saving can show up as a large step or as nothing.
   - In fixed-work Release runs, if ticks take under 10 ms, `elapsed` hits the sleep floor.
   - Use `tick_ns`, `seal_ns_by_branch / seals_by_branch` and `cpu_ns` as primary metrics, not `elapsed` or `complete_ns`.

5. **Medium — representativeness of the cache config.** The patch is a no-op without a cache (`:309`). If the deployed Runtime runs with the cache disabled or at the 4,096 default, a 32,768-entry result does not qualify the deployed configuration. Also, the fixture's account trie is tiny, so per-fallback savings understate mainnet-sized tries. That direction is a false negative, not a false positive.

6. **Low — the rendezvous adds jitter.** The `appended` callback blocks the Host tick on a cross-task wake. This adds scheduler jitter to one primary tick's `tick_ns`. Exclude that tick or report it separately.

7. **Low — receipts are reconstructed, not producer bytes.** `assertEffects` builds receipts with hardcoded `status = 1`, zero bloom, no logs, and cumulative gas from `charged_gas`. Their equality proves only that the gas and tx-type sequences match. The authoritative check is the payload digest, provided `Output` carries the receipts root or block hash. Also, receipts are collected in `runtime.slots` order but exported as primary/secondary. This is harmless here only because both branches are identical.

8. **Low — the retention-after-teardown check depends on build mode.** It only discriminates under a poisoning or unmapping allocator, as in a Debug testing allocator. In Release, a use-after-free can hash identical stale bytes. Keep that assertion in the Debug/Safe runs.

9. **Interpretation, not a false positive.** `readStorage` at `:232` still re-reads the owner account on every call. If execution-phase storage reads dominate, the end-to-end delta will be small. Attribute any win to seal and finalizer time specifically.

## opus-owner-root-closure

Packet SHA-256: `08293ee3672c08b2c00cec2eb1df9a22b4ed38c2f5f6f6b6cf1effa4141c5985`. Result SHA-256: `1e8fc3f9aaa165a29690465800860386e6110affda7b5190258bf23d4cd13e72`.

# Closure review: exact-parent owner-root reuse

I reviewed only this packet and ran no tools. The production delta is unchanged, so the prior audit still applies and there is nothing new to raise in production code.

## Verdict

| Scope | Status |
|---|---|
| Production correctness, ownership, authentication, cancellation | **Closed.** No blocker. |
| Local mechanism claim on the fixed-work saturated fixture | **Supported by the evidence you already have.** The counters and literal payload/receipt equality are deterministic and do not depend on the allocator. One item remains: B1. |
| Any CPU or time number | **Not yet.** It is gated on the pending production-allocator run and on B3. |

## Blockers

### B1. Baseline negative control: pin the exact expected failure set (pending)

The final baseline should fail exactly 5 tests, each at an `owner_reads` assertion:
- `:686`
- the sibling/absent test
- the unreachable/corrupt/missing test
- the cancellation test at `native_state_tests.zig:931`
- the allocation test at `:946`, reached through the first unfaulted pass of `:988`

The other 52 should pass. If anything else fails, or a test fails at a non-`owner_reads` line, the tests are measuring more than the delta. Record the failing names and lines alongside the result.

### B2. "All allocation-failure points" overstates the allocation test

**What the test actually exercises.** `saturatedAllocationRead` sends all scratch through `ArenaAllocator(allocator)`. The FailingAllocator therefore only sees arena node refills; `noResize` makes every refill a new node. After `readAccount` at `:943` has warmed the arena, the reuse `readNode` at `:944` may see zero or one failure points.

**What it proves:**
- No leak of cache metadata or arena nodes.
- `active_leases` is released on every backing failure.

**What it does not prove:**
- OOM handling at each reuse-path site (`openStorageTrie`, `nodeAtPath`, `hashedChildReferences`).
- Lease usability after a mid-read OOM. Each iteration builds a fresh lease and returns at the first error.

This is not a production blocker, because the delta adds no allocation site. It is a blocker only for the sentence as written. Pick one fix:
- **Reword** to "every backing-allocator (arena-refill) failure point".
- **Minimum strengthening.** Give `readNode` its own fresh arena so its first allocation always reaches the backing allocator. Or record `alloc_index` around `:944` in the unfaulted pass and assert it is greater than 0.
- **Real per-site coverage:**
  1. Use one pre-saturated lease.
  2. For the `readNode` call only, use `FailingAllocator.init(arena.allocator(), .{ .fail_index = i })` and loop `i` until the call succeeds.
  3. After each OOM, assert that `entries`, `retained_bytes`, `capacity_misses` and `owner_reads == 0` are unchanged.
  4. Then assert that an unfaulted read returns the control bytes.

  You need no leak check here, because scratch is caller-reset by contract.

### B3. Gates for a performance number (only if you report one)

1. **Pending run.** Don't publish 23.031 s → 20.288 s. It is instrumented-allocator evidence.
2. **The independent unit is the process.** One ABBA block is 2 processes per arm; your 4 observations per arm/schedule are two within-process pairs.
   - Report the paired block differences T₁−C₀ and T₂−C₃.
   - With one block, the most you can claim is "direction consistent in both pairs".
   - A magnitude needs at least 3 blocks, alternating ABBA and BAAB.
3. **First-position bias.** Control always occupies position 0, which gets cold binary pages, a fresh tmp/page cache and frequency ramp. ABBA cancels linear drift but not a first-process step, so this bias favours the treatment.
   - Fix: add a discarded priming process, or show that control run 0 and run 3 are indistinguishable on in-loop metrics.
4. **Metric.** Primary metrics should be fixed-work in-loop `cpuNs`, plus `seal_cpu_ns / seal_calls` and `seal_wall_ns / seal_calls` from `finalMetrics`.
   - `/usr/bin/time` user+sys covers Env build, signatures, warmups and assertions.
   - If the 23 → 20 figure is that number, label it as whole-process CPU.
5. **Build provenance.** The driver hashes binaries but does not bind them to source or flags. The `owner_reads` gate proves which `readNodeUncached` is linked. It does not prove that the optimize mode, CPU target, compiler and other sources match.
   - For each binary, record the zig hash, `-Doptimize`, target/cpu and source-file hashes.
   - Assert they are identical except for `src/native_state.zig`.
   - If the build helper already records this, reference it from `manifest.json`.
6. **The summarizer is not in the packet.** Medians and ranges must come from a hashed script recorded in the manifest. It must filter `warmup == false`, and only `fixed_work` may feed equal-work estimates.
7. **"As deployed" has two preconditions.** It assumes the deployment is `-Doptimize=safe` and that the adapter's `a` is an unwrapped `init.gpa`. State both in the manifest. In ReleaseFast the gpa is `c_allocator` or `smp_allocator`, and this run would overstate the allocation savings.

## Added tests

### Cancellation test (`:894`)

In my trace it passes for the right reason:
- Call 1 is the `checkedView` in `readNode`.
- The reuse lookup performs no check.
- Call 2 is `:299`, or a check inside the trie open/walk; either way it comes before `remember`.

It also discriminates against baseline: baseline increments `owner_reads` before `readAccount`, so `:931` fails. Recommended cheap tightenings (not blocking):
- **`:929–930` are vacuous at saturation.** A full map with `max_bytes = 0` cannot change `entries` or `retained_bytes` even if publication ran. The observable that tests ordering is `capacity_misses`, which `remember` increments at saturation. Assert it is unchanged.
- **`owner_reads == 0` alone also holds if cancellation fired before the fallback.** Add `fallback_reads == before.fallback_reads + 1` to prove the reuse branch was entered.
- **The name promises "authorization usable", but `:933` would succeed without the root.** Assert `owner_reads == 0` after it.
- Optionally, failing at call 3 should succeed. That pins exactly 2 checks on the reuse path.

### Allocation addition (`:983–991`)

- **Nit.** `control` at `:983` has no `defer`. If `nodeQueries` fails, the `Reader.deinit` assert fires instead of returning a clean error.
- **Nit.** There is no `owner_reads` assertion after the second read at `:948`.

## Benchmark allocator lifecycle

The lifecycle is correct:
- The `production_allocator` defer is registered first, so it runs last.
- `retained.release()` runs before it.
- `sample.deinit()` releases outputs and old results.
- On runHost error paths, the `old`/`final` errdefers release once; the Sample is discarded, so nothing is released twice.
- The leak check therefore runs after everything is released.

**Scope caveat.** `std.testing.io` is Threaded over the strong-poison testing allocator (test_runner `:281`). Io task allocations, Env/Snapshots, and `assertEffects`/`digest`/`emit` still use it. That is negligible and mostly outside the loop. The accurate wording is "Runtime/Host/Intake on the production-default allocator", not "the process".

**Retention check.** `retainedAfterRuntimeTeardown` is genuinely checked by `sample.verify()` after runHost has torn down the runtime. Under default options it is weak use-after-free evidence; keep citing the strong-poison run for ownership.

## Optional nits

- **Primary/position confound.** Primary 2 is always iteration 2. This is matched across arms, so don't interpret per-primary differences.
- **Rendezvous wait (prior item 6).** It is still inside `tick_ns`. This is matched jitter; keep `tick_ns` secondary or exclude the trigger tick.
- **`deployed_owner` has no `owner_reads` gate.** This is redundant given the same-process fixed-work gate.
- **Budgets differ from the adapter.**
  - Runtime: `worker_bytes` 512 vs 384 MiB, `result_bytes` 16 vs 32 MiB, `retained_bytes` 128 vs 256 MiB.
  - Host: `drain_per_tick` and `branches`.

  List these under Limits. If 384 MiB would fail this workload, say so.
- **Fixture-specific control gate.** `owner_reads == fallback_reads` holds only because this fixture has no account-trie fallbacks.
- **Cross-manifest check.** The production-allocator run's payload artifacts and fixed counters should be byte-identical to the instrumented run's. A one-line diff confirms allocator independence.
- **Baseline error-equivalence.** The negative control stops at the first `owner_reads` failure. Build baseline with baseline-expected `owner_reads` values to show the errors are unchanged: `TrieNodeHashMismatch`, `StateRootMismatch`, `SubTrieNotAvailable`, `TrieNodePathUnavailable`.
- **Docs.** The 16,384 → 32,768 correction is still bundled; splitting it out is optional. Also grep for consumers that treat `owner_reads` as a fallback proxy.
- **Extra metric.** Report `seal_scratch_peak_bytes` as a secondary, ungated metric.

## Supportable claim wording

**Now:**
> On a synthetic 65,536-slot fixture with a saturated 32,768-entry / 4 MiB lease cache (two branches, 65 transactions, Safe build), reusing the lease-authenticated owner storage root eliminates every fallback owner-account read: 224,148 → 0 per fixed-work sample. Payloads and receipts are byte-identical, and node reads, seals and all other cache counters are equal.

**After B3, if the paired differences agree in sign:**
> Across N ABBA blocks using the production-default SafeAllocator, fixed-work in-loop CPU changed by [range of paired differences], and seal CPU per seal changed by [range].

**Not supportable:** live, Prepared, gossip or deadline effects, bid value, or deployed magnitude. Two reasons:
- The fixture's account trie is tiny, so the per-read saving is likely understated.
- The real-block fallback rate is unknown.
