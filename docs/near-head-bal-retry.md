# Bounded near-head BAL acquisition retry

CL-managed native construction cannot build on a new execution parent until its
block access list (BAL) has been fetched and the resulting state root verified.
The generic ETH request timeout starts at three times a five-second RTT estimate.
A silent peer can therefore hold up this path for fifteen seconds. Sepolia
observations on 26 November 2026 showed 13.9–27-second healing episodes and missing
gossip opportunities, with the header already available and no SNAP work pending.
The pre-change logs did not identify the individual peer or timeout transition;
acquisition delay was supported by the inflight ETH request, not proven per peer.

`Downloader.retryNearHeadBal` adds one alternate-peer send attempt for a waiting
single-block heal. Eligibility requires CL-managed operation, an existing verified
snapshot, a not-yet-applied BAL for the heal's final block, and the exact matching
single-hash request still in the downloader's inflight list. It waits one second
from that send and runs on the existing one-second tick, so nominal dispatch is
one to two seconds after the original send. This is not a bound on event-loop
scheduling, peer response time, validation or state readiness. Bootstrap and
multi-block batch requests retain their normal behavior.

The alternate must be a different connection epoch, advertise a recent block
range, and have spare per-peer request capacity. Geth broadcasts its range every
32 blocks (v1.17.4, `eth/handler.go:blockRangeState.shouldSend`); an announcement up
to 32 blocks behind is eligible. A range known to have pruned the required block
is excluded. Without a candidate, the original request is untouched and the
next tick may check again. Once selected, the extra-send budget is spent for the
exact logical block hash, including on a stale connection or full write queue.
Empty/invalid responses, ordinary retries and new CL heads do not replenish it.
Branch selection continues to wait for the existing heal to finish.

The extra send is a hedge. After successful enqueue, bounded metadata records a
second wire identity for the same pooled request, including its original peer,
request ID and block hash. The original identity and deadline remain unchanged.
The server copies the wire bytes into its bounded write queue; failed enqueue
leaves no alias. The alias also counts against the alternate peer's request limit.

Downloader event dispatch is single-owner and cancellation protected. The first
matching nonempty reply claims the single inflight node and transfers
it to validation; late duplicates and the losing reply cannot start another
validation. An already-received original reply remains eligible. An unavailable response (no entries or the protocol
`0x80` missing-BAL sentinel) keeps the other identity eligible: an empty alternate retires only its alias; an
empty original promotes the alternate on the same node with the original deadline.
Neither unavailable response enters validation while the other identity remains
live. The valid `0xc0` empty BAL still enters normal commitment validation. A timeout clears
the alias before the normal reissue. Exact original identity binding prevents an
old alternate reply from claiming a later retry for the same block. Requests
already handed to asynchronous validation cannot acquire a hedge. This neither
adds a second request-pool owner nor extends the original timeout.

The extra attempt applies no synthetic RTT penalty and disconnects no peer.
Generic timeout handling remains the fallback; both peers can still be slow. A
nonempty alternate still needs full validation: if it is invalid, ordinary reissue
applies. This is not a race of independently validated responses.
BAL decoding, commitment matching, authenticated trie updates, root checks and
atomic checkpoint publication are unchanged. No state is accepted because a
retry succeeded, and the retry does not access a second database writer.

The counters `downloader_bal_early_retry_attempts_total` and
`downloader_bal_early_retries_total` distinguish selected attempts from successfully
enqueued hedges. The no-peer counter counts eligible ticks without an alternate.
Rare retry logs record the block, original/alternate wire identity,
elapsed wait, winning response, decoded list count and successful state apply.
A decoded list is not yet an authenticated checkpoint.

Qualification must exercise real provider/queue ownership, timeout and delayed
responses, wrong identities, exhausted budget, cancellation and branch changes,
and identical authenticated checkpoint state with/without retry in Debug and
Safe. Production promotion additionally requires the normal native owner handoff
and a bounded Plataberget observation before Sepolia. A quiet observation alone
does not prove that a slow-peer retry was exercised or that win rate improved.
