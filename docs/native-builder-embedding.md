# Optional native builder embedding

The public `node` build module exports `mainWithBuilder(init, Builder)` for a
separately built native constructor. The normal executable calls the same entry
with `void`, preserves its existing behavior and refuses `--native-builder` when
no adapter is linked. This hook does not change the execution engine or turn
zevm into a bid publisher.

The opt-in adapter receives the actual `Eth` and `Snapshots` owners and returns
a typed public handoff sink and a consensus attribute sink. It must remain at a
stable address until both its task and all producers have joined. The handoff
copies borrowed transaction bytes before returning. The consensus callback may
copy to a bounded queue but must not execute, acquire state or perform I/O.

`AttributesEvent` binds the full borrowed JSON to a verified execution parent
and beacon root, with wall/monotonic receipt clocks. Fork-choice verification
precedes delivery; delivery precedes execution-parent deduplication. A repeated
parent hash can therefore supply a different slot, withdrawal set or beacon
branch. The adapter must validate every relevant attribute and obtain an exact
native state lease; an event is not permission to substitute the latest head.

An actual stream loss/reconnect calls `invalidate`. Transient per-event target
lookup failures do not revoke previously verified attributes: for example a
FULL event can precede its validated fork-choice entry while the EMPTY context
remains usable. The adapter must still impose short deadlines and explicit
authority generations on retained contexts. No callback may outlive the adapter.

An attribute event's read-only fork-choice GET retries once only on clean EOF
before any response bytes (`HttpConnectionClosing`). Both attempts share the
existing two-second timeout and publication mutex. The SSE
frame and wall/monotonic clocks sampled at its first dispatch remain unchanged;
the consumer's original target-based expiry policy is untouched. The successful
response must still certify the event's exact execution parent and beacon root.
Other transport failures,
semantic rejection, mailbox refusal and publication failure are not retried;
head/reconciliation and execution-payload events retain their existing policy.
This bounded GET policy also applies to the stock node without an attribute sink.
Another pooled connection can also be stale; two failures still drop the event.
Terminal event warnings identify the event kind without exposing its contents.

`test/consensus_attributes_retry_test.py` uses the optional `attributes` mode of
`consensus-probe` against a local fixture. It exercises recovery, primary and
alternate frames, a single stale pooled keep-alive socket, exhausted retry,
shared timeout, cancellation, malformed and unverified/unbound attributes, and
unchanged non-attribute behavior. The probe
copies only fixed scalar metadata and a body digest into a bounded nonblocking
observation queue. These tests establish recovery from one clean pre-header EOF,
not recovery from every possible transport interruption, nor the cause or
outcome of any particular historical missed slot.

Node supervision joins the sync and builder tasks together. It then joins the
tracker/public producers before destroying the adapter, and destroys snapshots
and the store last. Adapter failures cannot silently leave sync running under
the appearance of a healthy constructor. A deliberate shadow artifact failure
can be handled locally by the adapter, while cancellation must propagate.

The initial consumer is zbuilder's opt-in combined shadow node. It constructs
from public peer input and exact native state without Geth RPC. Private orders,
cancellation generations, signing and publisher reveal obligations are not part
of this module. See `docs/public-intake.md` and `docs/public-intake-blobs.md` for
the owned transaction sink, asynchronous status and blob capability contracts.
