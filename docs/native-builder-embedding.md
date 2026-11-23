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
