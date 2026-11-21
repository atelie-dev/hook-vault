# 0001 — Wake signal for the event stream

- **Status**: accepted
- **Date**: 2026-11-21
- **Related**: `internal/httpapi/stream.go`, `internal/httpapi/ingest.go`,
  AGENTS invariant 4, `README.md` (Streaming), `docs/consumer-guide.md`

## Context

`GET /v1/events/stream` pushes committed events as server-sent events. The
stream needs to learn that an ingest committed. Three facts bound the choice:

- Both planes run in one process, and every insert happens in that process. An
  in-process signal is available without any infrastructure.
- The stream always **re-reads** through `store.FetchEvents`, so the signal only
  has to say "look again". A missed signal costs latency, never correctness.
- The ingest path must never fail because of the read path: the project already
  refuses to 5xx a delivery for quota reasons (AGENTS invariant 5), and the same
  reasoning applies to anything the streaming side introduces.

## Decision

The ingest handler signals after commit with a non-blocking send on a capacity-1
channel (`Server.wakeReaders`). A stream wakes on any of: request context done,
the signal, a 1s fallback tick (`streamFallback`), a 15s ping tick
(`streamHeartbeat`). No payload travels on the signal: the wake itself is the
only message, and the stream drains everything visible with `streamPageSize`
(200) events per query.

No `LISTEN`/`NOTIFY`. No in-process fan-out of event bodies.

## Consequences

Positive:

- No extra database connection, so no interaction with PgBouncer transaction
  pooling, no session state to babysit, and no new way for the service to look
  healthy while it is not.
- A coalesced, late or missed signal degrades to one tick by construction, which
  is the same bound as the multi-replica case. There is no silent-failure mode
  to monitor.
- The database stays the single source of truth: the wake carries nothing, so it
  cannot disagree with what a reader would fetch.

Negative:

- Each open stream costs one query per second while idle. At the current scale
  this is noise next to the ingest traffic, but it is not free.
- Cross-replica delivery has a worst case of 1s, set by the tick rather than by
  the commit.

## Alternatives considered

1. **Client polling** (what `hook-vault fetch --watch` still does, with
   `--interval` 5s). Works and needs no server support, but multiplies requests
   by consumer count. Kept for the CLI; the stream is the better path for a
   long-lived consumer.
2. **`LISTEN`/`NOTIFY`.** Attractive because notification is delivered at commit
   time. Rejected:
   - `LISTEN` is session state: it needs a connection held for the process
     lifetime, with its own reconnect and shutdown handling.
   - It does not survive transaction-mode pooling (PgBouncer), which the
     deployment contract does not forbid.
   - A dropped listener connection degrades the stream to the fallback tick with
     nothing in the logs — a silent failure, against this project's rules.
   - The notification queue has a bound: a stalled listener can make the
     notifying transaction fail, which would turn a webhook ingest into a 5xx
     and amplify provider retries. A reader must not be able to break the writer.
   - `NOTIFY` payloads are capped at 8000 bytes, so the event could never travel
     in it; the design stays a nudge, and the win is only the idle query.
3. **In-process hub broadcasting events.** Would avoid the re-read, but adds
   per-consumer buffering and backpressure, lets the hub disagree with the
   database, and does nothing for another replica.
4. **Push delivery to consumers' HTTP endpoints.** Out of scope: this is an
   append-only log; push belongs in front (Svix, Hookdeck Outpost).

## Revisit when

- more than one replica runs **and** measured p95 commit-to-delivery exceeds 1s
  under real traffic, or
- idle queries from open streams become a measurable share of database load.

Order of escalation: first lower `streamFallback` (a 250ms tick is still cheap
and adds no state), measure again, and only then consider opt-in
`LISTEN`/`NOTIFY` with an empty payload, the ticker kept, and a health check
that fails loudly when the listener connection is gone.
