"""Arenyxa P99 Phase 7 observer v3 — psycopg C-generator aware.

Why v3 exists
-------------
psycopg-binary 3.3.5 replaces `psycopg.generators.execute/send/fetch*` with
C-extension implementations. The first diagnostic observer correctly wrapped
the high-level `BaseCursor.execute` exchange, but Python `_send/_fetch` hooks
were bypassed. V3 observes the *actual C execute generator* only through its
existing yield/send protocol. It never calls PQconsumeInput, recv/read,
poll/select, or SQL.

Psycopg 3.3.5 C source establishes a useful semantic distinction:
- `send()` yields WAIT_RW only while libpq flush is incomplete.
- after `send()` returns, `fetch_many()`/`fetch()` may yield WAIT_R while waiting
  for response data; at this point libpq flush has already returned 0.

Therefore V3 can directly distinguish send-backpressure waits from post-flush
fetch waits without replacing the C implementation. The exact instant at which
PQflush returned 0 remains NOT DIRECTLY OBSERVABLE. The first WAIT_R yield is a
post-flush upper-bound boundary (`postflush_fetch_wait_begin`).
"""
from __future__ import annotations

from typing import Any

import phase7_attribution as base


class Phase7RecorderV3(base.Phase7Recorder):
    def install(self):
        super().install()
        if not self.full:
            return

        import psycopg._cursor_base as cb
        from psycopg._enums import Ready, Wait

        R = self
        parent_exchange = cb.execute
        WAIT_R = int(Wait.R)
        WAIT_W = int(Wait.W)
        READY_R = int(Ready.R)
        READY_W = int(Ready.W)

        def _get_new_exchange(ctx: dict[str, Any], before: int):
            exchanges = ctx.get("exchanges") or []
            return exchanges[before] if len(exchanges) > before else None

        def observed_c_exchange(pgconn):
            ctx = R._ctx()
            if ctx is None:
                return (yield from parent_exchange(pgconn))

            before = len(ctx.get("exchanges") or [])
            gen = parent_exchange(pgconn)
            state = None
            ex = None

            try:
                try:
                    state = next(gen)
                except StopIteration as stop:
                    ex = _get_new_exchange(ctx, before)
                    if ex is not None:
                        now = base.PC()
                        ex.update({
                            "v3_generator_begin": ex.get("begin"),
                            "v3_generator_end": now,
                            "v3_waits": [],
                            "v3_immediate_completion": True,
                            "v3_first_send_wait": None,
                            "v3_postflush_fetch_wait_begin": None,
                            "v3_first_fetch_ready": None,
                        })
                    return stop.value

                ex = _get_new_exchange(ctx, before)
                if ex is not None:
                    ex.update({
                        "v3_generator_begin": ex.get("begin"),
                        "v3_generator_end": None,
                        "v3_waits": [],
                        "v3_immediate_completion": False,
                        "v3_first_send_wait": None,
                        "v3_postflush_fetch_wait_begin": None,
                        "v3_first_fetch_ready": None,
                    })

                while True:
                    requested = base.PC()
                    state_i = int(state)
                    if state_i & WAIT_W:
                        phase = "send_wait"
                    elif state_i & WAIT_R:
                        phase = "fetch_wait"
                    else:
                        phase = "other_wait"

                    event = {
                        "phase": phase,
                        "state": state_i,
                        "wait_requested": requested,
                        "ready": None,
                        "resumed": None,
                    }
                    if ex is not None:
                        ex["v3_waits"].append(event)
                        if phase == "send_wait" and ex["v3_first_send_wait"] is None:
                            ex["v3_first_send_wait"] = requested
                        if (
                            phase == "fetch_wait"
                            and ex["v3_postflush_fetch_wait_begin"] is None
                        ):
                            # C source guarantee: fetch_many() starts only after
                            # send() has returned, and send() returns after
                            # PQflush()==0. This is an upper bound on exact T2.
                            ex["v3_postflush_fetch_wait_begin"] = requested

                    ready = yield state
                    resumed = base.PC()
                    event["ready"] = None if ready is None else int(ready)
                    event["resumed"] = resumed

                    if ex is not None and ready is not None:
                        ready_i = int(ready)
                        if (
                            phase == "fetch_wait"
                            and (ready_i & READY_R)
                            and ex["v3_first_fetch_ready"] is None
                        ):
                            # This is when psycopg's existing wait path resumes
                            # the generator. It is NOT kernel-first-readable.
                            ex["v3_first_fetch_ready"] = resumed
                        if phase == "send_wait" and (ready_i & READY_R):
                            ex["v3_send_wait_read_ready"] = int(
                                ex.get("v3_send_wait_read_ready", 0)
                            ) + 1
                        if phase == "send_wait" and (ready_i & READY_W):
                            ex["v3_send_wait_write_ready"] = int(
                                ex.get("v3_send_wait_write_ready", 0)
                            ) + 1

                    try:
                        state = gen.send(ready)
                    except StopIteration as stop:
                        if ex is None:
                            ex = _get_new_exchange(ctx, before)
                        if ex is not None:
                            ex["v3_generator_end"] = base.PC()
                        return stop.value
            except BaseException:
                if ex is None:
                    ex = _get_new_exchange(ctx, before)
                if ex is not None and ex.get("v3_generator_end") is None:
                    ex["v3_generator_end"] = base.PC()
                    ex["v3_exception"] = True
                raise

        self.patch(cb, "execute", observed_c_exchange)

    def result(self):
        result = super().result()
        result["phase7_profile"] = (
            "cgen+schedstat" if self.schedstat else "cgen-core"
        )
        semantics = result.setdefault("phase7_semantics", {})
        semantics.update({
            "observer_version": "v3-c-generator-aware",
            "actual_exchange_generator_observed": True,
            "pqflush_exact_return_time": "NOT DIRECTLY OBSERVABLE",
            "postflush_fetch_wait_begin": (
                "DIRECTLY OBSERVED generator boundary after C send() returned; "
                "upper bound on exact PQflush()==0 time"
            ),
            "first_fetch_ready": (
                "DIRECTLY OBSERVED when existing psycopg wait resumes a fetch WAIT_R; "
                "NOT kernel-first-readable"
            ),
            "pqconsumeinput_directly_observed": False,
            "socket_consumption_by_observer": False,
            "poll_or_select_by_observer": False,
            "extra_sql": False,
        })
        return result


base.Phase7Recorder = Phase7RecorderV3


if __name__ == "__main__":
    raise SystemExit(base.main())
