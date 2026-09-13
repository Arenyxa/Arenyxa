"""Phase 7 observer v2: harden T3_driver to a post-flush readiness boundary.

The first Phase 7 observer recorded the first driver read-ready event anywhere
inside a libpq exchange. Psycopg's `_send()` can legally yield WAIT_RW while
outbound data is still being flushed; in that state a READY_R can be observed
and psycopg may consume input before `flush()` reaches zero. Such an event is
not the requested T2->T3 boundary.

This diagnostic-only extension preserves the original observer and adds a new,
strict field: `first_postflush_driver_read_ready`. It is set only when the
existing psycopg wait path reports READY_R after the exchange's recorded
`flush_end`. No socket read, poll/select call, SQL, or protocol operation is
introduced by this extension.
"""
from __future__ import annotations

import phase7_attribution as base


class Phase7RecorderV2(base.Phase7Recorder):
    def install(self):
        super().install()
        if not self.full:
            return

        import psycopg.waiting as waiting

        R = self
        parent_wait = waiting.wait
        READY_R = waiting.READY_R

        def postflush_proxy(gen):
            try:
                state = next(gen)
                while True:
                    ready = yield state
                    if ready & READY_R:
                        ex = R._exchange()
                        if ex is not None and ex.get("flush_end") is not None:
                            now = base.PC()
                            ex["postflush_read_ready_events"] = int(
                                ex.get("postflush_read_ready_events", 0)
                            ) + 1
                            if ex.get("first_postflush_driver_read_ready") is None:
                                ex["first_postflush_driver_read_ready"] = now
                    state = gen.send(ready)
            except StopIteration as stop:
                return stop.value

        def corrected_wait(gen, fileno, interval=0.1):
            ctx = R._ctx()
            if ctx is None:
                return parent_wait(gen, fileno, interval=interval)
            return parent_wait(postflush_proxy(gen), fileno, interval=interval)

        self.patch(waiting, "wait", corrected_wait)

    def result(self):
        result = super().result()
        semantics = result.setdefault("phase7_semantics", {})
        semantics.update({
            "t3_driver_field": "first_postflush_driver_read_ready",
            "t3_driver_requires_flush_complete": True,
            "preflush_read_ready_retained_only_as_control": True,
            "t3_driver_is_kernel_first_readable": False,
        })
        return result


# base.main() resolves this global at runtime.
base.Phase7Recorder = Phase7RecorderV2


if __name__ == "__main__":
    raise SystemExit(base.main())
