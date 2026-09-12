"""Phase 6 observer revision: no SQL polling and no OS process polling.

Calibration run 34689736263 rejected the full observer. Each psutil process
sweep took about 2.4 seconds in that measured host. This revision removes
only that diagnostic polling thread. Existing business-call timings, exact
gate clock capture, and per-thread getrusage observations remain unchanged.
The original calibration thresholds remain unchanged and must pass again.
"""
import phase6_trace

class LocalCountersOnly(phase6_trace.OSObserver):
    def start(self):
        # Intentionally no worker, polling, file read, SQL or sleep.
        return None

if __name__ == '__main__':
    phase6_trace.OSObserver = LocalCountersOnly
    raise SystemExit(phase6_trace.main())
