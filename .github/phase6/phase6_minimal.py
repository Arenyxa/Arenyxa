"""Reduced Phase6 observer: retain required boundaries, remove auxiliary hooks.

Full OS observer: rejected. Local-only full observer: rejected (-5.60% TPS).
This revision does not change thresholds. It removes due-check, facade, and
fd-select decoration; their local overhead remains inside unattributed wall.
The underlying methods still execute unchanged. No extra probes or SQL.
"""
import phase6_trace as base

class NoPolling(base.OSObserver):
    def start(self):
        return None

class MinimalRecorder(base.Recorder):
    def unhook(self, owner, name):
        for i in range(len(self.originals)-1, -1, -1):
            obj, attr, value = self.originals[i]
            if obj is owner and attr == name:
                if value is base.MISSING:
                    delattr(obj, attr)
                else:
                    setattr(obj, attr, value)
                self.originals.pop(i)
                return
        raise RuntimeError('Expected diagnostic hook not found: ' + name)

    def install(self):
        super().install()
        if self.full:
            self.unhook(self.Q, '_recover_expired_leases_if_due')
            self.unhook(self.rs._ConnectionFacade, 'execute')
            self.unhook(self.rs, 'select')

    def result(self):
        result = super().result()
        result['observation_profile'] = 'minimal-no-polling'
        result['availability'] = {
            'driver_execute_wall': True, 'checkout_wall': True,
            'existing_health_probe_wall': True, 'fetch_wall': True,
            'lease_materialization_wall': True, 'thread_rusage': True,
            'due_check_wall': False, 'facade_overhead_wall': False,
            'fd_select_decision': False, 'os_polling': False,
        }
        return result

if __name__ == '__main__':
    base.OSObserver = NoPolling
    base.Recorder = MinimalRecorder
    raise SystemExit(base.main())
