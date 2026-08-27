# Arenyxa v7.8 P0/P1 Security and Reliability Fixes

- Added explicit external binary version/capability contracts for tshark, dumpcap, and mitmdump.
- Required tshark schema fields are verified before capture/analysis execution.
- Hardened distributed lease recovery against renew/recover and complete/recover races.
- Added queue invariant auditing for lease ownership and worker active-lease accounting.
- Moved blocking persistence work away from the asyncio event-loop thread.
- Added bounded cancellation/finalization behavior for async request tasks.
- Added non-interactive Developer authentication using the existing signed bundle and encrypted vault model without plaintext environment-secret injection.
- Reduced and statically classified broad exception boundaries in critical execution paths.
- Raised global coverage governance and added critical-module coverage thresholds to CI.
