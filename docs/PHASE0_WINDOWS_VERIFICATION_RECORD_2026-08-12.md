# Arenyxa v6.8 Phase 0 — Native Windows Verification Record

Date: 2026-08-12  
Status: **PENDING NATIVE WINDOWS SIGN-OFF**

This record is intentionally not pre-checked. A real Windows run is a Roadmap hard gate and must not be replaced by headless/offscreen evidence.

## Host identity

- Windows edition/build: ____________________
- Python/runtime lane: Modern / Legacy Enterprise
- Qt binding/version: ____________________
- GPU/driver: ____________________
- Monitor count: ____________________
- Monitor resolutions/scales: ____________________
- Capture backend (if used): ____________________

## Required checks

- [ ] Freshly extract the frozen source ZIP to a new directory.
- [ ] Run `python scripts/verify_phase0_baseline.py` and record PASS.
- [ ] Run the normal project regression/test command and record 0 unexpected failures.
- [ ] Run application `test-all`.
- [ ] Run `stress-test standard`; verify bounded ramp and zero unexpected errors.
- [ ] Run `stress-test extreme`; verify bounded ramp and zero unexpected errors.
- [ ] Launch repeatedly with both monitors active; Splash/logo and main window stay on the intended screen and maintain geometric continuity.
- [ ] Verify per-monitor DPI/scaling paths and manual UI text scaling.
- [ ] Verify X-style center-logo handoff: no second-window feel, no early main-panel reveal, no stale splash after the main surface becomes visible.
- [ ] Run Repair Center repeatedly; one visible progress terminal only, lifecycle terminates cleanly.
- [ ] Start/stop Browser and native/tshark Capture; progress indicator clears at terminal state.
- [ ] Exercise pause/resume/stop for a representative Run/Workflow and verify persisted state matches the visible state after restart.
- [ ] Verify storage disconnect/full-disk or another controlled persistence-failure path produces an explicit error rather than silent success.

## Result

- Gate result: PASS / FAIL
- Blocking observations: ____________________
- Verifier: ____________________
- Time: ____________________
