# Arenyxa Phase 1–2 Native Windows Verification Record

Status: PENDING

Use this after extracting the final Phase 1–2 source ZIP on the target Windows machine.

## Startup baseline preservation

- [ ] `RUN_ARENYXA.cmd` starts successfully from a clean/current project path.
- [ ] Approved startup animation looks identical to the accepted Phase 0 animation.
- [ ] Icon-to-main-window handoff timing/continuity is unchanged.
- [ ] Dual-monitor placement remains coherent.
- [ ] 100%, 125%, 150%, 175%, 200% DPI do not alter the intended animation appearance.

## Phase 1 behavior

- [ ] Existing Run pause/resume/stop behavior remains unchanged.
- [ ] Workflow/Dataset operations retain existing lifecycle behavior.
- [ ] Capture start/pause/resume/stop remains stable.
- [ ] Repair Center still opens and exits normally.
- [ ] Existing CLI aliases `arenyxa` and `arenyxa` continue to work in the environment.

## Phase 2 Web Intelligence Center

- [ ] Intelligence Studio opens without UI regression.
- [ ] `Analyze SmartPath 2.0` returns Web Intelligence report data.
- [ ] Static HTML case shows static inspection in execution path.
- [ ] Captured API/XHR/GraphQL case shows structured endpoint evidence.
- [ ] Browser-required case retains browser fallback evidence.
- [ ] `Top API -> HTTP Builder` never copies Authorization/Cookie/token query values.
- [ ] `Top API -> Workflow` succeeds for safe idempotent structured requests.
- [ ] `Top API -> Workflow` refuses sensitive or POST/PATCH/PUT/DELETE requests without explicit review path.
- [ ] Selector review-only mode does not auto-apply.
- [ ] Selector auto-apply only selects a unique high-confidence candidate.
- [ ] Recorder semantic output recognizes login/search/pagination/extraction/download examples.
- [ ] Time Machine linkage file contains hashes/links and no raw tested secrets.

## Native Capture / lifecycle

- [ ] Browser Capture can complete and its activity indicator stops.
- [ ] Packet Capture / tshark/Npcap path behaves as before where installed.
- [ ] App closes without orphan browser/terminal/capture processes.
- [ ] Sleep/resume and network switch do not leave a false-running capture state.

## Result

- [ ] PASS — Phase 1/2 native Windows gate accepted.
- [ ] FAIL — attach exact reproduction steps/logs before freezing a new baseline.
