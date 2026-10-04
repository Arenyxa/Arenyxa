Arenyxa v6.6beta2 Windows fsync hotfix

Fixes Windows startup failure:
  OSError: [Errno 9] Bad file descriptor
  database.py -> backup_to() -> os.fsync(handle.fileno())

Cause: completed artifacts were reopened read-only immediately before os.fsync().
On Windows Python implements os.fsync() through the Microsoft CRT _commit primitive;
Arenyxa now reopens completed files with a write-capable descriptor without truncation.

Also hardens the same pattern in:
- SQLite migration backups
- run exports
- project package saves
- diagnostic package exports
- source repair seed generation

Validation performed on the corrected source tree:
  332 passed, 6 skipped, 0 failed

Apply: extract this overlay into the Arenyxa source root and replace existing files.
Then run:
  .\.venv\Scripts\python.exe scripts\build_source_repair_seed.py
  .\.venv\Scripts\python.exe scripts\build_source_manifest.py
  .\.venv\Scripts\python.exe -c "from arenyxa.bootstrap import bootstrap; c=bootstrap(); print('BOOTSTRAP OK'); c.shutdown()"
  .\scripts\run.ps1
