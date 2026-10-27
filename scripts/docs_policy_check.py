#!/usr/bin/env python3
"""Warning-only documentation layout policy; use --strict when backlog is closed."""
from __future__ import annotations
import argparse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ALLOW={"README.md","SECURITY.md","VERSIONING.md","CHANGELOG.md"}
REQUIRED=("status:","owner:","last_reviewed:")
def archived(p:Path)->bool:
 parts=tuple(x.casefold() for x in p.relative_to(ROOT).parts)
 return any(parts[i:i+2]==("internal","history") for i in range(len(parts)-1))
def main()->int:
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--strict",action="store_true",help="fail on any documentation-policy warning")
 args=parser.parse_args()
 warnings=[]
 extras=sorted(p.name for p in ROOT.glob("*.md") if p.name not in ALLOW)
 if extras:warnings.append("root Markdown files outside allowlist: "+", ".join(extras))
 missing=[];malformed=[]
 for p in sorted(x for x in (ROOT/"docs").rglob("*.md") if not archived(x)):
  rel=p.relative_to(ROOT).as_posix(); body=p.read_text(encoding="utf-8")
  if not body.startswith("---\n"):missing.append(rel);continue
  end=body.find("\n---",4);header=body[4:end] if end>=0 else ""
  if end<0 or any(field not in header for field in REQUIRED):malformed.append(rel)
 if missing:warnings.append(f"{len(missing)} active Markdown file(s) lack required front matter; sample: {', '.join(missing[:12])}")
 if malformed:warnings.append("Markdown front matter missing fields: "+", ".join(malformed[:12]))
 if warnings:
  print("Documentation policy: WARNING (non-blocking)")
  for item in warnings:print("- "+item)
 else:print("Documentation policy: PASS")
 return 1 if args.strict and warnings else 0
if __name__=="__main__":raise SystemExit(main())
