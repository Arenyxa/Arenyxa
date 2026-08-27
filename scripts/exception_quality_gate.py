from pathlib import Path
import ast,json,sys
root=Path('src/arenyxa')
findings=[]
for p in root.rglob('*.py'):
    try: tree=ast.parse(p.read_text(encoding='utf-8'))
    except Exception: continue
    for n in ast.walk(tree):
        if isinstance(n,ast.ExceptHandler) and n.type is None:
            findings.append({'file':str(p),'line':n.lineno,'issue':'bare except'})
print(json.dumps({'healthy':not findings,'findings':findings},indent=2))
sys.exit(1 if findings else 0)
