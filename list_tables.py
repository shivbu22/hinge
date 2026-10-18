import re

with open('hinge_sql.txt', 'r', encoding='utf-8') as f:
    sql = f.read()

tables = set()
for m in re.finditer(r'(?:FROM|INTO|UPDATE|TABLE)\s+[`]?([a-zA-Z0-9_]+)', sql, re.IGNORECASE):
    t = m.group(1).replace('_new_', '').replace('_new', '').replace('temp_', '')
    if not any(k in t for k in ['Work', 'SystemId', 'Dependency', 'ExoPlayer', 'room_master', 'Preference', 'sqlite', 'IF', 'INDEX']):
        tables.add(t)

print(f'Discovered {len(tables)} Hinge SQLite domain tables:')
for t in sorted(tables):
    print(f'  - {t}')
