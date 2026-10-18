import zipfile
import struct
import re
from collections import defaultdict

def read_uleb128(data, offset):
    result = 0
    shift = 0
    while True:
        b = data[offset]
        offset += 1
        result |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, offset

def extract_dex_strings(dex_data):
    magic = dex_data[:8]
    if not magic.startswith(b'dex\n'):
        return []
    
    string_ids_size, string_ids_off = struct.unpack('<II', dex_data[56:64])
    strings = []
    
    offsets = struct.unpack(f'<{string_ids_size}I', dex_data[string_ids_off:string_ids_off + 4 * string_ids_size])
    
    for off in offsets:
        length, str_off = read_uleb128(dex_data, off)
        # Find null terminator
        end = dex_data.find(b'\x00', str_off)
        if end != -1:
            raw = dex_data[str_off:end]
            try:
                s = raw.decode('utf-8', errors='ignore')
                strings.append(s)
            except Exception:
                pass
    return strings

def main():
    print("Reading base.apk...")
    all_strings = set()
    dex_names = []
    
    with zipfile.ZipFile('base.apk') as z:
        for name in z.namelist():
            if name.endswith('.dex'):
                dex_names.append(name)
                print(f"Extracting strings from {name}...")
                dex_bytes = z.read(name)
                strs = extract_dex_strings(dex_bytes)
                print(f"  Found {len(strs)} strings in {name}")
                all_strings.update(strs)
                
    print(f"Total unique strings across {len(dex_names)} DEX files: {len(all_strings)}")
    
    # 1. Classes and Packages in co.hinge
    hinge_classes = sorted([s for s in all_strings if s.startswith('Lco/hinge/') or s.startswith('co.hinge.')])
    print(f"Found {len(hinge_classes)} Hinge class references")
    
    # Group by subsystem
    packages = defaultdict(int)
    for c in hinge_classes:
        clean = c.lstrip('L').replace('/', '.')
        parts = clean.split('.')
        if len(parts) >= 3:
            pkg = '.'.join(parts[:3])
            packages[pkg] += 1
            
    print("\n--- Subsystems in co.hinge ---")
    for pkg, count in sorted(packages.items(), key=lambda x: -x[1])[:30]:
        print(f"  {pkg:40}: {count} classes/references")
        
    # 2. SQLite queries and schemas
    sql_strings = [s for s in all_strings if any(k in s.upper() for k in ['CREATE TABLE', 'SELECT ', 'INSERT INTO', 'UPDATE ', 'ALTER TABLE'])]
    print(f"\nFound {len(sql_strings)} SQL query/schema strings")
    create_tables = [s for s in sql_strings if 'CREATE TABLE' in s.upper()]
    print(f"  CREATE TABLE statements ({len(create_tables)}):")
    for ct in sorted(create_tables)[:25]:
        first_line = ct.strip().replace('\n', ' ')
        print(f"    {first_line[:120]}")
        
    # 3. API Endpoints & URLs
    api_strings = [s for s in all_strings if re.match(r'^https?://', s) or s.startswith('/api/') or s.startswith('/v1/') or s.startswith('/v2/') or s.startswith('/v3/')]
    print(f"\nFound {len(api_strings)} API/URL strings")
    for url in sorted(set(api_strings))[:30]:
        print(f"    {url}")
        
    # 4. Save detailed reports
    with open('hinge_classes.txt', 'w', encoding='utf-8') as f:
        for c in hinge_classes:
            f.write(c + '\n')
            
    with open('hinge_sql.txt', 'w', encoding='utf-8') as f:
        for s in sorted(sql_strings):
            f.write(s + '\n---\n')
            
    with open('hinge_urls.txt', 'w', encoding='utf-8') as f:
        for s in sorted(api_strings):
            f.write(s + '\n')
            
    # 5. Search for specific feature terms
    features = ['hingex', 'plus', 'standout', 'most_compatible', 'we_met', 'boost', 'superboost', 'rose', 'prompt', 'voice_note', 'video_prompt', 'verification', 'selfie', 'dealbreaker', 'undo', 'like_with_comment']
    print("\n--- Feature Mentions ---")
    for feat in features:
        matches = [s for s in all_strings if feat in s.lower()]
        print(f"  Feature '{feat}': {len(matches)} string matches")
        
    print("\nAnalysis complete. Artifacts written.")

if __name__ == '__main__':
    main()
