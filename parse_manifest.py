import struct
import zipfile

def extract_manifest_and_parse():
    with zipfile.ZipFile('base.apk') as z:
        data = z.read('AndroidManifest.xml')
    
    magic, size = struct.unpack('<II', data[:8])
    pos = 8
    strings = []
    xml_lines = []
    indent = 0
    ns_map = {}
    
    while pos < len(data):
        chunk_type, chunk_size = struct.unpack('<II', data[pos:pos+8])
        if chunk_type == 0x0001001c: # STRING_POOL
            c_type, c_size, string_count, style_count, flags, strings_start, styles_start = struct.unpack('<IIIIIII', data[pos:pos+28])
            offsets = struct.unpack(f'<{string_count}I', data[pos+28:pos+28 + 4*string_count])
            is_utf8 = bool(flags & (1 << 8))
            pool_data = data[pos + strings_start:pos + c_size]
            for off in offsets:
                if is_utf8:
                    p = off
                    u16len = pool_data[p]; p += 1
                    if u16len & 0x80: u16len = ((u16len & 0x7f) << 8) | pool_data[p]; p += 1
                    u8len = pool_data[p]; p += 1
                    if u8len & 0x80: u8len = ((u8len & 0x7f) << 8) | pool_data[p]; p += 1
                    s = pool_data[p:p+u8len].decode('utf-8', errors='ignore')
                else:
                    p = off
                    u16len = struct.unpack('<H', pool_data[p:p+2])[0]; p += 2
                    if u16len & 0x8000: u16len = ((u16len & 0x7fff) << 16) | struct.unpack('<H', pool_data[p:p+2])[0]; p += 2
                    s = pool_data[p:p+u16len*2].decode('utf-16le', errors='ignore')
                strings.append(s)
            pos += chunk_size
        elif chunk_type == 0x00080180: # RESOURCE_MAP
            pos += chunk_size
        elif chunk_type == 0x00100100: # START_NAMESPACE
            line_no, comment, prefix_idx, uri_idx = struct.unpack('<IIII', data[pos+8:pos+24])
            prefix = strings[prefix_idx] if prefix_idx < len(strings) else ''
            uri = strings[uri_idx] if uri_idx < len(strings) else ''
            ns_map[uri] = prefix
            pos += chunk_size
        elif chunk_type == 0x00100101: # END_NAMESPACE
            pos += chunk_size
        elif chunk_type == 0x00100102: # START_TAG
            line_no, comment, ns_idx, name_idx, attr_start, attr_size, attr_count, id_idx, class_idx, style_idx = struct.unpack('<IIIIHHHHHH', data[pos+8:pos+36])
            tag_name = strings[name_idx] if name_idx < len(strings) else f'unk_{name_idx}'
            attrs = []
            attr_offset = pos + 8 + attr_start
            for i in range(attr_count):
                a_ns_idx, a_name_idx, a_val_str_idx, a_type, a_data = struct.unpack('<IIIIHxx', data[attr_offset:attr_offset+20])
                a_name = strings[a_name_idx] if a_name_idx < len(strings) else f'attr_{a_name_idx}'
                a_ns = strings[a_ns_idx] if (a_ns_idx < len(strings) and a_ns_idx != 0xffffffff) else ''
                prefix = ns_map.get(a_ns, 'android') if a_ns else ''
                qname = f'{prefix}:{a_name}' if prefix else a_name
                
                val_type = a_type >> 24
                if a_val_str_idx != 0xffffffff and a_val_str_idx < len(strings):
                    val = strings[a_val_str_idx]
                elif val_type == 3:
                    val = strings[a_data] if a_data < len(strings) else str(a_data)
                elif val_type == 16:
                    val = str(a_data)
                elif val_type == 17:
                    val = hex(a_data)
                elif val_type == 18:
                    val = 'true' if a_data != 0 else 'false'
                elif val_type == 1:
                    val = f'@0x{a_data:08x}'
                else:
                    val = str(a_data)
                attrs.append(f'{qname}="{val}"')
                attr_offset += 20
            attr_str = (' ' + ' '.join(attrs)) if attrs else ''
            xml_lines.append('  ' * indent + f'<{tag_name}{attr_str}>')
            indent += 1
            pos += chunk_size
        elif chunk_type == 0x00100103: # END_TAG
            line_no, comment, ns_idx, name_idx = struct.unpack('<IIII', data[pos+8:pos+24])
            tag_name = strings[name_idx] if name_idx < len(strings) else f'unk_{name_idx}'
            indent -= 1
            xml_lines.append('  ' * indent + f'</{tag_name}>')
            pos += chunk_size
        elif chunk_type == 0x00100104: # TEXT
            pos += chunk_size
        else:
            pos += chunk_size if chunk_size > 0 else len(data)
            
    xml = '\n'.join(xml_lines)
    with open('decoded_manifest.xml', 'w', encoding='utf-8') as f:
        f.write(xml)
    print(f'Wrote decoded_manifest.xml ({len(xml)} characters)')

if __name__ == '__main__':
    extract_manifest_and_parse()
