def parse_ipv4(ip_str):
    parts = ip_str.split('.')
    if len(parts) != 4:
        raise ValueError("Invalid IPv4: must have 4 octets")
    
    res = 0
    for part in parts:
        if not part.isdigit():
            raise ValueError(f"Invalid IPv4: octet '{part}' is not a number")
        
        if len(part) > 1 and part[0] == '0':
            raise ValueError("Invalid IPv4: leading zeros are not allowed")
            
        val = int(part)
        if val < 0 or val > 255:
            raise ValueError(f"Invalid IPv4: octet '{part}' out of range")
            
        res = (res << 8) | val
        
    return res

def parse_ipv6(ip_str):
    # ipv4-mapped ipv6 (e.g. ::ffff:192.168.0.1)
    if '.' in ip_str:
        parts = ip_str.split(':')
        v4_part = parts[-1]
        v4_int = parse_ipv4(v4_part)
        
        hex1 = f"{(v4_int >> 16) & 0xFFFF:x}"
        hex2 = f"{v4_int & 0xFFFF:x}"
        
        parts = parts[:-1] + [hex1, hex2]
        ip_str = ':'.join(parts)

    if ip_str.count('::') > 1:
        raise ValueError("Invalid IPv6: '::' can only appear once")

    if '::' in ip_str:
        left, right = ip_str.split('::')
        left_parts = left.split(':') if left else []
        right_parts = right.split(':') if right else []
        
        missing = 8 - (len(left_parts) + len(right_parts))
        if missing < 0:
            raise ValueError("Invalid IPv6: too many groups")
            
        parts = left_parts + ['0'] * missing + right_parts
    else:
        parts = ip_str.split(':')
        if len(parts) != 8:
            raise ValueError("Invalid IPv6: must have exactly 8 groups")

    res = 0
    for part in parts:
        if part == '':
            raise ValueError("Invalid IPv6: empty group")
        if len(part) > 4:
            raise ValueError(f"Invalid IPv6: group '{part}' too long")
            
        try:
            val = int(part, 16)
        except ValueError:
            raise ValueError(f"Invalid IPv6: group '{part}' is not valid hex")
            
        if val < 0 or val > 0xFFFF:
            raise ValueError(f"Invalid IPv6: group '{part}' out of range")
            
        res = (res << 16) | val
        
    return res

def int_to_ipv4_mask(prefix):
    mask_int = ((1 << prefix) - 1) << (32 - prefix)
    octets = []
    for i in range(4):
        shift = 24 - (i * 8)
        octets.append(str((mask_int >> shift) & 0xFF))
    return '.'.join(octets)

def int_to_ipv6_mask(prefix):
    mask_int = ((1 << prefix) - 1) << (128 - prefix)
    groups = []
    for i in range(8):
        shift = 112 - (i * 16)
        groups.append(f"{(mask_int >> shift) & 0xFFFF:x}")
    
    # zero compression
    best_start = -1
    best_len = 0
    curr_start = -1
    curr_len = 0
    
    for i in range(8):
        if groups[i] == '0':
            if curr_start == -1:
                curr_start = i
            curr_len += 1
        else:
            if curr_len > best_len:
                best_len = curr_len
                best_start = curr_start
            curr_start = -1
            curr_len = 0
            
    if curr_len > best_len:
        best_len = curr_len
        best_start = curr_start
        
    if best_len > 1:
        left = groups[:best_start]
        right = groups[best_start + best_len:]
        
        res = ':'.join(left) + '::' + ':'.join(right)
        if res == '::':
            return '::'
        if res.startswith(':::'):
            return res[1:]
        if res.endswith(':::'):
            return res[:-1]
        return res
        
    return ':'.join(groups)

def get_minimum_mask(ip1, ip2):
    is_v4_1 = '.' in ip1 and ':' not in ip1
    is_v4_2 = '.' in ip2 and ':' not in ip2
    
    if is_v4_1 != is_v4_2:
        raise ValueError("Cannot compare IPv4 with IPv6")
        
    if is_v4_1:
        val1 = parse_ipv4(ip1)
        val2 = parse_ipv4(ip2)
        total_bits = 32
    else:
        val1 = parse_ipv6(ip1)
        val2 = parse_ipv6(ip2)
        total_bits = 128
        
    diff = val1 ^ val2
    prefix = total_bits - diff.bit_length()
    
    if is_v4_1:
        mask_str = int_to_ipv4_mask(prefix)
    else:
        mask_str = int_to_ipv6_mask(prefix)
        
    return {
        'cidr': f"/{prefix}",
        'mask': mask_str
    }

if __name__ == '__main__':
    # tests
    res = get_minimum_mask('192.168.1.10', '192.168.1.20')
    assert res['cidr'] == '/27'
    assert res['mask'] == '255.255.255.224'
    
    res = get_minimum_mask('10.0.0.1', '10.255.255.254')
    assert res['cidr'] == '/8'
    
    res = get_minimum_mask('2001:db8::1', '2001:db8::2')
    assert res['cidr'] == '/126'
    
    res = get_minimum_mask('::ffff:192.168.1.1', '::ffff:192.168.1.2')
    assert res['cidr'] == '/126'
    
    try:
        parse_ipv4('192.168.01.1')
        assert False
    except ValueError:
        pass
        
    print("All tests passed!")