def extract_ip_bytes(ip_file):
    with open(ip_file) as fp:
        ip_data = fp.read().split()
        source, dest = ip_data[0], ip_data[1]
        source = list(map(int, source.split('.')))
        dest = list(map(int, dest.split('.')))
        source = b''.join([i.to_bytes(1, 'big') for i in source])
        dest = b''.join([i.to_bytes(1, 'big') for i in dest])
    return source, dest

def get_tcp_data_len(tcp_file):
	with open(tcp_file, "rb") as fp:
	    tcp_data = fp.read()
	    tcp_length = len(tcp_data)
	return tcp_length

def make_pseudo_ip_header(ip_file, tcp_file):
    source, dest = extract_ip_bytes(ip_file)
    tcp_length = get_tcp_data_len(tcp_file)
    header = source + dest + b'\x00' + b'\x06' + tcp_length.to_bytes(2, 'big')
    return header

def extract_checksum(tcp_file):
    with open(tcp_file, "rb") as fp:
	    tcp_data = fp.read()
	    checksum = tcp_data[16:18]
    checksum = int.from_bytes(checksum, 'big')
    return checksum

def zeroed_tcp_header(tcp_file):
    with open(tcp_file, "rb") as fp:
	    tcp_data = fp.read()
	    tcp_zero_cksum = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

    if len(tcp_zero_cksum) % 2 == 1:
        tcp_zero_cksum += b'\x00'
    return tcp_zero_cksum

def checksum(pseudo_header, tcp_data):
    data = pseudo_header + tcp_data
    total = 0
    offset = 0   # byte offset into data

    while offset < len(data):
        # Slice 2 bytes out and get their value:

        word = int.from_bytes(data[offset:offset + 2], "big")
        total += word
        total = (total & 0xffff) + (total >> 16)  # carry around

        offset += 2   # Go to the next 2-byte value
    return (~total) & 0xffff  # one's complement
        

for i in list(range(0,10)):
    pseudoheader = make_pseudo_ip_header(f"tcp_addrs_{i}.txt", f"tcp_data_{i}.dat")
    tcp_data = zeroed_tcp_header(f"tcp_data_{i}.dat")

    calculated_checksum = checksum(pseudoheader, tcp_data)
    og_checksum = extract_checksum(f"tcp_data_{i}.dat")

    if calculated_checksum == og_checksum:
        print("PASS")
    else:
        print("FAIL")
    
 