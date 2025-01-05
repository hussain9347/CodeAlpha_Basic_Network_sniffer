import socket
import struct

def mac_address(bytes_addr):
    """Convert MAC address from bytes to a human-readable format."""
    return ':'.join(map('{:02x}'.format, bytes_addr))

def ipv4_address(addr):
    """Convert an IPv4 address from bytes to a human-readable format."""
    return '.'.join(map(str, addr))

def main():
    # Create a raw socket to sniff packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        # Receive raw packet data
        raw_data, addr = conn.recvfrom(65535)

        # Parse Ethernet frame
        dest_mac, src_mac, proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(f"  Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {proto}")

        # Parse IPv4 packets
        if proto == 8:  # IPv4
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print("  IPv4 Packet:")
            print(f"    Version: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(f"    Protocol: {proto}, Source: {src}, Target: {target}")

def ethernet_frame(data):
    """Unpack Ethernet frame."""
    dest_mac = mac_address(data[0:6])
    src_mac = mac_address(data[6:12])
    proto = struct.unpack('!H', data[12:14])[0]
    return dest_mac, src_mac, proto, data[14:]

def ipv4_packet(data):
    """Unpack IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src = ipv4_address(src)
    target = ipv4_address(target)
    return version, header_length, ttl, proto, src, target, data[header_length:]

if __name__ == "__main__":
    main()
