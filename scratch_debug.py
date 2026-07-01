import socket
import struct
import time
import os
import sys

def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return socket.htons(~s & 0xffff)

def debug_raw_icmp():
    print("Initializing raw ICMP socket...")
    try:
        # Create raw ICMP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("PermissionError: Must run as Administrator.")
        return
    except Exception as e:
        print(f"Error creating socket: {e}")
        return

    # Let's bind the socket to the default local interface.
    # Find the correct active interface IP by creating a temporary socket
    try:
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.connect(("8.8.8.8", 80))
        local_ip = temp_sock.getsockname()[0]
        temp_sock.close()
        sock.bind((local_ip, 0))
        print(f"Socket bound to active local IP: {local_ip}")
    except Exception as e:
        print(f"Error binding socket: {e}")

    target_ip = "8.8.8.8"
    try:
        dest_addr = socket.gethostbyname(target_ip)
    except Exception as e:
        print(f"Failed to resolve {target_ip}: {e}")
        return

    # Set TTL = 1
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    print(f"Set socket TTL to 1. Target: {dest_addr}")

    # Build ICMP Echo Request
    # Header: Type(8), Code(0), Checksum(0), ID(12345), Seq(1)
    my_id = 12345
    seq = 1
    header = struct.pack("!BBHHH", 8, 0, 0, my_id, seq)
    payload = b"omnitrace_engine_payload_data!!!"
    chk = calculate_checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, chk, my_id, seq)
    packet = header + payload

    print(f"Sending ICMP packet (size {len(packet)} bytes) to {dest_addr}...")
    sock.sendto(packet, (dest_addr, 0))

    print("Listening for responses for 3 seconds...")
    start_time = time.time()
    sock.settimeout(1.0)
    
    while time.time() - start_time < 3.0:
        try:
            data, addr = sock.recvfrom(1024)
            rtt = (time.time() - start_time) * 1000
            print(f"\nReceived {len(data)} bytes from {addr} after {rtt:.2f}ms")
            
            # Parse IP header
            if len(data) < 20:
                print("Packet too short for IP header")
                continue
                
            ip_header_len = (data[0] & 0x0F) * 4
            ip_proto = data[9]
            print(f"  IP Header: Version={data[0] >> 4}, IHL={ip_header_len} bytes, Protocol={ip_proto}")
            
            if ip_proto != 1:
                print("  Not an ICMP packet")
                continue
                
            if len(data) < ip_header_len + 8:
                print("  Packet too short for ICMP header")
                continue
                
            icmp_data = data[ip_header_len:]
            # ICMP Header: Type, Code, Checksum, ID, Seq
            icmp_type, icmp_code, icmp_chk, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_data[:8])
            print(f"  ICMP Header: Type={icmp_type}, Code={icmp_code}, Checksum={icmp_chk}, ID={icmp_id}, Seq={icmp_seq}")
            
            if icmp_type in (11, 3):
                # Time Exceeded or Destination Unreachable
                # Payload contains inner IP header
                inner_ip_offset = ip_header_len + 8
                if len(data) >= inner_ip_offset + 20:
                    inner_ip_data = data[inner_ip_offset:]
                    inner_ihl = (inner_ip_data[0] & 0x0F) * 4
                    inner_proto = inner_ip_data[9]
                    print(f"  Inner IP Header: IHL={inner_ihl} bytes, Protocol={inner_proto}")
                    
                    if len(inner_ip_data) >= inner_ihl + 8:
                        inner_icmp_data = inner_ip_data[inner_ihl:]
                        inner_type, inner_code, inner_ichk, inner_iid, inner_iseq = struct.unpack("!BBHHH", inner_icmp_data[:8])
                        print(f"    Inner ICMP: Type={inner_type}, Code={inner_code}, ID={inner_iid}, Seq={inner_iseq}")
                        if inner_iid == my_id and inner_iseq == seq:
                            print("    *** MATCHED OUR SENT PACKET! ***")
            
        except socket.timeout:
            print(".", end="")
            sys.stdout.flush()
        except Exception as e:
            print(f"\nError receiving: {e}")

if __name__ == '__main__':
    debug_raw_icmp()
