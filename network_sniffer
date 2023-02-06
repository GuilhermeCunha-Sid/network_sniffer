import socket
import struct
import textwrap

"""
    .-------------.
    | Description |
    '-------------'
    Program     : Network Sniffer
    Creator     : Guilherme Cunha
    Objective   : Substitute TCPDump to create more efficient IDS and IPS.
    Version     : 0.0.1
    Tested      : Linux Kali - Python 3.9
    References :
        * Socket Lib Python
            - https://docs.python.org/3/library/socket.htm
            
        * Supported Protocols ex: 0x0003
            - https://sites.uclouvain.be/SystInfo/usr/include/linux/if_ether.h.html
        
        * Youtube Channel: thenewboston 
            Note: Outdated Video
            - https://www.youtube.com/watch?v=WGJC5vT5YJo&list=PL6gx4Cwl9DGDdduy0IPDDHYnUx66Vc4ed

                                                                                                                [BRASIL]
"""

DATA_TAB = '\t\t\t\t\t\t\t'


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003), fileno=None)

    network_interface = input("Network Interface:")

    conn.bind((str(network_interface), 0))

    while True:
        packet = conn.recvfrom(65535)
        (mac_dst, mac_src, prototype, data) = ethernet_frame(packet)

        print("\nEthernet Frame:")
        print(f"Destination: {mac_dst}, Source: {mac_src}, Proto:{prototype}")

        if prototype == 2048:
            if len(packet[0][14:]) > 20:
                (version, header_length, ttl, proto, src, dst, data) = ip_packet(packet[0][14:])
                print("\tProtocol: IPv4")
                print(f"\t\tVersion:{version}, IHL:{header_length}, TTL:{ttl}")
                print(f"\t\tProtocol:{proto}, Source Address:{src}, Destination Address:{dst}")

                # ICMP
                if proto == 1:
                    (icmp_type, code, checksum, data) = icmp_packet(data)
                    print("\t\t\tProtocol: ICMP")
                    print(f"\t\t\t\tICMP Type:{icmp_type}, Code:{code}, Checksum:{checksum}")
                    converter(data)

                # TCP
                elif proto == 6:
                    (src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                     flag_fin, data) = tcp_segment(data)
                    print(f"\t\t\tProtocol: TCP")
                    print(f"\t\t\t\tSource Port:{src_port}, Destination Port:{dst_port}")
                    print(f"\t\t\t\tSequence Number:{sequence}, Acknowledgement Number:{acknowledgement}")
                    print(f"\t\t\t\tFlags:")
                    print(f"\t\t\t\t\tFlag URG:{flag_urg}")
                    print(f"\t\t\t\t\tFlag ACK:{flag_ack}")
                    print(f"\t\t\t\t\tFlag PSH:{flag_psh}")
                    print(f"\t\t\t\t\tFlag RST:{flag_rst}")
                    print(f"\t\t\t\t\tFlag SYN:{flag_syn}")
                    print(f"\t\t\t\t\tFlag FIN:{flag_fin}")
                    print(f"\t\t\t\t\t\tData:")

                    converter(data)

                # UDP
                elif proto == 17:
                    (src_port, dst_port, size, data) = udp_segment(data)
                    print(f"\t\t\tProtocol: UDP")
                    print(f"\t\t\t\tSource Port:{src_port}, Destination Port:{dst_port}, Size:{size}")
                    print(f"\t\t\t\tData:")

                    converter(data)
                else:
                    print(f"Protocol:{proto}")
            else:
                converter(data)
        else:
            converter(data)


def ethernet_frame(packet):
    mac_src, mac_dst, prototype = struct.unpack('! 6s 6s H', packet[0][:14])
    data = packet[0][14:]
    return get_mac_addr(mac_src), get_mac_addr(mac_dst), prototype, data


def get_mac_addr(mac):
    bytes_str = map('{:02x}'.format, mac)
    return ':'.join(bytes_str).upper()


def ip_packet(packet):
    version_header_length = packet[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', packet[:20])
    return version, header_length, ttl, proto, ip_formate(src), ip_formate(dst), packet[header_length:]


def ip_formate(addr):
    return '.'.join(map(str, addr))


def icmp_packet(packet):
    icmp_type, code, checksum = struct.unpack('! B B H', packet[:4])
    return icmp_type, code, checksum, packet[4:]


def tcp_segment(data):
    (src_port, dst_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1

    return src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
        data[offset:]


def udp_segment(packet):
    src_port, dst_port, size = struct.unpack('! H H 2x H', packet[:8])
    return src_port, dst_port, size, packet[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def converter(data):
    byte_counter = 0
    buffer = []
    print(DATA_TAB, end="")

    for data_byte in data:
        byte_counter += 1
        buffer.append(data_byte)
        print(f"{data_byte:02x}", end=" ")
        if byte_counter % 16 == 0:
            for byte_counter2 in buffer:
                if (byte_counter2 >= 32) and (byte_counter2 <= 126):
                    print(chr(byte_counter2), end="")
                else:
                    print("*", end="")
            buffer = []
            print("")
            print(DATA_TAB, end="")


main()
