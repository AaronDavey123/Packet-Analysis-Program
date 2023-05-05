import socket
import struct
import textwrap


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t ' 
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def  main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = s.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print(TAB_1 + 'Destination: {}, Source {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        
        #8 means we are looking at IPv4 
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version,header_length,ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            
            # 1 means ICMP Packet(Internet Control Message Protocol)
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            
            #6 means its a TCP Packet (Transmission Control Protocol)
            elif proto == 6:
                (src_port, dest_port, sequence, ackmowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = TCP_Packet(data)
                print(TAB_1 + 'TCP Pakcet:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ackmowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
                
            #17 means its a UDP Packet (User Diragram Protocol)
            elif proto == 17:
                src_port, dest_port, Length, data = udp_packet(data)
                print(TAB_1 + 'UDP Packet:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, Length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            
            #Other
            else:
                print(TAB_1 + 'Unknown Packet:')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
        
        else:
            print(TAB_1 + 'Unknown Packet:')
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))            
            
#unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]
            


#formatting MAC address (ie: AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()    


#Unpacking Ipv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


#returns formatted IPv4 address (ie: 192.168.0.1)
def ipv4(addr):
    return '.'.join(map(str,addr))
    

#unpack ICMP packet (Internet Control Message Protocol)
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpack TCP Packet (Transmission Control Protocol)    
def TCP_Packet(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reseved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reseved_flags >> 12) * 4
    flag_urg = (offset_reseved_flags & 32) >> 5  
    flag_ack = (offset_reseved_flags & 16) >> 4
    flag_psh = (offset_reseved_flags & 8) >> 3
    flag_rst = (offset_reseved_flags & 4) >> 2
    flag_syn = (offset_reseved_flags & 2) >> 1
    flag_fin =  offset_reseved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpacking udp packets (User Datagram Protocol)
def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


#format multi-line data, found online
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()