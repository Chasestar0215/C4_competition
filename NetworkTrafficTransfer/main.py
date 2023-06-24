# This is a sample Python script.
from scapy.all import *
from collections import defaultdict
import pandas as pd
import os
import math
from scapy.layers.inet import IP, TCP, UDP
import pyshark

pyshark.tshark.tshark.TSHARK_DISPLAY_FILTER_FLAG = r'D:\Program Files\Wireshark\tshark.exe'

PROTO_DICT = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP", 5: "ST", 6: "TCP", 7: "CBT",
    8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON",
    15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM",
    22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP",
    28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "SEP",
    34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL",
    41: "IPv6", 42: "SDRP", 43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP",
    47: "GRE", 48: "MHRP", 49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SWIPE",
    54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 61: "Host internal protocol", 62: "CFTP", 63: "Local network",
    64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 68: "Distributed file system",
    69: "SAT-MON", 70: "VISA", 71: "IPCV", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP",
    76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP",
    82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 85: "NSFNET-IGP", 86: "DGP", 87: "TCF",
    88: "EIGRP", 89: "OSPFIGP", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25",
    94: "IPIP", 95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "Private encryption scheme",
    100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS",
    106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP",
    112: "VRRP", 113: "PGM", 114: "Any 0-hop protocol", 115: "L2TP", 116: "DDX",
    117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP", 122: "SM",
    123: "PTP", 124: "ISIS over IPv4", 125: "FIRE", 126: "CRTP", 127: "CRUDP",
    128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC"
}

def extract_proto(packet):
    try:
        protocol = packet.ip.proto
        return PROTO_DICT.get(int(protocol), "-")
    except AttributeError:
        return None

def extract_service(packet):
    try:
        protocol = packet.transport_layer.lower()
        if protocol == 'tcp':
            port = int(packet.tcp.dstport)
            if port == 80:
                return 'http'
            elif port == 22:
                return 'ssh'
            elif port == 21:
                return 'ftp'
            else:
                return '-'
        elif protocol == 'udp':
            port = int(packet.udp.dstport)
            if port == 53:
                return 'dns'
            else:
                return '-'
        else:
            return '-'
    except AttributeError:
        return None


def extract_state(packet):
    try:
        if hasattr(packet, 'tcp'):
            tcp_flags = int(packet.tcp.flags, 16)

            if tcp_flags & 0x02:  # SYN
                if tcp_flags & 0x10:  # ACK
                    return 'ACC'  # SYN-ACK
                else:
                    return 'REQ'  # SYN
            elif tcp_flags & 0x01:  # FIN
                return 'FIN'
            elif tcp_flags & 0x04:  # RST
                return 'RST'
            elif tcp_flags & 0x10:  # ACK
                return 'CON'  # Considered as continue
            else:
                return 'CLO'  # Considered as closed if no other flags

        elif hasattr(packet, 'icmp'):
            if int(packet.icmp.type) == 0:
                return 'ECR'  # Echo reply
            elif int(packet.icmp.type) == 8:
                return 'ECO'  # Echo request
            elif int(packet.icmp.type) in [3, 4, 11]:
                if int(packet.icmp.code) in [0, 1]:
                    return 'URN'  # Destination network unreachable
                elif int(packet.icmp.code) in [2, 3]:
                    return 'URH'  # Destination host unreachable
            else:
                return 'CLO'  # Closed for other ICMP messages

        elif hasattr(packet, 'http'):
            if int(packet.http.response.code) in range(200, 300):
                return 'ACC'  # Accepted
            elif int(packet.http.response.code) == 100:
                return 'CON'  # Continue
            else:
                return 'REQ'  # Request for other HTTP codes

        elif hasattr(packet, 'ftp'):
            return 'INT'  # Interrupted for FTP protocol

        elif hasattr(packet, 'modbus'):
            if packet.modbus.func_code == 8:  # Diagnostic function
                return 'TST'  # Test
            else:
                return 'MAS'  # Master for Modbus protocol

        elif hasattr(packet, 'serial'):
            return 'PAR'  # Parity error for Serial protocol

        elif hasattr(packet, 'tx'):
            return 'TXD'  # Transmit Data for tx protocol

        else:
            return 'CLO'  # Closed for other protocols

    except AttributeError:
        return 'CLO'  # Closed if any error

def calculate_sload(packet):
    try:
        return int(packet.ip.len) / float(packet.sniff_timestamp)
    except AttributeError:
        return None

def calculate_dload(packet):
    try:
        return int(packet.ip.len) / float(packet.sniff_timestamp)
    except AttributeError:
        return None

retransmissions = dict()
def calculate_sloss(packet):
    try:
        if 'tcp' in packet:
            # Use the 'tcp.analysis.retransmission' flag to determine if the packet is a retransmission
            if 'tcp.analysis.retransmission' in packet.tcp.field_names:
                # Extract the sequence number of the packet
                seq_num = int(packet.tcp.seq, 16)
                # If the sequence number is in the dictionary, increment the value, else set the value to 1
                retransmissions[seq_num] = retransmissions.get(seq_num, 0) + 1
                return retransmissions[seq_num]
        return 0
    except AttributeError:
        return None

def calculate_dloss(packet):
    try:
        if 'tcp' in packet:
            # Use the 'tcp.analysis.retransmission' flag to determine if the packet is a retransmission
            if 'tcp.analysis.retransmission' in packet.tcp.field_names:
                # Extract the sequence number of the packet
                seq_num = int(packet.tcp.seq, 16)
                # If the sequence number is in the dictionary, increment the value, else set the value to 1
                retransmissions[seq_num] = retransmissions.get(seq_num, 0) + 1
                return retransmissions[seq_num]
        return 0
    except AttributeError:
        return None

# Initialize the packet counts and timestamps for source and destination
src_pkt_count, dst_pkt_count = 0, 0
prev_src_time, prev_dst_time = None, None
src_jitter, dst_jitter = 0, 0

def calculate_spkts(packet):
    global src_pkt_count
    if 'ip' in packet:
        src_ip = packet.ip.src
        if src_ip == packet.ip.src:
            src_pkt_count += 1
    return src_pkt_count

def calculate_dpkts(packet):
    global dst_pkt_count
    if 'ip' in packet:
        dst_ip = packet.ip.dst
        if dst_ip == packet.ip.dst:
            dst_pkt_count += 1
    return dst_pkt_count

def calculate_sbytes(packet):
    if 'ip' in packet:
        return int(packet.length)
    return None

def calculate_dbytes(packet):
    if 'ip' in packet:
        return int(packet.length)
    return None

def calculate_rate(data):
    if 'dur' not in data or data['dur'][-1] == 0 or data['spkts'][-1] is None or data['dpkts'][-1] is None:
        return None
    else:
        return (data['spkts'][-1] + data['dpkts'][-1]) / data['dur'][-1]

source_times = dict()
destination_times = dict()
source_jitters = dict()
destination_jitters = dict()

def calculate_sinpkt(packet):
    global source_times
    try:
        if 'ip' in packet:
            source_ip = packet.ip.src
            current_time = float(packet.sniff_time.timestamp())
            if source_ip in source_times:
                # calculate the time difference
                time_diff = current_time - source_times[source_ip]
                source_times[source_ip] = current_time
                return time_diff
            else:
                source_times[source_ip] = current_time
                return None
        else:
            return None
    except AttributeError:
        return None

def calculate_dinpkt(packet):
    global destination_times
    try:
        if 'ip' in packet:
            dest_ip = packet.ip.dst
            current_time = float(packet.sniff_time.timestamp())
            if dest_ip in destination_times:
                # calculate the time difference
                time_diff = current_time - destination_times[dest_ip]
                destination_times[dest_ip] = current_time
                return time_diff
            else:
                destination_times[dest_ip] = current_time
                return None
        else:
            return None
    except AttributeError:
        return None

def calculate_sjit(packet):
    global source_jitters
    try:
        if 'ip' in packet:
            source_ip = packet.ip.src
            current_time = float(packet.sniff_time.timestamp())
            if source_ip in source_times:
                # calculate the time difference
                time_diff = current_time - source_times[source_ip]
                if source_ip in source_jitters:
                    jitter = abs(time_diff - source_jitters[source_ip])
                    source_jitters[source_ip] = time_diff
                    return jitter
                else:
                    source_jitters[source_ip] = time_diff
                    return None
            else:
                source_times[source_ip] = current_time
                return None
        else:
            return None
    except AttributeError:
        return None

def calculate_djit(packet):
    global destination_jitters
    try:
        if 'ip' in packet:
            dest_ip = packet.ip.dst
            current_time = float(packet.sniff_time.timestamp())
            if dest_ip in destination_times:
                # calculate the time difference
                time_diff = current_time - destination_times[dest_ip]
                if dest_ip in destination_jitters:
                    jitter = abs(time_diff - destination_jitters[dest_ip])
                    destination_jitters[dest_ip] = time_diff
                    return jitter
                else:
                    destination_jitters[dest_ip] = time_diff
                    return None
            else:
                destination_times[dest_ip] = current_time
                return None
        else:
            return None
    except AttributeError:
        return None

# TCP base sequence numbers
def calculate_stcpb(packet):
    try:
        if 'tcp' in packet:
            return int(packet.tcp.seq)
        else:
            return None
    except AttributeError:
        return None

def calculate_dtcpb(packet):
    try:
        if 'tcp' in packet:
            return int(packet.tcp.ack)
        else:
            return None
    except AttributeError:
        return None

# Mean packet size
source_packet_sizes = defaultdict(list)
destination_packet_sizes = defaultdict(list)

def calculate_smeansz(packet):
    try:
        if 'ip' in packet:
            source_ip = packet.ip.src
            size = int(packet.length)
            source_packet_sizes[source_ip].append(size)
            return sum(source_packet_sizes[source_ip]) / len(source_packet_sizes[source_ip])
        else:
            return None
    except AttributeError:
        return None

def calculate_dmeansz(packet):
    try:
        if 'ip' in packet:
            destination_ip = packet.ip.dst
            size = int(packet.length)
            destination_packet_sizes[destination_ip].append(size)
            return sum(destination_packet_sizes[destination_ip]) / len(destination_packet_sizes[destination_ip])
        else:
            return None
    except AttributeError:
        return None

# 使用字典保存每个TCP连接的握手过程信息
handshakes = {}

def record_handshake(packet, handshakes):
    try:
        if 'tcp' in packet and 'ip' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            flags = int(packet.tcp.flags, 16)

            # SYN packet
            if flags & 0x02:
                handshakes[(src_ip, dst_ip, src_port, dst_port)] = {
                    'syn_time': packet.sniff_time.timestamp(),
                    'synack_time': None,
                    'ack_time': None
                }

    except AttributeError:
        pass

def log_error(packet, message):
    with open('log.txt', 'a', encoding='utf-8') as log_file:
        log_file.write(f"{message}: {packet}\n")

def calculate_synack_ackdat_tcprtt(packet, handshakes):
    try:
        if 'tcp' not in packet or 'ip' not in packet:
            log_error(packet, "Packet does not contain TCP or IP")
            return 0, 0, 0

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport
        flags = int(packet.tcp.flags, 16)

        handshake = handshakes.get((src_ip, dst_ip, src_port, dst_port),
                                    handshakes.get((dst_ip, src_ip, dst_port, src_port)))

        if not handshake:
            log_error(packet, "Handshake not found")
            return 0, 0, 0

        # SYN packet
        if flags & 0x02 and handshake['syn_time'] is None:
            handshake['syn_time'] = packet.sniff_time.timestamp()

        # SYN-ACK packet
        elif flags & 0x12 and handshake['synack_time'] is None:
            handshake['synack_time'] = packet.sniff_time.timestamp()

        # ACK packet
        elif flags & 0x10 and handshake['ack_time'] is None:
            handshake['ack_time'] = packet.sniff_time.timestamp()

        # Calculate synack, ackdat, tcprtt if all timestamps are available
        if None not in handshake.values():
            synack = handshake['synack_time'] - handshake['syn_time']
            ackdat = handshake['ack_time'] - handshake['synack_time']
            tcprtt = handshake['ack_time'] - handshake['syn_time']
            return synack, ackdat, tcprtt

        else:
            log_error(packet, "Handshake incomplete")

        return 0, 0, 0

    except AttributeError as e:
        log_error(packet, f"Packet caused an AttributeError: {str(e)}")
        return 0, 0, 0

def calculate_trans_depth(packet):
    try:
        if 'http' in packet:
            return int(packet.http.request_in)
        else:
            return 0
    except AttributeError:
        return 0

def calculate_response_body_len(packet):
    try:
        if 'http' in packet:
            # Pyshark does not decompress the http content, so we just return the length of the content body
            return len(packet.http.content_length)
        else:
            return 0
    except AttributeError:
        return 0

def is_ftp_login(packet):
    try:
        if 'ftp' in packet:
            # Check if the packet is a USER or PASS command
            if packet.ftp.request.command in ["USER", "PASS"]:
                return 1
        return 0
    except AttributeError:
        return 0

def ct_ftp_cmd(packet):
    try:
        if 'ftp' in packet:
            # Check if the packet contains an FTP command
            if packet.ftp.request.command:
                return 1
        return 0
    except AttributeError:
        return 0

def pcap_to_unsw_nb15(pcap_file, csv_file):
    packets_scapy = rdpcap(pcap_file)
    cap_pyshark = pyshark.FileCapture(pcap_file, keep_packets=False, tshark_path=r'D:\Program Files\Wireshark\tshark.exe')

    # First pass: record handshakes
    handshakes = {}
    for packet_pyshark in cap_pyshark:
        record_handshake(packet_pyshark, handshakes)

    cap_pyshark.reset()

    # Second pass: calculate synack, ackdat, tcprtt
    data = defaultdict(list)
    for packet_scapy, packet_pyshark in zip(packets_scapy, cap_pyshark):
        # Calculate duration
        data['dur'].append(packet_scapy.time)

        # Protocol
        data['proto'].append(extract_proto(packet_pyshark))

        # Service and State
        data['service'].append(extract_service(packet_pyshark))
        data['state'].append(extract_state(packet_pyshark))

        # Packets and bytes
        data['spkts'].append(calculate_spkts(packet_pyshark))
        data['dpkts'].append(calculate_dpkts(packet_pyshark))
        data['sbytes'].append(calculate_sbytes(packet_pyshark))
        data['dbytes'].append(calculate_dbytes(packet_pyshark))

        # Rate
        data['rate'].append(calculate_rate(data))

        # TTL
        if IP in packet_scapy:
            data['sttl'].append(packet_scapy[IP].ttl)
            data['dttl'].append(packet_scapy[IP].ttl)
        else:
            data['sttl'].append(None)
            data['dttl'].append(None)

        # Load
        data['sload'].append(calculate_sload(packet_pyshark))
        data['dload'].append(calculate_dload(packet_pyshark))

        # Loss
        data['sloss'].append(calculate_sloss(packet_pyshark))
        data['dloss'].append(calculate_dloss(packet_pyshark))

        # Packet time
        data['sinpkt'].append(calculate_sinpkt(packet_pyshark))
        data['dinpkt'].append(calculate_dinpkt(packet_pyshark))

        # Jitter
        data['sjit'].append(calculate_sjit(packet_pyshark))
        data['djit'].append(calculate_djit(packet_pyshark))

        # Window size
        if TCP in packet_scapy:
            data['swin'].append(packet_scapy[TCP].window)
            data['dwin'].append(packet_scapy[TCP].window)
        else:
            data['swin'].append(0)
            data['dwin'].append(0)

        # TCP base sequence numbers
        data['stcpb'].append(calculate_stcpb(packet_pyshark))
        data['dtcpb'].append(calculate_dtcpb(packet_pyshark))

        # TCP RTT and SYN/ACK data
        synack, ackdat, tcprtt = calculate_synack_ackdat_tcprtt(packet_pyshark, handshakes)
        data['synack'].append(synack)
        data['ackdat'].append(ackdat)
        data['tcprtt'].append(tcprtt)

        # Mean packet size
        data['smean'].append(calculate_smeansz(packet_pyshark))
        data['dmean'].append(calculate_dmeansz(packet_pyshark))

        # Transaction depth and response body length
        data['trans_depth'].append(calculate_trans_depth(packet_pyshark))
        data['response_body_len'].append(calculate_response_body_len(packet_pyshark))

        # Count fields
        data['ct_srv_src'].append(None)#No. of connections that contain the same service (14) and source address (1) in 100 connections according to the last time (26).
        data['ct_state_ttl'].append(None)#No. for each state (6) according to specific range of values for source/destination time to live (10) (11).
        data['ct_dst_ltm'].append(None)#No. of connections of the same destination address (3) in 100 connections according to the last time (26).
        data['ct_src_dport_ltm'].append(None)#No of connections of the same source address (1) and the destination port (4) in 100 connections according to the last time (26).
        data['ct_dst_sport_ltm'].append(None)#No of connections of the same destination address (3) and the source port (2) in 100 connections according to the last time (26).
        data['ct_dst_src_ltm'].append(None)#No of connections of the same source (1) and the destination (3) address in in 100 connections according to the last time (26).

        # FTP login and command count
        data['is_ftp_login'].append(is_ftp_login(packet_pyshark))#Binary	If the ftp session is accessed by user and password then 1 else 0.
        data['ct_ftp_cmd'].append(ct_ftp_cmd(packet_pyshark))#No of flows that has a command in ftp session.

        # HTTP method count
        data['ct_flw_http_mthd'].append(None)#No. of flows that has methods such as Get and Post in http service.

        # Source and destination counts
        data['ct_src_ltm'].append(None)#No. of connections of the same source address (1) in 100 connections according to the last time (26).
        data['ct_srv_dst'].append(None)#No. of connections that contain the same service (14) and destination address (3) in 100 connections according to the last time (26).

        # Same source and destination IPs and ports
        data['is_sm_ips_ports'].append(None)#Binary If source (1) and destination (3)IP addresses equal and port numbers (2)(4)  equal then, this variable takes value 1 else 0

        # Attack category and label
        data['attack_cat'].append(None)
        data['label'].append(None)

    df = pd.DataFrame(data)

    # Post-process 'dur' field to represent duration rather than timestamp
    df['dur'] = df['dur'] - df['dur'].shift(1)
    df.at[0, 'dur'] = 0

    df.to_csv(csv_file, index=False)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    pcap_to_unsw_nb15('F:\\Users\\Jerry\Downloads\\27.pcap', 'D:\\Users\\Jerry\\Downloads\\output.csv')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
