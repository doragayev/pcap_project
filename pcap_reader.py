"""
קריאה וניתוח קבצי pcap
"""

import logging
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.utils import rdpcap
from datetime import datetime


logger = logging.getLogger(__name__)


def extract_packet_info(pkt):
    """
    מקבלת חבילה אחת
    ומחלצת את המידע שאני צריך
    """
    info = {
        'timestamp': datetime.fromtimestamp(float(pkt.time)).isoformat(),
        'timestamp_raw': float(pkt.time),
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'l4_protocol': 'other',
        'packet_length': len(pkt)
    }

    if IP in pkt:
        ip_layer = pkt[IP]
        info['src_ip'] = ip_layer.src
        info['dst_ip'] = ip_layer.dst

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            info['src_port'] = tcp_layer.sport
            info['dst_port'] = tcp_layer.dport
            info['l4_protocol'] = 'tcp'

        elif UDP in pkt:
            udp_layer = pkt[UDP]
            info['src_port'] = udp_layer.sport
            info['dst_port'] = udp_layer.dport
            info['l4_protocol'] = 'udp'

        elif ICMP in pkt:
            info['l4_protocol'] = 'icmp'

    elif ARP in pkt:
        arp_layer = pkt[ARP]
        info['src_ip'] = arp_layer.psrc
        info['dst_ip'] = arp_layer.pdst
        info['l4_protocol'] = 'arp'
    
    return info




def read_pcap(pcap_file):
    """
    קוראת קובץ pcap ומחזיר כל פעם חבילה אחת כשהן מומרות למילון עם המידע הרלוונטי
    """
    try:
        logger.info(f"Reading PCAP file: {pcap_file}")
        packets = rdpcap(pcap_file)
        logger.info(f"Total packets in file: {len(packets)}")
        
        for i, pkt in enumerate(packets):
            try:
                packet_info = extract_packet_info(pkt)
                packet_info['packet_number'] = i + 1
                yield packet_info
            except Exception as e:
                logger.warning(f"Error processing packet {i+1}: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    for packet in read_pcap('samples/packetcapture-igb1-20260113105742.pcap'):
        print(packet)
        break
