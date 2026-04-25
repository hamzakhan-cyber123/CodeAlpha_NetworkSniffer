#!/usr/bin/env python3
# =============================================================
# CodeAlpha Internship — Task 1: Basic Network Sniffer
# Author : Ameer Hamza Khan
# Tool   : Scapy (Python)
# =============================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

# Packet counter
packet_count = 0

def get_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"

def get_payload(pkt):
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        try:
            return raw.decode("utf-8", errors="replace")[:80]
        except:
            return "[Binary Data]"
    return "No Payload"

def process_packet(pkt):
    global packet_count

    if not pkt.haslayer(IP):
        return

    packet_count += 1
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    protocol  = get_protocol(pkt)
    src_ip    = pkt[IP].src
    dst_ip    = pkt[IP].dst
    payload   = get_payload(pkt)

    src_port = dst_port = "-"
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    print(f"\n[#{packet_count}] ─── {timestamp} ─── {protocol}")
    print(f"  SRC : {src_ip}:{src_port}")
    print(f"  DST : {dst_ip}:{dst_port}")
    print(f"  PAY : {payload[:60]}")
    print("  " + "─"*50)

def main():
    print("""
╔══════════════════════════════════════╗
║   CodeAlpha — Basic Network Sniffer  ║
║   Press Ctrl+C to stop capture       ║
╚══════════════════════════════════════╝
""")
    print("[*] Starting packet capture...\n")
    try:
        sniff(prn=process_packet, store=False, filter="ip")
    except KeyboardInterrupt:
        print(f"\n\n[!] Capture stopped. Total packets: {packet_count}")

if __name__ == "__main__":
    main()
