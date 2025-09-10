# sniffer.py
import argparse
from scapy.all import sniff, IP
from datetime import datetime
import database

db_conn = None

def packet_handler(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol_num = packet[IP].proto
        protocol = database.PROTOCOL_MAP.get(protocol_num, f"Other({protocol_num})")
        size = len(packet)
        timestamp = datetime.now().isoformat()
        packet_info = (timestamp, source_ip, destination_ip, protocol, size)
        if db_conn:
            database.store_packet(db_conn, packet_info)
            print(f".", end='', flush=True)

def print_statistics(stats):
    if not stats:
        print("Could not retrieve statistics.")
        return
    print("\n\n--- Network Traffic Analysis ---")
    print(f"Total Packets Captured: {stats.get('total_packets', 0)}")
    print("\n--- Packets per Protocol ---")
    for proto, count in stats.get('protocol_counts', {}).items():
        print(f"{proto}: {count}")
    print("\n--- Top 5 Source IPs ---")
    for i, (ip, count) in enumerate(stats.get('top_source_ips', []), 1):
        print(f"{i}. {ip}: {count} packets")
    print("\n--- Top 5 Destination IPs ---")
    for i, (ip, count) in enumerate(stats.get('top_destination_ips', []), 1):
        print(f"{i}. {ip}: {count} packets")
    print("--------------------------------")

def main():
    global db_conn
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on.")
    parser.add_argument("-c", "--count", type=int, default=50, help="Number of packets to capture.")
    args = parser.parse_args()
    db_conn = database.create_connection()
    if db_conn is None: return
    database.create_table(db_conn)
    print(f"[*] Sniffing {args.count} packets on interface {args.interface}...")
    try:
        sniff(iface=args.interface, count=args.count, prn=packet_handler, store=0)
    except Exception as e:
        print(f"\n[!] An error occurred during sniffing: {e}")
        db_conn.close()
        return
    print(f"\n[*] Packet capture complete.")
    stats = database.get_statistics(db_conn)
    print_statistics(stats)
    db_conn.close()

if __name__ == "__main__":
    main()