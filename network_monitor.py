from scapy.all import sniff, Ether, IP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip}")

def start_sniffing(interface="en0", count=10):
    print(f"Sniffing {count} packets on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=count)

if __name__ == "__main__":
    start_sniffing()
