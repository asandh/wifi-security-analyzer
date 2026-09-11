from scapy.all import rdpcap, DNS, TCP, Raw, IP

packets = rdpcap("capture.pcap")

dns_count = 0
http_count = 0
tcp_count = 0
unique_ips = set()

for packet in packets:
    if packet.haslayer(IP):
        unique_ips.add(packet[IP].src)
        unique_ips.add(packet[IP].dst)

    if packet.haslayer(TCP):
        tcp_count += 1

    if packet.haslayer(DNS):
        dns_count += 1

    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
            http_count += 1

print("===== WiFi Security Analyzer Report =====")
print(f"Total packets analyzed: {len(packets)}")
print(f"TCP packets: {tcp_count}")
print(f"DNS requests detected: {dns_count}")
print(f"Insecure HTTP packets detected: {http_count}")
print(f"Unique IP addresses seen: {len(unique_ips)}")


print("\n===== Security Analysis =====")

if http_count > 0:
    print("⚠️ Insecure HTTP traffic detected – possible risk of data exposure")

if dns_count > 200:
    print("⚠️ High DNS activity – potential heavy browsing or scanning")

if len(unique_ips) > 30:
    print("⚠️ High number of external connections detected")



ip_count = {}

for packet in packets:
    if packet.haslayer(IP):
        ip = packet[IP].dst
        ip_count[ip] = ip_count.get(ip, 0) + 1

top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]

print("\nTop 5 Most Contacted IPs:")
for ip, count in top_ips:
    print(ip, "-", count, "connections")