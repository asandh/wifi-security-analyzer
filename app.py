from flask import Flask
from scapy.all import rdpcap, DNS, TCP, Raw, IP

app = Flask(__name__)

def analyze_packets():
    packets = rdpcap("capture.pcap")

    dns_count = 0
    http_count = 0
    tcp_count = 0
    unique_ips = set()
    ip_count = {}

    for packet in packets:
        if packet.haslayer(IP):
            unique_ips.add(packet[IP].src)
            unique_ips.add(packet[IP].dst)

            dst_ip = packet[IP].dst
            ip_count[dst_ip] = ip_count.get(dst_ip, 0) + 1

        if packet.haslayer(TCP):
            tcp_count += 1

        if packet.haslayer(DNS):
            dns_count += 1

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                http_count += 1

    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_packets": len(packets),
        "tcp_count": tcp_count,
        "dns_count": dns_count,
        "http_count": http_count,
        "unique_ips": len(unique_ips),
        "top_ips": top_ips
    }

@app.route("/")
def home():
    data = analyze_packets()

    top_ip_rows = ""
    for ip, count in data["top_ips"]:
        top_ip_rows += f"<tr><td>{ip}</td><td>{count}</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>WiFi Security Analyzer</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #0f172a;
                color: white;
                margin: 0;
                padding: 40px;
            }}

            h1 {{
                text-align: center;
                margin-bottom: 10px;
            }}

            .subtitle {{
                text-align: center;
                color: #94a3b8;
                margin-bottom: 40px;
            }}

            .cards {{
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 20px;
                margin-bottom: 40px;
            }}

            .card {{
                background: #1e293b;
                padding: 25px;
                border-radius: 14px;
                text-align: center;
                box-shadow: 0 4px 10px rgba(0,0,0,0.3);
            }}

            .card h2 {{
                font-size: 32px;
                margin: 0;
                color: #38bdf8;
            }}

            .card p {{
                color: #cbd5e1;
            }}

            .section {{
                background: #1e293b;
                padding: 25px;
                border-radius: 14px;
                margin-bottom: 25px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }}

            th, td {{
                padding: 12px;
                border-bottom: 1px solid #334155;
                text-align: left;
            }}

            th {{
                color: #38bdf8;
            }}

            .warning {{
                color: #f87171;
                font-weight: bold;
            }}

            .good {{
                color: #4ade80;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <h1>WiFi Security Analyzer</h1>
        <p class="subtitle">Network traffic analysis using Wireshark, Python, Scapy, and Flask</p>

        <div class="cards">
            <div class="card">
                <h2>{data["total_packets"]}</h2>
                <p>Total Packets</p>
            </div>

            <div class="card">
                <h2>{data["tcp_count"]}</h2>
                <p>TCP Packets</p>
            </div>

            <div class="card">
                <h2>{data["dns_count"]}</h2>
                <p>DNS Requests</p>
            </div>

            <div class="card">
                <h2>{data["http_count"]}</h2>
                <p>HTTP Packets</p>
            </div>

            <div class="card">
                <h2>{data["unique_ips"]}</h2>
                <p>Unique IPs</p>
            </div>
        </div>

        <div class="section">
            <h2>Security Notes</h2>
            <p class="{ "warning" if data["http_count"] > 0 else "good" }">
                {"Insecure HTTP traffic detected." if data["http_count"] > 0 else "No insecure HTTP traffic detected."}
            </p>

            <p class="{ "warning" if data["dns_count"] > 200 else "good" }">
                {"High DNS activity detected." if data["dns_count"] > 200 else "DNS activity appears normal."}
            </p>

            <p class="{ "warning" if data["unique_ips"] > 30 else "good" }">
                {"High number of external connections detected." if data["unique_ips"] > 30 else "Connection count appears normal."}
            </p>
        </div>

        <div class="section">
            <h2>Top 5 Most Contacted IP Addresses</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Connections</th>
                </tr>
                {top_ip_rows}
            </table>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)