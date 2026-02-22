
# Network Traffic Analyzer

A lightweight command-line network traffic analyzer built in C++ using libpcap. Captures packets in real-time, parses protocol headers across OSI layers (L2–L4), identifies common services, and generates traffic statistics.

> Built as a learning project to understand how network protocols work at the packet level — the same principles used by tools like Wireshark and tcpdump.

## Features

- **Real-time packet capture** on any network interface
- **Protocol parsing** across multiple layers:
  - L2: Ethernet (MAC addresses, EtherType)
  - L3: IPv4 (source/destination IP)
  - L4: TCP, UDP, ICMP (ports, protocol identification)
- **Service detection** — recognizes common ports (HTTPS, DNS, SSH, HTTP, FTP, DHCP, WireGuard, and more)
- **Live traffic statistics** — press `Ctrl+C` to display:
  - Total packets and data volume
  - Protocol distribution (TCP / UDP / ICMP)
  - Most active IP addresses

## Example Output

```
Zachytavam pakety na en0... (Ctrl+C pro statistiky)
============================================================
[14:23:01] #1 | TCP (HTTPS) | 192.168.1.5:54321 -> 142.250.74.46:443 | 1240B
[14:23:01] #2 | UDP (DNS)   | 192.168.1.5:51000 -> 8.8.8.8:53 | 74B
[14:23:02] #3 | TCP (HTTPS) | 142.250.74.46:443 -> 192.168.1.5:54321 | 580B
[14:23:03] #4 | TCP (HTTP)  | 192.168.1.5:49800 -> 93.184.216.34:80 | 420B
[14:23:05] #5 | UDP (NTP)   | 192.168.1.5:52100 -> 17.253.34.123:123 | 90B
^C

========== STATISTIKY ==========
Celkem paketu: 5
Celkem dat:    2404 bajtu (2 KB)

--- Protokoly ---
  TCP: 3 paketu
  UDP: 2 paketu

--- Top IP adresy ---
  192.168.1.5: 5 paketu
  142.250.74.46: 2 paketu
  8.8.8.8: 1 paketu
=================================
```

## Interesting Finding — VPN Effect

When running the analyzer **without a VPN**, you can see a full mix of protocols and destination IPs — DNS queries, HTTPS connections to various servers, etc.

With a **VPN (e.g., WireGuard) enabled**, all traffic is encapsulated into a single encrypted UDP tunnel to one IP address. The analyzer only sees UDP packets on the WireGuard port (51820), demonstrating exactly why VPNs are effective at hiding your traffic from network observers.

<!-- Add your own screenshots here -->
<!-- ![Without VPN](screenshots/no-vpn.png) -->
<!-- ![With VPN](screenshots/vpn.png) -->

## How It Works

The analyzer follows the OSI model to parse each packet layer by layer:

```
Raw packet data
  └── Ethernet Header (14 bytes) ─── L2: MAC addresses, EtherType
        └── IP Header (20+ bytes) ─── L3: Source/Destination IP, Protocol
              └── TCP/UDP Header ──── L4: Source/Destination Port
```

1. **libpcap** captures raw packets from the network interface in promiscuous mode
2. The **Ethernet header** is parsed first (14 bytes) to check if it's an IP packet (`EtherType 0x0800`)
3. The **IP header** provides source/destination addresses and identifies the transport protocol
4. The **TCP or UDP header** is parsed for port numbers, which are matched against known services
5. Statistics are accumulated in `std::map` containers and displayed on `SIGINT` (Ctrl+C)

## Requirements

- macOS or Linux
- libpcap (pre-installed on macOS, `sudo apt install libpcap-dev` on Linux)
- C++17 compatible compiler (g++ or clang++)
- Root/sudo privileges (required for packet capture)

## Build & Run

```bash
# Compile
g++ -o sniffer sniffer.cpp -L/usr/lib -lpcap

# Run (requires sudo for raw packet access)
sudo ./sniffer
```

### Linux

```bash
# Install libpcap
sudo apt install libpcap-dev

# Compile & run
g++ -o sniffer sniffer.cpp -lpcap
sudo ./sniffer
```

## Recognized Services

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 25 | SMTP | Email sending |
| 53 | DNS | Domain Name System |
| 67/68 | DHCP | Dynamic Host Configuration |
| 80 | HTTP | Web (unencrypted) |
| 110 | POP3 | Email retrieval |
| 123 | NTP | Network Time Protocol |
| 143 | IMAP | Email retrieval |
| 443 | HTTPS | Web (encrypted) |
| 3389 | RDP | Remote Desktop |
| 51820 | WireGuard | VPN tunnel |

## Project Structure

```
.
├── sniffer.cpp    # Main source file
└── README.md
```

## What I Learned

- How packets are structured across OSI layers (Ethernet → IP → TCP/UDP)
- Working with raw memory and pointer arithmetic in C++ to parse binary data
- Using libpcap for live packet capture and promiscuous mode
- Network byte order (big-endian) vs host byte order — `ntohs()` for conversion
- Signal handling in C/C++ (`SIGINT` / `Ctrl+C`)
- How VPNs encapsulate traffic and why they protect privacy
- Using `std::map` for accumulating and analyzing data

## Legal & Ethical Notice

- This tool captures network traffic on **your own machine/network only**
- Intercepting others' network traffic without consent is **illegal** in most jurisdictions
- Built for **educational purposes** and network troubleshooting
- Always follow responsible and ethical practices

## Author

**Matěj Kulíšek** — IT Student & Security Enthusiast

- Portfolio: [kulisekmatej.github.io](https://kulisekmatej.github.io)
- GitHub: [github.com/Kulisekmatej](https://github.com/Kulisekmatej)
- Certifications: CCNA 1, CompTIA Security+

## References

- [libpcap documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [Programming with pcap](https://www.tcpdump.org/pcap.html)
- [RFC 791 — Internet Protocol (IPv4)](https://datatracker.ietf.org/doc/html/rfc791)
- [RFC 793 — Transmission Control Protocol](https://datatracker.ietf.org/doc/html/rfc793)
