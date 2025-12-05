💀 Net-Blade

"The wire never lies. It only waits to be harvested."

Packet Reaper is a Python-based forensic reconnaissance tool designed to scavenge sensitive data from captured network traffic (PCAP files).

Unlike heavy GUIs like Wireshark, Packet Reaper is a lightweight CLI assassin. It parses unencrypted traffic to automatically extract credentials, detect covert exfiltration tunnels, and identify file attachments without manual stream following.

⚡ Capabilities

Packet Reaper focuses on "Low Hanging Fruit" — the critical data often missed in the noise of massive capture files.

🔓 Credential Harvesting

Cleartext Protocols: Automatically extracts USER and PASS commands from FTP, POP3, IMAP, and Telnet.

HTTP Auth: Detects Authorization: Basic headers and automatically Base64 decodes them into username:password.

Session Hijacking: Identifies unsecure Cookies and Auth tokens.

🚇 Covert Channel Detection

ICMP Tunneling: Inspects Ping (Echo Request) payloads for hidden data/flags (ignoring standard padding).

DNS Exfiltration: Flags suspiciously long DNS queries or encoded subdomains often used by C2 beacons.

📂 File Forensics

Magic Byte Detection: Alerts on the presence of file headers inside TCP streams (ZIP, PDF).

Email Attachments: Detects Uuencode blocks and MIME Content-Disposition headers in SMTP traffic.

📥 Installation

Packet Reaper depends on scapy for packet manipulation.

1. Prerequisites

sudo apt install python3-pip
pip3 install scapy


2. Setup

Download the script to your analysis machine.
using git clone or wget
chmod +x net-blade.py


⚔️ Usage

Simply feed the Reaper a PCAP file.

python3 net-blade.py <capture_file.pcap>


Example

root@kali:~$ python3 net-blade.py capture.pcap

    .           .
  /' \         /`\
 /   | .---.  |   \
|    |/  _  \|    |
 \   | '---'  |   /   PACKET
  \./         \./     REAPER
   |           |
   |           |    Harvesting the wire.

[*] Loading PCAP: capture.pcap...
[+] Packets Loaded: 1450
[*] Hunting for sensitive data...

[CREDENTIAL] Found: admin:password123 (Packet #45)
[DNS EXFIL]  Suspicious Query: 5fb00e942-37cb.pentesterlab.com
[ICMP TUNNEL] Data: ecf76ba6-68c7-4039-9b9b-407167fe2757
[FILE FOUND] ZIP Header Detected in TCP Stream.


⚠️ Limitations

Packet Reaper is a Passive Reconnaissance tool. It operates under specific constraints:

Encryption: It cannot analyze encrypted traffic (TLS/SSL) unless you are using an SSL-stripping proxy during capture. It looks for data exposed before encryption or on unencrypted ports.

Fragmentation: It analyzes packets individually. It does not perform full TCP stream reassembly (File Carving). It detects signatures of files, but you will need foremost or Wireshark to extract the full binary.

⚖️ Disclaimer

This tool is designed for security professionals, CTF players, and network administrators to audit their own networks. Unauthorized interception or analysis of traffic you do not own is illegal. The developer assumes no liability for misuse.

Happy Hunting.
