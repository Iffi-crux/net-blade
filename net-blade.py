#!/usr/bin/env python3
import logging
# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import re
import base64
import sys
import binascii

# --- THE ASSASSIN PALETTE ---
RED     = '\033[91m'
GREEN   = '\033[92m'
GOLD    = '\033[93m'
WHITE   = '\033[97m'
BOLD    = '\033[1m'
RESET   = '\033[0m'
GREY    = '\033[90m'

def banner():
    print(f"""{RED}
    .           .
  /' \         /`\\
 /   | .---.  |   \\
|    |/  _  \|    |
|    |\   _  /|    |
 \   | '---'  |   /
  \./         \./   {WHITE}PACKET{RED}
   |           |    {WHITE}REAPER{RED}
   |           |
   |           |    {GREY}Harvesting the wire.{RESET}
    """)

def analyze_pcap(pcap_file):
    print(f"{GREY}[*] Loading PCAP: {pcap_file}...{RESET}")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"{RED}[!] File not found.{RESET}")
        return
    except Exception as e:
        print(f"{RED}[!] Error loading PCAP: {e}{RESET}")
        return

    print(f"{GREEN}[+] Packets Loaded: {len(packets)}{RESET}")
    print(f"{GREY}[*] Hunting for sensitive data...{RESET}\n")

    found_creds = []
    found_files = []
    
    for pkt in packets:
        
        # 1. CREDENTIAL HARVESTER (Cleartext)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            
            # FTP / POP3 / IMAP / Telnet Patterns
            cred_patterns = [
                b'USER ([\w]+)', 
                b'PASS ([\w]+)', 
                b'Authorization: Basic ([\w=]+)',
                b'auth=([\w]+)',  # Cookie based
                b'Set-Cookie: ([\w=]+)'
            ]

            for pattern in cred_patterns:
                match = re.search(pattern, payload, re.IGNORECASE)
                if match:
                    data = match.group(1).decode('utf-8', errors='ignore')
                    
                    # If it's Basic Auth, try to decode it
                    if b'Basic' in pattern:
                        try:
                            decoded = base64.b64decode(data).decode()
                            data = f"{data} -> {GREEN}{decoded}{RESET}"
                        except:
                            pass
                            
                    print(f"{RED}[CREDENTIAL]{RESET} Found: {BOLD}{data}{RESET} (Packet {pkt.summary()})")

        # 2. ICMP EXFILTRATION (Tunneling)
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8: # Echo Request
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                # Ignore standard padding (abcde...) or nulls
                if len(payload) > 1 and not payload.startswith(b'\x00') and not payload.startswith(b'abcde'):
                    try:
                        clean_data = payload.decode('utf-8', errors='ignore')
                        # Heuristic: If it looks like a UUID or flag
                        if len(clean_data) > 10:
                            print(f"{GOLD}[ICMP TUNNEL]{RESET} Data: {WHITE}{clean_data}{RESET}")
                    except:
                        pass

        # 3. DNS EXFILTRATION
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            # Look for long subdomains or known hex/base64 chars
            if len(query) > 30: 
                # Check if it looks like a hex dump or base64
                print(f"{GOLD}[DNS EXFIL]{RESET} Suspicious Query: {WHITE}{query}{RESET}")

        # 4. FILE CARVING (Signatures)
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            
            # Zip File Signature (PK..)
            if payload.startswith(b'\x50\x4b\x03\x04'):
                print(f"{GREEN}[FILE FOUND]{RESET} ZIP Header Detected in TCP Stream.")
            
            # PDF Signature
            if payload.startswith(b'%PDF'):
                print(f"{GREEN}[FILE FOUND]{RESET} PDF Header Detected.")
            
            # Uuencode / Base64 Email Attachments
            if b'begin 644' in payload:
                print(f"{GREEN}[FILE FOUND]{RESET} Uuencode attachment detected (Email).")
                
            if b'Content-Disposition: attachment' in payload:
                print(f"{GREEN}[FILE FOUND]{RESET} MIME Attachment detected.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 packet_reaper.py <file.pcap>")
        sys.exit(1)
        
    banner()
    analyze_pcap(sys.argv[1])
