# ==============================================================================
# PROJECT: AEGIS (Advanced Engine for Global Interception & Security)
# FILE:    main.py
# PURPOSE: Intercepts DNS and HTTPS traffic directly from the network interface.
# ==============================================================================

import sys      # Used for system exit.
import struct   # Byte manipulation/unpacking.
import logging  # Activity logging.
import argparse # Command line argument parsing.

# --- EXTERNAL DEPENDENCIES CHECK (CHECKPOINT 1) ---
try:
    import pydivert               # Windows Packet Divert driver wrapper.
    from dnslib import DNSRecord  # DNS packet parsing library.
    from colorama import init, Fore, Style # Terminal coloring.
except ImportError as e:
    print(f"[!] CRITICAL ERROR: Missing library '{e.name}'.")
    print(f"    Run: pip install pydivert dnslib colorama")
    sys.exit(1)

# --- CONFIGURATION CHECK (CHECKPOINT 2) ---
try:
    # Import the blacklist dictionary.
    from domains import BLACKLIST_DB 
except ImportError:
    print("[!] ERROR: 'domains.py' not found. File missing.")
    sys.exit(1)

# Initialize color output.
init(autoreset=True)

# Configure logging format.
logging.basicConfig(
    format=f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} | %(message)s',
    level=logging.INFO,
    datefmt='%H:%M:%S'
)


# ==============================================================================
# FUNCTION 1: HTTPS SNI PARSING
# ==============================================================================
# Extracts the Server Name Indication (SNI) from the TLS Client Hello packet.
# This allows us to identify the destination domain even in encrypted traffic.
def get_https_domain(payload_bytes):
    """
    Parses raw TCP payload bytes.
    Returns: Domain string (e.g., google.com) or None if not found.
    """
    try:
        # Step 1: Validate TLS Handshake header.
        # 0x16 = Handshake, 0x03 = TLS Version, 0x01 = Client Hello.
        if len(payload_bytes) < 50: 
            return None 
        
        if payload_bytes[0] != 0x16 or payload_bytes[5] != 0x01:
            return None 

        # Step 2: Pointer Arithmetic to find extensions.
        # Skip the fixed header (43 bytes).
        cursor = 43 

        # Skip Session ID.
        len_session = payload_bytes[cursor]
        cursor += 1 + len_session

        # Skip Cipher Suites.
        len_ciphers = struct.unpack('!H', payload_bytes[cursor : cursor+2])[0]
        cursor += 2 + len_ciphers

        # Skip Compression Methods.
        len_compress = payload_bytes[cursor]
        cursor += 1 + len_compress

        # Step 3: Extensions Block.
        # Read total extensions length.
        len_ext_total = struct.unpack('!H', payload_bytes[cursor : cursor+2])[0]
        cursor += 2
        
        end_point = cursor + len_ext_total

        # Step 4: Iterate through extensions.
        while cursor < end_point:
            ext_type, ext_len = struct.unpack('!HH', payload_bytes[cursor : cursor+4])
            
            # Extension Type 0 (0x00) is SERVER NAME.
            if ext_type == 0:
                # Skip List Length + Name Type.
                name_len = struct.unpack('!H', payload_bytes[cursor+7 : cursor+9])[0]
                
                # Extract Domain Name.
                domain_bytes = payload_bytes[cursor+9 : cursor+9+name_len]
                return domain_bytes.decode('utf-8').lower()

            # Move to next extension.
            cursor += 4 + ext_len

    except Exception:
        return None # Return None on malformed packets.
    
    return None


# ==============================================================================
# FUNCTION 2: TRAFFIC INSPECTION LOGIC
# ==============================================================================
# Checks if the extracted domain exists in the blacklist.
def inspect_traffic(domain_name):
    """
    Input: Domain string.
    Returns: Threat Category (Malware, Spyware, etc.) or None if clean.
    """
    if not domain_name:
        return None

    # Iterate through categories in blacklist database.
    for category, patterns in BLACKLIST_DB.items():
        for pattern in patterns:
            # Suffix match check (e.g., 'evil.ddns.net' ends with '.ddns.net').
            if domain_name.endswith(pattern):
                return category 
    
    return None


# ==============================================================================
# MAIN ENGINE LOOP
# ==============================================================================
def start_aegis(block_mode=False):
    print(f"\n{Fore.GREEN}>>> AEGIS SYSTEM ONLINE <<<")
    
    if block_mode:
        print(f"{Fore.RED}[!] MODE: ACTIVE BLOCKING (Malicious packets will be dropped)")
    else:
        print(f"{Fore.YELLOW}[!] MODE: MONITORING (Logging only)")

    # WinDivert Filter:
    # "outbound" = Capture outgoing traffic only.
    # "udp.DstPort == 53" = DNS queries.
    # "tcp.DstPort == 443" = HTTPS connections.
    # Optimizes performance by ignoring irrelevant traffic (e.g., video streaming).
    traffic_filter = "outbound and (udp.DstPort == 53 or tcp.DstPort == 443)"

    try:
        # Open network handle.
        with pydivert.WinDivert(traffic_filter) as network_stream:
            for packet in network_stream:
                
                domain = None
                protocol = "N/A"

                # CASE 1: DNS Traffic (UDP 53)
                if packet.udp:
                    try:
                        dns_data = DNSRecord.parse(packet.payload)
                        # Extract query name (qname) and strip trailing dot.
                        domain = str(dns_data.q.qname).strip('.').lower()
                        protocol = "DNS"
                    except:
                        pass # Ignore malformed DNS.

                # CASE 2: HTTPS Traffic (TCP 443)
                elif packet.tcp:
                    # Parse SNI using custom function.
                    domain = get_https_domain(packet.payload)
                    protocol = "TLS"

                # If a domain was identified, inspect it.
                if domain:
                    threat = inspect_traffic(domain)

                    if threat:
                        # THREAT DETECTED
                        msg = f"[{protocol}] {domain} -> DETECTED AS {threat}"
                        
                        if block_mode:
                            # ACTION: BLOCK
                            logging.warning(f"{Fore.RED}BLOCKED: {msg}")
                            # packet is NOT sent (drop).
                            continue 
                        else:
                            # ACTION: LOG
                            logging.info(f"{Fore.YELLOW}ALERT:   {msg}")
                    
                    else:
                        # TRAFFIC CLEAN
                        # Uncomment for verbose debugging:
                        logging.info(f"{Fore.GREEN}CLEAN:   [{protocol}] {domain}")
                        pass

                # Re-inject packet into the network stack.
                network_stream.send(packet)

    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}>>> AEGIS SHUTTING DOWN <<<")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!!!] CRITICAL ERROR: {e}")
        print("Hint: Run terminal as Administrator.")


# --- ENTRY POINT ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Network Defense System")
    parser.add_argument("-b", "--block", action="store_true", help="Enable active traffic blocking.")
    
    args = parser.parse_args()
    
    start_aegis(args.block)