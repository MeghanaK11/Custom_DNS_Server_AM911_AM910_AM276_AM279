import socket
import struct

def handshake(sock, server_ip, port):
    """
    Two-way handshake:
      Client → Server : HELLO
      Server → Client : ACK
      Client → Server : CONFIRM
      Server → Client : READY
    Returns True if all four steps succeed.
    """
    try:
        # Step 1
        print("[HS] Sending HELLO...")
        sock.sendto(b"HELLO", (server_ip, port))

        # Step 2
        data, _ = sock.recvfrom(512)
        if data.strip() != b"ACK":
            print(f"[HS] ❌ Expected ACK, got: {data}")
            return False
        print("[HS] ACK received")

        # Step 3
        print("[HS] Sending CONFIRM...")
        sock.sendto(b"CONFIRM", (server_ip, port))

        # Step 4
        data, _ = sock.recvfrom(512)
        if data.strip() != b"READY":
            print(f"[HS] ❌ Expected READY, got: {data}")
            return False

        print("[HS] ✅ Handshake complete — connection established\n")
        return True

    except socket.timeout:
        print("[HS] ❌ Timeout — is the server running at that IP?")
        return False
    except Exception as e:
        print(f"[HS] ❌ Error: {e}")
        return False


# ── DNS packet builder ────────────────────────────────────────────────────────

def build_dns_query(domain):
    """Build a raw DNS A-record query packet for the given domain."""
    header = (
        b"\xaa\xaa"  +  # transaction ID
        b"\x01\x00"  +  # flags: standard query, recursion desired
        b"\x00\x01"  +  # QDCOUNT = 1
        b"\x00\x00"  +  # ANCOUNT = 0
        b"\x00\x00"  +  # NSCOUNT = 0
        b"\x00\x00"     # ARCOUNT = 0
    )

    qname = b""
    for label in domain.rstrip(".").split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"  # root null terminator

    question = qname + b"\x00\x01" + b"\x00\x01"  # QTYPE=A, QCLASS=IN

    return header + question


# ── IP extractor ──────────────────────────────────────────────────────────────

def extract_ip(response):
    """Extract the IPv4 address from the last 4 bytes of a DNS response."""
    try:
        return ".".join(str(b) for b in response[-4:])
    except Exception:
        return "could not parse IP"


# ── Main query flow ───────────────────────────────────────────────────────────

def send_dns_query(domain, server_ip, port=8053):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    print(f"[CLIENT] Connecting to {server_ip}:{port}")

    if not handshake(sock, server_ip, port):
        print("[CLIENT] Aborting — handshake failed.")
        sock.close()
        return

    print(f"[CLIENT] Querying: {domain}")
    packet = build_dns_query(domain)
    sock.sendto(packet, (server_ip, port))

    try:
        response, _ = sock.recvfrom(512)

        if response == b"ERR_NO_HANDSHAKE":
            print("[CLIENT] ❌ Server rejected query — handshake not recognised")
            return

        ip = extract_ip(response)
        print(f"\n✅  {domain}  →  {ip}\n")

    except socket.timeout:
        print("[CLIENT] ❌ No response (timeout)")
    finally:
        sock.close()


if __name__ == "__main__":
    server_ip = input("Enter DNS server IP: ").strip()
    domain    = input("Enter domain to query: ").strip()
    send_dns_query(domain, server_ip)