import socket
import threading
from dns_records import DNS_RECORDS
from utils import parse_dns_query, build_response

UPSTREAM_DNS  = ("8.8.8.8", 53)
UPSTREAM_PORT = 53

# Thread-safe set of client addresses that completed the handshake
_verified     = set()
_verified_lock = threading.Lock()


# ── Upstream forwarding ───────────────────────────────────────────────────────

def forward_query(data):
    """Forward a raw DNS packet to Google DNS. Retries once on timeout."""
    for attempt in range(2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(data, UPSTREAM_DNS)
            response, _ = sock.recvfrom(512)
            sock.close()
            return response
        except socket.timeout:
            print(f"[WARN] Upstream timeout (attempt {attempt + 1}/2)")
    return None


# ── DNS query handler (runs in thread) ───────────────────────────────────────

def handle_dns(data, addr, sock):
    try:
        query  = parse_dns_query(data)
        domain = query["domain"]

        print(f"[QUERY] {addr} → {domain}")

        if not domain or len(domain) > 253:
            print("[DROP] Invalid domain length")
            return

        if domain in DNS_RECORDS:
            ip       = DNS_RECORDS[domain]
            response = build_response(query, ip)
            sock.sendto(response, addr)
            print(f"[LOCAL] {domain} → {ip}")
        else:
            response = forward_query(data)
            if response:
                sock.sendto(response, addr)
                print(f"[FORWARD] {domain} → upstream")
            else:
                print(f"[ERROR] Upstream failed for {domain}")

    except Exception as e:
        print(f"[ERROR] handle_dns: {e}")


# ── Main server loop ──────────────────────────────────────────────────────────

def start_server(host="0.0.0.0", port=8053):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))

    print(f"[SERVER] DNS server listening on {host}:{port}")
    print("[SERVER] Waiting for clients...\n")

    while True:
        try:
            data, addr = sock.recvfrom(512)

            # ── Handshake Step 1: client says HELLO ──────────────────────────
            if data == b"HELLO":
                print(f"[HS] HELLO from {addr}")
                sock.sendto(b"ACK", addr)
                print(f"[HS] ACK sent to {addr}")
                continue

            # ── Handshake Step 3: client confirms ACK received ───────────────
            if data == b"CONFIRM":
                with _verified_lock:
                    _verified.add(addr)
                sock.sendto(b"READY", addr)
                print(f"[HS] ✅ Handshake complete — {addr} is verified")
                continue

            # ── DNS query: only serve verified clients ────────────────────────
            with _verified_lock:
                verified = addr in _verified

            if not verified:
                print(f"[REJECT] {addr} sent DNS query without handshake")
                sock.sendto(b"ERR_NO_HANDSHAKE", addr)
                continue

            threading.Thread(
                target=handle_dns,
                args=(data, addr, sock),
                daemon=True
            ).start()

        except Exception as e:
            print(f"[ERROR] Main loop: {e}")


if __name__ == "__main__":
    start_server()