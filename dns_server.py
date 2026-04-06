# server.py

import socket
from dns_records import DNS_RECORDS
from utils import parse_dns_query, build_response

UPSTREAM_DNS = ("8.8.8.8", 53)


def forward_query(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(data, UPSTREAM_DNS)
    try:
        response, _ = sock.recvfrom(512)
        return response
    except socket.timeout:
        return None


def start_dns_server(host="0.0.0.0", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    print(f"DNS Server running on {host}:{port}")

    while True:
        data, addr = sock.recvfrom(512)

        try:
            query = parse_dns_query(data)
            domain = query["domain"]

            print(f"Query: {domain} from {addr}")

            # 🔒 basic validation
            if len(domain) > 255:
                print("Invalid domain length")
                continue

            if domain in DNS_RECORDS:
                ip = DNS_RECORDS[domain]
                response = build_response(query, ip)
                sock.sendto(response, addr)
                print(f"Resolved locally: {domain} → {ip}")

            else:
                response = forward_query(data)
                if response:
                    sock.sendto(response, addr)
                    print(f"Forwarded: {domain}")
                else:
                    print("Upstream timeout")

        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    start_dns_server(host="0.0.0.0", port=53)