import socket
def send_dns_query(domain, server_ip="127.0.0.1", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transaction_id = b'\xaa\xaa'
    flags = b'\x01\x00'
    questions = b'\x00\x01'
    answer_rrs = b'\x00\x00'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'

    header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs

    # Convert domain to DNS format
    query = b''
    for part in domain.split('.'):
        query += bytes([len(part)]) + part.encode()
    query += b'\x00'

    query_type = b'\x00\x01'   # Type A
    query_class = b'\x00\x01'  # Class IN

    dns_query = header + query + query_type + query_class

    # Send query
    sock.sendto(dns_query, (server_ip, port))

    # Receive response
    response, _ = sock.recvfrom(512)

    print(f"\nResponse received for {domain}:")
    print(response)


if __name__ == "__main__":
    domain = input("Enter domain: ")
    send_dns_query(domain)