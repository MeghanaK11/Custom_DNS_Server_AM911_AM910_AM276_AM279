import struct


def parse_dns_query(data):
    """
    Parse a raw DNS UDP query packet.
    Returns dict: id, flags, domain (no trailing dot), qtype, qclass
    """
    transaction_id = data[:2]
    flags          = data[2:4]

    labels = []
    i = 12  # DNS header is always 12 bytes

    while True:
        length = data[i]
        if length == 0:
            break
        labels.append(data[i + 1 : i + 1 + length].decode(errors="replace"))
        i += 1 + length

    # i points at the 0x00 null terminator
    qtype  = data[i + 1 : i + 3]   # 2 bytes
    qclass = data[i + 3 : i + 5]   # 2 bytes

    return {
        "id":     transaction_id,
        "flags":  flags,
        "domain": ".".join(labels),  # e.g. "example.com" — no trailing dot
        "qtype":  qtype,
        "qclass": qclass,
    }


def build_response(query, ip):
    """
    Build a DNS A-record response packet.
    query: dict from parse_dns_query
    ip:    IPv4 string e.g. "1.2.3.4"
    """
    # Header
    header = (
        query["id"]    +
        b"\x81\x80"    +   # QR=1 response, RD=1, RA=1, RCODE=0 no error
        b"\x00\x01"    +   # QDCOUNT = 1
        b"\x00\x01"    +   # ANCOUNT = 1
        b"\x00\x00"    +   # NSCOUNT = 0
        b"\x00\x00"        # ARCOUNT = 0
    )

    # Question section — rebuild QNAME from domain string
    qname = b""
    for part in query["domain"].split("."):
        if part:
            qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"  # root null terminator

    question = qname + query["qtype"] + b"\x00\x01"  # QCLASS = IN

    # Answer section
    answer = (
        b"\xc0\x0c"        +   # pointer to QNAME at offset 12
        b"\x00\x01"        +   # TYPE  = A
        b"\x00\x01"        +   # CLASS = IN
        b"\x00\x00\x00\x3c" +  # TTL   = 60 seconds
        b"\x00\x04"        +   # RDLENGTH = 4 bytes
        bytes(map(int, ip.split(".")))  # RDATA = IPv4
    )

    return header + question + answer