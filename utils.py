
import struct
def parse_dns_query(data):
    transaction_id = data[:2]
    flags = data[2:4]
    qdcount = struct.unpack(">H", data[4:6])[0]
    domain = ""
    i = 12
    while True:
        length = data[i]
        if length == 0:
            break
        domain += data[i+1:i+1+length].decode() + "."
        i += length + 1
    qtype = data[i+1:i+3]
    return {
        "id": transaction_id,
        "flags": flags,
        "domain": domain,
        "qtype": qtype,
        "question_end": i + 5
    }
def build_response(query, ip):
    transaction_id = query["id"]
    flags = b"\x81\x80"  # standard response, no error
    qdcount = b"\x00\x01"
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = transaction_id + flags + qdcount + ancount + nscount + arcount
    question = b''
    for part in query["domain"].split("."):
        if part:
            question += bytes([len(part)]) + part.encode()
    question += b"\x00" + query["qtype"] + b"\x00\x01"
    answer = b"\xc0\x0c"  # pointer to domain
    answer += b"\x00\x01"  # type A
    answer += b"\x00\x01"  # class IN
    answer += b"\x00\x00\x00\x3c"  # TTL
    answer += b"\x00\x04"  # data length

    answer += bytes(map(int, ip.split(".")))
    return header + question + answer