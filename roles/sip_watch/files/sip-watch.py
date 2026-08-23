#!/usr/bin/env python3

import socket
import struct
import time
import re
import select

PUBLIC_INTERFACE = "eth0"
TUNNEL_INTERFACE = "awg0"

ASTERISK_IP = "192.168.2.12"

SIP_PORT = 5060
LOGFILE = "/var/log/sip-watch.log"

TX_TTL = 120

#
# Универсальная коллекция интересующих client request methods.
#
TRACK_METHODS = {
    "REGISTER",
    "INVITE",
    "OPTIONS",
    "SUBSCRIBE",
    "MESSAGE",
    "REFER",
    "NOTIFY",
    "INFO",
    "UPDATE",
    "PRACK",
    "BYE",
    "CANCEL",
}


transactions = {}


def write_log(message):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{stamp} {message}"

    print(line, flush=True)

    with open(LOGFILE, "a", buffering=1) as f:
        f.write(line + "\n")


def get_header(headers, *names):
    wanted = {x.lower() for x in names}

    for line in headers:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        if name.strip().lower() in wanted:
            return value.strip()

    return ""


def parse_branch(via):
    if not via:
        return ""

    m = re.search(
        r"(?:^|;)\s*branch=([^;,\s]+)",
        via,
        flags=re.IGNORECASE,
    )

    return m.group(1) if m else ""


def parse_uri_user(value):
    if not value:
        return ""

    m = re.search(
        r"sip:([^@;>]+)",
        value,
        flags=re.IGNORECASE,
    )

    return m.group(1) if m else ""


def parse_auth_username(auth):
    if not auth:
        return ""

    m = re.search(
        r'username\s*=\s*"([^"]+)"',
        auth,
        flags=re.IGNORECASE,
    )

    if m:
        return m.group(1)

    m = re.search(
        r"username\s*=\s*([^,\s]+)",
        auth,
        flags=re.IGNORECASE,
    )

    return m.group(1) if m else ""


def parse_sip(payload):
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None

    if "\r\n" in text:
        lines = text.split("\r\n")
    else:
        lines = text.split("\n")

    if not lines:
        return None

    start = lines[0].strip()
    headers = lines[1:]

    #
    # SIP response
    #
    if start.startswith("SIP/2.0 "):
        parts = start.split(None, 2)

        if len(parts) < 2:
            return None

        try:
            status = int(parts[1])
        except ValueError:
            return None

        reason = parts[2] if len(parts) > 2 else ""

        cseq = get_header(headers, "CSeq")
        cp = cseq.split()

        return {
            "kind": "response",
            "status": status,
            "reason": reason,

            "call_id": get_header(
                headers, "Call-ID", "i"
            ),

            "cseq_number": (
                cp[0] if len(cp) >= 1 else ""
            ),

            "cseq_method": (
                cp[1].upper()
                if len(cp) >= 2
                else ""
            ),

            "branch": parse_branch(
                get_header(headers, "Via", "v")
            ),

            "www_authenticate": get_header(
                headers,
                "WWW-Authenticate",
            ),

            "proxy_authenticate": get_header(
                headers,
                "Proxy-Authenticate",
            ),
        }

    #
    # SIP request
    #
    parts = start.split()

    if len(parts) < 3:
        return None

    method = parts[0].upper()

    if method not in TRACK_METHODS:
        return None

    if parts[-1].upper() != "SIP/2.0":
        return None

    cseq = get_header(headers, "CSeq")
    cp = cseq.split()

    auth = (
        get_header(headers, "Authorization")
        or
        get_header(headers, "Proxy-Authorization")
    )

    request_uri = parts[1]

    return {
        "kind": "request",
        "method": method,

        "call_id": get_header(
            headers, "Call-ID", "i"
        ),

        "cseq_number": (
            cp[0] if len(cp) >= 1 else ""
        ),

        "cseq_method": (
            cp[1].upper()
            if len(cp) >= 2
            else method
        ),

        "branch": parse_branch(
            get_header(headers, "Via", "v")
        ),

        "has_auth": bool(auth),
        "auth_user": parse_auth_username(auth),

        "from_user": parse_uri_user(
            get_header(headers, "From", "f")
        ),

        "to_user": parse_uri_user(
            get_header(headers, "To", "t")
        ),

        "request_user": parse_uri_user(
            request_uri
        ),

        "user_agent": get_header(
            headers, "User-Agent"
        ),
    }


def transaction_key(sip):
    if not sip.get("call_id"):
        return None

    if not sip.get("cseq_number"):
        return None

    if not sip.get("cseq_method"):
        return None

    return (
        sip["call_id"],
        sip["cseq_number"],
        sip["cseq_method"],
        sip.get("branch", ""),
    )


def clean(value):
    if value is None or value == "":
        return "-"

    return str(value).replace(" ", "_")


def log_transaction(tx, response):
    challenge = (
        response.get("www_authenticate")
        or response.get("proxy_authenticate")
        or ""
    )

    stale = (
        "yes"
        if "stale=true" in challenge.lower()
        else "no"
    )

    fields = {
        "type": tx["method"],

        # Именно настоящий Internet source IP
        "ip": tx["src_ip"],
        "port": tx["src_port"],

        "status": response["status"],
        "reason": response["reason"],

        "auth": (
            "yes" if tx["has_auth"] else "no"
        ),

        "stale": stale,

        "auth_user": tx["auth_user"],
        "from": tx["from_user"],
        "to": tx["to_user"],
        "uri_user": tx["request_user"],

        "ua": tx["user_agent"],

        "callid": tx["call_id"],
        "cseq": tx["cseq_number"],
    }

    message = "SIP-EVENT"

    for name, value in fields.items():
        message += f" {name}={clean(value)}"

    write_log(message)


def parse_ipv4_udp(packet):
    #
    # SOCK_DGRAM AF_PACKET:
    # packet начинается непосредственно с IPv4 header.
    #

    if len(packet) < 28:
        return None

    version_ihl = packet[0]

    version = version_ihl >> 4
    ihl = (version_ihl & 0x0f) * 4

    if version != 4 or ihl < 20:
        return None

    if len(packet) < ihl + 8:
        return None

    protocol = packet[9]

    if protocol != 17:
        return None

    src_ip = socket.inet_ntoa(
        packet[12:16]
    )

    dst_ip = socket.inet_ntoa(
        packet[16:20]
    )

    udp_offset = ihl

    src_port, dst_port, udp_len, _ = struct.unpack(
        "!HHHH",
        packet[
            udp_offset:
            udp_offset + 8
        ],
    )

    if udp_len < 8:
        return None

    payload = packet[
        udp_offset + 8:
        udp_offset + udp_len
    ]

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    )


def make_socket(interface):
    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_DGRAM,
        socket.htons(0x0800),
    )

    sock.bind((interface, 0))

    return sock


def cleanup(now):
    expired = [
        key
        for key, tx in transactions.items()
        if now - tx["time"] > TX_TTL
    ]

    for key in expired:
        transactions.pop(key, None)


public_sock = make_socket(
    PUBLIC_INTERFACE
)

tunnel_sock = make_socket(
    TUNNEL_INTERFACE
)


write_log(
    "WATCH-START "
    f"requests={PUBLIC_INTERFACE} "
    f"responses={TUNNEL_INTERFACE} "
    f"port={SIP_PORT}"
)


last_cleanup = time.time()


while True:

    readable, _, _ = select.select(
        [public_sock, tunnel_sock],
        [],
        [],
        1.0,
    )

    now = time.time()

    for sock in readable:

        packet, _ = sock.recvfrom(65535)

        parsed = parse_ipv4_udp(packet)

        if parsed is None:
            continue

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
        ) = parsed

        if (
            src_port != SIP_PORT
            and dst_port != SIP_PORT
        ):
            continue

        sip = parse_sip(payload)

        if sip is None:
            continue

        #
        # PUBLIC eth0:
        #
        # Только client -> public PBX requests.
        #
        if sock is public_sock:

            if dst_port != SIP_PORT:
                continue

            if sip["kind"] != "request":
                continue

            key = transaction_key(sip)

            if key is None:
                continue

            #
            # Retransmission той же SIP transaction
            # ничего нового не создаёт.
            #
            if key not in transactions:

                transactions[key] = {
                    "src_ip": src_ip,
                    "src_port": src_port,

                    "method": sip["method"],

                    "call_id": sip["call_id"],
                    "cseq_number": sip["cseq_number"],

                    "has_auth": sip["has_auth"],
                    "auth_user": sip["auth_user"],

                    "from_user": sip["from_user"],
                    "to_user": sip["to_user"],
                    "request_user": sip["request_user"],

                    "user_agent": sip["user_agent"],

                    "time": now,
                }

        #
        # AWG:
        #
        # Только Asterisk -> VPS responses.
        #
        elif sock is tunnel_sock:

            if src_ip != ASTERISK_IP:
                continue

            if src_port != SIP_PORT:
                continue

            if sip["kind"] != "response":
                continue

            key = transaction_key(sip)

            if key is None:
                continue

            tx = transactions.get(key)

            if tx is None:
                continue

            #
            # Любой response логируем как результат
            # того request, который пришёл с Internet.
            #
            log_transaction(
                tx,
                sip,
            )

            #
            # 100 / 180 / 183 — provisional.
            # Transaction оставляем.
            #
            # >= 200 — final response.
            #
            if sip["status"] >= 200:
                transactions.pop(
                    key,
                    None,
                )

    if now - last_cleanup >= 30:
        cleanup(now)
        last_cleanup = now
