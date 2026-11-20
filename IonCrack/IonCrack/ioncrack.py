#!/usr/bin/env python3
"""
ION AI Auth Bypass Server
=========================
Local stand-in for socket.keyauth.shop that accepts ANY license key entered
in the ION_Pro.exe web UI (http://127.0.0.1:17676).

Wire protocol (recovered from ION_Pro.exe disassembly + live captures):

    server -> CHALLENGE|<id>|<msg>                     >= 3 fields, field0 == "CHALLENGE"
    client -> <TOKEN|KEY|SIG>RESPONSE|<id>|<proof>      proof = HMAC-SHA256(key, msg)
    server -> ACCESS|<until>|<proof>                    >= 3 fields, field0 == "ACCESS"
    client -> <verify>
    server -> VALID|ok                                  >= 2 fields, field0 == "VALID"
    server -> INFO|<payload>

The ACCESS proof is computed over a message built from the challenge and the
until-field.  The construction lives in proof_expr.txt so it can be tweaked
without touching code:

    line 1  message template, placeholders:
                {ch}    CHALLENGE message field
                {id}    CHALLENGE id field
                {until} value of {until} (line 2)
                {key}   license key typed by the user
                {tok}   APP_TOKEN
                {tok2}  APP_TOKEN as sent on the wire
                {sig}   static signature from the client preamble
    line 2  value substituted into {until}

Usage:
    pip install cryptography
    right-click start_ion_server.bat  ->  Run as administrator   (binds 3389)
"""

import datetime
import hashlib
import hmac
import json
import os
import random
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

# ----------------------------------------------------------------- constants
APP_TOKEN = "2fa42fcfa77cb35bdc458c192ff0b397"
SIG_STATIC = "de4b93ad0211c7576a5d91c458d2925bf1af2604170f3c8cec80e6963664c14e"

AUTH_HOST = "127.0.0.1"
AUTH_PORT = 3389
HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")

BASE = Path(__file__).parent
CERT_FILE = BASE / "fake_cert.pem"
KEY_FILE = BASE / "fake_key.pem"
LOG_FILE = BASE / "ion_server.log"
TEMPLATE_FILE = BASE / "proof_expr.txt"

# Working default, used when proof_expr.txt is missing or empty.
DEFAULT_TEMPLATE = "{ch}|{until}"
DEFAULT_UNTIL = "Lifetime"

INFO_PAYLOAD = {
    "status": "active",
    "sub": "lifetime",
    "type": "lifetime",
    "exp": "never",
    "expiry": "2099-12-31T23:59:59Z",
    "remaining": 99999999,
    "duration": 99999999,
    "activated": 1,
    "token": APP_TOKEN,
}

# ------------------------------------------------------------------- console
GREEN, YELLOW, CYAN, RED = "\033[92m", "\033[93m", "\033[96m", "\033[91m"
DIM, RESET, BOLD = "\033[2m", "\033[0m", "\033[1m"

stats = {
    "total_connections": 0,
    "successful_auths": 0,
    "failed_auths": 0,
    "start_time": None,
}
stats_lock = threading.Lock()


def _timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")


def log(symbol, colour, msg):
    """Print to the console and append to ion_server.log."""
    print(f"{DIM}[{_timestamp()}]{RESET} {colour}{symbol}{RESET}  {msg}", flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_timestamp()}] {symbol} {msg}\n")
    except OSError:
        pass


def info(msg):
    log("*", CYAN, msg)


def ok(msg):
    log("+", GREEN, msg)


def warn(msg):
    log("!", YELLOW, msg)


def err(msg):
    log("-", RED, msg)


def pkt(msg):
    log(">", DIM, msg)


def bump(counter):
    with stats_lock:
        stats[counter] += 1


def visual(data: bytes, limit=500) -> str:
    """Render bytes for logging: printable ASCII, escapes for the rest."""
    text = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in data[:limit])
    if len(data) > limit:
        text += f"... (+{len(data) - limit}B)"
    return text


# --------------------------------------------------------------------- proof
def compute_proof(key: str, msg: str) -> str:
    """The client's proof function: HMAC-SHA256(key, msg) as lowercase hex."""
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def load_template() -> tuple:
    """
    Read proof_expr.txt -> (template, until_value).
    Falls back to the known-good construction when the file is absent.
    """
    try:
        lines = [ln.strip() for ln in TEMPLATE_FILE.read_text(encoding="utf-8").splitlines()]
    except OSError:
        return DEFAULT_TEMPLATE, DEFAULT_UNTIL

    lines = [ln for ln in lines if ln]
    if not lines:
        return DEFAULT_TEMPLATE, DEFAULT_UNTIL

    return lines[0], (lines[1] if len(lines) > 1 else DEFAULT_UNTIL)


def resolve_access(key, ch_id, ch_msg):
    """Build the ACCESS until-field and proof -> (until, proof)."""
    template, until = load_template()
    try:
        message = template.format(
            ch=ch_msg,
            id=ch_id,
            until=until,
            key=key,
            tok=APP_TOKEN,
            tok2="2" + APP_TOKEN,
            sig=SIG_STATIC,
        )
    except (KeyError, IndexError, ValueError) as exc:
        warn(f"Bad template {template!r}: {exc}")
        return until, ""

    info(f"proof message = {message!r}")
    return until, compute_proof(key, message)


# ----------------------------------------------------------------------- io
def recv_until(conn, predicate, timeout=20.0, idle=0.6, strict=True):
    """
    Accumulate socket data until predicate(buf) is true.

    strict=True  keep waiting for the predicate across idle gaps; only the
                 overall timeout or EOF ends the wait.
    strict=False return once nothing more arrives within `idle` seconds.
    """
    conn.settimeout(idle)
    buf = b""
    start = time.time()
    last = start
    while time.time() - start < timeout:
        try:
            chunk = conn.recv(8192)
            if not chunk:
                break
            buf += chunk
            last = time.time()
            if predicate(buf):
                return buf, True
        except socket.timeout:
            if not strict and buf and (time.time() - last) >= idle:
                break
        except (ssl.SSLError, OSError) as exc:
            pkt(f"recv error: {exc!r}")
            break
    return buf, predicate(buf)


def send(conn, data: bytes, label):
    conn.sendall(data)
    pkt(f"SEND  {label}: {visual(data, 300)}")


# ------------------------------------------------------------------ handler
def handle_client(conn, addr):
    peer = f"{addr[0]}:{addr[1]}"
    bump("total_connections")
    info(f"ION_Pro connected from {peer}")

    try:
        # --- 1. challenge -------------------------------------------------
        ch_id = "".join(random.choices("0123456789abcdef", k=8))
        ch_msg = "".join(random.choices("0123456789abcdef", k=16))
        send(conn, f"CHALLENGE|{ch_id}|{ch_msg}".encode(), "CHALLENGE")

        # --- 2. auth preamble + RESPONSE ----------------------------------
        buf, got = recv_until(
            conn, lambda b: b"RESPONSE|" in b, timeout=20, idle=0.8, strict=True
        )
        pkt(f"RECV  [{visual(buf)}]")
        if not got:
            warn("No RESPONSE from client")
            bump("failed_auths")
            return

        split_at = buf.index(b"RESPONSE|")
        auth_raw = buf[:split_at].decode("utf-8", "replace").strip()
        resp_raw = buf[split_at:].decode("utf-8", "replace").strip()

        auth_fields = auth_raw.split("|")
        entered_key = auth_fields[1] if len(auth_fields) >= 2 else ""
        if not entered_key:
            warn(f"Could not extract key from preamble: {auth_raw!r}")
            bump("failed_auths")
            return

        resp_fields = resp_raw.split("|")
        client_proof = resp_fields[2] if len(resp_fields) >= 3 else ""

        ok(f"key = '{entered_key}'")
        info(f"challenge id={ch_id} msg={ch_msg}")
        info(
            f"client proof = {client_proof}   "
            f"[{'OK' if compute_proof(entered_key, ch_msg) == client_proof else 'MISMATCH'}]"
        )

        # --- 3. ACCESS ----------------------------------------------------
        until, proof = resolve_access(entered_key, ch_id, ch_msg)
        if not proof:
            warn("No proof to send -- aborting")
            bump("failed_auths")
            return
        info(f"until = {until!r}")
        send(conn, f"ACCESS|{until}|{proof}".encode(), "ACCESS")

        # --- 4. whatever the client sends next -----------------------------
        buf2, _ = recv_until(conn, lambda b: bool(b), timeout=5, idle=0.5, strict=True)
        if buf2:
            pkt(f"RECV  [{visual(buf2)}]")

        # --- 5. VALID ------------------------------------------------------
        send(conn, b"VALID|ok", "VALID")

        buf3, _ = recv_until(conn, lambda b: bool(b), timeout=4, idle=0.5, strict=True)
        if buf3:
            pkt(f"RECV  [{visual(buf3)}]")

        # --- 6. INFO -------------------------------------------------------
        payload = json.dumps(INFO_PAYLOAD, separators=(",", ":"))
        send(conn, f"INFO|{payload}".encode(), "INFO")

        bump("successful_auths")
        ok(f"Handshake completed for {peer}")

        # keep the socket open for any follow-up traffic
        conn.settimeout(180)
        while True:
            try:
                more = conn.recv(4096)
                if not more:
                    break
                pkt(f"KEEP  [{visual(more, 300)}]")
            except (ssl.SSLError, socket.timeout, OSError):
                break

    except Exception as exc:
        warn(f"Client {peer} error: {exc!r}")
        bump("failed_auths")
    finally:
        conn.close()
        info(f"Client {peer} disconnected")


# ------------------------------------------------------------- TLS / hosts
def generate_cert():
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        err("cryptography not installed.  Run:  pip install cryptography")
        sys.exit(1)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NY"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "NYC"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KeyAuth"),
        x509.NameAttribute(NameOID.COMMON_NAME, "socket.keyauth.shop"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("socket.keyauth.shop")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    ok(f"Certificate written to {CERT_FILE.name}")


def build_ssl_context():
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        info("Generating self-signed TLS cert for socket.keyauth.shop ...")
        generate_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
    return ctx


def patch_hosts():
    try:
        text = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
        if "socket.keyauth.shop" in text:
            ok("hosts file already patched")
            return
        with HOSTS_FILE.open("a") as fh:
            fh.write("\n127.0.0.1 socket.keyauth.shop\n")
        ok("hosts file patched: socket.keyauth.shop -> 127.0.0.1")
    except PermissionError:
        err("Run as Administrator to patch the hosts file!")
        sys.exit(1)


# ------------------------------------------------------------------ reporting
def print_stats():
    elapsed = datetime.timedelta(0)
    if stats["start_time"]:
        elapsed = datetime.datetime.now() - stats["start_time"]
    hours, rem = divmod(int(elapsed.total_seconds()), 3600)
    minutes, seconds = divmod(rem, 60)
    print()
    info("=== Session Stats ===")
    info(f"  Uptime:         {hours}h {minutes}m {seconds}s")
    info(f"  Connections:    {stats['total_connections']}")
    info(f"  Successful:     {stats['successful_auths']}")
    info(f"  Failed:         {stats['failed_auths']}")
    print()


def print_banner():
    print(f"""{BOLD}{GREEN}  ██╗ ██████╗ ███╗   ██╗     █████╗ ██╗
  ██║██╔═══██╗████╗  ██║    ██╔══██╗██║
  ██║██║   ██║██╔██╗ ██║    ███████║██║
  ██║██║   ██║██║╚██╗██║    ██╔══██║██║
  ██║╚██████╔╝██║ ╚████║    ██║  ██║██║
  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝╚═╝{RESET}
{BOLD}       Auth Bypass Server{RESET}  {DIM}(Cracked by cgt.confuzz & Mr Pickles ;b){RESET}
{"=" * 60}
""")


# --------------------------------------------------------------------- main
def main():
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()

    stats["start_time"] = datetime.datetime.now()
    patch_hosts()
    ctx = build_ssl_context()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((AUTH_HOST, AUTH_PORT))
    except PermissionError:
        err(f"Cannot bind port {AUTH_PORT} -- run as Administrator!")
        sys.exit(1)
    except OSError as exc:
        err(f"Bind failed: {exc}")
        sys.exit(1)

    sock.listen(10)
    print()
    ok(f"Listening on {AUTH_HOST}:{AUTH_PORT} (SSL)")
    ok("Intercepting socket.keyauth.shop -- ANY key will be accepted")
    template, until = load_template()
    info(f"proof template = {template!r}  until = {until!r}")
    print()
    info("Start ION_Pro.exe, open the web UI and enter any license key ...")
    print(f"{DIM}{'=' * 60}{RESET}")
    print(flush=True)

    try:
        while True:
            client, addr = sock.accept()
            try:
                ssl_conn = ctx.wrap_socket(client, server_side=True)
            except ssl.SSLError as exc:
                warn(f"TLS handshake failed from {addr}: {exc}")
                client.close()
                continue
            threading.Thread(
                target=handle_client, args=(ssl_conn, addr), daemon=True
            ).start()
    except KeyboardInterrupt:
        print()
        warn("Stopped.")
        print_stats()
    finally:
        sock.close()


if __name__ == "__main__":
    main()
