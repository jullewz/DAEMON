#!/usr/bin/env python3
"""
DAEMON - the dev & IT toolkit from hell. Zero dependencies, Linux & Windows.
summoned by jullewz

Run with no arguments for the interactive menu, or use subcommands:
    python daemon.py http https://example.com      HTTP probe: timing, headers, TLS cert
    python daemon.py jwt <token>                    decode a JWT
    python daemon.py encode "text"                  base64 / hex / url / binary / rot13
    python daemon.py decode "SGVsbG8="              auto-detect and decode
    python daemon.py hash "text"                    md5 / sha1 / sha256 / sha512 / blake2b
    python daemon.py hashid <hash>                  identify a hash type
    python daemon.py secrets .                      find leaked keys and passwords in code
    python daemon.py grep "TODO" .                  fast multithreaded code search
    python daemon.py loc .                          count lines of code per language
    python daemon.py ports                          what is listening on this machine
    python daemon.py kill 3000                      free a busy port
    python daemon.py serve . --lan                  share a folder over HTTP
    python daemon.py gen                            uuid / tokens / passwords / secret keys
    python daemon.py time 1700000000                timestamp converter
    python daemon.py json data.json                 validate + pretty print JSON
    python daemon.py regex "\\d+" "abc 123"          regex tester
    python daemon.py cidr 192.168.1.0/24            subnet calculator
"""

import argparse
import base64
import codecs
import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import html
import http.client
import http.server
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.parse
import uuid
from collections import defaultdict

__version__ = "6.6.6"
AUTHOR = "jullewz"
TOOL = "DAEMON"


# --------------------------------------------------------------------------- #
#  Terminal setup (ANSI colors on Windows PowerShell / cmd, UTF-8 output)
# --------------------------------------------------------------------------- #
def _enable_terminal():
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            handle = k32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(handle, ctypes.byref(mode)):
                k32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            os.system("")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_enable_terminal()
USE_COLOR = (sys.stdout.isatty() and not os.environ.get("NO_COLOR")) or bool(os.environ.get("FORCE_COLOR"))
LIVE = sys.stdout.isatty()


# --------------------------------------------------------------------------- #
#  Theme: black & red (24-bit color)
# --------------------------------------------------------------------------- #
ESC = "\033["
BOLD = ESC + "1m"
RESET_FG = ESC + "22;39m"


class R:
    BG = (0, 0, 0)
    BLOOD = (80, 10, 10)
    DEEP = (127, 29, 29)
    RED = (185, 28, 28)
    ACCENT = (220, 38, 38)
    HOT = (248, 113, 113)
    BONE = (254, 226, 226)
    EMBER = (251, 146, 60)
    TEXT = (231, 229, 228)
    MUTED = (120, 113, 108)
    FAINT = (68, 44, 44)
    WARN = (250, 204, 21)
    ERR = (255, 85, 85)


GRADIENT = [(90, 8, 8), (150, 15, 15), (200, 25, 25), (235, 45, 35), (255, 95, 70)]
BLACK_BG = False


def rgb(c):
    return f"{ESC}38;2;{c[0]};{c[1]};{c[2]}m"


def rgb_bg(c):
    return f"{ESC}48;2;{c[0]};{c[1]};{c[2]}m"


def bg_restore():
    return rgb_bg(R.BG) if BLACK_BG else ESC + "49m"


def st(text, color=None, bold=False):
    if not USE_COLOR:
        return str(text)
    return (BOLD if bold else "") + rgb(color or R.TEXT) + str(text) + RESET_FG


def pill(text, bg=None, fg=(255, 255, 255)):
    if not USE_COLOR:
        return f"[{text}]"
    return rgb_bg(bg or R.RED) + rgb(fg) + BOLD + f" {text} " + RESET_FG + bg_restore()


def mark(text):
    """Highlight a match: bone text on a blood-red background."""
    if not USE_COLOR:
        return f"[{text}]"
    return rgb_bg(R.BLOOD) + rgb(R.BONE) + BOLD + text + RESET_FG + bg_restore()


def grad(t):
    t = max(0.0, min(1.0, t))
    seg = t * (len(GRADIENT) - 1)
    i = min(int(seg), len(GRADIENT) - 2)
    f = seg - i
    a, b = GRADIENT[i], GRADIENT[i + 1]
    return tuple(int(a[k] + (b[k] - a[k]) * f) for k in range(3))


def grad_rule(n, ch="━"):
    if not USE_COLOR:
        return "-" * n
    return "".join(rgb(grad(i / max(1, n - 1))) + ch for i in range(n)) + RESET_FG


def meter(frac, width=14):
    frac = max(0.0, min(1.0, frac))
    filled = round(width * frac)
    if not USE_COLOR:
        return "#" * filled + "-" * (width - filled)
    bar = "".join(rgb(grad(i / max(1, width - 1))) + "━" for i in range(filled))
    return bar + rgb(R.FAINT) + "━" * (width - filled) + RESET_FG


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def vlen(s):
    return len(ANSI_RE.sub("", s))


def term_width():
    return max(40, shutil.get_terminal_size((80, 24)).columns)


def shorten(s, n):
    s = str(s)
    if n < 5 or len(s) <= n:
        return s
    head = n // 2 - 1
    return s[:head] + "…" + s[-(n - head - 1):]


def rel(path):
    try:
        r = os.path.relpath(path)
        return path if r.startswith("..") else r
    except ValueError:
        return path


# --------------------------------------------------------------------------- #
#  UI building blocks
# --------------------------------------------------------------------------- #
def ok(msg):
    print(f"  {st('✔', R.HOT, True)} {msg}")


def info(msg):
    print(f"  {st('●', R.ACCENT)} {msg}")


def warn(msg):
    print(f"  {st('▲', R.WARN, True)} {st(msg, R.WARN)}")


def fail(msg):
    print(f"  {st('✖', R.ERR, True)} {st(msg, R.ERR)}")


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def dur(seconds):
    return f"{seconds * 1000:.0f} ms" if seconds < 1 else f"{seconds:.2f} s"


def done(t0, extra=""):
    tail = f"  {st('·', R.FAINT)}  {st(extra, R.MUTED)}" if extra else ""
    print(f"  {st('◷', R.DEEP)} {st('finished in', R.MUTED)} {st(dur(time.perf_counter() - t0), R.HOT, True)}{tail}")


def section(title, meta=""):
    print()
    print(f"  {st('◆', R.ACCENT)} {st(title.upper(), R.TEXT, True)}   {st(meta, R.MUTED)}")
    print("  " + st("─" * min(64, term_width() - 4), R.FAINT))


def panel(lines, title=None, min_width=0):
    inner = max([vlen(l) for l in lines] + [min_width, (vlen(title) + 4) if title else 0])
    if inner + 6 > term_width():
        if title:
            section(title)
        for l in lines:
            print("   " + l)
        return
    border = lambda s: st(s, R.DEEP)
    if title:
        t = f" {st(title.upper(), R.HOT, True)} "
        top = border("╭─") + t + border("─" * (inner + 1 - vlen(t)) + "╮")
    else:
        top = border("╭" + "─" * (inner + 2) + "╮")
    print("  " + top)
    for l in lines:
        print("  " + border("│") + " " + l + " " * (inner - vlen(l)) + " " + border("│"))
    print("  " + border("╰" + "─" * (inner + 2) + "╯"))


def kv_lines(rows, short=True):
    width = max(len(k) for k, _ in rows)
    room = term_width() - width - 12
    out = []
    for k, v in rows:
        v = str(v)
        if "\x1b" not in v:
            v = st(shorten(v, room) if short else v, R.TEXT)
        out.append(f"{st(k.ljust(width), R.MUTED)}   {v}")
    return out


def value_rows(rows, color=None):
    """Label + full value (never shortened, so it can be copied)."""
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"   {st(k.ljust(width), R.MUTED)}   {st(v, color or R.BONE)}")


class Progress:
    def __init__(self, total, label=""):
        self.total = max(1, total)
        self.n = 0
        self.label = label
        self.last = 0.0

    def tick(self, k=1):
        self.n += k
        now = time.perf_counter()
        if LIVE and (now - self.last > 0.04 or self.n >= self.total):
            self.last = now
            frac = self.n / self.total
            sys.stdout.write(f"\r{ESC}2K  {meter(frac, 30)}  {st(f'{frac * 100:5.1f}%', R.HOT, True)}"
                             f"  {st(f'{self.n}/{self.total}', R.MUTED)}  {st(self.label, R.MUTED)}")
            sys.stdout.flush()

    def clear(self):
        if LIVE:
            sys.stdout.write(f"\r{ESC}2K")
            sys.stdout.flush()


JSON_TOKEN = re.compile(r'("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)')


def color_json(text):
    if not USE_COLOR:
        return text

    def repl(m):
        if m.group(1) and m.group(2):
            return st(m.group(1), R.HOT, True) + m.group(2)
        if m.group(1):
            return st(m.group(1), R.BONE)
        if m.group(3):
            return st(m.group(3), R.ACCENT, True)
        return st(m.group(4), R.EMBER)

    return JSON_TOKEN.sub(repl, text)


def print_json(obj, indent="   "):
    for line in json.dumps(obj, indent=2, ensure_ascii=False).splitlines():
        print(indent + color_json(line))


def rel_time(ts):
    d = ts - time.time()
    a = abs(d)
    for unit, sec in (("y", 31536000), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if a >= sec or unit == "s":
            s = f"{int(a // sec)}{unit}"
            break
    return f"in {s}" if d > 0 else f"{s} ago"


# --------------------------------------------------------------------------- #
#  Banner
# --------------------------------------------------------------------------- #
BANNER = r"""
██████╗  █████╗ ███████╗███╗   ███╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔════╝████╗ ████║██╔═══██╗████╗  ██║
██║  ██║███████║█████╗  ██╔████╔██║██║   ██║██╔██╗ ██║
██║  ██║██╔══██║██╔══╝  ██║╚██╔╝██║██║   ██║██║╚██╗██║
██████╔╝██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║ ╚████║
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
"""

BANNER_ASCII = r"""
 ____    _    _____ __  __  ___  _   _
|  _ \  / \  | ____|  \/  |/ _ \| \ | |
| | | |/ _ \ |  _| | |\/| | | | |  \| |
| |_| / ___ \| |___| |  | | |_| | |\  |
|____/_/   \_\_____|_|  |_|\___/|_| \_|
"""


def _gradient_line(line, width, fancy):
    out = []
    for x, ch in enumerate(line):
        if ch == " ":
            out.append(ch)
            continue
        col = grad(x / max(1, width - 1))
        if fancy and ch != "█":
            col = tuple(int(c * 0.4) for c in col)
        out.append(rgb(col) + ch)
    return "".join(out) + RESET_FG


def banner():
    art, fancy = BANNER, True
    try:
        art.encode(sys.stdout.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        art, fancy = BANNER_ASCII, False
    lines = art.strip("\n").splitlines()
    width = max(len(l) for l in lines)
    print()
    for line in lines:
        print("  " + (_gradient_line(line, width, fancy) if USE_COLOR else line))
    print()
    print(f"  {pill('v' + __version__)}  {st('dev & it toolkit from hell', R.TEXT)}  {st('·', R.FAINT)}  "
          f"{st('summoned by', R.MUTED)} {st(AUTHOR, R.HOT, True)}")
    print("  " + grad_rule(width))


# --------------------------------------------------------------------------- #
#  Files
# --------------------------------------------------------------------------- #
IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".idea", ".vscode", "dist", "build", ".next", ".nuxt", "target", ".cache",
    ".tox", ".mypy_cache", ".pytest_cache", ".gradle", "vendor", "bin", "obj",
}


def walk_files(root):
    if os.path.isfile(root):
        yield root
        return
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in IGNORE_DIRS:
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            yield entry.path
                    except OSError:
                        continue
        except OSError:
            continue


def read_text(path, limit=8 << 20):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def label_path(path):
    return os.path.basename(os.path.abspath(path)) if path in (".", "./", ".\\") else path


def _check_path(path):
    if not os.path.exists(path):
        fail(f"not found: {path}")
        return False
    return True


WORKERS = min(32, (os.cpu_count() or 4) * 4)


# --------------------------------------------------------------------------- #
#  http  - probe a URL: timing waterfall, redirects, headers, TLS cert
# --------------------------------------------------------------------------- #
SEC_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame"),
    ("x-content-type-options", "X-Content-Type"),
    ("referrer-policy", "Referrer"),
    ("permissions-policy", "Permissions"),
]


def _status_pill(code, reason):
    bg = R.DEEP if code < 300 else (120, 90, 10) if code < 400 else R.ACCENT
    return pill(f"{code} {reason}", bg=bg)


def cmd_http(args):
    url = args.url
    if "://" not in url:
        host = urllib.parse.urlsplit("//" + url).hostname or ""
        try:
            local = host == "localhost" or ipaddress.ip_address(host).is_private
        except ValueError:
            local = False
        url = ("http://" if local else "https://") + url
    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    section("http probe", url)
    t_all = time.perf_counter()
    hops = 0
    while True:
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            fail(f"bad url: {url}")
            return 1
        https = u.scheme == "https"
        port = u.port or (443 if https else 80)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        try:
            t0 = time.perf_counter()
            ip = socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)[0][4][0]
            t_dns = time.perf_counter()
            if https:
                conn = http.client.HTTPSConnection(u.hostname, port, timeout=args.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(u.hostname, port, timeout=args.timeout)
            conn.connect()
            t_conn = time.perf_counter()
            cert, tls = None, None
            if https:
                cert = conn.sock.getpeercert()
                tls = (conn.sock.version(), conn.sock.cipher()[0])
            conn.request(args.method, path, headers={"User-Agent": f"daemon/{__version__}", "Accept": "*/*"})
            resp = conn.getresponse()
            t_ttfb = time.perf_counter()
            body = resp.read()
            t_end = time.perf_counter()
            conn.close()
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            fail(f"{type(e).__name__}: {e}")
            return 1

        location = resp.getheader("Location")
        if 300 <= resp.status < 400 and location and not args.no_follow and hops < 8:
            nxt = urllib.parse.urljoin(url, location)
            print(f"   {st('↳', R.ACCENT, True)} {_status_pill(resp.status, resp.reason)}  {st(shorten(nxt, term_width() - 24), R.MUTED)}")
            url = nxt
            hops += 1
            continue
        break

    print()
    print(f"   {_status_pill(resp.status, resp.reason)}  {st(ip, R.BONE)}  {st('·', R.FAINT)}  "
          f"{st(human(len(body)), R.MUTED)}  {st('·', R.FAINT)}  {st(f'HTTP/{resp.version / 10:.1f}', R.MUTED)}")
    print()
    phases = [
        ("dns", t_dns - t0),
        ("connect" + (" + tls" if https else ""), t_conn - t_dns),
        ("wait (ttfb)", t_ttfb - t_conn),
        ("download", t_end - t_ttfb),
    ]
    total = t_end - t0
    for name, secs in phases:
        print(f"   {st(name.ljust(16), R.MUTED)}{meter(secs / total if total else 0, 24)}  {st(dur(secs).rjust(8), R.BONE)}")
    print(f"   {st('total'.ljust(16), R.TEXT, True)}{' ' * 24}  {st(dur(total).rjust(8), R.HOT, True)}")

    headers = resp.getheaders()
    section("headers", f"{len(headers)} received")
    w = min(28, max(len(k) for k, _ in headers)) if headers else 10
    for k, v in headers[:30]:
        print(f"   {st(k.lower().ljust(w), R.HOT)}  {st(shorten(v, term_width() - w - 8), R.TEXT)}")
    present = {k.lower() for k, _ in headers}
    score = sum(1 for h, _ in SEC_HEADERS if h in present)
    print()
    marks = "  ".join(
        (st("✔ ", R.HOT, True) + st(label, R.BONE)) if h in present else (st("✖ ", R.FAINT) + st(label, R.MUTED))
        for h, label in SEC_HEADERS
    )
    print(f"   {st('security', R.MUTED)}  {st(f'{score}/{len(SEC_HEADERS)}', R.HOT, True)}   {marks}")

    if cert:
        def name_of(field, key):
            for rdn in cert.get(field, ()):
                for k, v in rdn:
                    if k == key:
                        return v
            return "—"

        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((expires - time.time()) // 86400)
        exp_col = R.ERR if days < 14 else R.BONE
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        rows = [
            ("subject", name_of("subject", "commonName")),
            ("issuer", name_of("issuer", "organizationName")),
            ("expires", st(time.strftime("%Y-%m-%d", time.gmtime(expires)), exp_col, True) + st(f"  ({days} days left)", R.MUTED)),
            ("names", f"{len(sans)} SAN · {shorten(', '.join(sans[:4]), 40)}"),
            ("protocol", f"{tls[0]} · {tls[1]}"),
        ]
        print()
        panel(kv_lines(rows), title="tls certificate")
    elif https and args.insecure:
        warn("certificate not verified (--insecure)")
    print()
    done(t_all, f"{hops} redirect(s)")
    return 0


# --------------------------------------------------------------------------- #
#  jwt
# --------------------------------------------------------------------------- #
def b64url_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cmd_jwt(args):
    token = args.token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        fail("that doesn't look like a JWT (expected header.payload.signature)")
        return 1
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        fail("could not decode the token")
        return 1
    t0 = time.perf_counter()
    section("jwt decoder", f"alg {header.get('alg', '?')} · signature not verified")
    print(f"   {st('HEADER', R.MUTED, True)}")
    print_json(header, "   ")
    print()
    print(f"   {st('PAYLOAD', R.MUTED, True)}")
    print_json(payload, "   ")
    rows = []
    for claim, label in (("iat", "issued"), ("nbf", "not before"), ("exp", "expires")):
        v = payload.get(claim)
        if isinstance(v, (int, float)):
            when = dt.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
            rows.append((label, f"{st(when, R.BONE)}  {st('(' + rel_time(v) + ')', R.MUTED)}"))
    if rows:
        print()
        value_rows([(k, v) for k, v in rows])
    exp = payload.get("exp")
    print()
    if isinstance(exp, (int, float)):
        if exp < time.time():
            print(f"   {pill('EXPIRED', bg=R.ACCENT)}")
        else:
            print(f"   {pill('VALID TIME', bg=R.DEEP)}  {st('not expired (signature still unchecked)', R.MUTED)}")
    else:
        print(f"   {pill('NO EXPIRY', bg=(120, 90, 10))}  {st('token never expires', R.MUTED)}")
    print()
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  encode / decode
# --------------------------------------------------------------------------- #
def cmd_encode(args):
    t0 = time.perf_counter()
    text = args.text
    data = text.encode("utf-8")
    section("encoder", f"{len(data)} bytes in")
    value_rows([
        ("base64", base64.b64encode(data).decode()),
        ("base64url", base64.urlsafe_b64encode(data).decode().rstrip("=")),
        ("hex", data.hex()),
        ("url", urllib.parse.quote(text, safe="")),
        ("html", html.escape(text)),
        ("binary", " ".join(f"{b:08b}" for b in data)),
        ("rot13", codecs.encode(text, "rot13")),
    ])
    print()
    done(t0)
    return 0


def _printable(s):
    return bool(s) and all(c.isprintable() or c in "\r\n\t" for c in s)


def cmd_decode(args):
    t0 = time.perf_counter()
    s = args.text.strip()
    results = []

    def try_add(name, fn):
        try:
            out = fn()
            if isinstance(out, bytes):
                out = out.decode("utf-8")
            if _printable(out) and out != s:
                results.append((name, out))
        except Exception:
            pass

    compact = re.sub(r"\s+", "", s)
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        try_add("base64", lambda: base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True))
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", compact):
        try_add("base64url", lambda: b64url_decode(compact))
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", compact) and len(compact.replace("0x", "")) % 2 == 0:
        try_add("hex", lambda: bytes.fromhex(compact.replace("0x", "")))
    if "%" in s or "+" in s:
        try_add("url", lambda: urllib.parse.unquote_plus(s))
    if "&" in s and ";" in s:
        try_add("html", lambda: html.unescape(s))
    if re.fullmatch(r"[01]{8}(?:\s*[01]{8})*", s):
        try_add("binary", lambda: bytes(int(b, 2) for b in re.findall(r"[01]{8}", s)))
    if not results and re.search(r"[A-Za-z]", s):
        try_add("rot13", lambda: codecs.decode(s, "rot13"))

    seen, unique = set(), []
    for name, out in results:
        if out not in seen:
            seen.add(out)
            unique.append((name, out))
    section("decoder", f"{len(unique)} possible decoding(s)")
    if s.count(".") == 2 and s.startswith("eyJ"):
        info(f"this looks like a JWT — try {st('jwt', R.HOT, True)}")
    if not unique:
        warn("nothing decoded cleanly")
    else:
        value_rows(unique)
    print()
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  hash / hashid
# --------------------------------------------------------------------------- #
def cmd_hash(args):
    t0 = time.perf_counter()
    data = args.text.encode("utf-8")
    section("hash", f"{len(data)} bytes")
    value_rows([(a, hashlib.new(a, data).hexdigest())
                for a in ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")])
    print()
    done(t0)
    return 0


HASH_SIGS = [
    (r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$", ["bcrypt"]),
    (r"^\$argon2(id|i|d)\$", ["Argon2"]),
    (r"^\$y\$", ["yescrypt (Linux /etc/shadow)"]),
    (r"^\$6\$", ["SHA-512 crypt (Linux /etc/shadow)"]),
    (r"^\$5\$", ["SHA-256 crypt"]),
    (r"^\$1\$", ["MD5 crypt"]),
    (r"^\$apr1\$", ["Apache MD5 (htpasswd)"]),
    (r"^pbkdf2_sha256\$", ["Django PBKDF2-SHA256"]),
    (r"^scrypt:", ["Werkzeug scrypt"]),
    (r"^\*[A-F0-9]{40}$", ["MySQL 4.1+"]),
    (r"^[a-f0-9]{8}$", ["CRC32", "Adler-32"]),
    (r"^[a-f0-9]{16}$", ["MySQL 3.x", "FNV-64"]),
    (r"^[a-f0-9]{32}$", ["MD5", "NTLM", "MD4"]),
    (r"^[a-f0-9]{40}$", ["SHA-1", "RIPEMD-160"]),
    (r"^[a-f0-9]{56}$", ["SHA-224", "SHA3-224"]),
    (r"^[a-f0-9]{64}$", ["SHA-256", "SHA3-256", "BLAKE2s"]),
    (r"^[a-f0-9]{96}$", ["SHA-384", "SHA3-384"]),
    (r"^[a-f0-9]{128}$", ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"]),
]


def cmd_hashid(args):
    t0 = time.perf_counter()
    h = args.hash.strip()
    found = []
    for pattern, names in HASH_SIGS:
        if re.match(pattern, h, re.I):
            found.extend(names)
    charset = "hex" if re.fullmatch(r"[0-9a-fA-F]+", h) else "mixed"
    section("hash identifier", f"{len(h)} chars · {charset}")
    if not found:
        warn("unknown hash format")
    for i, name in enumerate(found):
        tag = pill("most likely", bg=R.DEEP) if i == 0 else st("possible", R.MUTED)
        print(f"   {st('◆', R.ACCENT if i == 0 else R.FAINT)} {st(name.ljust(34), R.BONE if i == 0 else R.TEXT, i == 0)}{tag}")
    print()
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  secrets  - scan code for leaked keys, tokens and passwords
# --------------------------------------------------------------------------- #
SECRET_RULES = [
    ("Private key", "high", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("AWS access key", "high", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", "high", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("GitHub fine-grained token", "high", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("GitLab token", "high", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ("Slack token", "high", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    ("Slack webhook", "high", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("Discord webhook", "high", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    ("Stripe live key", "high", r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"),
    ("Google API key", "high", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Anthropic API key", "high", r"\bsk-ant-[A-Za-z0-9_-]{32,}"),
    ("OpenAI-style API key", "high", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    ("Database URL with password", "high",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@[^\s'\"]+"),
    ("JWT", "medium", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Hardcoded secret", "medium",
     r"(?i)\b(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
]
SECRET_RX = [(name, sev, re.compile(rx)) for name, sev, rx in SECRET_RULES]


def mask(s):
    if len(s) <= 10:
        return s[:2] + "*" * (len(s) - 2)
    return s[:5] + "*" * min(16, len(s) - 9) + s[-4:]


def _scan_secrets(path):
    text = read_text(path, limit=4 << 20)
    if not text:
        return path, []
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue
        taken = []
        for name, sev, rx in SECRET_RX:
            for m in rx.finditer(line):
                if any(m.start() < b and a < m.end() for a, b in taken):
                    continue
                taken.append((m.start(), m.end()))
                hits.append((n, name, sev, m.group(0)))
    return path, hits


def cmd_secrets(args):
    if not _check_path(args.path):
        return 1
    t0 = time.perf_counter()
    paths = list(walk_files(args.path))
    section("secret scanner", f"{shorten(label_path(args.path), 40)} · {len(paths)} files")
    bar = Progress(len(paths), "scanning")
    findings = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for path, hits in ex.map(_scan_secrets, paths):
            bar.tick()
            for h in hits:
                findings.append((path,) + h)
    bar.clear()
    if not findings:
        ok("clean — no leaked secrets found")
        done(t0)
        return 0
    order = {"high": 0, "medium": 1}
    findings.sort(key=lambda f: (order[f[3]], f[0], f[1]))
    room = term_width() - 12
    for path, n, name, sev, value in findings:
        tag = pill("HIGH", bg=R.ACCENT) if sev == "high" else pill("MED", bg=(120, 90, 10))
        print(f"   {tag} {st(name, R.BONE, True)}")
        print(f"         {st(shorten(rel(path), room - 20) + ':' + str(n), R.MUTED)}   {st(mask(value), R.HOT)}")
    high = sum(1 for f in findings if f[3] == "high")
    print()
    fail(f"{len(findings)} finding(s) · {high} high severity")
    info("rotate leaked keys and remove them from your git history")
    done(t0)
    return 1


# --------------------------------------------------------------------------- #
#  grep  - multithreaded code search
# --------------------------------------------------------------------------- #
def _grep_file(path, rx):
    text = read_text(path)
    if text is None or not rx.search(text):
        return path, []
    return path, [(n, line) for n, line in enumerate(text.splitlines(), 1) if rx.search(line)]


def highlight(line, rx, room):
    line = line.replace("\t", "    ").rstrip()
    m = rx.search(line)
    if len(line) > room:
        start = max(0, (m.start() if m else 0) - 20)
        line = ("…" if start else "") + line[start:start + room - 1]
    if not USE_COLOR:
        return line
    out, pos = [], 0
    for m in rx.finditer(line):
        if m.end() == m.start():
            continue
        out.append(st(line[pos:m.start()], R.TEXT))
        out.append(mark(m.group(0)))
        pos = m.end()
    out.append(st(line[pos:], R.TEXT))
    return "".join(out)


def cmd_grep(args):
    if not _check_path(args.path):
        return 1
    try:
        rx = re.compile(args.pattern, re.I if args.ignore_case else 0)
    except re.error as e:
        fail(f"bad regex: {e}")
        return 1
    t0 = time.perf_counter()
    paths = list(walk_files(args.path))
    section("code hunter", f"/{args.pattern}/ · {len(paths)} files")
    total = files_hit = 0
    room = term_width() - 14
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for path, hits in ex.map(lambda p: _grep_file(p, rx), paths):
            if not hits or total >= args.limit:
                continue
            files_hit += 1
            print(f"  {st('▸', R.ACCENT, True)} {st(rel(path), R.BONE, True)}")
            for n, line in hits:
                print(f"    {st(str(n).rjust(5), R.MUTED)} {st('│', R.FAINT)} {highlight(line, rx, room)}")
                total += 1
                if total >= args.limit:
                    break
    print()
    if total >= args.limit:
        warn(f"stopped at {args.limit} matches (use -l to raise the limit)")
    ok(f"{st(total, R.HOT, True)} matches in {st(files_hit, R.HOT, True)} files")
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  loc  - lines of code per language
# --------------------------------------------------------------------------- #
LANGS = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin", ".c": "C", ".h": "C/C++ header",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C/C++ header", ".cs": "C#", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".php": "PHP", ".swift": "Swift", ".lua": "Lua", ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".ps1": "PowerShell", ".bat": "Batch", ".cmd": "Batch", ".html": "HTML", ".htm": "HTML", ".css": "CSS",
    ".scss": "SCSS", ".sass": "SCSS", ".vue": "Vue", ".svelte": "Svelte", ".sql": "SQL", ".md": "Markdown",
    ".json": "JSON", ".yml": "YAML", ".yaml": "YAML", ".toml": "TOML", ".xml": "XML", ".dart": "Dart",
    ".r": "R", ".scala": "Scala", ".zig": "Zig", ".nim": "Nim", ".ex": "Elixir", ".exs": "Elixir",
    ".hs": "Haskell", ".ml": "OCaml", ".pl": "Perl", ".asm": "Assembly", ".s": "Assembly",
}


def _count_lines(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return path, 0, 0
    lines = data.splitlines()
    return path, len(lines), sum(1 for l in lines if not l.strip())


def cmd_loc(args):
    if not _check_path(args.path):
        return 1
    t0 = time.perf_counter()
    paths = [p for p in walk_files(args.path) if os.path.splitext(p)[1].lower() in LANGS]
    stats = defaultdict(lambda: [0, 0, 0])  # files, code, blank
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for path, lines, blank in ex.map(_count_lines, paths):
            s = stats[LANGS[os.path.splitext(path)[1].lower()]]
            s[0] += 1
            s[1] += lines - blank
            s[2] += blank
    section("line counter", shorten(label_path(args.path), 50))
    if not stats:
        warn("no source files found")
        done(t0)
        return 0
    rows = sorted(stats.items(), key=lambda kv: kv[1][1], reverse=True)
    total_code = sum(v[1] for _, v in rows) or 1
    print(f"   {st('LANGUAGE'.ljust(16), R.MUTED, True)}{st('FILES'.rjust(7), R.MUTED, True)}"
          f"{st('CODE'.rjust(10), R.MUTED, True)}{st('BLANK'.rjust(9), R.MUTED, True)}   {st('SHARE', R.MUTED, True)}")
    for lang, (files, code, blank) in rows:
        print(f"   {st(lang.ljust(16), R.BONE, True)}{st(str(files).rjust(7), R.TEXT)}"
              f"{st(f'{code:,}'.rjust(10), R.HOT, True)}{st(f'{blank:,}'.rjust(9), R.MUTED)}   "
              f"{meter(code / total_code, 14)} {st(f'{code / total_code * 100:4.1f}%', R.MUTED)}")
    files = sum(v[0] for _, v in rows)
    print()
    ok(f"{st(f'{total_code:,}', R.HOT, True)} lines of code in {st(files, R.HOT, True)} files · {len(rows)} languages")
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  ports / kill  - what is listening, and free a busy port
# --------------------------------------------------------------------------- #
def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _listeners_linux():
    inode_pid = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if link.startswith("socket:["):
                    inode_pid[link[8:-1]] = int(pid)
        except OSError:
            continue
    out = []
    for fname, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(fname) as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":  # 0A = LISTEN
                continue
            addr_hex, port_hex = parts[1].split(":")
            raw = bytes.fromhex(addr_hex)
            if v6:
                raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
                addr = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                addr = socket.inet_ntop(socket.AF_INET, raw[::-1])
            pid = inode_pid.get(parts[9])
            name = "—"
            if pid:
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        name = f.read().strip()
                except OSError:
                    pass
            out.append((int(port_hex, 16), addr, pid, name))
    return out


def _listeners_windows():
    names = {}
    for row in csv.reader(_run(["tasklist", "/FO", "CSV", "/NH"]).splitlines()):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = row[0]
    out = []
    for line in _run(["netstat", "-ano", "-p", "TCP"]).splitlines() + _run(["netstat", "-ano", "-p", "TCPv6"]).splitlines():
        parts = line.split()
        # listening sockets have a foreign address of 0.0.0.0:0 / [::]:0 (works on any Windows language)
        if len(parts) >= 5 and parts[0].upper().startswith("TCP") and parts[2] in ("0.0.0.0:0", "[::]:0"):
            addr, port = parts[1].rsplit(":", 1)
            pid = int(parts[-1]) if parts[-1].isdigit() else None
            out.append((int(port), addr.strip("[]"), pid, names.get(pid, "—")))
    return out


def _listeners_mac():
    out = []
    for line in _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 9:
            addr, port = parts[-2].rsplit(":", 1)
            out.append((int(port), addr.strip("[]"), int(parts[1]), parts[0]))
    return out


def listeners():
    if os.name == "nt":
        data = _listeners_windows()
    elif sys.platform == "darwin":
        data = _listeners_mac()
    else:
        data = _listeners_linux()
    seen, out = set(), []
    for item in sorted(data, key=lambda x: (x[0], x[1])):
        if (item[0], item[1]) not in seen:
            seen.add((item[0], item[1]))
            out.append(item)
    return out


def cmd_ports(args):
    t0 = time.perf_counter()
    rows = listeners()
    section("port watch", f"{len(rows)} listening socket(s)")
    print(f"   {st('PORT'.ljust(8), R.MUTED, True)}{st('ADDRESS'.ljust(26), R.MUTED, True)}"
          f"{st('PID'.ljust(9), R.MUTED, True)}{st('PROCESS', R.MUTED, True)}")
    for port, addr, pid, name in rows:
        exposed = addr in ("0.0.0.0", "::")
        print(f"   {st(str(port).ljust(8), R.HOT, True)}{st(addr.ljust(26), R.EMBER if exposed else R.TEXT)}"
              f"{st(str(pid or '—').ljust(9), R.MUTED)}{st(name, R.BONE)}")
    print()
    if any(pid is None for _, _, pid, _ in rows):
        info(f"some processes are hidden — run as {'administrator' if os.name == 'nt' else 'root (sudo)'} to see all")
    info(f"{st('orange', R.EMBER)} addresses accept connections from your whole network")
    done(t0)
    return 0


def _kill(pid):
    if os.name == "nt":
        r = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True, errors="replace")
        return r.returncode == 0, (r.stdout or r.stderr).strip()
    try:
        os.kill(pid, signal.SIGTERM)
        return True, "SIGTERM sent"
    except ProcessLookupError:
        return False, "process already gone"
    except PermissionError:
        return False, "permission denied — try sudo"


def cmd_kill(args):
    t0 = time.perf_counter()
    targets = {(pid, name) for port, _, pid, name in listeners() if port == args.port}
    section("port killer", f"port {args.port}")
    if not targets:
        ok(f"nothing is listening on port {args.port}")
        return 0
    for pid, name in sorted(targets, key=lambda t: t[0] or 0):
        if not pid:
            fail(f"{name}: process id hidden — run as {'administrator' if os.name == 'nt' else 'root'}")
            continue
        if pid in (0, 4) or pid == os.getpid():
            warn(f"refusing to kill system process {pid}")
            continue
        print(f"   {st('◆', R.ACCENT)} {st(name, R.BONE, True)}  {st(f'pid {pid}', R.MUTED)}")
        if not args.yes:
            ans = input(f"   {st('kill it?', R.TEXT)} {st('(y/N)', R.MUTED)} {st('›', R.ACCENT, True)} ").strip().lower()
            if ans not in ("y", "yes"):
                info("skipped")
                continue
        good, msg = _kill(pid)
        (ok if good else fail)(f"{name} ({pid}): {msg}")
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  serve  - share a folder over HTTP
# --------------------------------------------------------------------------- #
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def cmd_serve(args):
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        fail(f"not a directory: {root}")
        return 1
    bind = "0.0.0.0" if args.lan else "127.0.0.1"

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=root, **k)

        def log_message(self, fmt, *a):
            msg = "".join(c if c.isprintable() else "?" for c in (fmt % a))
            msg = shorten(msg, term_width() - 34)
            print(f"   {st(time.strftime('%H:%M:%S'), R.MUTED)}  {st(self.client_address[0].ljust(15), R.HOT)}  {st(msg, R.TEXT)}")

    try:
        httpd = http.server.ThreadingHTTPServer((bind, args.port), Handler)
    except OSError as e:
        fail(f"cannot use port {args.port}: {e}")
        return 1
    rows = [("folder", shorten(root, 44)), ("local", st(f"http://127.0.0.1:{args.port}", R.HOT, True))]
    if args.lan:
        rows.append(("network", st(f"http://{local_ip()}:{args.port}", R.HOT, True)))
    print()
    panel(kv_lines(rows), title="file server", min_width=40)
    if args.lan:
        warn("anyone on your network can browse this folder while it runs")
    info("press ctrl+c to stop")
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        ok("server stopped")
    finally:
        httpd.server_close()
    return 0


# --------------------------------------------------------------------------- #
#  gen  - uuid / tokens / passwords / keys
# --------------------------------------------------------------------------- #
def _password(n=24):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


def cmd_gen(args):
    t0 = time.perf_counter()
    for i in range(args.count):
        section("generator" if i == 0 else "", "cryptographically secure" if i == 0 else "")
        value_rows([
            ("uuid", str(uuid.uuid4())),
            ("hex token", secrets.token_hex(16)),
            ("url token", secrets.token_urlsafe(32)),
            ("password", _password(24)),
            ("pin", "".join(secrets.choice(string.digits) for _ in range(6))),
            ("secret key", secrets.token_hex(32)),
        ])
    print()
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  time  - timestamp converter
# --------------------------------------------------------------------------- #
def cmd_time(args):
    t0 = time.perf_counter()
    v = (args.value or "").strip()
    try:
        if not v or v.lower() == "now":
            ts = time.time()
        elif re.fullmatch(r"-?\d+(\.\d+)?", v):
            x = float(v)
            ts = x / 1000 if abs(x) > 1e11 else x
        else:
            d = dt.datetime.fromisoformat(v.replace("Z", "+00:00").replace("/", "-"))
            ts = d.timestamp()  # naive dates are treated as local time
    except (ValueError, OverflowError):
        fail("could not read that — use a unix timestamp or a date like 2026-11-02 19:30")
        return 1
    local = dt.datetime.fromtimestamp(ts).astimezone()
    utc = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    print()
    panel(kv_lines([
        ("unix", st(str(int(ts)), R.HOT, True)),
        ("unix ms", str(int(ts * 1000))),
        ("utc", utc.strftime("%Y-%m-%dT%H:%M:%SZ")),
        ("local", local.strftime("%Y-%m-%d %H:%M:%S %Z")),
        ("weekday", local.strftime("%A")),
        ("relative", st(rel_time(ts), R.BONE)),
    ]), title="time", min_width=40)
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  json  - validate, pretty print, minify
# --------------------------------------------------------------------------- #
def cmd_json(args):
    t0 = time.perf_counter()
    try:
        raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8-sig").read()
    except OSError as e:
        fail(str(e))
        return 1
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        section("json", "invalid")
        fail(f"{e.msg} at line {e.lineno}, column {e.colno}")
        lines = raw.splitlines()
        if 0 < e.lineno <= len(lines):
            line = lines[e.lineno - 1]
            print(f"   {st(str(e.lineno).rjust(5), R.MUTED)} {st('│', R.FAINT)} {st(line[:term_width() - 14], R.TEXT)}")
            print(f"   {' ' * 5} {st('│', R.FAINT)} {' ' * min(e.colno - 1, term_width() - 15)}{st('^', R.ERR, True)}")
        return 1
    out = (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) if args.min
           else json.dumps(obj, indent=args.indent, ensure_ascii=False))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        ok(f"valid JSON · written to {args.output}")
        done(t0)
        return 0
    if not USE_COLOR:
        print(out)  # clean output for pipes
        return 0
    kind = type(obj).__name__.replace("dict", "object").replace("list", "array")
    size = len(obj) if isinstance(obj, (dict, list)) else 1
    section("json", f"valid · {kind} with {size} item(s) · {human(len(raw.encode()))}")
    for line in out.splitlines():
        print("   " + color_json(line))
    print()
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  regex tester
# --------------------------------------------------------------------------- #
def cmd_regex(args):
    t0 = time.perf_counter()
    try:
        rx = re.compile(args.pattern, re.I if args.ignore_case else 0)
    except re.error as e:
        fail(f"bad regex: {e}")
        return 1
    matches = [m for m in rx.finditer(args.text) if m.end() > m.start()]
    section("regex tester", f"/{args.pattern}/ · {len(matches)} match(es)")
    for line in args.text.splitlines() or [""]:
        print("   " + highlight(line, rx, 10_000))
    if matches:
        print()
        for i, m in enumerate(matches[:50], 1):
            groups = "  ".join(st(f"${j}=", R.MUTED) + st(g, R.EMBER) for j, g in enumerate(m.groups(), 1) if g is not None)
            print(f"   {st(f'{i:>3}', R.FAINT)}  {st(f'{m.start()}-{m.end()}'.ljust(9), R.MUTED)}{st(m.group(0), R.BONE, True)}  {groups}")
    print()
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  cidr  - subnet calculator
# --------------------------------------------------------------------------- #
def cmd_cidr(args):
    t0 = time.perf_counter()
    try:
        net = ipaddress.ip_network(args.cidr.strip(), strict=False)
    except ValueError as e:
        fail(str(e))
        return 1
    n = net.num_addresses
    if net.version == 4 and net.prefixlen < 31:
        first, last, usable = net[1], net[-2], n - 2
    else:
        first, last, usable = net[0], net[-1], n
    kind = next((name for name, flag in (
        ("loopback", net.is_loopback), ("private", net.is_private), ("multicast", net.is_multicast),
        ("link-local", net.is_link_local), ("reserved", net.is_reserved), ("public", net.is_global),
    ) if flag), "special")
    rows = [("network", st(str(net), R.HOT, True))]
    if net.version == 4:
        rows += [
            ("netmask", str(net.netmask)),
            ("wildcard", str(net.hostmask)),
            ("broadcast", str(net.broadcast_address)),
        ]
    rows += [
        ("first host", str(first)),
        ("last host", str(last)),
        ("addresses", f"{n:,}"),
        ("usable hosts", st(f"{usable:,}", R.BONE, True)),
        ("type", kind),
    ]
    if net.version == 4:
        rows.append(("mask bits", ".".join(f"{o:08b}" for o in net.netmask.packed)))
    print()
    panel(kv_lines(rows, short=False), title=f"ipv{net.version} subnet")
    done(t0)
    return 0


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="daemon",
        description=f"{TOOL} - dev & IT toolkit by {AUTHOR}. Run without arguments for the interactive menu.",
    )
    p.add_argument("-v", "--version", action="version", version=f"daemon {__version__} by {AUTHOR}")
    p.add_argument("--no-banner", action="store_true", help="hide the banner")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    s = sub.add_parser("http", help="probe a URL: timing, redirects, headers, TLS cert")
    s.add_argument("url")
    s.add_argument("-X", "--method", default="GET")
    s.add_argument("--timeout", type=float, default=10)
    s.add_argument("--no-follow", action="store_true", help="don't follow redirects")
    s.add_argument("-k", "--insecure", action="store_true", help="skip certificate verification")
    s.set_defaults(func=cmd_http)

    s = sub.add_parser("jwt", help="decode a JSON Web Token")
    s.add_argument("token")
    s.set_defaults(func=cmd_jwt)

    s = sub.add_parser("encode", help="base64 / hex / url / html / binary / rot13")
    s.add_argument("text")
    s.set_defaults(func=cmd_encode)

    s = sub.add_parser("decode", help="auto-detect and decode")
    s.add_argument("text")
    s.set_defaults(func=cmd_decode)

    s = sub.add_parser("hash", help="hash a string")
    s.add_argument("text")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("hashid", help="identify a hash type")
    s.add_argument("hash")
    s.set_defaults(func=cmd_hashid)

    s = sub.add_parser("secrets", help="find leaked keys, tokens and passwords in code")
    s.add_argument("path", nargs="?", default=".")
    s.set_defaults(func=cmd_secrets)

    s = sub.add_parser("grep", help="fast multithreaded code search")
    s.add_argument("pattern")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-i", "--ignore-case", action="store_true")
    s.add_argument("-l", "--limit", type=int, default=500)
    s.set_defaults(func=cmd_grep)

    s = sub.add_parser("loc", help="count lines of code per language")
    s.add_argument("path", nargs="?", default=".")
    s.set_defaults(func=cmd_loc)

    s = sub.add_parser("ports", help="list listening ports and their processes")
    s.set_defaults(func=cmd_ports)

    s = sub.add_parser("kill", help="kill whatever is listening on a port")
    s.add_argument("port", type=int)
    s.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    s.set_defaults(func=cmd_kill)

    s = sub.add_parser("serve", help="share a folder over HTTP")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-p", "--port", type=int, default=8000)
    s.add_argument("--lan", action="store_true", help="make it reachable from other devices on your network")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("gen", help="uuid / tokens / passwords / secret keys")
    s.add_argument("-n", "--count", type=int, default=1)
    s.set_defaults(func=cmd_gen)

    s = sub.add_parser("time", help="timestamp converter")
    s.add_argument("value", nargs="?", default="")
    s.set_defaults(func=cmd_time)

    s = sub.add_parser("json", help="validate, pretty print or minify JSON (use - for stdin)")
    s.add_argument("file")
    s.add_argument("--min", action="store_true", help="minify")
    s.add_argument("--indent", type=int, default=2)
    s.add_argument("-o", "--output", help="write the result to a file")
    s.set_defaults(func=cmd_json)

    s = sub.add_parser("regex", help="test a regular expression")
    s.add_argument("pattern")
    s.add_argument("text")
    s.add_argument("-i", "--ignore-case", action="store_true")
    s.set_defaults(func=cmd_regex)

    s = sub.add_parser("cidr", help="subnet calculator")
    s.add_argument("cidr")
    s.set_defaults(func=cmd_cidr)
    return p


# --------------------------------------------------------------------------- #
#  Interactive mode (full-screen black & red)
# --------------------------------------------------------------------------- #
def ask(label, default=None):
    hint = f" {st('(' + default + ')', R.MUTED)}" if default else ""
    val = input(f"  {st('◇', R.ACCENT)} {st(label, R.TEXT)}{hint} {st('›', R.ACCENT, True)} ").strip()
    return val or (default or "")


def yes(label):
    return ask(label + " y/N").lower() in ("y", "yes")


MENU = [
    ("01", "HTTP probe", "timing · headers · tls cert", lambda: ["http", ask("URL", "https://github.com")]),
    ("02", "JWT decoder", "header · payload · expiry", lambda: ["jwt", "--", ask("Token")]),
    ("03", "Encoder", "base64 · hex · url · binary", lambda: ["encode", "--", ask("Text")]),
    ("04", "Decoder", "auto-detect encoding", lambda: ["decode", "--", ask("Encoded text")]),
    ("05", "Hash text", "md5 · sha · blake2b", lambda: ["hash", "--", ask("Text")]),
    ("06", "Hash identifier", "what kind of hash is this", lambda: ["hashid", "--", ask("Hash")]),
    ("07", "Secret scanner", "leaked keys in your code", lambda: ["secrets", ask("Folder", ".")]),
    ("08", "Code hunter", "multithreaded grep", lambda: ["grep", "--", ask("Pattern (regex)"), ask("Folder", ".")]),
    ("09", "Line counter", "code per language", lambda: ["loc", ask("Folder", ".")]),
    ("10", "Port watch", "what is listening", lambda: ["ports"]),
    ("11", "Port killer", "free a busy port", lambda: ["kill", ask("Port", "3000")]),
    ("12", "File server", "share a folder", lambda: (
        ["serve", ask("Folder", "."), "-p", ask("Port", "8000")] + (["--lan"] if yes("Share on your network?") else []))),
    ("13", "Generator", "uuid · tokens · keys", lambda: ["gen"]),
    ("14", "Time converter", "unix ⇄ human dates", lambda: ["time", "--", ask("Timestamp or date (empty = now)")]),
    ("15", "JSON tool", "validate · pretty print", lambda: ["json", ask("JSON file path")]),
    ("16", "Regex tester", "highlight matches", lambda: ["regex", "--", ask("Pattern"), ask("Text")]),
    ("17", "Subnet calc", "cidr · masks · hosts", lambda: ["cidr", ask("CIDR or IP", "192.168.1.0/24")]),
]


def clear_screen():
    if LIVE:
        sys.stdout.write(f"{ESC}2J{ESC}3J{ESC}H")
        sys.stdout.flush()


def print_menu(notice=""):
    print()
    lines = [f"{st(num, R.ACCENT, True)}   {st(name.ljust(18), R.TEXT, True)}{st(desc, R.MUTED)}"
             for num, name, desc, _ in MENU]
    lines.append(f"{st('00', R.FAINT, True)}   {st('Exit', R.MUTED)}")
    panel(lines, title="arsenal", min_width=52)
    dot = st("◦", R.FAINT)
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
    print(f"  {st('●', R.ACCENT)} {st(user + '@' + socket.gethostname(), R.MUTED)}   {dot}   "
          f"{st(platform.system(), R.MUTED)}   {dot}   {st(time.strftime('%H:%M'), R.MUTED)}")
    if notice:
        print()
        warn(notice)
    print()


def interactive(parser):
    global BLACK_BG
    if LIVE and USE_COLOR:
        BLACK_BG = True
        sys.stdout.write(rgb_bg(R.BG))
    by_num = {num.lstrip("0"): build for num, _, _, build in MENU}
    notice = ""
    try:
        while True:
            clear_screen()
            banner()
            print_menu(notice)
            notice = ""
            try:
                choice = input(f"  {st('daemon', R.HOT, True)} {st('❯', R.ACCENT, True)} ").strip().lower()
            except EOFError:
                return 0
            if choice in ("0", "00", "q", "exit", "quit"):
                return 0
            build = by_num.get(choice.lstrip("0"))
            if not build:
                notice = "pick a number from the menu"
                continue
            try:
                args = parser.parse_args(build())
                args.func(args)
            except KeyboardInterrupt:
                print()
                warn("cancelled")
            except SystemExit:
                pass
            print()
            try:
                input(f"  {st('↵', R.ACCENT, True)} {st('press enter to return', R.MUTED)} ")
            except EOFError:
                return 0
    except KeyboardInterrupt:
        return 0
    finally:
        if BLACK_BG:
            BLACK_BG = False
            sys.stdout.write(ESC + "0m")
            clear_screen()
        print(f"\n  {st('●', R.ACCENT)} {st(TOOL, R.HOT, True)} {st('summoned by ' + AUTHOR, R.MUTED)}  "
              f"{st('· back to the shadows', R.MUTED)}\n")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not args.cmd:
            return interactive(parser)
        if not args.no_banner and USE_COLOR:
            banner()
        return args.func(args) or 0
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        return 130
    except BrokenPipeError:  # output piped into head/more and closed early
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
