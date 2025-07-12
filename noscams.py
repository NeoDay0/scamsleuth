#!/usr/bin/env python3
"""
ScamSleuth / NoScams – GUI tool to investigate scam callers & e-mails
Author: NeoDay (2025)  |  License: MIT
"""

import json, re, socket, threading, datetime, tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import requests, phonenumbers
from phonenumbers import PhoneNumberType, NumberParseException, geocoder, carrier, timezone
from email_validator import validate_email, EmailNotValidError
import dns.resolver
import tldextract

# ──────────────────────────── constants ────────────────────────────────────────
TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE:            "FIXED_LINE",
    PhoneNumberType.MOBILE:                "MOBILE",
    PhoneNumberType.FIXED_LINE_OR_MOBILE:  "FIXED/MOBILE",
    PhoneNumberType.TOLL_FREE:             "TOLL_FREE",
    PhoneNumberType.PREMIUM_RATE:          "PREMIUM_RATE",
    PhoneNumberType.SHARED_COST:           "SHARED_COST",
    PhoneNumberType.VOIP:                  "VOIP",
    PhoneNumberType.PERSONAL_NUMBER:       "PERSONAL",
    PhoneNumberType.PAGER:                 "PAGER",
    PhoneNumberType.UAN:                   "UAN",
    PhoneNumberType.VOICEMAIL:             "VOICEMAIL",
    PhoneNumberType.UNKNOWN:               "UNKNOWN",
}

# ──────────────────────────── helpers ──────────────────────────────────────────
def banner(msg: str) -> str:
    return f"[{datetime.datetime.now():%H:%M:%S}] {msg}"

def safe_resolve(func, default=None, *a, **kw):
    try:
        return func(*a, **kw)
    except Exception:
        return default

# ──────────────────────────── look-up engines ──────────────────────────────────
def phone_report(raw: str) -> dict:
    """Return detailed information on a phone number."""
    try:
        num = phonenumbers.parse(raw, None)
    except NumberParseException as e:
        return {"error": str(e)}

    ptype_int  = phonenumbers.number_type(num)
    ptype_name = TYPE_NAMES.get(ptype_int, str(ptype_int))

    report = {
        "international": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "region":     geocoder.description_for_number(num, "en"),
        "carrier":    carrier.name_for_number(num, "en"),
        "timezones":  timezone.time_zones_for_number(num),
        "type":       ptype_name,
    }

    # optional crowdsourced spam check (comment out if unneeded)
    try:
        r = requests.get(
            f"https://communitynumlookup.kami/api/v1/ratings/{raw}",
            timeout=5,
        )
        if r.ok:
            data = r.json()
            report["spam_reports"]  = data.get("reports", 0)
            report["spam_category"] = data.get("category", "unknown")
    except Exception:
        pass

    return report


def email_report(addr: str) -> dict:
    """Validate address, check DNS, and look for breaches."""
    try:
        v = validate_email(addr, check_deliverability=True)
    except EmailNotValidError as e:
        return {"error": str(e)}

    local, domain = v.local_part, v.domain.lower()
    rep = {"normalized": v.email, "domain": domain}

    # DNS records
    for rec in ("MX", "TXT"):
        rep[rec] = safe_resolve(
            lambda r=rec: [str(x).strip() for x in dns.resolver.resolve(domain, r)],
            [],
        )

    # SPF + DMARC helpers
    def get_spf(records):
        for txt in records:
            if txt.lower().startswith("v=spf1"):
                return txt
        return ""

    def get_dmarc():
        try:
            return str(dns.resolver.resolve(f"_dmarc.{domain}", "TXT")[0]).strip()
        except Exception:
            return ""

    rep["SPF"]   = get_spf(rep["TXT"])
    rep["DMARC"] = get_dmarc()

    # public breach lookup (anonymous endpoint)
    try:
        hibp = requests.get(
            f"https://haveibeenpwned.com/unifiedsearch/{addr}",
            timeout=6,
            headers={"User-Agent": "ScamSleuth/1.0"},
        )
        rep["breaches"] = hibp.json().get("Breaches", []) if hibp.ok else []
    except Exception:
        pass

    return rep


def ip_domain_report(target: str) -> dict:
    """Resolve domain→IP (or accept raw IP) and return GeoIP info."""
    ext = tldextract.extract(target)
    is_domain = bool(ext.domain) and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", target)

    out = {}
    try:
        ip = socket.gethostbyname(target) if is_domain else target
        out["ip"] = ip
        out["geo"] = safe_resolve(
            lambda: requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json(), {}
        )
    except socket.gaierror as e:
        out["error"] = str(e)

    return out


def risk_score(rep: dict) -> int:
    """Very simple heuristic risk score 0-10."""
    score = 0
    if rep.get("spam_reports", 0):
        score += min(rep["spam_reports"], 10)
    if rep.get("breaches"):
        score += 5
    if rep.get("SPF") == "" or rep.get("DMARC") == "":
        score += 2
    if rep.get("geo", {}).get("bogon"):
        score += 5
    return min(score, 10)

# ──────────────────────────── GUI class ────────────────────────────────────────
class ScamSleuthGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ScamSleuth – Scam Caller & Phish Hunter")
        self.config(bg="#0f0f0f")
        self.geometry("900x640")
        self._build_widgets()

    def _build_widgets(self):
        font = ("Courier New", 11)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=5, pady=5)

        self.tabs = {}
        for name in ("Phone", "Email", "IP/Domain"):
            frame = tk.Frame(nb, bg="#0f0f0f")
            nb.add(frame, text=name)
            self.tabs[name] = frame

        # phone tab
        self.phone_entry = self._add_entry(self.tabs["Phone"], "Phone Number (+1…):", font)
        tk.Button(
            self.tabs["Phone"],
            text="Lookup",
            font=font,
            command=lambda: threading.Thread(target=self.do_phone, daemon=True).start(),
        ).pack(pady=4)

        # email tab
        self.email_entry = self._add_entry(self.tabs["Email"], "E-mail Address:", font)
        tk.Button(
            self.tabs["Email"],
            text="Lookup",
            font=font,
            command=lambda: threading.Thread(target=self.do_email, daemon=True).start(),
        ).pack(pady=4)

        # ip/domain tab
        self.ip_entry = self._add_entry(self.tabs["IP/Domain"], "IP or Domain:", font)
        tk.Button(
            self.tabs["IP/Domain"],
            text="Lookup",
            font=font,
            command=lambda: threading.Thread(target=self.do_ip, daemon=True).start(),
        ).pack(pady=4)

        # shared output box
        self.out = scrolledtext.ScrolledText(
            self, bg="#000", fg="#00ff41", insertbackground="#00ff41",
            font=font, height=20, wrap=tk.WORD,
        )
        self.out.pack(fill="both", expand=True, padx=5, pady=5)

        # save button
        tk.Button(
            self, text="💾  Export JSON", font=font, bg="#222", fg="white",
            command=self.save_json,
        ).pack(pady=(0, 5))

    # ─────────── tab helpers
    def _add_entry(self, parent, label, font):
        tk.Label(parent, text=label, bg="#0f0f0f", fg="white", font=font).pack()
        e = tk.Entry(parent, font=font, width=42)
        e.pack(pady=2)
        return e

    def log(self, msg: str):
        self.out.insert(tk.END, msg + "\n")
        self.out.see(tk.END)

    def pretty(self, data: dict):
        self.log(json.dumps(data, indent=2))
        self.log(f"🔥 Scam Score: {risk_score(data)}/10\n" + "-" * 60)

    # ─────────── lookup threads
    def do_phone(self):
        target = self.phone_entry.get().strip()
        self.log(banner(f"Phone lookup for {target}"))
        try:
            self.pretty(phone_report(target))
        except Exception as e:
            self.log(f"!! Error: {e}")

    def do_email(self):
        addr = self.email_entry.get().strip()
        self.log(banner(f"E-mail lookup for {addr}"))
        try:
            self.pretty(email_report(addr))
        except Exception as e:
            self.log(f"!! Error: {e}")

    def do_ip(self):
        target = self.ip_entry.get().strip()
        self.log(banner(f"IP/Domain lookup for {target}"))
        try:
            self.pretty(ip_domain_report(target))
        except Exception as e:
            self.log(f"!! Error: {e}")

    # ─────────── export
    def save_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            with open(path, "w") as f:
                f.write(self.out.get("1.0", tk.END))
            self.log(banner(f"Saved to {path}"))

# ──────────────────────────── runner ───────────────────────────────────────────
if __name__ == "__main__":
    ScamSleuthGUI().mainloop()
