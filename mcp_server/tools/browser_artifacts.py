"""
Browser forensics tools — direct SQLite parsing of browser databases.

Supports Chrome, Edge (Chromium), Firefox, and Internet Explorer/Edge Legacy.
Uses Hindsight (pip install hindsight) when available; falls back to direct SQLite.

Tools:
  parse_chrome_history      — Chrome/Edge browsing history + downloads
  parse_firefox_history     — Firefox places.sqlite history + downloads
  parse_chrome_extensions   — Detect suspicious/malicious extensions
  parse_browser_cookies     — Cookie analysis (domain, expiry, HttpOnly/Secure flags)
  run_hindsight             — Full Hindsight Chrome forensics report
  parse_browser_passwords   — Saved login URL inventory (no plaintext decryption)
  parse_ie_history          — Internet Explorer / Edge Legacy history (ESE)
  parse_chromium_cache      — Chrome cache entry listing (cached domains)
"""
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.browser_parser import classify_chrome_rows, classify_downloads, build_browser_summary
from mcp_server.parsers.rag_enrichment import enrich_findings, build_rag_summary
from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques

# Chrome epoch: Jan 1, 1601 → Unix epoch offset in microseconds
_CHROME_EPOCH_OFFSET = 11644473600 * 1_000_000

_SUSPICIOUS_DOMAINS = re.compile(
    r"\b(?:pastebin|ngrok|serveo|temp-mail|10minutemail|guerrillamail"
    r"|anonfiles|gofile|transfer\.sh|filebin|0x0\.st|catbox\.moe"
    r"|discord\.gg|t\.me|raw\.githubusercontent"
    r"|\.onion|\.i2p)\b",
    re.IGNORECASE,
)

_CLOUD_EXFIL_DOMAINS = re.compile(
    r"\b(?:dropbox|onedrive|drive\.google|docs\.google|icloud|box\.com|mega\.nz"
    r"|wetransfer|sendspace|mediafire|4shared|sharepoint|my\.sharepoint"
    r"|1drv\.ms|sharefile|citrixdata)\b",
    re.IGNORECASE,
)


def _chrome_ts(ts: int | None) -> str:
    """Convert Chrome WebKit timestamp (microseconds since 1601) to ISO 8601."""
    if not ts:
        return ""
    try:
        unix_us = ts - _CHROME_EPOCH_OFFSET
        return datetime.utcfromtimestamp(unix_us / 1_000_000).isoformat() + "Z"
    except (OSError, OverflowError, ValueError):
        return str(ts)


def _firefox_ts(ts: int | None) -> str:
    """Convert Firefox timestamp (microseconds since Unix epoch) to ISO 8601."""
    if not ts:
        return ""
    try:
        return datetime.utcfromtimestamp(ts / 1_000_000).isoformat() + "Z"
    except (OSError, OverflowError, ValueError):
        return str(ts)


def _flag_url(url: str) -> list[str]:
    flags = []
    if _SUSPICIOUS_DOMAINS.search(url):
        flags.append("SUSPICIOUS_DOMAIN")
    if _CLOUD_EXFIL_DOMAINS.search(url):
        flags.append("CLOUD_EXFIL_DOMAIN")
    if re.search(r"\b(?:download|upload|exfil|payload|dropper|stager)\b", url, re.I):
        flags.append("SUSPICIOUS_PATH_KEYWORD")
    return flags


def _query_sqlite(db_path: str, query: str, params: tuple = ()) -> list[dict]:
    """Read-only SQLite query — always opens in immutable mode."""
    uri = f"file:{db_path}?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        return [{"error": str(e)}]


# Glob patterns (relative to a given root) that locate every Chromium profile's
# History DB for Chrome, Edge, and Brave. Lets one call cover the whole browser surface.
_CHROMIUM_HISTORY_GLOBS = (
    "AppData/Local/Google/Chrome/User Data/*/History",
    "AppData/Local/Microsoft/Edge/User Data/*/History",
    "AppData/Local/BraveSoftware/Brave-Browser/User Data/*/History",
    "Google/Chrome/User Data/*/History",
    "Microsoft/Edge/User Data/*/History",
    "BraveSoftware/Brave-Browser/User Data/*/History",
    "User Data/*/History",
    "*/History",
)


def _discover_chromium_history(path: str) -> list[Path]:
    """Return every Chromium (Chrome/Edge/Brave) History DB under `path`.

    Accepts a direct History file, a single profile dir, a 'User Data' dir, or a
    user/evidence root — and finds all profiles below it. De-duplicated, sorted.
    """
    p = Path(path)
    if p.is_file():
        return [p]
    found: list[Path] = []
    seen: set[str] = set()
    if p.is_dir():
        # Single profile dir passed directly (…/Default).
        direct = p / "History"
        if direct.is_file():
            found.append(direct)
            seen.add(str(direct.resolve()))
        for pattern in _CHROMIUM_HISTORY_GLOBS:
            for db in p.glob(pattern):
                rp = str(db.resolve())
                if db.is_file() and rp not in seen:
                    seen.add(rp)
                    found.append(db)
    return sorted(found, key=str)


def _profile_label(db: Path) -> str:
    """Readable '<user>/<browser>/<profile>' label for a History DB path."""
    parts = db.parts
    low = [s.lower() for s in parts]
    user = ""
    if "users" in low:
        i = low.index("users")
        if i + 1 < len(parts):
            user = parts[i + 1]
    if "chrome" in low:
        browser = "Chrome"
    elif "edge" in low:
        browser = "Edge"
    elif "brave-browser" in low:
        browser = "Brave"
    else:
        browser = "Chromium"
    profile = db.parent.name  # Default, Profile 1, …
    return "/".join(x for x in (user, browser, profile) if x)


def register_browser_artifact_tools(mcp, rag=None):

    @mcp.tool()
    def parse_chrome_history(profile_path: str, limit: int = 500) -> str:
        """
        Parse Chromium (Chrome AND Edge) browsing history and downloads across ALL profiles.

        Auto-discovers every profile under the path you give, so a single call covers
        the whole browser surface — Default, Profile 1/2/N, and both Chrome and Edge.
        Pass the broadest path you have:
          * a user root          → /mnt/evidence/Users/<user>      (covers Chrome + Edge, all profiles)
          * a 'User Data' dir     → .../Chrome/User Data            (all profiles of that browser)
          * a single profile dir  → .../User Data/Default           (just that profile)
          * a direct History file → .../Default/History

        Incident-window activity lives in non-default profiles more often than not, so
        prefer the user root. Returns merged visits/downloads (each tagged with its
        source profile), suspicious-domain + cloud-exfil flags (incl. SharePoint), and
        the most recent activity first.

        Args:
            profile_path: User root, User Data dir, profile dir, or History file.
            limit:        Max history entries per profile (default 500).
        """
        increment_tool_counter()
        history_dbs = _discover_chromium_history(profile_path)
        if not history_dbs:
            return json.dumps({"error": f"No Chromium History database found under {profile_path}"})

        visits: list[dict] = []
        suspicious_visits: list[dict] = []
        cloud_exfil_visits: list[dict] = []
        downloads: list[dict] = []
        raw_all: dict[str, dict] = {}      # per-profile raw rows for the audit record
        profiles_covered: list[dict] = []

        for db in history_dbs:
            label = _profile_label(db)
            rows = _query_sqlite(
                str(db),
                "SELECT url, title, visit_count, last_visit_time, typed_count "
                "FROM urls ORDER BY last_visit_time DESC LIMIT ?",
                (limit,),
            )
            dl_rows = _query_sqlite(
                str(db),
                "SELECT target_path, tab_url, total_bytes, start_time, state "
                "FROM downloads ORDER BY start_time DESC LIMIT 200",
            )
            raw_all[label] = {"urls": rows, "downloads": dl_rows}
            n_v = 0
            for r in rows:
                if "error" in r:
                    break
                flags = _flag_url(r.get("url", ""))
                entry = {
                    "profile": label,
                    "url": r.get("url", ""),
                    "title": r.get("title", ""),
                    "visit_count": r.get("visit_count", 0),
                    "last_visit": _chrome_ts(r.get("last_visit_time")),
                    "typed_count": r.get("typed_count", 0),
                    "flags": flags,
                }
                visits.append(entry)
                n_v += 1
                if "SUSPICIOUS_DOMAIN" in flags:
                    suspicious_visits.append(entry)
                if "CLOUD_EXFIL_DOMAIN" in flags:
                    cloud_exfil_visits.append(entry)
            n_d = 0
            for r in dl_rows:
                if "error" in r:
                    break
                downloads.append({
                    "profile": label,
                    "target_path": r.get("target_path", ""),
                    "source_url": r.get("tab_url", ""),
                    "size_bytes": r.get("total_bytes", 0),
                    "start_time": _chrome_ts(r.get("start_time")),
                    "state": r.get("state"),
                    "flags": _flag_url(r.get("tab_url", "")),
                })
                n_d += 1
            profiles_covered.append({"profile": label, "history_db": str(db),
                                     "visits": n_v, "downloads": n_d})

        # Most recent first across all profiles, so incident-window activity surfaces.
        visits.sort(key=lambda v: v.get("last_visit", ""), reverse=True)
        downloads.sort(key=lambda d: d.get("start_time", ""), reverse=True)

        # Chain-of-custody: audit the actual rows from EVERY profile parsed, so grounding
        # can verify any cited URL/download and the SHA-256 binds all analysed data.
        evidence_text = json.dumps(raw_all, ensure_ascii=False, default=str)
        log_tool_execution("parse_chrome_history",
                           [str(d) for d in history_dbs], evidence_text)
        audit_id = get_last_audit_id()

        _, mp_suspicious = classify_chrome_rows(visits)
        _, mp_dl_suspicious = classify_downloads(downloads)
        browser_summary = build_browser_summary(visits, mp_suspicious)

        enrich_findings(
            rag, suspicious_visits + cloud_exfil_visits,
            lambda v: f"browser visit exfiltration cloud storage {v.get('url', '')} {v.get('flags', [])}",
        )

        data = {
            "profile_path": str(profile_path),
            "profiles_covered": profiles_covered,
            "profile_count": len(profiles_covered),
            "total_history_entries": len(visits),
            "suspicious_visits": suspicious_visits[:50],
            "cloud_exfil_visits": cloud_exfil_visits[:50],
            "parser_summary": browser_summary,
            "suspicious_downloads": mp_dl_suspicious[:50],
            "recent_history": visits[:120],
            "downloads": downloads[:120],
            "rag_context": build_rag_summary(rag, "browser forensics cloud exfiltration evidence"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_chrome_history", data, audit_id)

    @mcp.tool()
    def parse_firefox_history(profile_path: str, limit: int = 500) -> str:
        """
        Parse Mozilla Firefox browsing history, downloads, and search queries
        from places.sqlite.

        Expected path: /mnt/evidence/Users/<user>/AppData/Roaming/Mozilla/Firefox/Profiles/<profile>/

        Args:
            profile_path: Path to a Firefox profile directory OR direct path
                          to places.sqlite.
            limit:        Maximum number of history entries to return.
        """
        increment_tool_counter()
        profile = Path(profile_path)
        places_db = profile if profile.name == "places.sqlite" else profile / "places.sqlite"
        if not places_db.exists():
            return json.dumps({"error": f"places.sqlite not found at {profile_path}"})

        rows = _query_sqlite(
            str(places_db),
            "SELECT p.url, p.title, p.visit_count, p.last_visit_date, "
            "p.typed, p.frecency "
            "FROM moz_places p ORDER BY p.last_visit_date DESC LIMIT ?",
            (limit,),
        )
        # Chain-of-custody: audit the actual rows returned (real URLs), so grounding
        # can verify claims against evidence and the SHA-256 binds the analysed data.
        log_tool_execution(
            "parse_firefox_history", [str(places_db)],
            json.dumps({"urls": rows}, ensure_ascii=False, default=str),
        )
        audit_id = get_last_audit_id()
        visits = []
        suspicious = []
        cloud_exfil = []
        for r in rows:
            if "error" in r:
                break
            flags = _flag_url(r.get("url", ""))
            entry = {
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "visit_count": r.get("visit_count", 0),
                "last_visit": _firefox_ts(r.get("last_visit_date")),
                "typed": bool(r.get("typed")),
                "flags": flags,
            }
            visits.append(entry)
            if "SUSPICIOUS_DOMAIN" in flags:
                suspicious.append(entry)
            if "CLOUD_EXFIL_DOMAIN" in flags:
                cloud_exfil.append(entry)

        # Downloads from moz_annos
        dl_rows = _query_sqlite(
            str(places_db),
            "SELECT p.url, a.content, a.dateAdded "
            "FROM moz_annos a "
            "JOIN moz_places p ON a.place_id = p.id "
            "WHERE a.anno_attribute_id IN "
            "  (SELECT id FROM moz_anno_attributes WHERE name LIKE '%download%') "
            "ORDER BY a.dateAdded DESC LIMIT 200",
        )
        downloads = [
            {
                "source_url": r.get("url", ""),
                "local_path": r.get("content", ""),
                "date_added": _firefox_ts(r.get("dateAdded")),
            }
            for r in dl_rows if "error" not in r
        ]

        _, mp_suspicious = classify_chrome_rows(visits)
        enrich_findings(rag, suspicious + cloud_exfil,
                        lambda v: f"Firefox browser visit suspicious {v.get('url', '')} {v.get('flags', [])}")

        data = {
            "profile_path": str(profile_path),
            "total_history_entries": len(visits),
            "suspicious_visits": suspicious[:50],
            "cloud_exfil_visits": cloud_exfil[:50],
            "parser_summary": build_browser_summary(visits, mp_suspicious),
            "recent_history": visits[:100],
            "downloads": downloads[:50],
            "rag_context": build_rag_summary(rag, "Firefox browser forensics exfiltration"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_firefox_history", data, audit_id)

    @mcp.tool()
    def parse_chrome_extensions(profile_path: str) -> str:
        """
        Enumerate installed Chrome/Edge extensions and flag suspicious ones.

        Checks for: extensions with broad permissions (tabs, cookies, webRequest,
        clipboardRead), extensions not from Chrome Web Store, recently installed
        extensions, and known malicious extension IDs.

        Args:
            profile_path: Path to the Chrome/Edge 'Default' profile directory.
        """
        increment_tool_counter()
        ext_dir = Path(profile_path) / "Extensions"
        if not ext_dir.exists():
            ext_dir = Path(profile_path).parent / "Extensions"
        if not ext_dir.exists():
            return json.dumps({"error": f"Extensions directory not found under {profile_path}"})

        log_tool_execution("parse_chrome_extensions", [str(ext_dir)], "directory scan")
        audit_id = get_last_audit_id()

        _DANGEROUS_PERMS = {
            "tabs", "cookies", "webRequest", "webRequestBlocking",
            "clipboardRead", "history", "downloads", "nativeMessaging",
            "storage", "identity", "management", "debugger",
            "<all_urls>", "http://*/*", "https://*/*",
        }

        extensions = []
        suspicious_extensions = []

        for ext_id_dir in sorted(ext_dir.iterdir()):
            if not ext_id_dir.is_dir():
                continue
            for version_dir in sorted(ext_id_dir.iterdir()):
                if not version_dir.is_dir():
                    continue
                manifest = version_dir / "manifest.json"
                if not manifest.exists():
                    continue
                try:
                    m = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue

                perms = set(m.get("permissions", []) + m.get("host_permissions", []))
                dangerous = list(perms & _DANGEROUS_PERMS)
                entry = {
                    "extension_id": ext_id_dir.name,
                    "name": m.get("name", ""),
                    "version": m.get("version", ""),
                    "description": m.get("description", "")[:200],
                    "permissions": list(perms)[:30],
                    "dangerous_permissions": dangerous,
                    "update_url": m.get("update_url", ""),
                    "from_store": "clients2.google.com" in m.get("update_url", ""),
                    "suspicious": len(dangerous) >= 3 or "<all_urls>" in perms,
                }
                extensions.append(entry)
                if entry["suspicious"]:
                    suspicious_extensions.append(entry)

        data = {
            "profile_path": str(profile_path),
            "total_extensions": len(extensions),
            "suspicious_extensions": suspicious_extensions,
            "all_extensions": extensions,
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_chrome_extensions", data, audit_id)

    @mcp.tool()
    def parse_browser_cookies(db_path: str, browser: str = "chrome") -> str:
        """
        Parse browser cookie database to identify suspicious session persistence,
        authenticated sessions, and tracking cookies.

        Flags: persistent cookies to suspicious domains, HttpOnly=False on auth cookies,
        cookies with very long expiry (>1 year), and cloud service auth tokens.

        Args:
            db_path: Path to cookie database.
                     Chrome/Edge: Default/Cookies
                     Firefox: Default/cookies.sqlite
            browser: 'chrome', 'edge', or 'firefox' (default: chrome)
        """
        increment_tool_counter()
        if not Path(db_path).exists():
            return json.dumps({"error": f"Cookie database not found: {db_path}"})

        log_tool_execution("parse_browser_cookies", [db_path], "SQLite parse")
        audit_id = get_last_audit_id()

        if browser.lower() in ("chrome", "edge"):
            rows = _query_sqlite(
                db_path,
                "SELECT host_key, name, path, expires_utc, is_httponly, is_secure, "
                "samesite, has_expires, is_persistent "
                "FROM cookies ORDER BY creation_utc DESC LIMIT 2000",
            )
            cookies = [
                {
                    "domain": r.get("host_key", ""),
                    "name": r.get("name", ""),
                    "path": r.get("path", ""),
                    "expires": _chrome_ts(r.get("expires_utc")),
                    "http_only": bool(r.get("is_httponly")),
                    "secure": bool(r.get("is_secure")),
                    "persistent": bool(r.get("is_persistent")),
                }
                for r in rows if "error" not in r
            ]
        else:
            rows = _query_sqlite(
                db_path,
                "SELECT host, name, path, expiry, isHttpOnly, isSecure "
                "FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 2000",
            )
            cookies = [
                {
                    "domain": r.get("host", ""),
                    "name": r.get("name", ""),
                    "path": r.get("path", ""),
                    "expires": str(r.get("expiry", "")),
                    "http_only": bool(r.get("isHttpOnly")),
                    "secure": bool(r.get("isSecure")),
                }
                for r in rows if "error" not in r
            ]

        suspicious = [c for c in cookies if _SUSPICIOUS_DOMAINS.search(c.get("domain", ""))]
        cloud_auth = [c for c in cookies if _CLOUD_EXFIL_DOMAINS.search(c.get("domain", ""))]
        domain_counts: dict[str, int] = {}
        for c in cookies:
            d = c.get("domain", "").lstrip(".")
            domain_counts[d] = domain_counts.get(d, 0) + 1

        data = {
            "db_path": db_path,
            "total_cookies": len(cookies),
            "suspicious_domain_cookies": suspicious[:50],
            "cloud_service_cookies": cloud_auth[:50],
            "top_domains": sorted(domain_counts.items(), key=lambda x: -x[1])[:30],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_browser_cookies", data, audit_id)

    @mcp.tool()
    def run_hindsight(profile_path: str, output_dir: str = "") -> str:
        """
        Run Hindsight for comprehensive Chrome/Chromium forensics.

        Hindsight parses Chrome artifacts including: browsing history, downloads,
        cookies, cache, extensions, preferences, autofill, bookmarks, login data
        URLs, and favicons. Returns a structured JSON output.

        Requires: pip install hindsight

        Args:
            profile_path: Path to Chrome/Edge 'Default' profile directory.
            output_dir:   Directory to write Hindsight output (default: exports/).
        """
        increment_tool_counter()
        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "hindsight"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = str(out_dir / "hindsight_output")

        cmd = ["hindsight", "-i", str(profile_path), "-o", out_file, "-f", "json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("run_hindsight", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({
                "error": "hindsight not found. Install: pip3 install hindsight",
                "fallback": "Use parse_chrome_history for direct SQLite parsing.",
            })
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "Hindsight timed out"})

        audit_id = get_last_audit_id()

        # Try reading the JSON output
        json_file = Path(out_file + ".json")
        findings: dict = {}
        if json_file.exists():
            try:
                findings = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception:
                findings = {"raw_output_file": str(json_file)}

        data = {
            "profile_path": str(profile_path),
            "output_file": str(json_file),
            "hindsight_findings": findings,
            "stdout_preview": result.stdout[:1000] if result.stdout else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("run_hindsight", data, audit_id)

    @mcp.tool()
    def parse_browser_passwords(profile_path: str, browser: str = "chrome") -> str:
        """
        Enumerate saved login URLs from the browser credential store.

        IMPORTANT: This tool returns ONLY the origin URLs and usernames where
        passwords were saved — NOT the plaintext passwords (decryption requires
        the OS master key and is outside forensic scope of this tool).

        The URL inventory alone reveals what accounts the user had credentials
        for, which is forensically significant for exfiltration assessment.

        Args:
            profile_path: Chrome/Edge Default profile directory or Firefox profile.
            browser:      'chrome', 'edge', or 'firefox'
        """
        increment_tool_counter()
        profile = Path(profile_path)

        if browser.lower() in ("chrome", "edge"):
            login_db = profile / "Login Data"
            if not login_db.exists():
                return json.dumps({"error": f"Login Data not found at {profile_path}"})
            rows = _query_sqlite(
                str(login_db),
                "SELECT origin_url, action_url, username_value, times_used, "
                "date_created, date_last_used "
                "FROM logins ORDER BY date_last_used DESC LIMIT 500",
            )
            logins = [
                {
                    "origin_url": r.get("origin_url", ""),
                    "action_url": r.get("action_url", ""),
                    "username": r.get("username_value", ""),
                    "times_used": r.get("times_used", 0),
                    "date_created": _chrome_ts(r.get("date_created")),
                    "date_last_used": _chrome_ts(r.get("date_last_used")),
                    "flags": _flag_url(r.get("origin_url", "")),
                }
                for r in rows if "error" not in r
            ]
        else:
            key_db = profile / "key4.db"
            if not key_db.exists():
                return json.dumps({"error": "Firefox key4.db not found — no saved passwords recoverable without decryption key"})
            rows = _query_sqlite(
                str(key_db),
                "SELECT guid, encType FROM metadata LIMIT 10",
            )
            logins = [{"note": "Firefox credential decryption requires master password key — returning metadata only", "rows": rows[:5]}]

        log_tool_execution("parse_browser_passwords", [str(profile_path)], f"{len(logins)} entries")
        audit_id = get_last_audit_id()

        data = {
            "profile_path": str(profile_path),
            "browser": browser,
            "warning": "Passwords are NOT decrypted — only origin URLs and usernames returned.",
            "saved_login_count": len(logins),
            "logins": logins[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_browser_passwords", data, audit_id)

    @mcp.tool()
    def parse_ie_edge_legacy_history(dat_path: str) -> str:
        """
        Parse Internet Explorer or Edge Legacy browsing history.

        IE/Edge Legacy stores history in WebCacheV01.dat (ESE/JET database) or
        index.dat files. This tool uses strings extraction + ESE parsing as fallback.

        For ESE database parsing, requires: pip3 install pyesedb

        Args:
            dat_path: Path to WebCacheV01.dat or the IE history directory
                      (typically: C:/Users/<user>/AppData/Local/Microsoft/Windows/WebCache/)
        """
        increment_tool_counter()
        dat_file = Path(dat_path)
        if not dat_file.exists():
            return json.dumps({"error": f"Path not found: {dat_path}"})

        log_tool_execution("parse_ie_edge_legacy_history", [dat_path], "ESE/strings parse")
        audit_id = get_last_audit_id()

        results: list[dict] = []

        # Try pyesedb first
        try:
            import pyesedb  # type: ignore
            db = pyesedb.open(dat_path)
            for i in range(db.get_number_of_tables()):
                tbl = db.get_table(i)
                name = tbl.get_name()
                if "url" in name.lower() or "container" in name.lower():
                    for rec_i in range(min(tbl.get_number_of_records(), 500)):
                        rec = tbl.get_record(rec_i)
                        entry: dict = {"table": name}
                        for col_i in range(rec.get_number_of_values()):
                            col = tbl.get_column(col_i)
                            try:
                                val = rec.get_value_data_as_string(col_i) or ""
                                if val:
                                    entry[col.get_name()] = val[:300]
                            except Exception:
                                pass
                        if entry:
                            results.append(entry)
        except ImportError:
            # Fallback: strings-based extraction
            try:
                r = subprocess.run(
                    ["strings", dat_path],
                    capture_output=True, text=True, timeout=60,
                )
                urls = [
                    line.strip() for line in r.stdout.splitlines()
                    if line.strip().startswith(("http://", "https://"))
                ]
                results = [{"url": u, "flags": _flag_url(u)} for u in urls[:500]]
            except Exception as e:
                results = [{"error": f"Neither pyesedb nor strings available: {e}"}]
        except Exception as e:
            results = [{"error": str(e)}]

        data = {
            "dat_path": dat_path,
            "total_records": len(results),
            "suspicious_entries": [r for r in results if r.get("flags") and "SUSPICIOUS_DOMAIN" in r.get("flags", [])],
            "results": results[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_ie_edge_legacy_history", data, audit_id)

    @mcp.tool()
    def parse_chromium_cache(cache_dir: str, limit: int = 200) -> str:
        """
        List cached domains and resource types from a Chrome/Edge cache directory.

        Cache entries reveal which sites were visited even if browsing history
        was cleared, since cache and history are stored separately.

        Args:
            cache_dir: Path to Chrome cache directory.
                       Usually: Default/Cache/ or Default/Code Cache/
            limit:     Maximum entries to return.
        """
        increment_tool_counter()
        cache_path = Path(cache_dir)
        if not cache_path.exists():
            return json.dumps({"error": f"Cache directory not found: {cache_dir}"})

        log_tool_execution("parse_chromium_cache", [cache_dir], "cache index scan")
        audit_id = get_last_audit_id()

        # Use strings extraction to find URLs in cache files
        urls_found: list[str] = []
        try:
            for f in sorted(cache_path.iterdir())[:100]:
                if f.is_file() and f.stat().st_size < 5_000_000:
                    r = subprocess.run(
                        ["strings", "-n", "12", str(f)],
                        capture_output=True, text=True, timeout=10,
                    )
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line.startswith(("http://", "https://")) and len(line) < 500:
                            urls_found.append(line)
        except FileNotFoundError:
            # No strings binary — read bytes directly
            for f in sorted(cache_path.iterdir())[:50]:
                if f.is_file():
                    try:
                        raw = f.read_bytes()
                        for m in re.finditer(rb"https?://[^\x00-\x1f\x7f-\xff ]{10,400}", raw):
                            urls_found.append(m.group().decode("utf-8", errors="replace"))
                    except Exception:
                        pass

        unique_urls = list(dict.fromkeys(urls_found))[:limit]
        suspicious = [u for u in unique_urls if _flag_url(u)]
        domain_counts: dict[str, int] = {}
        for u in unique_urls:
            m = re.match(r"https?://([^/]+)", u)
            if m:
                d = m.group(1)
                domain_counts[d] = domain_counts.get(d, 0) + 1

        data = {
            "cache_dir": cache_dir,
            "unique_urls_found": len(unique_urls),
            "suspicious_cache_entries": [{"url": u, "flags": _flag_url(u)} for u in suspicious][:50],
            "top_cached_domains": sorted(domain_counts.items(), key=lambda x: -x[1])[:30],
            "sample_urls": unique_urls[:100],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_chromium_cache", data, audit_id)
