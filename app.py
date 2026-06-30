#!/usr/bin/env python3
import base64
import datetime as dt
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "app.db"
SECRET_PATH = DATA_DIR / "app.secret"
SESSION_COOKIE = "fmc_object_manager_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PBKDF2_ITERATIONS = 310_000

ROLE_LEVELS = {
    "viewer": 10,
    "operator": 20,
    "approver": 30,
    "admin": 40,
}

OBJECT_ENDPOINTS = {
    "Host": "hosts",
    "Network": "networks",
    "Range": "ranges",
    "FQDN": "fqdns",
    "NetworkGroup": "networkgroups",
    "ProtocolPortObject": "protocolportobjects",
    "ICMPV4Object": "icmpv4objects",
    "ICMPV6Object": "icmpv6objects",
    "PortGroup": "portobjectgroups",
}

PUBLIC_OBJECT_TYPES = ["Host", "Network", "Range", "FQDN", "NetworkGroup", "ProtocolPortObject", "PortGroup"]
PORT_OBJECT_TYPES = {"ProtocolPortObject", "ICMPV4Object", "ICMPV6Object"}

OBJECT_TYPE_ALIASES = {
    "Port": "ProtocolPortObject",
    "PortObject": "ProtocolPortObject",
    "PortObjectGroup": "PortGroup",
    "ICMP": "ICMPV4Object",
    "IPv6-ICMP": "ICMPV6Object",
}


def now_iso():
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def json_dumps(data):
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def load_app_secret():
    DATA_DIR.mkdir(exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(32))
        try:
            os.chmod(SECRET_PATH, 0o600)
        except OSError:
            pass
    return SECRET_PATH.read_bytes()


APP_SECRET = load_app_secret()


def secretbox_stream(nonce, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hmac.new(APP_SECRET, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def encrypt_secret(value):
    if not value:
        return ""
    raw = value.encode("utf-8")
    nonce = secrets.token_bytes(16)
    stream = secretbox_stream(nonce, len(raw))
    ciphertext = bytes(a ^ b for a, b in zip(raw, stream))
    tag = hmac.new(APP_SECRET, nonce + ciphertext, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(nonce + tag + ciphertext).decode("ascii")


def decrypt_secret(value):
    if not value:
        return ""
    try:
        blob = base64.urlsafe_b64decode(value.encode("ascii"))
        nonce, tag, ciphertext = blob[:16], blob[16:48], blob[48:]
        expected = hmac.new(APP_SECRET, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return ""
        stream = secretbox_stream(nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, stream)).decode("utf-8")
    except Exception:
        return ""


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password, encoded):
    try:
        algo, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def row_to_dict(row):
    return dict(row) if row is not None else None


def json_loads(value, fallback=None):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def init_db():
    DATA_DIR.mkdir(exist_ok=True)
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL UNIQUE,
              display_name TEXT NOT NULL,
              role TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1,
              force_password_change INTEGER NOT NULL DEFAULT 0,
              failed_attempts INTEGER NOT NULL DEFAULT 0,
              locked_until TEXT,
              last_login_at TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
              id TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              last_seen_at TEXT NOT NULL,
              ip_address TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS fmc_objects (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain_id TEXT NOT NULL DEFAULT 'local',
              fmc_id TEXT,
              object_type TEXT NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              overridable INTEGER NOT NULL DEFAULT 1,
              description TEXT NOT NULL DEFAULT '',
              raw_fmc_payload TEXT,
              source TEXT NOT NULL DEFAULT 'local',
              last_seen_at TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(domain_id, object_type, name)
            );

            CREATE TABLE IF NOT EXISTS fmc_object_overrides (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              object_id INTEGER NOT NULL REFERENCES fmc_objects(id) ON DELETE CASCADE,
              fmc_id TEXT,
              device_name TEXT NOT NULL,
              device_id TEXT,
              override_value TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              raw_fmc_payload TEXT,
              source TEXT NOT NULL DEFAULT 'local',
              last_seen_at TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(object_id, device_name)
            );

            CREATE TABLE IF NOT EXISTS change_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              requested_by INTEGER NOT NULL REFERENCES users(id),
              approved_by INTEGER REFERENCES users(id),
              status TEXT NOT NULL,
              target_type TEXT NOT NULL,
              target_id INTEGER,
              operation TEXT NOT NULL,
              before_value TEXT,
              after_value TEXT NOT NULL,
              fmc_response TEXT,
              created_at TEXT NOT NULL,
              applied_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
              username TEXT,
              action TEXT NOT NULL,
              target_type TEXT,
              target_id TEXT,
              before_value TEXT,
              after_value TEXT,
              metadata TEXT,
              ip_address TEXT,
              created_at TEXT NOT NULL
            );
            """
        )
        ensure_column(db, "fmc_objects", "overridable", "INTEGER NOT NULL DEFAULT 1")
        ensure_column(db, "fmc_object_overrides", "fmc_id", "TEXT")
        ensure_column(db, "fmc_object_overrides", "description", "TEXT NOT NULL DEFAULT ''")
        ensure_column(db, "fmc_object_overrides", "source", "TEXT NOT NULL DEFAULT 'local'")
        count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if count == 0:
            password = os.environ.get("FMC_APP_ADMIN_PASSWORD", "ChangeMe12345!")
            ts = now_iso()
            db.execute(
                """
                INSERT INTO users
                (username, display_name, role, password_hash, active, force_password_change, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, 1, ?, ?)
                """,
                ("admin", "Administrator", "admin", hash_password(password), ts, ts),
            )
            print("Bootstrap admin created: username=admin password=ChangeMe12345!", file=sys.stderr)
            print("Set FMC_APP_ADMIN_PASSWORD before first run to choose another bootstrap password.", file=sys.stderr)
        seed_demo_objects(db)


def seed_demo_objects(db):
    count = db.execute("SELECT COUNT(*) AS count FROM fmc_objects").fetchone()["count"]
    if count:
        return
    ts = now_iso()
    demo = [
        ("Host", "srv-dns-01", "10.62.8.53", "Internal DNS resolver"),
        ("Host", "srv-monitoring", "10.62.8.24", "Monitoring system"),
        ("Network", "net-datacenter", "10.62.0.0/16", "Primary DC network"),
        ("Network", "net-guest-wifi", "10.77.0.0/16", "Guest wireless network"),
        ("Range", "vpn-pool", "10.90.10.10-10.90.10.250", "Remote access VPN pool"),
        ("FQDN", "fqdn-updates-cisco", "tools.cisco.com", "Cisco update endpoint"),
        ("ProtocolPortObject", "tcp-https", "tcp/443", "HTTPS"),
        ("PortGroup", "grp-web", "tcp/80,tcp/443", "Common web ports"),
    ]
    for object_type, name, value, description in demo:
        db.execute(
            """
            INSERT INTO fmc_objects
            (domain_id, object_type, name, value, overridable, description, source, created_at, updated_at)
            VALUES ('local', ?, ?, ?, 1, ?, 'demo', ?, ?)
            """,
            (object_type, name, value, description, ts, ts),
        )
    dns_id = db.execute("SELECT id FROM fmc_objects WHERE name = 'srv-dns-01'").fetchone()["id"]
    db.execute(
        """
        INSERT INTO fmc_object_overrides
        (object_id, device_name, device_id, override_value, created_at, updated_at)
        VALUES (?, 'FTD-BRNO-01', 'demo-device-brno', '10.62.18.53', ?, ?)
        """,
        (dns_id, ts, ts),
    )


def ensure_column(db, table, column, definition):
    columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def audit(db, user, action, target_type=None, target_id=None, before=None, after=None, metadata=None, ip_address=None):
    db.execute(
        """
        INSERT INTO audit_log
        (user_id, username, action, target_type, target_id, before_value, after_value, metadata, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user.get("id") if user else None,
            user.get("username") if user else None,
            action,
            target_type,
            str(target_id) if target_id is not None else None,
            json.dumps(before, ensure_ascii=False) if before is not None else None,
            json.dumps(after, ensure_ascii=False) if after is not None else None,
            json.dumps(metadata, ensure_ascii=False) if metadata is not None else None,
            ip_address,
            now_iso(),
        ),
    )


def get_setting(db, key, default=""):
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(db, key, value):
    db.execute(
        """
        INSERT INTO settings(key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value, now_iso()),
    )


def public_fmc_settings(db):
    return {
        "base_url": get_setting(db, "fmc.base_url", "https://10.62.8.190"),
        "username": get_setting(db, "fmc.username", ""),
        "domain_uuid": get_setting(db, "fmc.domain_uuid", ""),
        "verify_tls": get_setting(db, "fmc.verify_tls", "true") == "true",
        "has_password": bool(get_setting(db, "fmc.password", "")),
    }


def fmc_configured(db):
    return bool(get_setting(db, "fmc.username", "") and get_setting(db, "fmc.password", ""))


def payload_bool(payload, key, default=False):
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def fmc_object_value(payload):
    value = payload.get("value")
    if value is None:
        value = payload.get("dnsResolution")
    if value is None and (payload.get("protocol") or payload.get("port")):
        protocol = str(payload.get("protocol") or "").lower()
        port = str(payload.get("port") or "")
        if protocol and protocol not in {"tcp", "udp"}:
            value = f"protocol/{protocol}/{port}".strip("/")
        else:
            value = f"{protocol}/{port}".strip("/")
    if value is None and payload.get("icmpType") is not None:
        prefix = "ipv6-icmp" if payload.get("type") == "ICMPV6Object" else "icmp"
        value = f"{prefix}/{payload.get('icmpType')}/{payload.get('code')}" if payload.get("code") is not None else f"{prefix}/{payload.get('icmpType')}"
    if value is None:
        value = payload.get("literals")
    if value is None:
        value = payload.get("objects")
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def normalize_object_type(object_type):
    return OBJECT_TYPE_ALIASES.get(object_type, object_type)


def parse_port_value(value):
    text = (value or "").strip()
    match = re.fullmatch(r"(?i)(tcp|udp|protocol)\s*/\s*(.+?)(?:\s*/\s*(.+))?", text)
    if match:
        protocol = match.group(1).upper()
        port = match.group(2).strip()
        if protocol == "PROTOCOL":
            protocol = port
            port = (match.group(3) or "any").strip()
        return protocol, port
    return "TCP", text


def parse_icmp_value(value, default_prefix="icmp"):
    text = (value or "").strip()
    pattern = r"(?i)(icmp|ipv6-icmp)\s*/\s*([^/]+)(?:\s*/\s*([^/]+))?"
    match = re.fullmatch(pattern, text)
    if match:
        return match.group(1).lower(), match.group(2).strip(), (match.group(3) or "any").strip()
    parts = [part.strip() for part in text.split("/") if part.strip()]
    icmp_type = parts[0] if parts else "any"
    code = parts[1] if len(parts) > 1 else "any"
    return default_prefix, icmp_type, code


def icmp_payload_fields(value, default_prefix="icmp"):
    _, icmp_type, code = parse_icmp_value(value, default_prefix)
    fields = {}
    if icmp_type.lower() != "any":
        fields["icmpType"] = icmp_type
    if code.lower() != "any":
        try:
            fields["code"] = int(code)
        except ValueError:
            fields["code"] = code
    return fields


def is_port_number_or_range(value, allow_any=False):
    text = (value or "").strip()
    if allow_any and text.lower() == "any":
        return True
    return bool(re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", text))


def port_group_objects_from_value(value):
    parsed = json_loads(value, [])
    if not isinstance(parsed, list):
        return []
    objects = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        object_id = item.get("id")
        if not object_id:
            continue
        objects.append(
            {
                "id": object_id,
                "type": item.get("type") or "ProtocolPortObject",
                "name": item.get("name", ""),
            }
        )
    return objects


def network_group_objects_from_value(value):
    parsed = json_loads(value, [])
    if not isinstance(parsed, list):
        return []
    objects = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        object_id = item.get("id")
        if not object_id:
            continue
        object_type = normalize_object_type(item.get("type") or "Host")
        if object_type not in {"Host", "Network", "Range", "FQDN"}:
            continue
        objects.append(
            {
                "id": object_id,
                "type": object_type,
                "name": item.get("name", ""),
            }
        )
    return objects


def group_display_value(value):
    parsed = json_loads(value, [])
    if not isinstance(parsed, list):
        return value or ""
    labels = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        raw_value = item.get("value")
        object_id = item.get("id")
        label = name or raw_value or object_id
        if label:
            labels.append(label)
    return ", ".join(labels) or (value or "")


def fmc_override_target(payload):
    overrides = payload.get("overrides") or {}
    target = overrides.get("target") or payload.get("target") or {}
    return {
        "id": target.get("id") or payload.get("overrideTargetId") or "",
        "name": target.get("name") or target.get("id") or payload.get("overrideTargetName") or "",
        "type": target.get("type") or "",
    }


def fmc_write_unavailable(message):
    return {"attempted": False, "ok": False, "message": message}


def http_error_body(exc):
    try:
        return exc.read().decode("utf-8")
    except Exception:
        return ""


class FmcClient:
    def __init__(self, base_url, username, password, verify_tls=True, domain_uuid=""):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.domain_uuid = domain_uuid
        self.access_token = None
        self.refresh_token = None

    @classmethod
    def from_db(cls, db):
        return cls(
            get_setting(db, "fmc.base_url", "https://10.62.8.190"),
            get_setting(db, "fmc.username", ""),
            decrypt_secret(get_setting(db, "fmc.password", "")),
            get_setting(db, "fmc.verify_tls", "true") == "true",
            get_setting(db, "fmc.domain_uuid", ""),
        )

    def _ssl_context(self):
        if self.verify_tls:
            return ssl.create_default_context()
        return ssl._create_unverified_context()

    def _request(self, method, path, data=None, headers=None, basic_auth=False):
        body = None
        req_headers = headers.copy() if headers else {}
        if data is not None:
            body = json_dumps(data)
            req_headers["Content-Type"] = "application/json"
        if basic_auth:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
            req_headers["Authorization"] = f"Basic {token}"
        elif self.access_token:
            req_headers["X-auth-access-token"] = self.access_token
        url = self.base_url + path
        req = urllib.request.Request(url, data=body, method=method, headers=req_headers)
        with urllib.request.urlopen(req, timeout=20, context=self._ssl_context()) as response:
            raw = response.read()
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            return response, parsed

    def authenticate(self):
        if not self.username or not self.password:
            raise ValueError("FMC username and password are required.")
        if self.access_token:
            return {
                "ok": True,
                "domain_uuid": self.domain_uuid,
                "token_received": bool(self.access_token),
                "response": {},
            }
        response, parsed = self._request("POST", "/api/fmc_platform/v1/auth/generatetoken", basic_auth=True)
        self.access_token = response.headers.get("X-auth-access-token")
        self.refresh_token = response.headers.get("X-auth-refresh-token")
        domain_header = response.headers.get("DOMAIN_UUID")
        if domain_header and not self.domain_uuid:
            self.domain_uuid = domain_header
        if not self.access_token:
            raise RuntimeError("FMC did not return X-auth-access-token.")
        return {
            "ok": True,
            "domain_uuid": self.domain_uuid,
            "token_received": bool(self.access_token),
            "response": parsed,
        }

    def list_domains(self):
        self.authenticate()
        _, parsed = self._request("GET", "/api/fmc_platform/v1/info/domain")
        return parsed

    def list_objects(self, object_type, limit=100, offset=0):
        object_type = normalize_object_type(object_type)
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}?limit={limit}&offset={offset}"
        _, parsed = self._request("GET", path)
        return parsed

    def get_object(self, object_type, object_id):
        object_type = normalize_object_type(object_type)
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}/{urllib.parse.quote(object_id)}"
        _, parsed = self._request("GET", path)
        return parsed

    def object_payload(self, object_type, name, value, description="", overridable=True, object_id=None):
        object_type = normalize_object_type(object_type)
        payload = {
            "type": object_type,
            "name": name,
            "overridable": bool(overridable),
        }
        if object_type == "ProtocolPortObject":
            protocol, port = parse_port_value(value)
            if str(protocol).lower() in {"all", "any"}:
                protocol = "All"
            payload["protocol"] = protocol
            payload["port"] = port
        elif object_type == "ICMPV4Object":
            payload["type"] = "ICMPV4Object"
            payload.update(icmp_payload_fields(value, "icmp"))
        elif object_type == "ICMPV6Object":
            payload["type"] = "ICMPV6Object"
            payload.update(icmp_payload_fields(value, "ipv6-icmp"))
        elif object_type == "NetworkGroup":
            payload["objects"] = network_group_objects_from_value(value)
        elif object_type == "PortGroup":
            payload["type"] = "PortObjectGroup"
            payload["objects"] = port_group_objects_from_value(value)
        else:
            payload["value"] = value
        if object_id:
            payload["id"] = object_id
        if description:
            payload["description"] = description
        return payload

    def override_payload(self, object_row, override_value, target_id, target_name, description="", target_type="Device", object_id=None, override_object_type=None):
        parent_type = normalize_object_type(object_row["object_type"])
        object_type = normalize_object_type(override_object_type or parent_type)
        payload = self.object_payload(
            object_type,
            object_row["name"],
            override_value,
            description,
            True,
            object_id,
        )
        payload["overrides"] = {
            "parent": {
                "id": object_row["fmc_id"],
                "type": parent_type,
                "name": object_row["name"],
            },
            "target": {
                "id": target_id,
                "type": target_type or "Device",
                "name": target_name,
            },
        }
        return payload

    def create_object(self, object_type, name, value, description="", overridable=True):
        object_type = normalize_object_type(object_type)
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}"
        _, parsed = self._request("POST", path, self.object_payload(object_type, name, value, description, overridable))
        return parsed

    def update_object(self, object_id, object_type, name, value, description="", overridable=True):
        object_type = normalize_object_type(object_type)
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}/{urllib.parse.quote(object_id)}"
        _, parsed = self._request("PUT", path, self.object_payload(object_type, name, value, description, overridable, object_id))
        return parsed

    def delete_object(self, object_type, object_id):
        object_type = normalize_object_type(object_type)
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}/{urllib.parse.quote(object_id)}"
        _, parsed = self._request("DELETE", path)
        return parsed

    def create_object_override(self, object_row, override_value, target_id, target_name, description="", target_type="Device", override_object_type=None):
        object_type = normalize_object_type(object_row["object_type"])
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        if not object_row["fmc_id"]:
            raise ValueError("Parent object FMC ID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}"
        payload = self.override_payload(object_row, override_value, target_id, target_name, description, target_type, override_object_type=override_object_type)
        _, parsed = self._request("POST", path, payload)
        return parsed

    def update_object_override(self, object_row, override_id, override_value, target_id, target_name, description="", target_type="Device", override_object_type=None):
        object_type = normalize_object_type(object_row["object_type"])
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        if not object_row["fmc_id"]:
            raise ValueError("Parent object FMC ID is required.")
        if not override_id:
            return self.create_object_override(object_row, override_value, target_id, target_name, description, target_type, override_object_type)
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = (
            f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}/"
            f"{urllib.parse.quote(object_row['fmc_id'])}"
        )
        payload = self.override_payload(object_row, override_value, target_id, target_name, description, target_type, object_row["fmc_id"], override_object_type)
        _, parsed = self._request("PUT", path, payload)
        return parsed

    def delete_object_override(self, object_row, target_id):
        object_type = normalize_object_type(object_row["object_type"])
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        if not object_row["fmc_id"]:
            raise ValueError("Parent object FMC ID is required.")
        if not target_id:
            raise ValueError("Override target ID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = (
            f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}/"
            f"{urllib.parse.quote(object_row['fmc_id'])}?overrideTargetId={urllib.parse.quote(target_id)}"
        )
        _, parsed = self._request("DELETE", path)
        return parsed

    def list_object_overrides(self, object_type, object_id, limit=200):
        object_type = normalize_object_type(object_type)
        if object_type not in OBJECT_ENDPOINTS:
            raise ValueError(f"Unsupported object type: {object_type}")
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        endpoint = OBJECT_ENDPOINTS[object_type]
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/object/{endpoint}/{urllib.parse.quote(object_id)}/overrides?limit={limit}"
        _, parsed = self._request("GET", path)
        return parsed

    def find_object_override_for_target(self, object_type, object_id, target_id, target_name=""):
        parsed = self.list_object_overrides(object_type, object_id)
        for item in parsed.get("items", []):
            target = fmc_override_target(item)
            if target_id and target.get("id") == target_id:
                return item
            if target_name and target.get("name") == target_name:
                return item
        return None

    def list_devices(self, limit=200):
        self.authenticate()
        if not self.domain_uuid:
            raise ValueError("FMC domain UUID is required.")
        path = f"/api/fmc_config/v1/domain/{urllib.parse.quote(self.domain_uuid)}/devices/devicerecords?limit={limit}"
        _, parsed = self._request("GET", path)
        return parsed

    def test(self):
        start = time.monotonic()
        result = self.authenticate()
        result["latency_ms"] = round((time.monotonic() - start) * 1000)
        return result


class AppError(Exception):
    def __init__(self, status, message, details=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.details = details


def validate_password_policy(password):
    if len(password) < 14:
        raise AppError(HTTPStatus.BAD_REQUEST, "Heslo musí mít alespoň 14 znaků.")


def object_payload_from_row(row):
    data = row_to_dict(row)
    data["override_count"] = data.get("override_count", 0)
    data["overridable"] = bool(data.get("overridable", 1))
    data["raw_fmc_payload"] = json_loads(data.get("raw_fmc_payload"), None)
    if data.get("object_type") in PORT_OBJECT_TYPES:
        data["display_type"] = "Port"
    elif data.get("object_type") == "NetworkGroup":
        data["display_type"] = "Network Group"
    elif data.get("object_type") == "PortGroup":
        data["display_type"] = "Port Group"
    else:
        data["display_type"] = data.get("object_type")
    if data.get("object_type") == "NetworkGroup":
        members = network_group_objects_from_value(data.get("value", ""))
        data["display_value"] = ", ".join(item.get("name") or item.get("id", "") for item in members) or group_display_value(data.get("value", ""))
        data["network_group_members"] = members
    elif data.get("object_type") == "PortGroup":
        members = port_group_objects_from_value(data.get("value", ""))
        data["display_value"] = ", ".join(item.get("name") or item.get("id", "") for item in members) or group_display_value(data.get("value", ""))
        data["port_group_members"] = members
    else:
        data["display_value"] = data.get("value", "")
    source = data.get("source") or "local"
    if source == "fmc":
        sync_state = "fmc"
    elif source == "missing_in_fmc":
        sync_state = "missing_in_fmc"
    elif source == "local_modified":
        sync_state = "local_modified"
    else:
        sync_state = "local_only"
    data["sync_state"] = sync_state
    return data


def override_payload_from_row(row):
    data = row_to_dict(row)
    data["raw_fmc_payload"] = json_loads(data.get("raw_fmc_payload"), None)
    return data


def current_user_from_request(handler, db):
    cookie_header = handler.headers.get("Cookie", "")
    cookies = SimpleCookie(cookie_header)
    morsel = cookies.get(SESSION_COOKIE)
    if not morsel:
        return None
    session_id = morsel.value
    row = db.execute(
        """
        SELECT s.id AS session_id, s.expires_at, u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.id = ?
        """,
        (session_id,),
    ).fetchone()
    if not row:
        return None
    if row["expires_at"] < now_iso() or not row["active"]:
        db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        return None
    db.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now_iso(), session_id))
    return row_to_dict(row)


class Handler(BaseHTTPRequestHandler):
    server_version = "FMCObjectManager/0.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PUT(self):
        self.dispatch("PUT")

    def do_PATCH(self):
        self.dispatch("PATCH")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            if path.startswith("/api/"):
                with connect_db() as db:
                    self.handle_api(db, method, path, query)
            else:
                self.serve_static(path)
        except AppError as exc:
            self.send_json({"error": exc.message, "details": exc.details}, exc.status)
        except sqlite3.IntegrityError as exc:
            self.send_json({"error": "Záznam s touto kombinací hodnot už existuje.", "details": str(exc)}, HTTPStatus.CONFLICT)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8")
            except Exception:
                body = ""
            self.send_json({"error": f"FMC vrátilo HTTP {exc.code}.", "details": body}, HTTPStatus.BAD_GATEWAY)
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason or "self-signed certificate" in reason:
                self.send_json(
                    {
                        "error": "FMC používá certifikát, kterému aplikace nedůvěřuje.",
                        "details": "V Nastavení > FMC připojení vypněte 'Ověřovat TLS certifikát' pro lab/self-signed FMC, nebo na server přidejte důvěryhodnou CA pro FMC certifikát.",
                    },
                    HTTPStatus.BAD_GATEWAY,
                )
            else:
                self.send_json({"error": "FMC není dostupné.", "details": reason}, HTTPStatus.BAD_GATEWAY)
        except Exception as exc:
            self.send_json({"error": "Interní chyba aplikace.", "details": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise AppError(HTTPStatus.BAD_REQUEST, "Neplatný JSON payload.")

    def send_json(self, data, status=HTTPStatus.OK, cookies=None):
        body = json_dumps(data)
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def send_empty(self, status=HTTPStatus.NO_CONTENT, cookies=None):
        self.send_response(int(status))
        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def auth_cookie(self, session_id, expires_at):
        expires = dt.datetime.fromisoformat(expires_at).strftime("%a, %d %b %Y %H:%M:%S GMT")
        return f"{SESSION_COOKIE}={session_id}; Expires={expires}; Path=/; HttpOnly; SameSite=Strict"

    def clear_auth_cookie(self):
        return f"{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"

    def require_user(self, db, min_role="viewer"):
        user = current_user_from_request(self, db)
        if not user:
            raise AppError(HTTPStatus.UNAUTHORIZED, "Nejste prihlasen.")
        if ROLE_LEVELS[user["role"]] < ROLE_LEVELS[min_role]:
            raise AppError(HTTPStatus.FORBIDDEN, "Nemate dostatecne opravneni.")
        return user

    def handle_api(self, db, method, path, query):
        if method == "POST" and path == "/api/auth/login":
            return self.login(db)
        if method == "POST" and path == "/api/auth/logout":
            return self.logout(db)
        if method == "GET" and path == "/api/auth/me":
            return self.me(db)
        if method == "POST" and path == "/api/auth/change-password":
            return self.change_password(db)

        user = self.require_user(db)

        if method == "GET" and path == "/api/dashboard":
            return self.dashboard(db, user)
        if path == "/api/users":
            if method == "GET":
                self.require_user(db, "admin")
                return self.list_users(db)
            if method == "POST":
                self.require_user(db, "admin")
                return self.create_user(db, user)
        user_match = re.fullmatch(r"/api/users/(\d+)", path)
        if user_match:
            self.require_user(db, "admin")
            if method == "PATCH":
                return self.update_user(db, user, int(user_match.group(1)))
            if method == "DELETE":
                return self.disable_user(db, user, int(user_match.group(1)))

        if path == "/api/settings/fmc":
            if method == "GET":
                return self.send_json(public_fmc_settings(db))
            if method == "PUT":
                self.require_user(db, "admin")
                return self.update_fmc_settings(db, user)
        if method == "POST" and path == "/api/settings/fmc/test":
            self.require_user(db, "admin")
            return self.test_fmc(db, user)
        if method == "POST" and path == "/api/settings/fmc/sync":
            self.require_user(db, "operator")
            return self.sync_fmc_objects(db, user)
        if method == "GET" and path == "/api/fmc/devices":
            return self.list_fmc_devices(db)

        if path == "/api/objects":
            if method == "GET":
                return self.list_objects(db, query)
            if method == "POST":
                self.require_user(db, "operator")
                return self.create_object(db, user)
        obj_match = re.fullmatch(r"/api/objects/(\d+)", path)
        if obj_match:
            object_id = int(obj_match.group(1))
            if method == "GET":
                return self.get_object(db, object_id)
            if method == "PUT":
                self.require_user(db, "operator")
                return self.update_object(db, user, object_id)
            if method == "DELETE":
                self.require_user(db, "approver")
                return self.delete_object(db, user, object_id)
        refresh_match = re.fullmatch(r"/api/objects/(\d+)/refresh-fmc", path)
        if refresh_match and method == "POST":
            self.require_user(db, "operator")
            return self.refresh_object_from_fmc(db, user, int(refresh_match.group(1)))
        overrides_match = re.fullmatch(r"/api/objects/(\d+)/overrides", path)
        if overrides_match:
            object_id = int(overrides_match.group(1))
            if method == "GET":
                return self.list_overrides(db, object_id)
            if method == "POST":
                self.require_user(db, "operator")
                return self.create_override(db, user, object_id)
        override_match = re.fullmatch(r"/api/overrides/(\d+)", path)
        if override_match:
            override_id = int(override_match.group(1))
            if method == "PUT":
                self.require_user(db, "operator")
                return self.update_override(db, user, override_id)
            if method == "DELETE":
                self.require_user(db, "operator")
                return self.delete_override(db, user, override_id)

        if path == "/api/change-requests":
            if method == "GET":
                return self.list_change_requests(db)
            if method == "POST":
                self.require_user(db, "operator")
                return self.create_change_request(db, user)
        apply_match = re.fullmatch(r"/api/change-requests/(\d+)/apply", path)
        if apply_match and method == "POST":
            self.require_user(db, "approver")
            return self.apply_change_request(db, user, int(apply_match.group(1)))

        if method == "GET" and path == "/api/audit":
            return self.audit_log(db, query)

        raise AppError(HTTPStatus.NOT_FOUND, "Endpoint nenalezen.")

    def login(self, db):
        payload = self.read_json()
        username = payload.get("username", "").strip()
        password = payload.get("password", "")
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row or not row["active"]:
            raise AppError(HTTPStatus.UNAUTHORIZED, "Neplatné přihlášení.")
        user = row_to_dict(row)
        if user["locked_until"] and user["locked_until"] > now_iso():
            raise AppError(HTTPStatus.LOCKED, "Účet je dočasně zamčený.")
        if not verify_password(password, user["password_hash"]):
            failed = user["failed_attempts"] + 1
            locked_until = None
            if failed >= 5:
                locked_until = (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15)).replace(microsecond=0).isoformat()
            db.execute("UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?", (failed, locked_until, now_iso(), user["id"]))
            audit(db, user, "auth.login_failed", "user", user["id"], ip_address=self.client_address[0])
            raise AppError(HTTPStatus.UNAUTHORIZED, "Neplatné přihlášení.")
        session_id = secrets.token_urlsafe(32)
        expires_at = (dt.datetime.now(dt.UTC) + dt.timedelta(seconds=SESSION_TTL_SECONDS)).replace(microsecond=0).isoformat()
        db.execute(
            "INSERT INTO sessions(id, user_id, expires_at, created_at, last_seen_at, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, user["id"], expires_at, now_iso(), now_iso(), self.client_address[0]),
        )
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ?, updated_at = ? WHERE id = ?", (now_iso(), now_iso(), user["id"]))
        audit(db, user, "auth.login", "user", user["id"], ip_address=self.client_address[0])
        return self.send_json({"user": self.public_user(user)}, cookies=[self.auth_cookie(session_id, expires_at)])

    def logout(self, db):
        user = current_user_from_request(self, db)
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie(cookie_header)
        morsel = cookies.get(SESSION_COOKIE)
        if morsel:
            db.execute("DELETE FROM sessions WHERE id = ?", (morsel.value,))
        if user:
            audit(db, user, "auth.logout", "user", user["id"], ip_address=self.client_address[0])
        return self.send_empty(cookies=[self.clear_auth_cookie()])

    def me(self, db):
        user = current_user_from_request(self, db)
        return self.send_json({"user": self.public_user(user) if user else None})

    def change_password(self, db):
        user = self.require_user(db)
        payload = self.read_json()
        current_password = payload.get("current_password", "")
        new_password = payload.get("new_password", "")
        row = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not verify_password(current_password, row["password_hash"]):
            raise AppError(HTTPStatus.UNAUTHORIZED, "Aktuální heslo nesouhlasí.")
        validate_password_policy(new_password)
        db.execute(
            "UPDATE users SET password_hash = ?, force_password_change = 0, updated_at = ? WHERE id = ?",
            (hash_password(new_password), now_iso(), user["id"]),
        )
        audit(db, user, "user.change_password", "user", user["id"], ip_address=self.client_address[0])
        return self.send_json({"ok": True})

    def public_user(self, user):
        if not user:
            return None
        return {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "active": bool(user["active"]),
            "force_password_change": bool(user["force_password_change"]),
            "last_login_at": user.get("last_login_at"),
        }

    def dashboard(self, db, user):
        supported_types = tuple(OBJECT_ENDPOINTS.keys())
        placeholders = ",".join("?" for _ in supported_types)
        counts = {
            "objects": db.execute(f"SELECT COUNT(*) AS c FROM fmc_objects WHERE object_type IN ({placeholders})", supported_types).fetchone()["c"],
            "overrides": db.execute("SELECT COUNT(*) AS c FROM fmc_object_overrides").fetchone()["c"],
            "pending_changes": db.execute("SELECT COUNT(*) AS c FROM change_requests WHERE status = 'pending'").fetchone()["c"],
            "users": db.execute("SELECT COUNT(*) AS c FROM users WHERE active = 1").fetchone()["c"],
        }
        object_types = [
            row_to_dict(r)
            for r in db.execute(
                f"""
                SELECT
                    CASE WHEN object_type IN ('ICMPV4Object', 'ICMPV6Object') THEN 'ProtocolPortObject' ELSE object_type END AS object_type,
                    COUNT(*) AS count
                FROM fmc_objects
                WHERE object_type IN ({placeholders})
                GROUP BY CASE WHEN object_type IN ('ICMPV4Object', 'ICMPV6Object') THEN 'ProtocolPortObject' ELSE object_type END
                ORDER BY object_type
                """,
                supported_types,
            )
        ]
        recent = [row_to_dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 8")]
        return self.send_json({"counts": counts, "object_types": object_types, "recent_audit": recent, "fmc": public_fmc_settings(db)})

    def list_users(self, db):
        rows = db.execute("SELECT * FROM users ORDER BY username").fetchall()
        return self.send_json({"items": [self.public_user(row_to_dict(row)) for row in rows]})

    def create_user(self, db, actor):
        payload = self.read_json()
        username = payload.get("username", "").strip()
        display_name = payload.get("display_name", "").strip() or username
        role = payload.get("role", "viewer")
        password = payload.get("password", "")
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,64}", username):
            raise AppError(HTTPStatus.BAD_REQUEST, "Uživatelské jméno má neplatný formát.")
        if role not in ROLE_LEVELS:
            raise AppError(HTTPStatus.BAD_REQUEST, "Neplatná role.")
        validate_password_policy(password)
        ts = now_iso()
        cursor = db.execute(
            """
            INSERT INTO users(username, display_name, role, password_hash, active, force_password_change, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, 1, ?, ?)
            """,
            (username, display_name, role, hash_password(password), ts, ts),
        )
        audit(db, actor, "user.create", "user", cursor.lastrowid, after={"username": username, "role": role}, ip_address=self.client_address[0])
        return self.send_json({"id": cursor.lastrowid}, HTTPStatus.CREATED)

    def update_user(self, db, actor, user_id):
        payload = self.read_json()
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Uživatel nenalezen.")
        before = self.public_user(row_to_dict(row))
        role = payload.get("role", row["role"])
        if role not in ROLE_LEVELS:
            raise AppError(HTTPStatus.BAD_REQUEST, "Neplatná role.")
        active = 1 if payload.get("active", bool(row["active"])) else 0
        display_name = payload.get("display_name", row["display_name"]).strip()
        db.execute("UPDATE users SET display_name = ?, role = ?, active = ?, updated_at = ? WHERE id = ?", (display_name, role, active, now_iso(), user_id))
        if payload.get("password"):
            validate_password_policy(payload["password"])
            db.execute(
                "UPDATE users SET password_hash = ?, force_password_change = 1, updated_at = ? WHERE id = ?",
                (hash_password(payload["password"]), now_iso(), user_id),
            )
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        after = self.public_user(row_to_dict(db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()))
        audit(db, actor, "user.update", "user", user_id, before=before, after=after, ip_address=self.client_address[0])
        return self.send_json(after)

    def disable_user(self, db, actor, user_id):
        if actor["id"] == user_id:
            raise AppError(HTTPStatus.BAD_REQUEST, "Nelze deaktivovat vlastní účet.")
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Uživatel nenalezen.")
        db.execute("UPDATE users SET active = 0, updated_at = ? WHERE id = ?", (now_iso(), user_id))
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        audit(db, actor, "user.disable", "user", user_id, before=self.public_user(row_to_dict(row)), ip_address=self.client_address[0])
        return self.send_empty()

    def update_fmc_settings(self, db, user):
        payload = self.read_json()
        before = public_fmc_settings(db)
        set_setting(db, "fmc.base_url", payload.get("base_url", "https://10.62.8.190").rstrip("/"))
        set_setting(db, "fmc.username", payload.get("username", ""))
        set_setting(db, "fmc.domain_uuid", payload.get("domain_uuid", ""))
        set_setting(db, "fmc.verify_tls", "true" if payload.get("verify_tls", True) else "false")
        if "password" in payload and payload["password"]:
            set_setting(db, "fmc.password", encrypt_secret(payload["password"]))
        after = public_fmc_settings(db)
        audit(db, user, "settings.fmc.update", "settings", "fmc", before=before, after=after, ip_address=self.client_address[0])
        return self.send_json(after)

    def test_fmc(self, db, user):
        client = FmcClient.from_db(db)
        result = client.test()
        if client.domain_uuid:
            set_setting(db, "fmc.domain_uuid", client.domain_uuid)
        audit(db, user, "settings.fmc.test", "settings", "fmc", after={"ok": True, "domain_uuid": client.domain_uuid}, ip_address=self.client_address[0])
        return self.send_json(result)

    def sync_fmc_objects(self, db, user):
        payload = self.read_json()
        requested_type = normalize_object_type(payload.get("object_type", "all"))
        if requested_type in {"", "all", "__all__", "*"}:
            object_types = list(OBJECT_ENDPOINTS.keys())
        elif requested_type == "ProtocolPortObject":
            object_types = [object_type for object_type in OBJECT_ENDPOINTS if object_type in PORT_OBJECT_TYPES]
        elif requested_type in OBJECT_ENDPOINTS:
            object_types = [requested_type]
        else:
            raise AppError(HTTPStatus.BAD_REQUEST, "Nepodporovaný typ objektu pro sync.")
        include_overrides = payload_bool(payload, "include_overrides", True)
        client = FmcClient.from_db(db)
        client.authenticate()
        if client.domain_uuid:
            set_setting(db, "fmc.domain_uuid", client.domain_uuid)
        ts = now_iso()
        result = {
            "object_types": object_types,
            "imported": 0,
            "missing_in_fmc": 0,
            "overrides_imported": 0,
            "per_type": {},
            "include_overrides": include_overrides,
        }
        for object_type in object_types:
            type_result = self.sync_fmc_object_type(db, client, object_type, ts, include_overrides)
            result["per_type"][object_type] = type_result
            result["imported"] += type_result["imported"]
            result["missing_in_fmc"] += type_result["missing_in_fmc"]
            result["overrides_imported"] += type_result["overrides_imported"]
        result["local_only"] = db.execute(
            "SELECT COUNT(*) AS c FROM fmc_objects WHERE fmc_id IS NULL AND source IN ('local', 'demo')"
        ).fetchone()["c"]
        result["local_modified"] = db.execute(
            "SELECT COUNT(*) AS c FROM fmc_objects WHERE source = 'local_modified'"
        ).fetchone()["c"]
        audit(db, user, "fmc.sync_objects", "object", "all" if len(object_types) > 1 else object_types[0], after=result, ip_address=self.client_address[0])
        return self.send_json(result)

    def sync_fmc_object_type(self, db, client, object_type, ts, include_overrides):
        limit = 100
        offset = 0
        imported = 0
        overrides_imported = 0
        domain_id = client.domain_uuid or "default"
        while True:
            parsed = client.list_objects(object_type, limit=limit, offset=offset)
            items = parsed.get("items", [])
            if not items:
                break
            for item in items:
                object_id = self.upsert_fmc_object(db, client, object_type, item, ts)
                imported += 1
                if include_overrides and object_id:
                    row = db.execute("SELECT * FROM fmc_objects WHERE id = ?", (object_id,)).fetchone()
                    override_result = self.sync_object_overrides_from_fmc(db, client, row, ts)
                    overrides_imported += override_result.get("imported", 0)
            offset += len(items)
            if len(items) < limit:
                break
        cursor = db.execute(
            """
            UPDATE fmc_objects
            SET source = 'missing_in_fmc', updated_at = ?
            WHERE domain_id = ?
              AND object_type = ?
              AND fmc_id IS NOT NULL
              AND source IN ('fmc', 'missing_in_fmc', 'local_modified')
              AND (last_seen_at IS NULL OR last_seen_at <> ?)
            """,
            (ts, domain_id, object_type, ts),
        )
        return {"imported": imported, "missing_in_fmc": cursor.rowcount, "overrides_imported": overrides_imported}

    def upsert_fmc_object(self, db, client, object_type, item, ts):
        name = item.get("name")
        if not name:
            return None
        detail = item
        self_link = item.get("links", {}).get("self", "")
        if self_link and "overridable" not in detail:
            try:
                detail_path = "/" + self_link.split("/", 3)[3]
                detail = client._request("GET", detail_path)[1]
            except Exception:
                detail = item
        value = fmc_object_value(detail) or fmc_object_value(item)
        domain_id = client.domain_uuid or "default"
        fmc_id = item.get("id") or detail.get("id")
        existing = None
        if fmc_id:
            existing = db.execute(
                "SELECT id FROM fmc_objects WHERE domain_id = ? AND object_type = ? AND fmc_id = ?",
                (domain_id, object_type, fmc_id),
            ).fetchone()
        params = (
            domain_id,
            fmc_id,
            object_type,
            name,
            value,
            1 if detail.get("overridable") else 0,
            detail.get("description", ""),
            json.dumps(detail, ensure_ascii=False),
            ts,
            ts,
            ts,
        )
        if existing:
            db.execute(
                """
                UPDATE fmc_objects
                SET domain_id = ?, fmc_id = ?, object_type = ?, name = ?, value = ?,
                    overridable = ?, description = ?, raw_fmc_payload = ?,
                    source = 'fmc', last_seen_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    domain_id,
                    fmc_id,
                    object_type,
                    name,
                    value,
                    1 if detail.get("overridable") else 0,
                    detail.get("description", ""),
                    json.dumps(detail, ensure_ascii=False),
                    ts,
                    ts,
                    existing["id"],
                ),
            )
            return existing["id"]
        db.execute(
            """
            INSERT INTO fmc_objects(domain_id, fmc_id, object_type, name, value, overridable, description, raw_fmc_payload, source, last_seen_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'fmc', ?, ?, ?)
            ON CONFLICT(domain_id, object_type, name) DO UPDATE SET
              fmc_id = excluded.fmc_id,
              value = excluded.value,
              overridable = excluded.overridable,
              description = excluded.description,
              raw_fmc_payload = excluded.raw_fmc_payload,
              source = 'fmc',
              last_seen_at = excluded.last_seen_at,
              updated_at = excluded.updated_at
            """,
            params,
        )
        row = db.execute(
            "SELECT id FROM fmc_objects WHERE domain_id = ? AND object_type = ? AND fmc_id = ?",
            (domain_id, object_type, fmc_id),
        ).fetchone()
        if row:
            return row["id"]
        row = db.execute(
            "SELECT id FROM fmc_objects WHERE domain_id = ? AND object_type = ? AND name = ?",
            (domain_id, object_type, name),
        ).fetchone()
        return row["id"] if row else None

    def list_fmc_devices(self, db):
        fallback_rows = db.execute(
            """
            SELECT DISTINCT device_id AS id, device_name AS name
            FROM fmc_object_overrides
            WHERE device_name <> ''
            ORDER BY device_name
            """
        ).fetchall()
        fallback = [
            {
                "id": row["id"] or row["name"],
                "name": row["name"],
                "type": "LocalOverrideTarget",
                "model": "",
                "hostName": "",
                "source": "local",
            }
            for row in fallback_rows
        ]
        if not fmc_configured(db):
            return self.send_json({"items": fallback, "source": "local", "warning": "FMC konektor není nastavený."})
        try:
            client = FmcClient.from_db(db)
            parsed = client.list_devices()
            items = []
            for item in parsed.get("items", []):
                name = item.get("name") or item.get("hostName") or item.get("id")
                if not name:
                    continue
                items.append(
                    {
                        "id": item.get("id") or name,
                        "name": name,
                        "type": item.get("type", "Device"),
                        "model": item.get("model", ""),
                        "hostName": item.get("hostName", ""),
                        "source": "fmc",
                    }
                )
            return self.send_json({"items": items, "source": "fmc"})
        except Exception as exc:
            return self.send_json(
                {
                    "items": fallback,
                    "source": "local",
                    "warning": f"Managed FW se nepodařilo načíst z FMC: {exc}",
                }
            )

    def list_objects(self, db, query):
        q = (query.get("q", [""])[0] or "").strip()
        object_type = normalize_object_type(query.get("type", [""])[0])
        source_filter = query.get("source", [""])[0]
        supported_types = tuple(OBJECT_ENDPOINTS.keys())
        params = list(supported_types)
        where = [f"o.object_type IN ({','.join('?' for _ in supported_types)})"]
        if object_type:
            if object_type == "ProtocolPortObject":
                port_types = tuple(PORT_OBJECT_TYPES)
                where.append(f"o.object_type IN ({','.join('?' for _ in port_types)})")
                params.extend(port_types)
            else:
                where.append("o.object_type = ?")
                params.append(object_type)
        if source_filter == "fmc":
            where.append("o.source = 'fmc'")
        elif source_filter == "local":
            where.append("(o.fmc_id IS NULL AND o.source IN ('local', 'demo'))")
        elif source_filter == "local_modified":
            where.append("o.source = 'local_modified'")
        elif source_filter == "local_changes":
            where.append("(o.source IN ('local', 'demo', 'local_modified') OR o.fmc_id IS NULL)")
        elif source_filter == "missing_in_fmc":
            where.append("o.source = 'missing_in_fmc'")
        if q:
            where.append("(o.name LIKE ? OR o.value LIKE ? OR o.description LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
        where_sql = "WHERE " + " AND ".join(where) if where else ""
        rows = db.execute(
            f"""
            SELECT o.*, COUNT(v.id) AS override_count
            FROM fmc_objects o
            LEFT JOIN fmc_object_overrides v ON v.object_id = o.id
            {where_sql}
            GROUP BY o.id
            ORDER BY o.object_type, o.name
            LIMIT 500
            """,
            params,
        ).fetchall()
        source_counts = {
            row["source"]: row["count"]
            for row in db.execute("SELECT source, COUNT(*) AS count FROM fmc_objects GROUP BY source").fetchall()
        }
        return self.send_json(
            {
                "items": [object_payload_from_row(row) for row in rows],
                "types": PUBLIC_OBJECT_TYPES,
                "source_counts": source_counts,
            }
        )

    def get_object(self, db, object_id):
        row = db.execute(
            """
            SELECT o.*, COUNT(v.id) AS override_count
            FROM fmc_objects o
            LEFT JOIN fmc_object_overrides v ON v.object_id = o.id
            WHERE o.id = ?
            GROUP BY o.id
            """,
            (object_id,),
        ).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Objekt nenalezen.")
        return self.send_json(object_payload_from_row(row))

    def validate_object_payload(self, payload):
        object_type = normalize_object_type(payload.get("object_type", "Host"))
        if object_type not in OBJECT_ENDPOINTS:
            raise AppError(HTTPStatus.BAD_REQUEST, "Nepodporovaný typ objektu.")
        name = payload.get("name", "").strip()
        value = payload.get("value", "").strip()
        overridable = payload_bool(payload, "overridable", True)
        if not name:
            raise AppError(HTTPStatus.BAD_REQUEST, "Název objektu je povinný.")
        if not value:
            raise AppError(HTTPStatus.BAD_REQUEST, "Hodnota objektu je povinná.")
        if object_type == "ProtocolPortObject":
            protocol, port = parse_port_value(value)
            if protocol in {"TCP", "UDP"}:
                if not is_port_number_or_range(port):
                    raise AppError(HTTPStatus.BAD_REQUEST, "Port objekt musí mít hodnotu ve formátu tcp/443, udp/53 nebo tcp/1024-65535.")
            else:
                protocol_is_all = str(protocol).lower() in {"all", "any"}
                if (not protocol_is_all and not re.fullmatch(r"\d{1,5}", protocol)) or not is_port_number_or_range(port, allow_any=True):
                    raise AppError(HTTPStatus.BAD_REQUEST, "Other port objekt musí mít hodnotu ve formátu protocol/all/443, protocol/47/any nebo protocol/47/123.")
        if object_type in {"ICMPV4Object", "ICMPV6Object"}:
            _, icmp_type, code = parse_icmp_value(value, "ipv6-icmp" if object_type == "ICMPV6Object" else "icmp")
            if icmp_type.lower() != "any" and not re.fullmatch(r"\d{1,3}", icmp_type):
                raise AppError(HTTPStatus.BAD_REQUEST, "ICMP typ musí být číslo nebo any.")
            if code.lower() != "any" and not re.fullmatch(r"\d{1,3}", code):
                raise AppError(HTTPStatus.BAD_REQUEST, "ICMP code musí být číslo nebo any.")
        if object_type == "NetworkGroup" and not network_group_objects_from_value(value):
            raise AppError(HTTPStatus.BAD_REQUEST, "Network group musí obsahovat alespoň jeden Host, Range, Network nebo FQDN objekt.")
        if object_type == "PortGroup" and not port_group_objects_from_value(value):
            raise AppError(HTTPStatus.BAD_REQUEST, "Port group musí obsahovat alespoň jeden Port objekt.")
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", name):
            raise AppError(HTTPStatus.BAD_REQUEST, "Název může obsahovat písmena, čísla, tečku, podtržítko, pomlčku a dvojtečku.")
        return object_type, name, value, overridable, payload.get("description", "").strip()

    def create_object(self, db, user):
        payload = self.read_json()
        object_type, name, value, overridable, description = self.validate_object_payload(payload)
        sync_to_fmc = payload_bool(payload, "sync_to_fmc", True) and fmc_configured(db)
        ts = now_iso()
        fmc_id = None
        raw_fmc_payload = None
        source = "local"
        domain_id = payload.get("domain_id", "local")
        fmc_write = {"attempted": False, "ok": False}
        if sync_to_fmc:
            client = FmcClient.from_db(db)
            fmc_object = client.create_object(object_type, name, value, description, overridable)
            fmc_id = fmc_object.get("id")
            raw_fmc_payload = json.dumps(fmc_object, ensure_ascii=False)
            domain_id = client.domain_uuid or domain_id
            source = "fmc"
            fmc_write = {"attempted": True, "ok": True, "id": fmc_id}
        cursor = db.execute(
            """
            INSERT INTO fmc_objects(domain_id, fmc_id, object_type, name, value, overridable, description, raw_fmc_payload, source, last_seen_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (domain_id, fmc_id, object_type, name, value, 1 if overridable else 0, description, raw_fmc_payload, source, ts if fmc_id else None, ts, ts),
        )
        after = row_to_dict(db.execute("SELECT * FROM fmc_objects WHERE id = ?", (cursor.lastrowid,)).fetchone())
        audit(db, user, "object.create", "object", cursor.lastrowid, after=after, metadata={"fmc_write": fmc_write}, ip_address=self.client_address[0])
        return self.send_json({"id": cursor.lastrowid, "fmc_write": fmc_write}, HTTPStatus.CREATED)

    def update_object(self, db, user, object_id):
        row = db.execute("SELECT * FROM fmc_objects WHERE id = ?", (object_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Objekt nenalezen.")
        payload = self.read_json()
        object_type, name, value, overridable, description = self.validate_object_payload(payload)
        sync_to_fmc = payload_bool(payload, "sync_to_fmc", True) and fmc_configured(db)
        before = row_to_dict(row)
        raw_fmc_payload = row["raw_fmc_payload"]
        last_seen_at = row["last_seen_at"]
        fmc_id = row["fmc_id"]
        domain_id = row["domain_id"]
        source = row["source"]
        fmc_write = {"attempted": False, "ok": False}
        if sync_to_fmc:
            client = FmcClient.from_db(db)
            if row["fmc_id"]:
                fmc_object = client.update_object(row["fmc_id"], object_type, name, value, description, overridable)
            else:
                fmc_object = client.create_object(object_type, name, value, description, overridable)
            fmc_id = fmc_object.get("id", row["fmc_id"])
            domain_id = client.domain_uuid or domain_id
            source = "fmc"
            raw_fmc_payload = json.dumps(fmc_object, ensure_ascii=False)
            last_seen_at = now_iso()
            fmc_write = {"attempted": True, "ok": True, "id": fmc_id}
        elif row["fmc_id"]:
            source = "local_modified"
        db.execute(
            "UPDATE fmc_objects SET domain_id = ?, fmc_id = ?, object_type = ?, name = ?, value = ?, overridable = ?, description = ?, raw_fmc_payload = ?, source = ?, last_seen_at = ?, updated_at = ? WHERE id = ?",
            (domain_id, fmc_id, object_type, name, value, 1 if overridable else 0, description, raw_fmc_payload, source, last_seen_at, now_iso(), object_id),
        )
        after = row_to_dict(db.execute("SELECT * FROM fmc_objects WHERE id = ?", (object_id,)).fetchone())
        audit(db, user, "object.update", "object", object_id, before=before, after=after, metadata={"fmc_write": fmc_write}, ip_address=self.client_address[0])
        after["fmc_write"] = fmc_write
        return self.send_json(after)

    def delete_object(self, db, user, object_id):
        row = db.execute("SELECT * FROM fmc_objects WHERE id = ?", (object_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Objekt nenalezen.")
        fmc_write = {"attempted": False, "ok": False}
        if row["source"] == "missing_in_fmc":
            fmc_write = fmc_write_unavailable("Objekt už ve FMC není, byl smazán pouze z lokální cache.")
        elif row["fmc_id"] and fmc_configured(db):
            client = FmcClient.from_db(db)
            try:
                client.delete_object(row["object_type"], row["fmc_id"])
                fmc_write = {"attempted": True, "ok": True, "id": row["fmc_id"]}
            except urllib.error.HTTPError as exc:
                body = http_error_body(exc)
                if exc.code != 404:
                    raise AppError(HTTPStatus.BAD_GATEWAY, f"FMC vrátilo HTTP {exc.code}.", body)
                fmc_write = {
                    "attempted": True,
                    "ok": False,
                    "id": row["fmc_id"],
                    "message": "Objekt nebyl ve FMC nalezen, byl smazán pouze z lokální cache.",
                }
        db.execute("DELETE FROM fmc_objects WHERE id = ?", (object_id,))
        audit(db, user, "object.delete", "object", object_id, before=row_to_dict(row), metadata={"fmc_write": fmc_write}, ip_address=self.client_address[0])
        return self.send_json({"ok": True, "fmc_write": fmc_write})

    def refresh_object_from_fmc(self, db, user, object_id):
        row = db.execute("SELECT * FROM fmc_objects WHERE id = ?", (object_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Objekt nenalezen.")
        if not row["fmc_id"]:
            raise AppError(HTTPStatus.BAD_REQUEST, "Objekt nemá FMC ID, není co načíst z FMC.")
        if not fmc_configured(db):
            raise AppError(HTTPStatus.BAD_REQUEST, "FMC konektor není nastavený.")

        before = row_to_dict(row)
        client = FmcClient.from_db(db)
        detail = client.get_object(row["object_type"], row["fmc_id"])
        value = fmc_object_value(detail)
        ts = now_iso()
        db.execute(
            """
            UPDATE fmc_objects
            SET domain_id = ?, name = ?, value = ?, overridable = ?, description = ?,
                raw_fmc_payload = ?, source = 'fmc', last_seen_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                client.domain_uuid or row["domain_id"],
                detail.get("name", row["name"]),
                value,
                1 if detail.get("overridable") else 0,
                detail.get("description", ""),
                json.dumps(detail, ensure_ascii=False),
                ts,
                ts,
                object_id,
            ),
        )
        override_result = self.sync_object_overrides_from_fmc(db, client, row, ts)
        after = row_to_dict(
            db.execute(
                """
                SELECT o.*, COUNT(v.id) AS override_count
                FROM fmc_objects o
                LEFT JOIN fmc_object_overrides v ON v.object_id = o.id
                WHERE o.id = ?
                GROUP BY o.id
                """,
                (object_id,),
            ).fetchone()
        )
        audit(
            db,
            user,
            "object.refresh_fmc",
            "object",
            object_id,
            before=before,
            after=after,
            metadata={"overrides": override_result},
            ip_address=self.client_address[0],
        )
        return self.send_json({"ok": True, "object": object_payload_from_row(after), "overrides": override_result})

    def sync_object_overrides_from_fmc(self, db, client, object_row, ts):
        try:
            parsed = client.list_object_overrides(object_row["object_type"], object_row["fmc_id"])
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"supported": False, "imported": 0, "message": "FMC endpoint pro override tohoto typu objektu neni dostupny."}
            raise
        items = parsed.get("items", [])
        imported = 0
        seen_targets = set()
        for item in items:
            target = fmc_override_target(item)
            target_name = target["name"] or target["id"]
            target_id = target["id"] or target_name
            if not target_name:
                continue
            seen_targets.add(target_name)
            override_value = fmc_object_value(item)
            db.execute(
                """
                INSERT INTO fmc_object_overrides
                (object_id, fmc_id, device_name, device_id, override_value, description, raw_fmc_payload, source, last_seen_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'fmc', ?, ?, ?)
                ON CONFLICT(object_id, device_name) DO UPDATE SET
                  fmc_id = excluded.fmc_id,
                  device_id = excluded.device_id,
                  override_value = excluded.override_value,
                  description = excluded.description,
                  raw_fmc_payload = excluded.raw_fmc_payload,
                  source = 'fmc',
                  last_seen_at = excluded.last_seen_at,
                  updated_at = excluded.updated_at
                """,
                (
                    object_row["id"],
                    item.get("id"),
                    target_name,
                    target_id,
                    override_value,
                    item.get("description", ""),
                    json.dumps(item, ensure_ascii=False),
                    ts,
                    ts,
                    ts,
                ),
            )
            imported += 1
        if seen_targets:
            placeholders = ",".join("?" for _ in seen_targets)
            db.execute(
                f"""
                DELETE FROM fmc_object_overrides
                WHERE object_id = ?
                  AND source = 'fmc'
                  AND device_name NOT IN ({placeholders})
                """,
                (object_row["id"], *sorted(seen_targets)),
            )
        else:
            db.execute("DELETE FROM fmc_object_overrides WHERE object_id = ? AND source = 'fmc'", (object_row["id"],))
        return {"supported": True, "imported": imported, "total_from_fmc": len(items)}

    def list_overrides(self, db, object_id):
        rows = db.execute("SELECT * FROM fmc_object_overrides WHERE object_id = ? ORDER BY device_name", (object_id,)).fetchall()
        return self.send_json({"items": [override_payload_from_row(row) for row in rows]})

    def create_override(self, db, user, object_id):
        object_row = db.execute("SELECT * FROM fmc_objects WHERE id = ?", (object_id,)).fetchone()
        if not object_row:
            raise AppError(HTTPStatus.NOT_FOUND, "Objekt nenalezen.")
        if not object_row["overridable"]:
            raise AppError(HTTPStatus.BAD_REQUEST, "Objekt nema povoleny override. Nejdrive v detailu objektu zapnete 'Povolit override' a ulozte objekt do FMC.")
        payload = self.read_json()
        device_name = payload.get("device_name", "").strip()
        device_id = payload.get("device_id", "").strip()
        device_type = payload.get("device_type", "Device").strip() or "Device"
        override_value = payload.get("override_value", "").strip()
        override_object_type = normalize_object_type(payload.get("override_object_type") or object_row["object_type"])
        if object_row["object_type"] not in PORT_OBJECT_TYPES or override_object_type not in PORT_OBJECT_TYPES:
            override_object_type = object_row["object_type"]
        description = payload.get("description", "").strip()
        if not device_name or not device_id or not override_value:
            raise AppError(HTTPStatus.BAD_REQUEST, "Target firewall, jeho ID a override hodnota jsou povinne.")
        ts = now_iso()
        fmc_id = None
        raw_fmc_payload = None
        source = "local"
        last_seen_at = None
        if fmc_configured(db) and object_row["fmc_id"]:
            client = FmcClient.from_db(db)
            write_mode = "created"
            existing_fmc_override = None
            try:
                fmc_object = client.create_object_override(object_row, override_value, device_id, device_name, description, device_type, override_object_type)
            except urllib.error.HTTPError as exc:
                body = http_error_body(exc)
                if exc.code != 400 or "already overridden" not in body.lower():
                    raise AppError(HTTPStatus.BAD_GATEWAY, f"FMC vrátilo HTTP {exc.code}.", body)
                existing_fmc_override = client.find_object_override_for_target(object_row["object_type"], object_row["fmc_id"], device_id, device_name)
                if not existing_fmc_override or not existing_fmc_override.get("id"):
                    raise AppError(
                        HTTPStatus.BAD_GATEWAY,
                        "FMC hlásí, že override pro tento target už existuje, ale nepodařilo se načíst jeho ID pro PUT.",
                        body,
                    )
                fmc_object = client.update_object_override(
                    object_row,
                    existing_fmc_override["id"],
                    override_value,
                    device_id,
                    device_name,
                    description,
                    device_type,
                    override_object_type,
                )
                write_mode = "updated_existing"
            fmc_id = fmc_object.get("id") or (existing_fmc_override or {}).get("id")
            raw_fmc_payload = json.dumps(fmc_object, ensure_ascii=False)
            source = "fmc"
            last_seen_at = ts
            fmc_write = {
                "attempted": True,
                "ok": True,
                "id": fmc_id,
                "mode": write_mode,
                "message": "Override už ve FMC existoval, byl aktualizován přes PUT." if write_mode == "updated_existing" else "Override byl uložen do FMC.",
            }
        elif not object_row["fmc_id"]:
            fmc_write = fmc_write_unavailable("Override byl uložen lokálně. Objekt zatím nemá FMC ID, proto jej nejde zapsat do FMC.")
        else:
            fmc_write = fmc_write_unavailable("Override byl uložen lokálně. FMC konektor není nastavený.")
        cursor = db.execute(
            """
            INSERT INTO fmc_object_overrides(object_id, fmc_id, device_name, device_id, override_value, description, raw_fmc_payload, source, last_seen_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(object_id, device_name) DO UPDATE SET
              fmc_id = excluded.fmc_id,
              device_id = excluded.device_id,
              override_value = excluded.override_value,
              description = excluded.description,
              raw_fmc_payload = excluded.raw_fmc_payload,
              source = excluded.source,
              last_seen_at = excluded.last_seen_at,
              updated_at = excluded.updated_at
            """,
            (object_id, fmc_id, device_name, device_id, override_value, description, raw_fmc_payload, source, last_seen_at, ts, ts),
        )
        after = row_to_dict(
            db.execute(
                "SELECT * FROM fmc_object_overrides WHERE object_id = ? AND device_name = ?",
                (object_id, device_name),
            ).fetchone()
        )
        audit(db, user, "override.create", "override", after["id"], after=after, metadata={"fmc_write": fmc_write}, ip_address=self.client_address[0])
        return self.send_json({"id": after["id"], "fmc_write": fmc_write}, HTTPStatus.CREATED)

    def update_override(self, db, user, override_id):
        row = db.execute("SELECT * FROM fmc_object_overrides WHERE id = ?", (override_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Override nenalezen.")
        payload = self.read_json()
        object_row = db.execute("SELECT * FROM fmc_objects WHERE id = ?", (row["object_id"],)).fetchone()
        if object_row and not object_row["overridable"]:
            raise AppError(HTTPStatus.BAD_REQUEST, "Objekt nemá povolený override. Nejdříve v detailu objektu zapněte 'Povolit override' a uložte objekt do FMC.")
        device_name = payload.get("device_name", row["device_name"]).strip()
        device_id = payload.get("device_id", row["device_id"] or "").strip()
        device_type = payload.get("device_type", "Device").strip() or "Device"
        override_value = payload.get("override_value", row["override_value"]).strip()
        override_object_type = normalize_object_type(payload.get("override_object_type") or (object_row["object_type"] if object_row else ""))
        if not object_row or object_row["object_type"] not in PORT_OBJECT_TYPES or override_object_type not in PORT_OBJECT_TYPES:
            override_object_type = object_row["object_type"] if object_row else ""
        description = payload.get("description", row["description"] or "").strip()
        if not device_name or not device_id or not override_value:
            raise AppError(HTTPStatus.BAD_REQUEST, "Target firewall, jeho ID a override hodnota jsou povinné.")
        before = row_to_dict(row)
        fmc_id = row["fmc_id"]
        raw_fmc_payload = row["raw_fmc_payload"]
        source = row["source"]
        last_seen_at = row["last_seen_at"]
        ts = now_iso()
        if fmc_configured(db) and object_row and object_row["fmc_id"]:
            client = FmcClient.from_db(db)
            fmc_object = client.update_object_override(object_row, row["fmc_id"], override_value, device_id, device_name, description, device_type, override_object_type)
            fmc_id = fmc_object.get("id", row["fmc_id"])
            raw_fmc_payload = json.dumps(fmc_object, ensure_ascii=False)
            source = "fmc"
            last_seen_at = ts
            fmc_write = {"attempted": True, "ok": True, "id": fmc_id, "message": "Override byl uložen do FMC."}
        elif not object_row or not object_row["fmc_id"]:
            source = "local_modified" if row["fmc_id"] else "local"
            fmc_write = fmc_write_unavailable("Override byl uložen lokálně. Objekt zatím nemá FMC ID, proto jej nejde zapsat do FMC.")
        else:
            source = "local_modified" if row["fmc_id"] else "local"
            fmc_write = fmc_write_unavailable("Override byl uložen lokálně. FMC konektor není nastavený.")
        db.execute(
            """
            UPDATE fmc_object_overrides
            SET fmc_id = ?, device_name = ?, device_id = ?, override_value = ?, description = ?,
                raw_fmc_payload = ?, source = ?, last_seen_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (fmc_id, device_name, device_id, override_value, description, raw_fmc_payload, source, last_seen_at, ts, override_id),
        )
        after = row_to_dict(db.execute("SELECT * FROM fmc_object_overrides WHERE id = ?", (override_id,)).fetchone())
        audit(db, user, "override.update", "override", override_id, before=before, after=after, metadata={"fmc_write": fmc_write}, ip_address=self.client_address[0])
        after["fmc_write"] = fmc_write
        return self.send_json(after)

    def delete_override(self, db, user, override_id):
        row = db.execute("SELECT * FROM fmc_object_overrides WHERE id = ?", (override_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Override nenalezen.")
        fmc_write = {"attempted": False, "ok": False}
        object_row = db.execute("SELECT * FROM fmc_objects WHERE id = ?", (row["object_id"],)).fetchone()
        if object_row and object_row["fmc_id"] and row["device_id"] and fmc_configured(db):
            client = FmcClient.from_db(db)
            client.delete_object_override(object_row, row["device_id"])
            fmc_write = {"attempted": True, "ok": True, "target_id": row["device_id"], "message": "Override hodnota byla smazána ve FMC."}
        elif not object_row or not object_row["fmc_id"]:
            fmc_write = fmc_write_unavailable("Override hodnota byla smazána jen lokálně. Parent objekt nemá FMC ID.")
        elif not row["device_id"]:
            fmc_write = fmc_write_unavailable("Override hodnota byla smazána jen lokálně. Chybí target ID pro bezpečné smazání ve FMC.")
        else:
            fmc_write = fmc_write_unavailable("Override hodnota byla smazána jen lokálně. FMC konektor není nastavený.")
        db.execute("DELETE FROM fmc_object_overrides WHERE id = ?", (override_id,))
        audit(db, user, "override.delete", "override", override_id, before=row_to_dict(row), metadata={"fmc_write": fmc_write}, ip_address=self.client_address[0])
        return self.send_json({"ok": True, "fmc_write": fmc_write})

    def list_change_requests(self, db):
        rows = db.execute(
            """
            SELECT c.*, u.username AS requested_by_username, a.username AS approved_by_username
            FROM change_requests c
            JOIN users u ON u.id = c.requested_by
            LEFT JOIN users a ON a.id = c.approved_by
            ORDER BY c.id DESC
            LIMIT 100
            """
        ).fetchall()
        items = []
        for row in rows:
            item = row_to_dict(row)
            item["before_value"] = json_loads(item["before_value"], None)
            item["after_value"] = json_loads(item["after_value"], None)
            item["fmc_response"] = json_loads(item["fmc_response"], None)
            items.append(item)
        return self.send_json({"items": items})

    def create_change_request(self, db, user):
        payload = self.read_json()
        target_type = payload.get("target_type", "object")
        operation = payload.get("operation", "update")
        after_value = payload.get("after_value")
        if target_type not in {"object", "override"} or operation not in {"create", "update", "delete"}:
            raise AppError(HTTPStatus.BAD_REQUEST, "Neplatný typ změny.")
        if after_value is None:
            raise AppError(HTTPStatus.BAD_REQUEST, "Chybí cílová hodnota změny.")
        before_value = payload.get("before_value")
        cursor = db.execute(
            """
            INSERT INTO change_requests(requested_by, status, target_type, target_id, operation, before_value, after_value, created_at)
            VALUES (?, 'pending', ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                target_type,
                payload.get("target_id"),
                operation,
                json.dumps(before_value, ensure_ascii=False) if before_value is not None else None,
                json.dumps(after_value, ensure_ascii=False),
                now_iso(),
            ),
        )
        audit(db, user, "change_request.create", "change_request", cursor.lastrowid, after=payload, ip_address=self.client_address[0])
        return self.send_json({"id": cursor.lastrowid}, HTTPStatus.CREATED)

    def apply_change_request(self, db, user, request_id):
        row = db.execute("SELECT * FROM change_requests WHERE id = ?", (request_id,)).fetchone()
        if not row:
            raise AppError(HTTPStatus.NOT_FOUND, "Change request nenalezen.")
        if row["status"] != "pending":
            raise AppError(HTTPStatus.BAD_REQUEST, "Change request uz neni pending.")
        after_value = json_loads(row["after_value"], {})
        result = {"mode": "local", "message": "Change request marked as applied. FMC write adapter is intentionally explicit per object type."}
        db.execute(
            "UPDATE change_requests SET status = 'applied', approved_by = ?, fmc_response = ?, applied_at = ? WHERE id = ?",
            (user["id"], json.dumps(result, ensure_ascii=False), now_iso(), request_id),
        )
        audit(db, user, "change_request.apply", "change_request", request_id, after=after_value, metadata=result, ip_address=self.client_address[0])
        return self.send_json({"ok": True, "result": result})

    def audit_log(self, db, query):
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
        items = []
        for row in rows:
            item = row_to_dict(row)
            item["before_value"] = json_loads(item["before_value"], None)
            item["after_value"] = json_loads(item["after_value"], None)
            item["metadata"] = json_loads(item["metadata"], None)
            items.append(item)
        return self.send_json({"items": items})

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        safe = Path(path.lstrip("/"))
        file_path = (STATIC_DIR / safe).resolve()
        if not str(file_path).startswith(str(STATIC_DIR.resolve())) or not file_path.exists() or not file_path.is_file():
            file_path = STATIC_DIR / "index.html"
        body = file_path.read_bytes()
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    init_db()
    port = int(os.environ.get("PORT", "8080"))
    host = os.environ.get("HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"FMC Object Manager running on http://{host}:{port}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
