"""
LiveLink Server  -  secure license + auction hub.
Made by Isoki (@isoki_tt)

Security model:
  - License validation is server-side (a cracked client is useless without it).
  - Persistent HWID lock: a key binds to the first machine that activates it;
    other machines are rejected. The write path (push / auction control) also
    requires the matching HWID, so a shared key can't drive a second machine.
  - Admin panel (Basic Auth) to generate / revoke / reset keys.
  - Works on SQLite locally; set DATABASE_URL (Supabase Postgres) for 24/7
    persistence in the cloud.

Env vars:
  ADMIN_USER       (default "admin")
  ADMIN_PASSWORD   (REQUIRED to enable the admin panel)
  ADMIN_TOKEN      (optional; for future SellAuth/Stripe auto-key API)
  DATABASE_URL     (optional Postgres URL; omit to use local SQLite)
  LATEST_VERSION   (e.g. "3.0"  -> what the app's updater reports)
  DOWNLOAD_URL     (link to the latest installer)
"""

import datetime
import functools
import hmac
import os
import secrets
import threading
import time
from collections import deque

from flask import Flask, request, jsonify, Response

HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.join(HERE, "overlay.html")
PORT = int(os.getenv("PORT", "8080"))

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
LATEST_VERSION = os.getenv("LATEST_VERSION", "")
DOWNLOAD_URL = os.getenv("DOWNLOAD_URL", "")

# ----------------------- database (SQLite or Postgres) -----------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_PG = DATABASE_URL.startswith("postgres")
if USE_PG:
    import psycopg2
    def _conn():
        return psycopg2.connect(DATABASE_URL, sslmode="require")
    PH = "%s"
else:
    import sqlite3
    DB_FILE = os.path.join(HERE, "licenses.db")
    def _conn():
        return sqlite3.connect(DB_FILE)
    PH = "?"

_dlock = threading.Lock()


def _q(sql):
    return sql if PH == "?" else sql.replace("?", "%s")


def db_exec(sql, args=(), fetch=None):
    with _dlock:
        con = _conn()
        try:
            cur = con.cursor()
            cur.execute(_q(sql), args)
            out = None
            if fetch == "one":
                out = cur.fetchone()
            elif fetch == "all":
                out = cur.fetchall()
            con.commit()
            return out
        finally:
            con.close()


def init_db():
    db_exec("""CREATE TABLE IF NOT EXISTS licenses(
        key TEXT PRIMARY KEY, plan TEXT, hwid TEXT, active INTEGER DEFAULT 1,
        created TEXT, note TEXT)""")


def make_key():
    block = lambda: "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4))
    return "LL-" + "-".join(block() for _ in range(3))


def create_key(plan="pro", note=""):
    k = make_key()
    db_exec("INSERT INTO licenses(key,plan,hwid,active,created,note) VALUES(?,?,?,?,?,?)",
            (k, plan, "", 1, datetime.datetime.utcnow().isoformat(timespec="seconds"), note))
    return k


def get_key(key):
    return db_exec("SELECT key,plan,hwid,active,created,note FROM licenses WHERE key=?", (key,), "one")


def list_keys():
    return db_exec("SELECT key,plan,hwid,active,created,note FROM licenses ORDER BY created DESC", (), "all") or []


def set_active(key, val):
    db_exec("UPDATE licenses SET active=? WHERE key=?", (1 if val else 0, key))


def set_hwid(key, hwid):
    db_exec("UPDATE licenses SET hwid=? WHERE key=?", (hwid, key))


# ----------------------- license checks -----------------------
def key_active(key):
    row = get_key(key)
    return bool(row and row[3])


def license_status(key, hwid):
    """Full check used at activation and on the write path (binds/enforces HWID)."""
    row = get_key(key)
    if not row:
        return (False, "invalid key")
    _, plan, stored, active, _, _ = row
    if not active:
        return (False, "key disabled")
    if hwid:
        if not stored:
            set_hwid(key, hwid)            # bind on first activation
        elif stored != hwid:
            return (False, "key is locked to another device")
    return (True, "ok")


# ----------------------- per-license rooms (auctions/relay) -----------------------
rooms = {}
rooms_lock = threading.Lock()


def new_auction():
    return {"active": False, "paused": False, "prize": "", "duration": 0,
            "snipe_delay": 10, "ends_at": 0.0, "remaining": 0.0,
            "leader": "", "leader_amount": 0, "contributions": {}, "winner": ""}


def get_room(key):
    with rooms_lock:
        r = rooms.get(key)
        if not r:
            r = {"events": deque(maxlen=300), "auction": new_auction(), "vouch": {}, "can_vouch": set()}
            rooms[key] = r
        return r


def remaining(a):
    if not a["active"]:
        return 0.0
    return a["remaining"] if a["paused"] else max(0.0, a["ends_at"] - time.monotonic())


def finalize_if_due(r):
    a = r["auction"]
    if a["active"] and not a["paused"] and remaining(a) <= 0:
        a["active"] = False
        a["winner"] = a["leader"]
        if a["leader"]:
            r["can_vouch"].add(a["leader"])


def process_event(r, evt):
    a = r["auction"]; t = evt.get("type")
    if t == "gift":
        value = (evt.get("value") or 0) * (evt.get("count") or 1)
        user = evt.get("user", "")
        with rooms_lock:
            finalize_if_due(r)
            if a["active"] and not a["paused"] and user:
                a["contributions"][user] = a["contributions"].get(user, 0) + value
                if a["contributions"][user] > a["leader_amount"]:
                    a["leader"], a["leader_amount"] = user, a["contributions"][user]
                if remaining(a) < a["snipe_delay"]:
                    a["ends_at"] = time.monotonic() + a["snipe_delay"]
    elif t == "chat":
        if (evt.get("message") or "").strip().lower() == "vouch":
            user = evt.get("user", "")
            with rooms_lock:
                if user in r["can_vouch"]:
                    r["vouch"][user] = r["vouch"].get(user, 0) + 1
                    r["can_vouch"].discard(user)
    r["events"].append(evt)


def ticker():
    while True:
        with rooms_lock:
            for r in rooms.values():
                finalize_if_due(r)
        time.sleep(0.5)


# ----------------------- admin auth -----------------------
def _is_admin(auth):
    if not ADMIN_PASSWORD or not auth:
        return False
    return (hmac.compare_digest(auth.username or "", ADMIN_USER)
            and hmac.compare_digest(auth.password or "", ADMIN_PASSWORD))


def admin_required(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not _is_admin(request.authorization):
            return Response("Admin login required.", 401,
                            {"WWW-Authenticate": 'Basic realm="LiveLink Admin"'})
        return f(*a, **k)
    return w


# ----------------------- Flask -----------------------
app = Flask(__name__)
init_db()


@app.route("/")
def root():
    return "LiveLink server is running."


@app.route("/version")
def version():
    return jsonify({"version": LATEST_VERSION, "url": DOWNLOAD_URL})


@app.route("/api/validate", methods=["POST"])
def api_validate():
    d = request.get_json(silent=True) or {}
    ok, msg = license_status(d.get("key", ""), d.get("hwid", ""))
    return jsonify({"valid": ok, "message": msg})


@app.route("/api/push", methods=["POST"])
def api_push():
    key = request.args.get("key", ""); hwid = request.args.get("hwid", "")
    ok, _ = license_status(key, hwid)          # write path enforces HWID
    if not ok:
        return jsonify({"error": "invalid license"}), 403
    r = get_room(key)
    for evt in (request.get_json(silent=True) or []):
        if isinstance(evt, dict):
            process_event(r, evt)
    return jsonify({"ok": True})


@app.route("/api/auction/control", methods=["POST"])
def api_auction_control():
    key = request.args.get("key", ""); hwid = request.args.get("hwid", "")
    ok, _ = license_status(key, hwid)
    if not ok:
        return jsonify({"error": "invalid license"}), 403
    d = request.get_json(silent=True) or {}; action = d.get("action")
    r = get_room(key); a = r["auction"]
    with rooms_lock:
        if action == "start":
            dur = int(d.get("duration", 120))
            a.update(active=True, paused=False, prize=d.get("prize", "Prize") or "Prize",
                     duration=dur, snipe_delay=int(d.get("snipe", 10)),
                     ends_at=time.monotonic() + dur, remaining=dur,
                     leader="", leader_amount=0, contributions={}, winner="")
        elif action == "pause":
            if a["active"] and not a["paused"]:
                a["remaining"] = remaining(a); a["paused"] = True
            elif a["active"] and a["paused"]:
                a["ends_at"] = time.monotonic() + a["remaining"]; a["paused"] = False
        elif action == "addtime":
            sec = int(d.get("seconds", 0))
            if a["active"]:
                if a["paused"]:
                    a["remaining"] = max(0.0, a["remaining"] + sec)
                else:
                    a["ends_at"] += sec
        elif action == "restart":
            if a["prize"]:
                dur = a["duration"]
                a.update(active=True, paused=False, ends_at=time.monotonic() + dur,
                         remaining=dur, leader="", leader_amount=0, contributions={}, winner="")
        elif action == "stop":
            a["active"] = False; a["winner"] = ""
    return jsonify({"ok": True})


@app.route("/events")
def get_events():
    key = request.args.get("key", "")
    if not key_active(key):
        return jsonify({"error": "invalid license"}), 403
    r = get_room(key)
    with rooms_lock:
        batch = list(r["events"]); r["events"].clear()
    return jsonify(batch)


@app.route("/auction")
def get_auction():
    key = request.args.get("key", "")
    if not key_active(key):
        return jsonify({"error": "invalid license"}), 403
    r = get_room(key); a = r["auction"]
    with rooms_lock:
        finalize_if_due(r)
        data = {"active": a["active"], "paused": a["paused"], "prize": a["prize"],
                "remaining": round(remaining(a), 1), "leader": a["leader"],
                "leader_amount": a["leader_amount"], "winner": a["winner"],
                "vouches_for_winner": r["vouch"].get(a["winner"], 0) if a["winner"] else 0}
    return jsonify(data)


@app.route("/overlay")
def overlay():
    try:
        with open(OVERLAY, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h1>overlay.html missing on server</h1>", 500


# ----------------------- automation API (for SellAuth/Stripe later) -----------------------
@app.route("/api/keys", methods=["POST"])
def api_create_key():
    if not ADMIN_TOKEN or request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    d = request.get_json(silent=True) or {}
    k = create_key(d.get("plan", "pro"), d.get("note", "auto"))
    return jsonify({"key": k})


# ----------------------- admin panel -----------------------
ADMIN_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>LiveLink Admin</title>
<style>
 body{background:#0e0f1a;color:#eaeaf0;font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:30px;}
 h1{margin:0 0 4px;} .sub{color:#8a8a98;margin-bottom:22px;}
 .bar{background:#191a23;border:1px solid #2a2b3a;border-radius:12px;padding:16px;margin-bottom:20px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
 input,select{background:#0e0f1a;color:#eaeaf0;border:1px solid #2a2b3a;border-radius:8px;padding:9px 11px;font-size:14px;}
 button{background:#FF3C8C;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:700;cursor:pointer;font-size:14px;}
 button.alt{background:#2a2b3a;} button.warn{background:#b3402f;}
 table{width:100%;border-collapse:collapse;background:#191a23;border-radius:12px;overflow:hidden;}
 th,td{padding:11px 12px;text-align:left;border-bottom:1px solid #2a2b3a;font-size:13px;}
 th{color:#8a8a98;text-transform:uppercase;font-size:11px;letter-spacing:1px;}
 .key{font-family:Consolas,monospace;font-weight:700;color:#25F4EE;}
 .on{color:#3BD16F;font-weight:700;} .off{color:#ff5252;font-weight:700;}
 .hwid{font-family:Consolas,monospace;color:#8a8a98;font-size:12px;}
 form.inline{display:inline;}
</style></head><body>
 <h1>LiveLink Admin</h1><div class="sub">Generate and manage license keys.</div>
 <form class="bar" method="post" action="/admin/create">
   <span>Generate</span>
   <input name="count" type="number" value="1" min="1" max="50" style="width:70px">
   <span>keys, plan</span>
   <input name="plan" value="pro" style="width:90px">
   <input name="note" placeholder="note (buyer name / order id)" style="flex:1;min-width:180px">
   <button type="submit">Generate keys</button>
 </form>
 %%NEW%%
 <table><tr><th>Key</th><th>Plan</th><th>Status</th><th>Device (HWID)</th><th>Created</th><th>Note</th><th>Actions</th></tr>
 %%ROWS%%
 </table>
</body></html>"""


@app.route("/admin")
@admin_required
def admin():
    rows = ""
    for key, plan, hwid, active, created, note in list_keys():
        status = '<span class="on">active</span>' if active else '<span class="off">disabled</span>'
        toggle = ("activate", "Enable", "alt") if not active else ("revoke", "Disable", "warn")
        rows += (
            "<tr><td class='key'>" + key + "</td><td>" + (plan or "") + "</td><td>" + status + "</td>"
            "<td class='hwid'>" + (hwid or "<i>not bound</i>") + "</td><td>" + (created or "") + "</td>"
            "<td>" + (note or "") + "</td><td>"
            "<form class='inline' method='post' action='/admin/" + toggle[0] + "'><input type='hidden' name='key' value='" + key + "'><button class='" + toggle[2] + "' type='submit'>" + toggle[1] + "</button></form> "
            "<form class='inline' method='post' action='/admin/resethwid'><input type='hidden' name='key' value='" + key + "'><button class='alt' type='submit'>Reset device</button></form>"
            "</td></tr>"
        )
    return ADMIN_PAGE.replace("%%ROWS%%", rows).replace("%%NEW%%", "")


@app.route("/admin/create", methods=["POST"])
@admin_required
def admin_create():
    count = max(1, min(50, int(request.form.get("count", 1))))
    plan = request.form.get("plan", "pro"); note = request.form.get("note", "")
    created = [create_key(plan, note) for _ in range(count)]
    box = ("<div class='bar'><b>New keys (copy now):</b>&nbsp;<span class='key'>"
           + ", ".join(created) + "</span></div>")
    rows = ""
    for key, plan, hwid, active, cr, nt in list_keys():
        status = '<span class="on">active</span>' if active else '<span class="off">disabled</span>'
        toggle = ("activate", "Enable", "alt") if not active else ("revoke", "Disable", "warn")
        rows += ("<tr><td class='key'>" + key + "</td><td>" + (plan or "") + "</td><td>" + status + "</td>"
                 "<td class='hwid'>" + (hwid or "<i>not bound</i>") + "</td><td>" + (cr or "") + "</td><td>" + (nt or "") + "</td><td>"
                 "<form class='inline' method='post' action='/admin/" + toggle[0] + "'><input type='hidden' name='key' value='" + key + "'><button class='" + toggle[2] + "' type='submit'>" + toggle[1] + "</button></form> "
                 "<form class='inline' method='post' action='/admin/resethwid'><input type='hidden' name='key' value='" + key + "'><button class='alt' type='submit'>Reset device</button></form></td></tr>")
    return ADMIN_PAGE.replace("%%ROWS%%", rows).replace("%%NEW%%", box)


@app.route("/admin/revoke", methods=["POST"])
@admin_required
def admin_revoke():
    set_active(request.form.get("key", ""), False)
    return Response("", 302, {"Location": "/admin"})


@app.route("/admin/activate", methods=["POST"])
@admin_required
def admin_activate():
    set_active(request.form.get("key", ""), True)
    return Response("", 302, {"Location": "/admin"})


@app.route("/admin/resethwid", methods=["POST"])
@admin_required
def admin_resethwid():
    set_hwid(request.form.get("key", ""), "")
    return Response("", 302, {"Location": "/admin"})


if __name__ == "__main__":
    threading.Thread(target=ticker, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
