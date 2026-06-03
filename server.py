"""
LiveLink Server  -  the hub you host on Render (free).
Made by Isoki (@isoki_tt)

License keys are read from the LICENSE_KEYS environment variable
(comma-separated) so they persist for free with no database.
Example:  LICENSE_KEYS=LL-AAAA-BBBB-CCCC,LL-DDDD-EEEE-FFFF

Run locally:   pip install flask
               LICENSE_KEYS=LL-TEST-TEST-TEST python server.py
Deploy free:   see DEPLOY.txt
"""

import json
import os
import threading
import time
from collections import deque

from flask import Flask, request, jsonify

HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.join(HERE, "overlay.html")
PORT = int(os.getenv("PORT", "8080"))

# Valid license keys come from the env var (persists across restarts on Render).
ENV_KEYS = {k.strip() for k in os.getenv("LICENSE_KEYS", "").split(",") if k.strip()}
# Optional anti-sharing: bind a key to one machine (in memory; resets on restart).
HWID_LOCK = os.getenv("HWID_LOCK", "0") == "1"
_hwid = {}
_hwid_lock = threading.Lock()


def key_known(key):
    return bool(key) and key in ENV_KEYS


def license_status(key, hwid):
    if not key_known(key):
        return (False, "invalid key")
    if HWID_LOCK and hwid:
        with _hwid_lock:
            bound = _hwid.get(key)
            if bound is None:
                _hwid[key] = hwid
            elif bound != hwid:
                return (False, "key already used on another device")
    return (True, "ok")


# ----------------------- per-license rooms -----------------------
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
            r = {"events": deque(maxlen=300), "auction": new_auction(),
                 "vouch": {}, "can_vouch": set()}
            rooms[key] = r
        return r


def remaining(a):
    if not a["active"]:
        return 0.0
    if a["paused"]:
        return a["remaining"]
    return max(0.0, a["ends_at"] - time.monotonic())


def finalize_if_due(r):
    a = r["auction"]
    if a["active"] and not a["paused"] and remaining(a) <= 0:
        a["active"] = False
        a["winner"] = a["leader"]
        if a["leader"]:
            r["can_vouch"].add(a["leader"])


# ----------------------- auction + vouch logic -----------------------
def process_event(r, evt):
    a = r["auction"]
    t = evt.get("type")
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


# ----------------------- Flask app -----------------------
app = Flask(__name__)


@app.route("/")
def root():
    return "LiveLink server is running."


@app.route("/api/validate", methods=["POST"])
def api_validate():
    d = request.get_json(silent=True) or {}
    ok, msg = license_status(d.get("key", ""), d.get("hwid", ""))
    return jsonify({"valid": ok, "message": msg})


@app.route("/api/push", methods=["POST"])
def api_push():
    key = request.args.get("key", "")
    if not key_known(key):
        return jsonify({"error": "invalid license"}), 403
    r = get_room(key)
    for evt in (request.get_json(silent=True) or []):
        if isinstance(evt, dict):
            process_event(r, evt)
    return jsonify({"ok": True})


@app.route("/events")
def get_events():
    key = request.args.get("key", "")
    if not key_known(key):
        return jsonify({"error": "invalid license"}), 403
    r = get_room(key)
    with rooms_lock:
        batch = list(r["events"]); r["events"].clear()
    return jsonify(batch)


@app.route("/auction")
def get_auction():
    key = request.args.get("key", "")
    if not key_known(key):
        return jsonify({"error": "invalid license"}), 403
    r = get_room(key); a = r["auction"]
    with rooms_lock:
        finalize_if_due(r)
        data = {"active": a["active"], "paused": a["paused"], "prize": a["prize"],
                "remaining": round(remaining(a), 1), "leader": a["leader"],
                "leader_amount": a["leader_amount"], "winner": a["winner"],
                "vouches_for_winner": r["vouch"].get(a["winner"], 0) if a["winner"] else 0}
    return jsonify(data)


@app.route("/api/auction/control", methods=["POST"])
def api_auction_control():
    key = request.args.get("key", "")
    if not key_known(key):
        return jsonify({"error": "invalid license"}), 403
    d = request.get_json(silent=True) or {}
    action = d.get("action"); r = get_room(key); a = r["auction"]
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


@app.route("/overlay")
def overlay():
    try:
        with open(OVERLAY, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h1>overlay.html missing on server</h1>", 500


if __name__ == "__main__":
    threading.Thread(target=ticker, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
