"""Make license keys locally (or against DATABASE_URL if set).
Usage:  python genkey.py        (1 key)
        python genkey.py 5       (5 keys)
Tip: once deployed, the easiest way is the /admin web page."""
import sys, server
server.init_db()
n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
for _ in range(n):
    print(server.create_key("pro", "manual"))
