"""Print LiveLink license keys to paste into the LICENSE_KEYS env var.
Usage:  python genkey.py            (1 key)
        python genkey.py 5          (5 keys)"""
import secrets, sys

def make():
    block = lambda: "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4))
    return "LL-" + "-".join(block() for _ in range(3))

n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
keys = [make() for _ in range(n)]
print("\n".join(keys))
print("\nPaste into Render's LICENSE_KEYS (comma-separated):")
print(",".join(keys))
