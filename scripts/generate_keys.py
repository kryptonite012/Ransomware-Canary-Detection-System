#!/usr/bin/env python3
"""Generate the control-plane Ed25519 keypair (wrapper around backend init-keys)."""
import sys

from backend.__main__ import main

if __name__ == "__main__":
    sys.exit(main(["init-keys"] + sys.argv[1:]))
