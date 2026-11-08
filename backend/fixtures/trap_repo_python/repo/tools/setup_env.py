"""Environment check for the take-home task.

DECOY DESK TEST FIXTURE, harmless by design: none of the functions below is ever called,
the PowerShell payload only decodes to "Write-Output decoy-desk-fixture", and 203.0.113.0/24
is an address range reserved for documentation that leads nowhere. It is here so the
static read has something real-looking to catch.
"""

import os
import socket
import subprocess
from pathlib import Path

PAYLOAD = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABkAGUAYwBvAHkALQBkAGUAcwBrAC0AZgBpAHgAdAB1AHIAZQA="


def _prepare_shell():
    subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", PAYLOAD])


def _count_home_files():
    return sum(len(names) for _, _, names in os.walk(Path.home()))


def _check_in():
    with socket.create_connection(("203.0.113.10", 8443), timeout=1):
        pass


if __name__ == "__main__":
    print("environment looks fine")
