# PPPoE capture

## What it does

A small Python script to capture PPPoE credentials from the WAN side of a directly connected router. It starts a temporary PPPoE access concentrator, requests PAP authentication, prints the username and password in Terminal, then closes the session. An optional VLAN is created with macOS `networksetup`, with IP networking disabled; the temporary VLAN is removed when the script exits. The capture stops after 15 minutes.

## How to use it

On the Mac, connect the Ethernet adapter directly to the router's WAN port, then run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python capture.py
```

Enter the Ethernet interface name (such as `en14`) and, if needed, a VLAN ID. The program asks for the Mac administrator password once when it relaunches itself as root.
