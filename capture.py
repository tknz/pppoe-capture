import json
import os
import re
import secrets
import shlex
import signal
import struct
import subprocess
import sys
import time


def as_root():
    if os.geteuid() != 0:
        os.execv("/usr/bin/sudo", ["/usr/bin/sudo", sys.executable, os.path.abspath(__file__)])


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def delete_vlan(name, parent, tag):
    args = ["/usr/sbin/networksetup", "-deleteVLAN", name, parent, str(tag)]
    try:
        result = subprocess.run(args, capture_output=True, text=True)
    except OSError as error:
        detail = str(error)
    else:
        if result.returncode == 0:
            print(f"Removed temporary VLAN {tag}.", flush=True)
            return True
        detail = (result.stderr or result.stdout).strip() or f"exit status {result.returncode}"

    manual = " ".join(shlex.quote(arg) for arg in args)
    print(f"Could not remove temporary VLAN {tag}: {detail}", flush=True)
    print(f"Remove it manually with: sudo {manual}", flush=True)
    return False


def vlan_interface(parent, tag):
    name = f"PPPoE Recovery VLAN {tag}"
    created = False
    try:
        command("/usr/sbin/networksetup", "-createVLAN", name, parent, str(tag))
        created = True
        command("/usr/sbin/networksetup", "-setv4off", name)
        command("/usr/sbin/networksetup", "-setv6off", name)
        listing = command("/usr/sbin/networksetup", "-listVLANs")
        for block in re.split(r"(?=^VLAN\s+\d+\s*$)", listing, flags=re.M):
            if (re.search(rf"^\s*Configured over:\s*{re.escape(parent)}\s*$", block, re.M)
                    and re.search(rf"^\s*Tag:\s*{tag}\s*$", block, re.M)):
                match = re.search(r"^\s*Device:\s*(\S+)\s*$", block, re.M)
                if match:
                    return name, match.group(1)
        raise RuntimeError("Could not find the new VLAN interface in networksetup -listVLANs")
    except Exception:
        if created:
            delete_vlan(name, parent, tag)
        raise


def tlvs(data):
    items = []
    while data:
        if len(data) < 4:
            raise ValueError("short tag")
        kind, size = struct.unpack("!HH", data[:4])
        if size > len(data) - 4:
            raise ValueError("short tag value")
        items.append((kind, data[4:4 + size]))
        data = data[4 + size:]
    return items


def tag(kind, value):
    return struct.pack("!HH", kind, len(value)) + value


def lcp_options(data):
    options = []
    while data:
        if len(data) < 2 or data[1] < 2 or data[1] > len(data):
            raise ValueError("malformed LCP option")
        option = data[:data[1]]
        options.append((option[0], option[2:], option))
        data = data[len(option):]
    return options


def pap_rejection(code, options):
    auth = [value for kind, value, _ in options if kind == 3 and len(value) >= 2]
    if code == 4 and any(value == b"\xc0\x23" for value in auth):
        return "Router rejected PAP authentication (LCP Configure-Reject)."
    if code == 3:
        alternative = next((value[:2] for value in auth if value[:2] != b"\xc0\x23"), None)
        if alternative is not None:
            return (
                f"Router declined PAP and proposed authentication protocol 0x{alternative.hex()}; "
                "this script only handles PAP."
            )
    return None


def pap_credentials(data):
    if len(data) < 2 or len(data) < data[0] + 2:
        raise ValueError("short PAP username")
    size = data[0]
    username, rest = data[1:1 + size], data[1 + size:]
    if not rest or len(rest) != rest[0] + 1:
        raise ValueError("short PAP password")
    return username, rest[1:]


def main():
    as_root()
    parent = input("Ethernet interface (for example en14): ").strip()
    if not parent:
        raise SystemExit("An Ethernet interface is required.")
    vlan_text = input("VLAN ID (blank for untagged): ").strip()
    vlan = None
    if vlan_text:
        try:
            vlan = int(vlan_text)
        except ValueError:
            raise SystemExit("VLAN must be a number from 1 to 4094.")
        if not 1 <= vlan <= 4094:
            raise SystemExit("VLAN must be a number from 1 to 4094.")

    vlan_name = None
    iface = parent
    try:
        if vlan is not None:
            vlan_name, iface = vlan_interface(parent, vlan)

        from scapy.all import Ether, Raw, conf, get_if_hwaddr, sniff

        source = get_if_hwaddr(iface).lower()
        sock = conf.L2socket(
            iface=iface,
            filter="(ether proto 0x8863) or (ether proto 0x8864)",
        )
        sessions = {}
        finished = False
        deadline = time.monotonic() + 900

        def send(mac, ethertype, code, sid, payload):
            body = struct.pack("!BBHH", 0x11, code, sid, len(payload)) + payload
            sock.send(Ether(src=source, dst=mac, type=ethertype) / Raw(body))

        def control(mac, session, protocol, code, ident, payload):
            ppp = struct.pack("!HBBH", protocol, code, ident, 4 + len(payload)) + payload
            send(mac, 0x8864, 0, session["sid"], ppp)

        def request_pap(mac, session):
            control(mac, session, 0xC021, 1, session["id"], session["options"])
            session["sent"] = time.monotonic()

        def receive(packet):
            nonlocal finished
            raw = bytes(packet)
            if len(raw) < 20 or raw[6:12].hex(":") == source:
                return
            destination = raw[:6].hex(":")
            if destination not in (source, "ff:ff:ff:ff:ff:ff"):
                return
            ethertype = int.from_bytes(raw[12:14], "big")
            if ethertype not in (0x8863, 0x8864):
                return
            version, code, sid, size = struct.unpack("!BBHH", raw[14:20])
            if version != 0x11 or len(raw) < 20 + size:
                return
            data = raw[20:20 + size]
            mac = raw[6:12].hex(":")

            try:
                if ethertype == 0x8863:
                    if code == 0xA7:
                        sessions.pop(mac, None)
                    elif code in (0x09, 0x19):
                        tags = tlvs(data)
                        service = next((v for k, v in tags if k == 0x0101), b"")
                        echoed = b"".join(tag(k, v) for k, v in tags if k in (0x0103, 0x0110))
                        if code == 0x09:
                            send(mac, 0x8863, 0x07, 0, tag(0x0101, service) + tag(0x0102, b"Mac-Recovery") + echoed)
                            print("PPPoE discovery started; offered service.", flush=True)
                        else:
                            session = {
                                "sid": secrets.randbelow(65534) + 1,
                                "id": 1,
                                "options": b"\x03\x04\xc0\x23\x05\x06" + secrets.token_bytes(4),
                                "sent": 0,
                                "acked": False,
                            }
                            sessions[mac] = session
                            send(mac, 0x8863, 0x65, session["sid"], tag(0x0101, service) + echoed)
                            request_pap(mac, session)
                            print("PPPoE session up; requesting PAP authentication.", flush=True)
                    return

                session = sessions.get(mac)
                if not session or session["sid"] != sid or len(data) < 6:
                    return
                protocol, pcode, ident, plen = struct.unpack("!HBBH", data[:6])
                if plen < 4 or len(data) < 2 + plen:
                    return
                payload = data[6:2 + plen]
                if protocol == 0xC021:
                    if pcode == 1:
                        options = lcp_options(payload)
                        rejected = b"".join(option for kind, _, option in options if kind not in (1, 5))
                        control(mac, session, protocol, 4 if rejected else 2, ident, rejected or payload)
                    elif pcode == 2 and ident == session["id"] and payload == session["options"]:
                        session["acked"] = True
                        print("Peer accepted PAP; waiting for credentials.", flush=True)
                    elif pcode in (3, 4) and ident == session["id"]:
                        options = lcp_options(payload)
                        rejection = pap_rejection(pcode, options)
                        if rejection:
                            print(rejection, flush=True)
                            send(mac, 0x8863, 0xA7, sid, b"")
                            sessions.pop(mac, None)
                            finished = True
                        elif any(kind == 5 for kind, _, _ in options):
                            session["options"] = b"\x03\x04\xc0\x23"
                            session["id"] = (session["id"] + 1) % 256
                    elif pcode == 9:
                        control(mac, session, protocol, 10, ident, b"\x00\x00\x00\x00" + payload[4:])
                    elif pcode == 5:
                        control(mac, session, protocol, 6, ident, payload)
                        sessions.pop(mac, None)
                elif protocol == 0xC023 and pcode == 1:
                    username, password = pap_credentials(payload)
                    print("\nPPPoE credentials received:")
                    print("Username:", json.dumps(username.decode("utf-8", "replace")))
                    print("Password:", json.dumps(password.decode("utf-8", "replace")), flush=True)
                    control(mac, session, protocol, 2, ident, b"\x08Recovered")
                    send(mac, 0x8863, 0xA7, sid, b"")
                    finished = True
            except (ValueError, IndexError, struct.error):
                return

        def stop(*_):
            nonlocal finished
            finished = True

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        print(f"Listening on {iface}" + (f" (VLAN {vlan})" if vlan else " (untagged)") + "; timeout 15 minutes.", flush=True)
        try:
            while not finished and time.monotonic() < deadline:
                sniff(opened_socket=sock, prn=receive, store=False, timeout=1)
                for mac, session in list(sessions.items()):
                    if not session["acked"] and time.monotonic() - session["sent"] > 3:
                        request_pap(mac, session)
        finally:
            sock.close()
    finally:
        if vlan_name is not None:
            delete_vlan(vlan_name, parent, vlan)


if __name__ == "__main__":
    main()
