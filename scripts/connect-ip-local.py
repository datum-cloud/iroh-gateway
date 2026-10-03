#!/usr/bin/env python3
"""Isolated Linux CONNECT-IP lab: real CLI, daemon, gateway, TUN, and IP traffic.

Only the Cloud API is simulated. No host routes, installed services, or deployed
resources are changed. Docker resources carry a unique run label and cleanup
targets only resources created by this invocation. --keep retains the live lab.
"""
import argparse
import http.server
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

HERE = Path(__file__).resolve()
GATEWAY = HERE.parents[1]
WORKSPACE = GATEWAY.parent
BODY = b"real-connect-ip-tun-http\n"


def fixture():
    source = Path("/workspace/connect/scripts/daemon-e2e.py")
    spec = importlib.util.spec_from_file_location("cloud_fixture", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    http.server.ThreadingHTTPServer(("127.0.0.1", 18080), module.Platform).serve_forever()


def origin(ipv6=False):
    class HTTP(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            packet, sock = self.request
            with open("/lab/origin-received.log", "a") as log:
                log.write(json.dumps({"source": self.client_address[0], "length": len(packet)}) + "\n")
            sock.sendto(packet, self.client_address)

    class UDPServer(socketserver.ThreadingUDPServer):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET

        def server_bind(self):
            if ipv6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    class HTTPServer(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET

        def server_bind(self):
            if ipv6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    host = "::" if ipv6 else "0.0.0.0"
    udp = UDPServer((host, 5353), UDP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    HTTPServer((host, 8080), HTTP).serve_forever()


def udp_probe(address):
    ipv6 = ipaddress.ip_address(address).version == 6
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        maximum = 1232 if ipv6 else 1252
        for payload in (b"connect-ip-udp", b"", bytes(range(256)) * 4, (bytes(range(256)) * 5)[:maximum]):
            sock.sendto(payload, (address, 5353))
            actual, _ = sock.recvfrom(65535)
            assert actual == payload, "UDP payload differs"
    print("UDP roundtrip passed")


def spoof(source, destination, extension=None):
    udp = struct.pack("!HHHH", 43001, 5353, 13, 0) + b"probe"
    if ipaddress.ip_address(source).version == 6:
        src, dst = socket.inet_pton(socket.AF_INET6, source), socket.inet_pton(socket.AF_INET6, destination)
        pseudo = src + dst + struct.pack("!I3xB", len(udp), 17)
        data = pseudo + udp + b"\0"
        total = sum(struct.unpack(f"!{len(data)//2}H", data))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        udp = udp[:6] + struct.pack("!H", ((~total) & 65535) or 65535) + udp[8:]
        # Even an atomic fragment or empty options header is unsupported by the
        # bounded prototype parser. Construct valid headers to test fail-closed
        # behavior, not merely checksum rejection by the destination kernel.
        next_header = 17
        if extension is not None:
            next_header = extension
            extra = struct.pack("!BBHI", 17, 0, 0, 123) if extension == 44 else bytes([17, 0]) + bytes(6)
            udp = extra + udp
        header = struct.pack("!IHBB16s16s", 6 << 28, len(udp), next_header, 64, src, dst)
        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
            sock.sendto(header + udp, (destination, 0))
        return
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    header = header[:10] + struct.pack("!H", (~total) & 65535) + header[12:]
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        sock.sendto(header + udp, (destination, 0))


def run_lab(args):
    ipv6 = args.ipv6
    family = "-6" if ipv6 else "-4"
    host_prefix = 128 if ipv6 else 32
    ping_payload = 1232 if ipv6 else 1252
    docker = ["docker", "--context", args.docker_context]
    subprocess.run([*docker, "info", "--format", "{{.OSType}}"], check=True, capture_output=True)
    tag = "connect-ip-" + uuid.uuid4().hex[:10]
    target = GATEWAY / "target"
    target.mkdir(exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=tag + "-", dir=target))
    print(f"Artifacts: {artifacts}", flush=True)
    binaries = args.binaries.resolve()
    for name in ("datum-connect-daemon", "iroh-gateway", "datumctl-connect", "datumctl"):
        if not (binaries / name).is_file():
            raise RuntimeError(f"Missing Linux binary: {binaries / name}; build the lab first")
    containers, networks = [], []

    def cmd(*words, check=True, stdin=None, timeout=60):
        result = subprocess.run([*docker, *map(str, words)], input=stdin, text=True,
                                capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"Docker command failed ({words[:3]}): {result.stderr[-3000:]}")
        return result

    def execute(name, *words, **kwargs):
        return cmd("exec", "-i", name, *words, **kwargs)

    def write_json(name, path, value):
        execute(name, "python3", "-c",
                "import os,sys; p=sys.argv[1]; fd=os.open(p,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600); "
                "os.write(fd,sys.stdin.buffer.read()); os.close(fd)", path, stdin=json.dumps(value))

    def launch(name, label, command):
        # Child PID and private logs live inside this disposable container only.
        execute(name, "python3", "-c",
                "import subprocess,sys,json,os; label=sys.argv[1]; "
                "log=open('/lab/'+label+'.log','ab'); "
                "p=subprocess.Popen(json.loads(sys.stdin.read()),stdout=log,stderr=log,"
                "env={**os.environ,'RUST_LOG':'info,connect_transport=debug,iroh_gateway=debug,datum_connect_daemon=debug'}); "
                "open('/lab/'+label+'.pid','w').write(str(p.pid))", label, stdin=json.dumps(command))

    def stop_process(name, label):
        execute(name, "python3", "-c",
                "import os,signal,sys,time; p=int(open('/lab/'+sys.argv[1]+'.pid').read()); "
                "os.kill(p,signal.SIGTERM); time.sleep(1)", label)

    def wait_health(name, port, host="127.0.0.1"):
        for _ in range(100):
            result = execute(name, "python3", "-c",
                             "import socket,sys; socket.create_connection((sys.argv[2],int(sys.argv[1])),.3).close()",
                             port, host, check=False)
            if not result.returncode:
                return
            time.sleep(.1)
        raise RuntimeError(f"{name}:{port} did not start")

    def cli(*words, expect=0):
        # Read the setup token inside the container, never emit or put it in argv.
        result = execute(client, "python3", "-c",
                         "import os,subprocess,sys; "
                         "token=open('/lab/repo/daemon_auth/setup.token').read().strip(); "
                         "r=subprocess.run(['/binaries/datumctl','connect',*sys.argv[1:]],cwd='/lab',"
                         "env={**os.environ,'PATH':'/binaries:'+os.environ['PATH'],"
                         "'DATUM_PROJECT':'demo','DATUMCTL_TRUSTED_PLUGINS':'connect','DATUM_CONNECT_TOKEN':token}); sys.exit(r.returncode)",
                         *words, "--daemon-url", "http://127.0.0.1:47780", "--output", "json",
                         check=False)
        with (artifacts / "cli.log").open("a") as log:
            log.write(f"{' '.join(words)}\n{result.stdout}{result.stderr}\n")
        if (result.returncode == 0) != (expect == 0):
            raise AssertionError(f"CLI {words}: {result.stdout}{result.stderr}")
        return json.loads(result.stdout) if expect == 0 else result.stderr

    def probe():
        execute(client, "ping", "-n", "-c", "2", "-W", "2", origin_ip)
        # Full 1280-byte IP packet, including the appropriate IP+ICMP headers.
        execute(client, "ping", "-n", "-c", "1", "-W", "2", "-M", "do", "-s", ping_payload, origin_ip)
        assert execute(client, "ping", "-n", "-c", "1", "-W", "1", "-M", "do", "-s", ping_payload + 1, origin_ip, check=False).returncode
        http = execute(client, "curl", "--noproxy", "*", "--fail", "--max-time", "5", origin_url)
        assert http.stdout.encode() == BODY
        execute(client, "python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--udp-probe", origin_ip)

    def interface_absent(name, interface):
        for _ in range(50):
            result = execute(name, "ip", "link", "show", "dev", interface, check=False)
            if result.returncode:
                return
            time.sleep(.1)
        raise AssertionError(f"stale interface {interface} in {name}")

    def container(role, network, address=None, tun=False):
        name = tag + "-" + role
        options = ["run", "-d", "--name", name, "--label", f"datum.connect.ip-lab={tag}",
                   "--network", network, "--cap-drop", "ALL", "--cap-add", "NET_RAW",
                   "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges", "--tmpfs", "/lab:mode=700",
                   "--mount", f"type=bind,src={WORKSPACE},dst=/workspace,readonly",
                   "--mount", f"type=bind,src={binaries},dst=/binaries,readonly"]
        if address:
            options += ["--ip6" if ipv6 else "--ip", address]
        if tun:
            options += ["--device", "/dev/net/tun"]
        if role == "gateway":
            options += ["--sysctl", "net.ipv6.conf.all.forwarding=1" if ipv6 else "net.ipv4.ip_forward=1"]
        cmd(*options, args.image, "sleep", "infinity")
        containers.append(name)
        return name

    try:
        # Docker chooses the underlay; choose a disjoint unused lab-only VPC.
        existing = json.loads(cmd("network", "inspect", *cmd("network", "ls", "-q").stdout.split()).stdout)
        occupied = [ipaddress.ip_network(item["Subnet"]) for net in existing
                    for item in (net.get("IPAM", {}).get("Config") or []) if item.get("Subnet")]
        if ipv6:
            prefix = f"fd{tag[-10:-8]}:{tag[-8:-4]}:{tag[-4:]}"
            underlay_subnet = ipaddress.ip_network(f"{prefix}:1::/64")
            vpc_subnet = ipaddress.ip_network(f"{prefix}:2::/64")
            assert not any(candidate.overlaps(net) for candidate in (underlay_subnet, vpc_subnet)
                           for net in occupied if net.version == 6), "random IPv6 lab subnet conflicts"
            assigned_ip, gateway_tun = f"{prefix}:3::2", f"{prefix}:3::1"
            spoof_ip, denied_ip = f"{prefix}:3::99", f"{prefix}:4::3"
        else:
            vpc_subnet = next(ipaddress.ip_network(f"10.{second}.78.0/24") for second in range(201, 250)
                              if not any(ipaddress.ip_network(f"10.{second}.78.0/24").overlaps(net)
                                         for net in occupied if net.version == 4))
            assigned_ip, gateway_tun = "192.0.2.2", "192.0.2.1"
            spoof_ip, denied_ip = "192.0.2.99", "198.51.100.3"
        gateway_vpc = str(vpc_subnet.network_address + 2)
        origin_ip = str(vpc_subnet.network_address + 3)
        origin_url = f"http://[{origin_ip}]:8080/" if ipv6 else f"http://{origin_ip}:8080/"
        underlay, vpc = tag + "-underlay", tag + "-vpc"
        network_options = ["--ipv6", "--ipv4=false"] if ipv6 else []
        cmd("network", "create", "--internal", "--label", f"datum.connect.ip-lab={tag}",
            *network_options, *(["--subnet", underlay_subnet] if ipv6 else []), underlay)
        networks.append(underlay)
        cmd("network", "create", "--internal", "--label", f"datum.connect.ip-lab={tag}",
            *network_options, "--subnet", vpc_subnet, vpc)
        networks.append(vpc)
        client = container("client", underlay, tun=True)
        gateway = container("gateway", underlay, tun=True)
        backend = container("origin", vpc, origin_ip)
        cmd("network", "connect", "--ip6" if ipv6 else "--ip", gateway_vpc, vpc, gateway)
        address_field = "GlobalIPv6Address" if ipv6 else "IPAddress"
        gateway_ip = json.loads(cmd("inspect", gateway).stdout)[0]["NetworkSettings"]["Networks"][underlay][address_field]
        client_ip = json.loads(cmd("inspect", client).stdout)[0]["NetworkSettings"]["Networks"][underlay][address_field]
        if ipv6:
            for name in containers:
                interfaces = json.loads(execute(name, "ip", "-j", "-4", "address", "show").stdout)
                assert all(not i.get("addr_info") for i in interfaces if i["ifname"] != "lo"), "IPv4 fallback interface present"
            execute(client, "ping", "-6", "-n", "-c", "1", "-W", "3", gateway_ip)
            print("PASS IPv6-only underlay: no non-loopback IPv4 addresses on any container", flush=True)
        (artifacts / "network-topology.json").write_text(cmd("network", "inspect", underlay, vpc).stdout)
        gateway_socket = f"[{gateway_ip}]:7777" if ipv6 else f"{gateway_ip}:7777"
        gateway_key = execute(gateway, "/binaries/iroh-gateway", "--key-file", "/lab/gateway.key", "--print-endpoint-id").stdout.strip()
        assert len(gateway_key) == 64
        binding = {"project": "demo", "network": "local-vpc", "gateway": gateway_key,
                   "addresses": [gateway_socket], "assigned_address": f"{assigned_ip}/{host_prefix}",
                   "routes": [str(vpc_subnet)], "interface_name": "dcip0", "mtu": 1280}
        write_json(client, "/lab/ip.json", {"underlay_address": client_ip, "bindings": [binding]})
        write_json(client, "/lab/credentials.json", {"type": "connector", "project_id": "demo",
                   "api_endpoint": "http://127.0.0.1:18080", "token_uri": "http://127.0.0.1:18080/token",
                   "client_id": "local-ip-lab", "refresh_token": "test-refresh-secret"})
        launch(client, "platform", ["python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--fixture"])
        wait_health(client, 18080)
        daemon_command = ["/binaries/datum-connect-daemon", "--repo", "/lab/repo", "--local-ip-config", "/lab/ip.json"]
        launch(client, "daemon", daemon_command)
        wait_health(client, 47780)
        enrolled = cli("up", "--credentials-file", "/lab/credentials.json")
        connector_key = enrolled["connector"]["public_key"]
        grant = {"network": "local-vpc", "peer": connector_key, "client_address": f"{assigned_ip}/{host_prefix}",
                 "gateway_address": f"{gateway_tun}/{host_prefix}", "routes": [str(vpc_subnet)], "interface_name": "gip0", "mtu": 1280}
        write_json(gateway, "/lab/ip.json", {"grants": [grant]})
        write_json(gateway, "/lab/gateway.json", {"ipv6_addr" if ipv6 else "ipv4_addr": gateway_socket,
                   "discovery_mode": "static", "transport": "masque"})
        gateway_command = ["/binaries/iroh-gateway", "--key-file", "/lab/gateway.key", "--config-file", "/lab/gateway.json",
                           "--ip-config", "/lab/ip.json", "--metrics-addr", "127.0.0.1", "--metrics-port", "9090"]
        launch(gateway, "gateway", gateway_command)
        wait_health(gateway, 8080)
        execute(backend, "ip", family, "route", "add", f"{assigned_ip}/{host_prefix}", "via", gateway_vpc)
        launch(backend, "origin", ["python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--origin", *(["--ipv6"] if ipv6 else [])])
        wait_health(backend, 8080, "::1" if ipv6 else "127.0.0.1")
        cli("join", "not-approved", expect=1)
        interface_absent(client, "dcip0")
        print("PASS unknown network fails closed without a TUN", flush=True)
        execute(gateway, "ip", "link", "add", "gip0", "type", "dummy")
        cli("join", "local-vpc", expect=1)
        interface_absent(client, "dcip0")
        assert "dummy" in execute(gateway, "ip", "-details", "link", "show", "dev", "gip0").stdout
        execute(gateway, "ip", "link", "delete", "gip0")
        print("PASS gateway TUN conflict rejects join and preserves the existing interface", flush=True)
        # Outer UDP payload is at most 1252 (1232 for IPv6) with this MTU, so
        # a 1280-byte inner packet cannot fit even before HTTP/QUIC framing.
        for name in (client, gateway):
            execute(name, "ip", "link", "set", "dev", "eth0", "mtu", "1280")
        try:
            error = cli("join", "local-vpc", expect=1)
            assert "mtu" in error.lower(), error
            interface_absent(client, "dcip0")
            interface_absent(gateway, "gip0")
        finally:
            for name in (client, gateway):
                execute(name, "ip", "link", "set", "dev", "eth0", "mtu", "1500")
        print("PASS insufficient underlay MTU rejects join without TUNs or capsule fallback", flush=True)
        joined = cli("join", "local-vpc")
        cli("join", "local-vpc")  # Idempotent while running.
        probe()
        print("PASS real CLI join -> iroh CONNECT-IP -> Linux TUN -> routed ping, TCP, and UDP", flush=True)
        status = cli("status")
        assert status.get("networks"), "status lacks joined network"
        before = execute(backend, "wc", "-l", "/lab/origin-received.log").stdout.split()[0]
        execute(client, "python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--spoof", spoof_ip, origin_ip)
        time.sleep(.3)
        after = execute(backend, "wc", "-l", "/lab/origin-received.log").stdout.split()[0]
        assert before == after, "spoofed source reached origin"
        # Force an out-of-grant destination into the client TUN. Kernel routing
        # alone must not grant access to an otherwise reachable backend alias.
        execute(backend, "ip", family, "address", "add", f"{denied_ip}/{host_prefix}", "dev", "lo")
        execute(gateway, "ip", family, "route", "add", f"{denied_ip}/{host_prefix}", "via", origin_ip)
        execute(client, "ip", family, "route", "add", f"{denied_ip}/{host_prefix}", "dev", "dcip0")
        execute(client, "python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--spoof", assigned_ip, denied_ip)
        time.sleep(.3)
        assert before == execute(backend, "wc", "-l", "/lab/origin-received.log").stdout.split()[0], "unapproved destination reached origin"
        execute(client, "ip", family, "route", "delete", f"{denied_ip}/{host_prefix}", "dev", "dcip0")
        assert cli("status")["networks"][0]["packets_dropped"] >= 2
        if ipv6:
            dropped = cli("status")["networks"][0]["packets_dropped"]
            execute(client, "python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py",
                    "--ipv6-extensions", assigned_ip, origin_ip)
            time.sleep(.3)
            assert before == execute(backend, "wc", "-l", "/lab/origin-received.log").stdout.split()[0], "unsupported IPv6 extension reached origin"
            assert cli("status")["networks"][0]["packets_dropped"] >= dropped + 2
            print("PASS IPv6 options and atomic fragments fail closed without delivery", flush=True)
        probe()
        print("PASS source spoofing and out-of-grant destinations drop without breaking the session", flush=True)
        # One actual outer-network loss window. Datagrams accepted by the
        # sender during the window must not be retransmitted after recovery.
        time.sleep(.2)
        before_loss = execute(backend, "wc", "-l", "/lab/origin-received.log").stdout.split()[0]
        execute(client, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%")
        try:
            execute(client, "python3", "-c",
                    "import socket,sys,time; s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM); "
                    "s.sendto(b'not-retransmitted',(sys.argv[1],5353)); time.sleep(.5)", origin_ip)
            qdisc = execute(client, "tc", "-s", "-j", "qdisc", "show", "dev", "eth0").stdout
            (artifacts / "packet-loss-qdisc.json").write_text(qdisc)
            assert sum(q.get("drops", 0) for q in json.loads(qdisc)) > 0, "netem did not drop an outer packet"
        finally:
            execute(client, "tc", "qdisc", "delete", "dev", "eth0", "root")
        time.sleep(1)
        assert before_loss == execute(backend, "wc", "-l", "/lab/origin-received.log").stdout.split()[0], "lost IP datagram was retransmitted"
        probe()
        print("PASS outer packet loss does not retransmit IP datagrams; session recovers", flush=True)
        # PMTUD must notice a path that can no longer carry the approved MTU,
        # then fail closed and remove interfaces instead of leaving a black hole.
        execute(client, "ip", "link", "set", "dev", "eth0", "mtu", "1280")
        try:
            for _ in range(20):
                execute(client, "ping", "-n", "-c", "1", "-W", "1", "-M", "do", "-s", ping_payload, origin_ip, check=False)
                failed = cli("status")["networks"][0]
                if not failed["running"]:
                    break
            assert not failed["running"], "MTU shrink left the attachment running"
            assert "mtu" in (failed.get("last_error") or "").lower(), failed
            (artifacts / "mtu-shrink-status.json").write_text(json.dumps(failed, indent=2))
            interface_absent(client, "dcip0")
            interface_absent(gateway, "gip0")
        finally:
            execute(client, "ip", "link", "set", "dev", "eth0", "mtu", "1500")
        cli("join", "local-vpc")
        probe()
        print("PASS runtime MTU shrink closes the attachment with diagnostics; rejoin recovers", flush=True)
        cli("leave", "local-vpc")
        interface_absent(client, "dcip0")
        interface_absent(gateway, "gip0")
        assert execute(client, "ping", "-n", "-c", "1", "-W", "1", origin_ip, check=False).returncode
        print("PASS leave removes both TUNs and network access", flush=True)
        cli("join", "local-vpc")
        probe()
        stop_process(gateway, "gateway")
        interface_absent(gateway, "gip0")
        interface_absent(client, "dcip0")
        print("PASS gateway shutdown revokes an active IP session and cleans client routes", flush=True)
        # Removing the static grant models local operator revocation.
        write_json(gateway, "/lab/ip.json", {"grants": []})
        launch(gateway, "gateway", gateway_command)
        wait_health(gateway, 8080)
        cli("join", "local-vpc", expect=1)
        interface_absent(client, "dcip0")
        print("PASS unapproved Connector cannot rejoin", flush=True)
        stop_process(gateway, "gateway")
        write_json(gateway, "/lab/ip.json", {"grants": [grant]})
        launch(gateway, "gateway", gateway_command)
        wait_health(gateway, 8080)
        cli("join", "local-vpc")
        stop_process(client, "daemon")
        interface_absent(client, "dcip0")
        interface_absent(gateway, "gip0")
        launch(client, "daemon", daemon_command)
        wait_health(client, 47780)
        assert not cli("status").get("networks"), "ephemeral joins unexpectedly persisted"
        cli("join", "local-vpc")
        probe()
        print("PASS daemon restart preserves Connector identity; explicit rejoin restores IP access", flush=True)
        final_status = cli("status")
        assert final_status["connector"]["public_key"] == connector_key
        assert final_status["networks"][0]["packets_sent"] > 0
        assert final_status["networks"][0]["packets_received"] > 0
        ip_transport = final_status["networks"][0]["transport"]
        assert final_status["networks"][0]["delivery_mode"] == "quic_datagram"
        assert final_status["networks"][0]["effective_datagram_ip_capacity"] >= 1280
        assert ip_transport["datagrams_sent"] > 0 and ip_transport["datagrams_received"] > 0
        topology = {}
        for name in containers:
            addresses = json.loads(execute(name, "ip", "-j", "address", "show").stdout)
            routes = json.loads(execute(name, "ip", family, "-j", "route", "show", "table", "all").stdout)
            if ipv6:
                assert all(a["family"] != "inet" for i in addresses if i["ifname"] != "lo"
                           for a in i.get("addr_info", [])), "IPv4 fallback appeared after join"
            topology[name] = {"addresses": addresses, "routes": routes}
        (artifacts / "container-network-state.json").write_text(json.dumps(topology, indent=2))
        metrics = execute(gateway, "curl", "--fail", "--silent", "http://127.0.0.1:9090/metrics").stdout
        counters = dict(line.split() for line in metrics.splitlines() if line.startswith("iroh_gateway_ip_"))
        assert int(counters["iroh_gateway_ip_packets_injected_total"]) > 0
        assert int(counters["iroh_gateway_ip_packets_returned_total"]) > 0
        assert int(counters["iroh_gateway_ip_active_sessions"]) == 1
        assert "iroh_gateway_ip_protocol_errors_total" in counters
        assert int(counters["iroh_gateway_ip_datagrams_sent_total"]) > 0
        assert int(counters["iroh_gateway_ip_datagrams_received_total"]) > 0
        assert int(counters["iroh_gateway_ip_effective_datagram_ip_capacity_min"]) >= 1280
        (artifacts / "metrics.txt").write_text(metrics)
        (artifacts / "status.json").write_text(json.dumps(final_status, indent=2))
        setup_token = execute(client, "python3", "-c", "print(open('/lab/repo/daemon_auth/setup.token').read().strip())").stdout.strip()
        for name, labels in ((client, ("daemon",)), (gateway, ("gateway",))):
            for label in labels:
                logs = execute(name, "python3", "-c", "import sys; print(open('/lab/'+sys.argv[1]+'.log').read())", label).stdout
                assert "ip_connected" in logs and "direct" in logs, f"{label} lacks CONNECT-IP path diagnostics"
                for secret in (setup_token, "test-access-secret", "test-refresh-secret"):
                    assert secret not in logs, f"{label} log exposes test credentials"
        print("PASS packet metrics, network status, and credential-redacted logs", flush=True)
        print("PASS CONNECT-IP local prototype suite (simulated Cloud API only)", flush=True)
        if args.keep:
            print(f"Live lab retained: {client}; origin {origin_ip}. See {artifacts / 'lab.json'}", flush=True)
    finally:
        (artifacts / "lab.json").write_text(json.dumps({"tag": tag,
                    "containers": containers, "networks": networks,
                    "context": args.docker_context, "ip_version": 6 if ipv6 else 4}, indent=2))
        for name in containers:
            # Docker archive/cp can miss a container's tmpfs mount (notably
            # under Kata). Read process logs inside its mount namespace instead.
            result = execute(name, "python3", "-c",
                "import pathlib,json; print(json.dumps({p.name:p.read_text(errors='replace') "
                "for p in pathlib.Path('/lab').glob('*.log') if p.is_file()}))", check=False)
            if result.returncode == 0:
                directory = artifacts / name
                directory.mkdir(mode=0o700, exist_ok=True)
                for label, contents in json.loads(result.stdout).items():
                    if Path(label).name == label:
                        (directory / label).write_text(contents)
            else:
                print(f"Warning: could not capture logs from {name}", file=sys.stderr)
        if not args.keep:
            for name in reversed(containers):
                cmd("rm", "-f", name, check=False)
            for name in reversed(networks):
                cmd("network", "rm", name, check=False)


def cleanup(path):
    state = json.loads(path.read_text())
    tag = state["tag"]
    if not tag.startswith("connect-ip-") or not tag[11:].isalnum():
        raise ValueError("Invalid lab ownership tag")
    docker = ["docker", "--context", state["context"]]
    # Never remove a resource solely because a manifest names it.
    for kind, names in (("container", state["containers"]), ("network", state["networks"])):
        for name in reversed(names):
            result = subprocess.run([*docker, kind, "inspect", name], capture_output=True, text=True)
            if result.returncode:
                continue
            resource = json.loads(result.stdout)[0]
            labels = resource.get("Config", {}).get("Labels", {}) if kind == "container" else resource.get("Labels", {})
            if labels.get("datum.connect.ip-lab") != tag:
                raise RuntimeError(f"Refusing to remove {name}: lab ownership label differs")
            subprocess.run([*docker, kind, "rm", *(["-f"] if kind == "container" else []), name], check=True)
    print("Removed this lab's containers and networks; diagnostic artifacts remain.")


def shell(path):
    state = json.loads(path.read_text())
    name = state["tag"] + "-client"
    if name not in state["containers"]:
        raise ValueError("Lab manifest has no client")
    docker = ["docker", "--context", state["context"]]
    resource = json.loads(subprocess.check_output([*docker, "container", "inspect", name]))[0]
    if resource.get("Config", {}).get("Labels", {}).get("datum.connect.ip-lab") != state["tag"]:
        raise ValueError("Client lab ownership label differs")
    subprocess.run([*docker, "exec", "-it", "-w", "/lab", name, "python3", "-c",
        "import os; os.environ.update(PATH='/binaries:'+os.environ['PATH'],DATUM_PROJECT='demo',"
        "DATUMCTL_TRUSTED_PLUGINS='connect',HISTFILE='/dev/null',"
        "DATUM_CONNECT_TOKEN=open('/lab/repo/daemon_auth/setup.token').read().strip()); "
        "os.execvp('bash',['bash','--noprofile','--norc'])"], check=True)


def build(args):
    if not args.datumctl_source or not (args.datumctl_source / "main.go").is_file():
        raise ValueError("--build requires --datumctl-source PATH to your datumctl checkout")
    binaries = args.binaries.resolve()
    binaries.mkdir(parents=True, exist_ok=True)
    docker = ["docker", "--context", args.docker_context]
    subprocess.run([*docker, "build", "-t", args.image, "-f", str(GATEWAY / "scripts/connect-ip/Dockerfile"),
                    str(GATEWAY / "scripts/connect-ip")], check=True)
    arch = subprocess.check_output([*docker, "run", "--rm", args.image, "uname", "-m"], text=True).strip()
    goarch = {"aarch64": "arm64", "x86_64": "amd64"}[arch]
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": goarch}
    for name, directory in (("datumctl-connect", WORKSPACE / "connect/connect-plugin"), ("datumctl", args.datumctl_source)):
        subprocess.run(["go", "build", "-o", str(binaries / name), "."], cwd=directory, env=env, check=True)
    subprocess.run([*docker, "run", "--rm", "--cpus", "4", "--memory", "8g",
        "--mount", f"type=bind,src={WORKSPACE},dst=/workspace,readonly",
        "--mount", f"type=bind,src={binaries},dst=/out",
        "--mount", "type=volume,src=datum-connect-ip-cargo,target=/usr/local/cargo",
        "--mount", "type=volume,src=datum-connect-ip-rustup,target=/usr/local/rustup",
        "--mount", "type=volume,src=datum-connect-ip-target,target=/build",
        "-e", "CARGO_TARGET_DIR=/build", "-e", "CARGO_BUILD_JOBS=4",
        "-e", "CARGO_PROFILE_DEV_DEBUG=0", "-e", "CARGO_INCREMENTAL=0",
        "-w", "/workspace/connect/connect-lib", args.image, "sh", "-c",
        "cargo test --locked -p connect-transport -p connect-ip-adapter -p datum-connect-daemon && "
        "cargo build --locked -p datum-connect-daemon && cp /build/debug/datum-connect-daemon /out/ && "
        "cargo test --locked --manifest-path /workspace/iroh-gateway/Cargo.toml && "
        "cargo build --locked --manifest-path /workspace/iroh-gateway/Cargo.toml && cp /build/debug/iroh-gateway /out/"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-context", default="colima-kata")
    parser.add_argument("--image", default="datum-connect-ip-lab:local")
    parser.add_argument("--binaries", type=Path, default=GATEWAY / "target/connect-ip-linux-bin")
    parser.add_argument("--keep", action="store_true", help="Keep isolated containers and networks for manual validation")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6-only underlay and VPC networks; IPv4 remains on loopback only")
    parser.add_argument("--cleanup", type=Path, metavar="LAB_JSON", help="Remove only the labeled resources recorded by a retained lab")
    parser.add_argument("--shell", type=Path, metavar="LAB_JSON", help="Open an authenticated client shell in a retained lab")
    parser.add_argument("--build", action="store_true", help="Build Linux Rust binaries in Docker and cross-compile both Go CLIs, then run the suite")
    parser.add_argument("--datumctl-source", type=Path, help="datumctl source checkout, required with --build; no files are edited")
    parser.add_argument("--fixture", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--origin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--udp-probe", help=argparse.SUPPRESS)
    parser.add_argument("--spoof", nargs=2, help=argparse.SUPPRESS)
    parser.add_argument("--ipv6-extensions", nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.cleanup:
        cleanup(args.cleanup)
    elif args.shell:
        shell(args.shell)
    elif args.fixture:
        fixture()
    elif args.origin:
        origin(args.ipv6)
    elif args.udp_probe:
        udp_probe(args.udp_probe)
    elif args.spoof:
        spoof(*args.spoof)
    elif args.ipv6_extensions:
        for extension in (0, 44):
            spoof(*args.ipv6_extensions, extension=extension)
    else:
        if args.build:
            build(args)
        run_lab(args)


if __name__ == "__main__":
    main()
