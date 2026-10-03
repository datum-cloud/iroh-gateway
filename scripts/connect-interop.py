#!/usr/bin/env python3
"""Real gateway <-> Connect daemon MASQUE interoperability on one machine.

The OAuth endpoint and control plane are simulated using Connect's shared E2E
fixture. No deployed cloud resources or installed services are changed.
"""

import argparse
import base64
import hashlib
import http.client
import http.server
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.request


BODY = b"real-gateway-connect-daemon-masque-roundtrip\n"


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests = []
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def do_GET(self):
        with self.lock:
            self.requests.append((self.path, {key.lower(): value for key, value in self.headers.items()}))
        if self.path == "/websocket" and self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            header = self.rfile.read(2)
            if len(header) == 2 and header[0] == 0x81 and header[1] & 0x80 and header[1] & 0x7F < 126:
                length = header[1] & 0x7F
                mask = self.rfile.read(4)
                payload = self.rfile.read(length)
                if len(mask) == 4 and len(payload) == length:
                    unmasked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
                    self.wfile.write(bytes((0x81, len(unmasked))) + unmasked)
                    self.wfile.flush()
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


class UDPOrigin(socketserver.BaseRequestHandler):
    packets = []
    lock = threading.Lock()

    def handle(self):
        payload, sock = self.request
        with self.lock:
            self.packets.append((self.server.server_address[1], payload))
        sock.sendto(b"udp:" + payload, self.client_address)


def udp_origin():
    instance = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDPOrigin)
    instance.daemon_threads = True
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    return instance


def load_fixture(connect_repo):
    source = connect_repo / "scripts" / "daemon-e2e.py"
    spec = importlib.util.spec_from_file_location("connect_process_e2e", source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load Connect fixture: {source}")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    return fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", required=True, type=Path, help="Built iroh-gateway with --transport masque")
    parser.add_argument("--transport-mode", choices=("masque", "auto"), default="masque", help="Gateway mode; auto tests explicit per-destination selection")
    parser.add_argument("--daemon", required=True, type=Path, help="Built datum-connect-daemon")
    parser.add_argument("--connect-repo", type=Path, default=Path(__file__).resolve().parents[2] / "connect", help="Connect checkout supplying scripts/daemon-e2e.py")
    args = parser.parse_args()
    gateway, daemon = args.gateway.resolve(), args.daemon.resolve()
    for binary in (gateway, daemon):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"Not an executable: {binary}")
    fixture = load_fixture(args.connect_repo.resolve())
    platform_class = fixture.Platform
    platform_class.objects, platform_class.writes = {}, []
    platform_class.gateway_connectors = []
    platform_class.observed_tokens = set()
    platform_class.accepted_tokens = {"test-access-secret"}
    root = Path(tempfile.mkdtemp(prefix="datum-gateway-interop-"))
    root.chmod(0o700)
    print(f"Artifacts: {root}", flush=True)
    processes, logs = {}, []
    servers = []
    env = {**os.environ, "RUST_LOG": "info,iroh_gateway=debug,datum_connect_daemon=debug,connect_transport=debug", "NO_COLOR": "1"}
    # Do not attach tests to optional production diagnostics or user gateway config.
    for key in ("IROH_SERVICES_API_KEY", "IROH_GATEWAY_CONFIG_FILE", "IROH_GATEWAY_RELAY_URLS"):
        env.pop(key, None)
    daemon_port, gateway_port, rogue_port, metrics_port = (fixture.free_port() for _ in range(4))

    def start(name, command):
        log = (root / f"{name}.log").open("ab")
        logs.append(log)
        processes[name] = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        return processes[name]

    def wait_ready(name, port, health=False):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if processes[name].poll() is not None:
                raise AssertionError(f"{name} exited; inspect {root / (name + '.log')}")
            try:
                if health:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/health", timeout=1) as response:
                        assert response.status == 200
                else:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        pass
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError(f"{name} did not become ready")

    def api(method, path, body=None):
        bearer = (root / "daemon" / "daemon_auth" / "setup.token").read_text().strip()
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon_port}/v1/{path}",
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=45) as response:
            assert response.headers.get("x-request-id"), "Daemon response lacks request correlation"
            return json.load(response)

    def origin_request(port, target_key, target_port, path="/ordinary-http", target_host="127.0.0.1"):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        try:
            connection.request("GET", path, headers={
                "x-iroh-endpoint-id": target_key,
                "x-datum-target-host": target_host,
                "x-datum-target-port": str(target_port),
                "x-datum-connect-transport": "masque-v1",
                "Connection": "close",
            })
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def connect_request(port, target_key, target_port):
        with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
            sock.settimeout(20)
            sock.sendall((f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                          f"Host: 127.0.0.1:{target_port}\r\n"
                          f"x-iroh-endpoint-id: {target_key}\r\nx-datum-connect-transport: masque-v1\r\n\r\n").encode())
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                part = sock.recv(1)
                assert part, "Gateway closed before CONNECT response"
                headers.extend(part)
                assert len(headers) <= 65536, "Oversized CONNECT headers"
            status = int(bytes(headers).split(b" ", 2)[1])
            if status != 200:
                return status, b""
            sock.sendall(b"GET /through-connect HTTP/1.1\r\nHost: local-origin\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(sock)
            response.begin()
            return response.status, response.read()

    def expect_denied(port, target_key, target_port):
        before = len(Origin.requests)
        status, body = origin_request(port, target_key, target_port, "/must-not-reach-origin")
        assert not 200 <= status < 300, f"Denied request returned HTTP {status}"
        assert body != BODY and len(Origin.requests) == before, "Denied request reached the origin"

    def websocket_roundtrip(target_key, target_port):
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=20) as sock:
            sock.settimeout(20)
            sock.sendall(("GET /websocket HTTP/1.1\r\nHost: local-origin\r\n"
                          "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                          "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                          f"x-iroh-endpoint-id: {target_key}\r\nx-datum-target-host: 127.0.0.1\r\n"
                          f"x-datum-target-port: {target_port}\r\nx-datum-connect-transport: masque-v1\r\n\r\n").encode())
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                part = sock.recv(1)
                assert part, "Gateway closed before WebSocket upgrade"
                headers.extend(part)
                assert len(headers) <= 65536
            assert bytes(headers).split(b" ", 2)[1] == b"101", "Gateway did not preserve WebSocket upgrade"
            assert b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in headers
            payload = b"browser-hot-reload-through-masque"
            mask = b"test"
            sock.sendall(bytes((0x81, 0x80 | len(payload))) + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
            echoed = bytearray()
            while len(echoed) < len(payload) + 2:
                part = sock.recv(len(payload) + 2 - len(echoed))
                assert part, "WebSocket frame was not forwarded"
                echoed.extend(part)
            assert echoed == bytes((0x81, len(payload))) + payload

    def metric_values():
        with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/metrics", timeout=5) as response:
            text = response.read().decode()
        values = {line.split()[0]: float(line.split()[1]) for line in text.splitlines() if line and not line.startswith("#")}
        return text, values

    def udp_client():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)
        return sock

    def udp_roundtrip(sock, port, payload):
        sock.settimeout(5)
        sock.sendto(payload, ("127.0.0.1", port))
        reply, address = sock.recvfrom(65535)
        assert address == ("127.0.0.1", port), "UDP response came from the wrong ingress socket"
        assert reply == b"udp:" + payload, "UDP association delivered another source's payload"

    def udp_denied(sock, port, payload=b"must-not-arrive", timeout=0.7):
        before = len(UDPOrigin.packets)
        sock.settimeout(timeout)
        sock.sendto(payload, ("127.0.0.1", port))
        try:
            sock.recvfrom(65535)
        except socket.timeout:
            assert len(UDPOrigin.packets) == before, "Denied UDP packet reached an origin"
            return
        raise AssertionError("Denied UDP packet unexpectedly received a reply")

    try:
        platform = fixture.server(platform_class)
        public_origin, private_origin = fixture.server(Origin), fixture.server(Origin)
        udp_service_origin, udp_unpublished_origin = udp_origin(), udp_origin()
        servers.extend((platform, public_origin, private_origin, udp_service_origin, udp_unpublished_origin))
        udp_origin_port = udp_service_origin.server_address[1]
        udp_wrong_port = udp_unpublished_origin.server_address[1]
        udp_ports = set()
        while len(udp_ports) < 3:
            udp_ports.add(fixture.free_udp_port())
        udp_ingress, udp_unpublished_ingress, udp_rogue_ingress = udp_ports
        key_file = root / "gateway.key"
        identity = subprocess.run([str(gateway), "--key-file", str(key_file), "--print-endpoint-id"], cwd=root, env=env,
                                  stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=15)
        assert identity.returncode == 0, f"Gateway identity setup failed: {identity.stderr}"
        gateway_key = identity.stdout.strip()
        assert len(gateway_key) == 64 and all(c in "0123456789abcdef" for c in gateway_key), "Invalid gateway public key output"
        assert key_file.stat().st_size == 32 and key_file.stat().st_mode & 0o077 == 0, "Gateway key must be raw 32-byte owner-only state"
        gateway_name = "connect-" + gateway_key[:40]
        platform_class.gateway_connectors = [gateway_name]
        platform_class.objects[("connectors", gateway_name)] = {
            "apiVersion": "networking.datumapis.com/v1alpha1", "kind": "Connector",
            "metadata": {"name": gateway_name, "uid": "gateway-fixture-uid", "resourceVersion": "1",
                         "annotations": {"connect.datum.net/transport": "masque-v1", "connect.datum.net/public-key": gateway_key}},
            "spec": {"connectorClassName": "local-masque"},
            "status": {"connectionDetails": {"type": "PublicKey", "publicKey": {"id": gateway_key, "addresses": []}}},
        }
        credentials = root / "credentials.json"
        credentials.write_text(json.dumps({"type": "connector", "project_id": "demo",
            "api_endpoint": f"http://127.0.0.1:{platform.server_port}", "token_uri": f"http://127.0.0.1:{platform.server_port}/token",
            "client_id": "local-interop", "refresh_token": "test-refresh-secret"}))
        credentials.chmod(0o600)
        start("daemon", [str(daemon), "--repo", str(root / "daemon"), "--port", str(daemon_port)])
        wait_ready("daemon", daemon_port, health=True)
        enrolled = api("POST", "up", {"project": "demo", "credentials_file": str(credentials)})
        connector = enrolled["connector"]
        connector_key = connector["public_key"]
        with platform_class.lock:
            details = platform_class.objects[("connectors", connector["name"])]["status"]["connectionDetails"]["publicKey"]
            addresses = list(details["addresses"])
        assert addresses, "Daemon did not publish direct addresses"
        peers = []
        for address in addresses:
            host = ipaddress.ip_address(address["address"])
            if host.is_unspecified or host.is_multicast:
                continue
            socket_address = f"[{host}]:{address['port']}" if host.version == 6 else f"{host}:{address['port']}"
            peers.extend(("--peer", f"{connector_key}={socket_address}"))
        assert peers, "No usable direct daemon address"
        with udp_client() as occupied:
            occupied_port = occupied.getsockname()[1]
            for label, bind in (("occupied-udp-bind", f"127.0.0.1:{occupied_port}"), ("public-udp-bind", "0.0.0.0:15353")):
                failing_port = fixture.free_port()
                result = subprocess.run([str(gateway), "--bind-addr", "127.0.0.1", "--port", str(failing_port),
                    "--key-file", str(key_file), "--transport", "masque", "--discovery", "static", *peers,
                    "--udp-forward", f"{bind}={connector_key}:{udp_origin_port}"],
                    cwd=root, env=env, stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=15)
                (root / f"{label}.log").write_text(result.stdout + result.stderr)
                assert result.returncode != 0, f"Gateway accepted {label}"
                with socket.socket() as probe:
                    probe.settimeout(0.5)
                    assert probe.connect_ex(("127.0.0.1", failing_port)) != 0, "Failed startup left a TCP listener running"
        print("PASS occupied UDP bind and non-loopback UDP ingress fail startup cleanly", flush=True)
        for name, port, key in (("gateway", gateway_port, key_file), ("unapproved-gateway", rogue_port, root / "rogue.key")):
            metrics = ["--metrics-addr", "127.0.0.1", "--metrics-port", str(metrics_port)] if name == "gateway" else []
            forwards = [(udp_ingress, udp_origin_port), (udp_unpublished_ingress, udp_wrong_port)] if name == "gateway" else [(udp_rogue_ingress, udp_origin_port)]
            udp_args = [argument for bind_port, target_port in forwards for argument in ("--udp-forward", f"127.0.0.1:{bind_port}={connector_key}:{target_port}")]
            start(name, [str(gateway), "--bind-addr", "127.0.0.1", "--port", str(port), "--key-file", str(key), "--transport", args.transport_mode, "--discovery", "static", "--udp-idle-timeout-secs", "2", "--udp-max-associations", "2", *peers, *metrics, *udp_args])
            wait_ready(name, port)
        public = api("POST", "services?project=demo", {"endpoint": f"127.0.0.1:{public_origin.server_port}", "public": True})
        assert public["public"] and ("httpproxies", public["id"]) in platform_class.objects
        assert origin_request(gateway_port, connector_key, public_origin.server_port) == (200, BODY)
        assert connect_request(gateway_port, connector_key, public_origin.server_port) == (200, BODY)
        websocket_roundtrip(connector_key, public_origin.server_port)
        assert origin_request(gateway_port, connector_key, public_origin.server_port, "/fixed-backend", target_host="127.0.0.2") == (200, BODY), "Untrusted host header redirected the fixed daemon destination"
        print("PASS public service: real gateway HTTP and CONNECT -> iroh HTTP/3 -> Connect daemon -> origin", flush=True)
        print("PASS WebSocket upgrade and masked-frame echo for browser hot reload", flush=True)
        for path, headers in Origin.requests:
            assert not any(name.startswith(("x-iroh-", "x-datum-")) for name in headers), f"Gateway routing header leaked to origin: {path}"
        expect_denied(gateway_port, connector_key, private_origin.server_port)
        expect_denied(rogue_port, connector_key, public_origin.server_port)
        print("PASS unpublished destination and unapproved gateway identity cannot reach origin", flush=True)
        default_private = api("POST", "services?project=demo", {"endpoint": f"127.0.0.1:{private_origin.server_port}"})
        assert not default_private["public"] and ("httpproxies", default_private["id"]) not in platform_class.objects
        expect_denied(gateway_port, connector_key, private_origin.server_port)
        print("PASS default-private service excludes approved public gateway identities", flush=True)
        api("DELETE", f"services/{default_private['id']}?project=demo")
        private = api("POST", "services?project=demo", {"endpoint": f"127.0.0.1:{private_origin.server_port}", "allow": [gateway_key]})
        assert not private["public"] and ("httpproxies", private["id"]) not in platform_class.objects
        assert origin_request(gateway_port, connector_key, private_origin.server_port, "/private-service") == (200, BODY)
        expect_denied(rogue_port, connector_key, private_origin.server_port)
        print("PASS private service allows only the explicitly authorized Connector; creates no HTTPProxy", flush=True)
        api("DELETE", f"services/{public['id']}?project=demo")
        expect_denied(gateway_port, connector_key, public_origin.server_port)
        print("PASS service removal revokes gateway access", flush=True)
        api("DELETE", f"services/{private['id']}?project=demo")

        default_udp = api("POST", "services?project=demo", {"endpoint": f"127.0.0.1:{udp_origin_port}", "protocol": "udp"})
        with udp_client() as probe:
            udp_denied(probe, udp_ingress)
        api("DELETE", f"services/{default_udp['id']}?project=demo")
        private_udp = api("POST", "services?project=demo", {"endpoint": f"127.0.0.1:{udp_origin_port}", "protocol": "udp", "allow": [gateway_key]})
        assert not private_udp["public"] and ("httpproxies", private_udp["id"]) not in platform_class.objects
        with udp_client() as probe:
            udp_denied(probe, udp_unpublished_ingress)
            udp_denied(probe, udp_rogue_ingress)
        print("PASS UDP default-private, unpublished destination, and unapproved gateway deny access", flush=True)
        with udp_client() as first, udp_client() as second, udp_client() as third:
            udp_roundtrip(first, udp_ingress, b"first-source")
            udp_roundtrip(second, udp_ingress, b"second-source")
            # Send both before reading so shared/incorrect response routing fails.
            first.sendto(b"first-isolated", ("127.0.0.1", udp_ingress))
            second.sendto(b"second-isolated", ("127.0.0.1", udp_ingress))
            assert first.recvfrom(65535)[0] == b"udp:first-isolated"
            assert second.recvfrom(65535)[0] == b"udp:second-isolated"
            udp_roundtrip(first, udp_ingress, b"")
            udp_denied(third, udp_ingress, b"association-cap", timeout=0.3)
            _, counters = metric_values()
            assert counters.get('iroh_gateway_udp_dropped_total{reason="association_limit"}', 0) > 0
            udp_denied(first, udp_ingress, b"x" * 1201, timeout=0.3)
            udp_roundtrip(first, udp_ingress, b"after-oversize")
            print("PASS UDP HTTP/3 tagged echo, empty datagram, source isolation, cap, and oversized-drop recovery", flush=True)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                _, counters = metric_values()
                if counters.get("iroh_gateway_udp_active_associations", -1) == 0:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Idle UDP associations did not release capacity")
            udp_roundtrip(third, udp_ingress, b"after-idle-expiry")
            print("PASS idle UDP association expiry releases capacity for a new client", flush=True)
            api("DELETE", f"services/{private_udp['id']}?project=demo")
            udp_denied(third, udp_ingress, b"after-revocation")
            print("PASS UDP service removal revokes an already-established association", flush=True)
        metrics, values = metric_values()
        (root / "gateway-metrics.txt").write_text(metrics)
        assert values.get("iroh_gateway_masque_bytes_sent_total", 0) > 0
        assert values.get("iroh_gateway_masque_bytes_received_total", 0) > 0
        assert sum(value for name, value in values.items() if name.startswith("iroh_gateway_error_responses_total{")) > 0
        for counter in ("packets_sent_total", "packets_received_total", "bytes_sent_total", "bytes_received_total", "connection_errors_total"):
            assert values.get("iroh_gateway_udp_" + counter, 0) > 0, f"Missing UDP telemetry: {counter}"
        assert values.get('iroh_gateway_udp_dropped_total{reason="oversize"}', 0) > 0
        assert values.get('iroh_gateway_udp_associations_closed_total{reason="idle"}', 0) > 0
        print("PASS gateway telemetry records payload bytes and denied-request errors", flush=True)
        shutdown_service = api("POST", "services?project=demo", {"endpoint": f"127.0.0.1:{udp_origin_port}", "protocol": "udp", "allow": [gateway_key]})
        with udp_client() as active:
            udp_roundtrip(active, udp_ingress, b"active-during-shutdown")
            processes["gateway"].terminate()
            assert processes["gateway"].wait(timeout=15) == 0, "Gateway did not shut down cleanly with a live UDP association"
        api("DELETE", f"services/{shutdown_service['id']}?project=demo")
        api("POST", "down?project=demo")
        print("PASS SIGTERM drains gateway tasks with a live UDP association", flush=True)
        setup_bearer = (root / "daemon" / "daemon_auth" / "setup.token").read_text().strip()
        for log_path in root.glob("*.log"):
            text = log_path.read_text(errors="replace")
            assert not any(secret in text for secret in ("test-access-secret", "test-refresh-secret", setup_bearer)), f"Credential leaked into {log_path.name}"
        print("PASS local interoperability suite; control-plane resources remain simulated", flush=True)
    finally:
        for process in reversed(list(processes.values())):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in logs:
            log.close()
        for instance in servers:
            instance.shutdown()
            instance.server_close()


if __name__ == "__main__":
    main()
