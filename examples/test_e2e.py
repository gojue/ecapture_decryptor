#!/usr/bin/env python3
"""Build and exercise every example with real Linux VM pcapng fixtures."""

import argparse
import base64
import collections
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test" / "testdata"


def run(label, argv, *, stdin_path=None, expected_code=0, output_contains=None, timeout=300, env=None):
    source = open(stdin_path, "rb") if stdin_path else None
    try:
        result = subprocess.run(
            argv,
            cwd=ROOT,
            stdin=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    finally:
        if source:
            source.close()
    if result.returncode != expected_code:
        raise AssertionError(
            f"{label}: exit {result.returncode}, want {expected_code}\n{result.stdout[-4000:]}"
        )
    if output_contains and output_contains not in result.stdout:
        raise AssertionError(f"{label}: missing {output_contains!r}\n{result.stdout[-4000:]}")
    print(f"PASS {label}", flush=True)
    return result.stdout


def check_packets(label, path, protocol, paths):
    packets = json.loads(path.read_text())
    counts = collections.Counter(packet["direction"] for packet in packets)
    expected = {"request": len(paths), "response": len(paths)}
    if counts != expected or any(packet["protocol"] != protocol for packet in packets):
        raise AssertionError(f"{label}: unexpected packet protocol/directions: {packets}")
    requests = [packet for packet in packets if packet["direction"] == "request"]
    actual_paths = {packet["metadata"].get("path", packet["metadata"].get("url")) for packet in requests}
    if actual_paths != set(paths):
        raise AssertionError(f"{label}: paths {actual_paths}, want {set(paths)}")
    if protocol in ("http/2", "http/3"):
        request_streams = {packet["metadata"].get("stream_id") for packet in requests}
        response_streams = {
            packet["metadata"].get("stream_id")
            for packet in packets
            if packet["direction"] == "response"
        }
        if None in request_streams or request_streams != response_streams or len(request_streams) != len(paths):
            raise AssertionError(f"{label}: request/response streams do not match")
    print(f"PASS {label}: {protocol}, {len(paths)} complete exchanges", flush=True)


def check_har(label, path, expected, authority):
    entries = json.loads(path.read_text())["log"]["entries"]
    actual = {}
    for entry in entries:
        url = urlparse(entry["request"]["url"])
        if url.scheme != "https" or url.netloc != authority:
            raise AssertionError(f"{label}: invalid HTTPS URL {url.geturl()!r}")
        actual[url.path] = (entry["response"]["status"], entry["response"]["content"]["text"])
    if set(actual) != set(expected) or len(entries) != len(expected):
        raise AssertionError(f"{label}: HAR paths {list(actual)}, want {list(expected)}")
    for path_name, (status, body_marker) in expected.items():
        got_status, body = actual[path_name]
        if got_status != status or not body or body_marker not in body:
            raise AssertionError(f"{label}: {path_name} status/body mismatch: {got_status}, {body[:80]!r}")
    print(f"PASS {label}: {len(entries)} matched HAR entries", flush=True)


def check_curl_har(path):
    entries = json.loads(path.read_text())["log"]["entries"]
    expected = {
        ("HTTP/1.0", "/"): b"Protocol: HTTP/1.0",
        ("HTTP/1.1", "/"): b"Protocol: HTTP/1.1",
        ("HTTP/2.0", "/"): b"Protocol: HTTP/2.0",
        ("HTTP/2.0", "/gzip"): b"compressed with gzip encoding",
    }
    actual = {}
    for entry in entries:
        request, response = entry["request"], entry["response"]
        url = urlparse(request["url"])
        if url.scheme != "https" or url.netloc != "local.koujue.cc":
            raise AssertionError(f"curl HAR: unexpected URL {url.geturl()!r}")
        if not any(
            header["name"].lower() == "user-agent" and header["value"].startswith("curl/")
            for header in request["headers"]
        ):
            raise AssertionError(f"curl HAR: missing curl User-Agent for {url.geturl()}")
        content = response["content"]
        if content.get("encoding") or content["mimeType"] != "text/plain":
            raise AssertionError(f"curl HAR: expected readable text body for {url.geturl()}")
        body = content["text"].encode()
        key = (request["httpVersion"], url.path)
        if key in actual:
            raise AssertionError(f"curl HAR: duplicate exchange {key}")
        actual[key] = (response["status"], body)
    if set(actual) != set(expected) or len(entries) != len(expected):
        raise AssertionError(f"curl HAR: exchanges {list(actual)}, want {list(expected)}")
    for key, marker in expected.items():
        status, body = actual[key]
        if status != 200 or marker not in body:
            raise AssertionError(f"curl HAR: {key} status/body mismatch: {status}, {body[:80]!r}")
    print(f"PASS go_demo curl HAR: {len(entries)} matched curl exchanges", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="retain generated HAR and JSON files here (default: temporary directory)",
    )
    args = parser.parse_args()
    if platform.system() not in ("Linux", "Darwin"):
        raise SystemExit("C example E2E tests require Linux or macOS")
    with tempfile.TemporaryDirectory(prefix="ecapture-examples-e2e-") as tmp_name:
        tmp = Path(tmp_name)
        output_dir = tmp
        if args.output_dir is not None:
            output_dir = args.output_dir.resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
            print(f"Retaining HAR and JSON files in {output_dir}", flush=True)
        go_demo = tmp / "go_demo"
        go_static = tmp / "go_static_demo"
        library = tmp / "libecapture_decryptor.a"
        run("build go_demo", ["go", "build", "-o", go_demo, "./examples/go_demo"])
        run("build go_static_demo", ["go", "build", "-o", go_static, "./examples/go_static_demo"])
        run(
            "build C archive",
            ["go", "build", "-buildmode=c-archive", "-o", library, "./capi"],
            env={**os.environ, "CGO_ENABLED": "1"},
        )
        c_binaries = {}
        for name in ("offline_decryption", "stream_decryption", "live_capture_simple"):
            binary = tmp / name
            command = [
                os.environ.get("CC", "cc"), "-Wall", "-Wextra", "-O2", f"-I{tmp}",
                "-o", binary, ROOT / "examples" / "c_demo" / f"{name}.c", library, "-lpthread", "-lresolv",
            ]
            if platform.system() == "Darwin":
                command.extend(["-framework", "CoreFoundation", "-framework", "Security"])
            run(f"build C {name}", command)
            c_binaries[name] = binary

        h11_capture = FIXTURES / "http11_keepalive_chunked_tcpdump_no_dsb.pcapng"
        h11_keylog = FIXTURES / "http11_keepalive_chunked_tcpdump.keys"
        h2_capture = FIXTURES / "http2_multiplex_ecapture_dsb.pcapng"
        h2_external = FIXTURES / "http2_multiplex_tcpdump_no_dsb.pcapng"
        h2_keylog = FIXTURES / "http2_multiplex_tcpdump.keys"
        h3_capture = FIXTURES / "http3_loopback_ecapture_dsb.pcapng"
        h3_external = FIXTURES / "http3_loopback_tcpdump_no_dsb.pcapng"
        h3_keylog = FIXTURES / "http3_loopback_tcpdump.keys"
        h3_public = FIXTURES / "http3_cloudflare_ecapture_dsb.pcapng"
        h10_capture = FIXTURES / "http10_ecapture_dsb.pcapng"
        curl_capture = FIXTURES / "curl_clients_external_keylog.pcapng"
        curl_keylog = FIXTURES / "all_clients_sslkey.log"

        go11_json, go11_har = output_dir / "go11.json", output_dir / "go11.har"
        run("go_demo HTTP/1.1 external keylog", [go_demo, "-pcap", h11_capture, "-sslkeylog", h11_keylog, "-json", go11_json, "-har", go11_har])
        check_packets("go_demo HTTP/1.1 JSON", go11_json, "http/1.1", ["/keep-one", "/chunked"])
        check_har("go_demo HTTP/1.1 HAR", go11_har, {"/keep-one": (200, "keep-one-response"), "/chunked": (201, "chunked-response")}, "localhost")

        go2_json, go2_har = output_dir / "go2.json", output_dir / "go2.har"
        run("go_demo HTTP/2 DSB", [go_demo, "-pcap", h2_capture, "-json", go2_json, "-har", go2_har])
        check_packets("go_demo HTTP/2 JSON", go2_json, "http/2", ["/alpha", "/beta"])
        check_har("go_demo HTTP/2 HAR", go2_har, {"/alpha": (200, "multiplexed-response-alpha"), "/beta": (200, "multiplexed-response-beta")}, "127.0.0.1:44436")

        go3_json, go3_har = output_dir / "go3.json", output_dir / "go3.har"
        run("go_demo HTTP/3 external keylog", [go_demo, "-pcap", h3_external, "-sslkeylog", h3_keylog, "-json", go3_json, "-har", go3_har])
        check_packets("go_demo HTTP/3 JSON", go3_json, "http/3", ["/one", "/upload"])
        check_har("go_demo HTTP/3 HAR", go3_har, {"/one": (200, "GET /one"), "/upload": (200, "POST /upload")}, "127.0.0.1:44433")
        public_json, public_har = output_dir / "public.json", output_dir / "public.har"
        run("go_demo public HTTP/3 DSB", [go_demo, "-pcap", h3_public, "-json", public_json, "-har", public_har])
        check_packets("go_demo public HTTP/3 JSON", public_json, "http/3", ["/robots.txt", "/favicon.ico"])
        check_har("go_demo public HTTP/3 HAR", public_har, {"/robots.txt": (200, "# Robots.txt for www.cloudflare.com"), "/favicon.ico": (200, "")}, "www.cloudflare.com")
        public_entries = json.loads(public_har.read_text())["log"]["entries"]
        by_path = {urlparse(entry["request"]["url"]).path: entry for entry in public_entries}
        robots = by_path["/robots.txt"]["response"]
        if robots["content"].get("encoding") or robots["content"]["size"] <= robots["bodySize"]:
            raise AssertionError("public robots.txt was not decoded from gzip into readable text")
        favicon = by_path["/favicon.ico"]["response"]["content"]
        if favicon.get("encoding") != "base64" or not base64.b64decode(favicon["text"]).startswith(b"\x89PNG\r\n\x1a\n"):
            raise AssertionError("public favicon body was not preserved as base64 binary")

        curl_har = output_dir / "curl_clients.har"
        run("go_demo curl pcapng external keylog", [go_demo, "-pcap", curl_capture, "-sslkeylog", curl_keylog, "-har", curl_har])
        check_curl_har(curl_har)

        run("go_demo statistics only", [go_demo, "-pcap", h10_capture], output_contains="Total packets: 2")

        static2 = output_dir / "static2.json"
        run("go_static_demo HTTP/2 external keylog", [go_static, "-pcap", h2_external, "-keylog", h2_keylog, "-output", static2])
        check_packets("go_static_demo HTTP/2 JSON", static2, "http/2", ["/alpha", "/beta"])
        static3 = output_dir / "static3.json"
        run("go_static_demo HTTP/3 DSB", [go_static, "-pcap", h3_capture, "-output", static3])
        check_packets("go_static_demo HTTP/3 JSON", static3, "http/3", ["/one", "/upload"])
        run("go_static_demo version", [go_static, "-version"], output_contains="Library version:")

        offline11 = output_dir / "offline11.json"
        run("C offline HTTP/1.1 external keylog", [c_binaries["offline_decryption"], h11_capture, h11_keylog, offline11])
        check_packets("C offline HTTP/1.1 JSON", offline11, "http/1.1", ["/keep-one", "/chunked"])
        offline3 = output_dir / "offline3.json"
        run("C offline HTTP/3 DSB", [c_binaries["offline_decryption"], h3_capture, offline3])
        check_packets("C offline HTTP/3 JSON", offline3, "http/3", ["/one", "/upload"])

        stream2 = output_dir / "stream2.json"
        run("C stream HTTP/2 external keylog", [c_binaries["stream_decryption"], h2_keylog, stream2], stdin_path=h2_external)
        check_packets("C stream HTTP/2 JSON", stream2, "http/2", ["/alpha", "/beta"])
        stream10 = output_dir / "stream10.json"
        run("C stream HTTP/1.0 DSB", [c_binaries["stream_decryption"], stream10], stdin_path=h10_capture)
        check_packets("C stream HTTP/1.0 JSON", stream10, "http/1.0", ["/legacy"])
        stream3 = output_dir / "stream3.json"
        run("C stream HTTP/3 DSB", [c_binaries["stream_decryption"], stream3], stdin_path=h3_capture)
        check_packets("C stream HTTP/3 JSON", stream3, "http/3", ["/one", "/upload"])

        live_output = output_dir / "live.json"
        run(
            "C live placeholder reports missing integration",
            [c_binaries["live_capture_simple"], "lo", h11_keylog, live_output, "1"],
            expected_code=2,
            output_contains="requires pcap library integration",
            timeout=10,
        )
        if live_output.stat().st_size != 0:
            raise AssertionError("C live placeholder unexpectedly wrote decrypted packets")


if __name__ == "__main__":
    main()
