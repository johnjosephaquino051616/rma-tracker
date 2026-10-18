#!/usr/bin/env python3
"""Local HTTP smoke tests using fictional RMA data. No external dependencies."""
import http.cookiejar
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:18765"

def assert_status(actual, expected, detail=""):
    assert actual == expected, f"HTTP {actual}, expected {expected}: {detail}"

def run():
    config = ROOT / "config.php"
    if config.exists():
        raise RuntimeError("Refusing to overwrite an existing config.php")
    with tempfile.TemporaryDirectory(prefix="rma-smoke-") as data_dir:
        setup = subprocess.run(
            ["php", "scripts/setup.php", "--local"], cwd=ROOT,
            check=True, capture_output=True, text=True
        )
        code = setup.stdout.splitlines()[1].strip()
        env = dict(os.environ, RMA_DATA_DIR=data_dir)
        log = open(os.devnull, "w")
        server = subprocess.Popen(
            ["php", "-S", "127.0.0.1:18765", "-t", "public"],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT
        )
        jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        token = ""

        def http(path, method="GET", body=None, send_token=True):
            headers = {}
            payload = None
            if method != "GET":
                headers["Content-Type"] = "application/json"
                if send_token:
                    headers["X-CSRF-Token"] = token
                payload = json.dumps(body if body is not None else {}).encode("utf-8")
            req = urllib.request.Request(BASE + path, data=payload, method=method, headers=headers)
            try:
                with client.open(req, timeout=5) as res:
                    return res.status, res.headers, res.read().decode("utf-8")
            except urllib.error.HTTPError as error:
                return error.code, error.headers, error.read().decode("utf-8")

        try:
            for _ in range(50):
                if server.poll() is not None:
                    raise RuntimeError("PHP server exited unexpectedly")
                try:
                    status, headers, page = http("/")
                    break
                except urllib.error.URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("PHP web server never became ready")

            assert_status(status, 200)
            assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
            assert headers["X-Frame-Options"] == "DENY"
            match = re.search(r'name="csrf-token" content="([0-9a-f]+)"', page)
            assert match, "Missing CSRF token meta tag"
            token = match.group(1)

            status, _, _ = http("/?api=rmas")
            assert_status(status, 401, "unauthenticated request")

            status, _, _ = http("/?api=auth", "POST", {"code": code}, send_token=False)
            assert_status(status, 403, "CSRF should be required")

            status, _, _ = http("/?api=auth", "POST", {"code": "incorrect"})
            assert_status(status, 401, "incorrect code")

            status, _, body = http("/?api=auth", "POST", {"code": code})
            assert_status(status, 200, body)

            example = {
                "supplier": "Fictional Computer Supplier", "processedBy": "Test Employee",
                "status": "Requested", "dateEntered": "2026-10-18",
                "notes": "<img src=x onerror=alert(1)>",
                "extraDetails": "{\"customField\":\"should remain\"}"
            }
            status, _, body = http("/?api=rmas", "POST", example)
            assert_status(status, 201, body)
            identifier = json.loads(body)["id"]

            status, _, body = http("/?api=rmas")
            assert_status(status, 200)
            records = json.loads(body)["records"]
            assert len(records) == 1
            original = records[0]
            assert original["extraDetails"] == example["extraDetails"]
            assert original["reference"].startswith("RMA-")
            assert original["notes"] == example["notes"]
            first_version = original["updatedAt"]

            status, _, body = http("/?api=rmas", "POST", {**example, "dateEntered": "2026-02-30"})
            assert_status(status, 422, body)
            status, _, body = http("/?api=rmas", "POST", {**example, "status": "Unknown"})
            assert_status(status, 422, body)
            status, _, body = http("/?api=rmas", "POST", example, send_token=False)
            assert_status(status, 403, body)

            update = {
                **example, "id": identifier, "updatedAt": first_version,
                "notes": "Updated note", "status": "Completed"
            }
            del update["extraDetails"]
            status, _, body = http("/?api=rmas", "PUT", update)
            assert_status(status, 200, body)

            status, _, body = http("/?api=rmas", "PUT", {**update, "notes": "Stale overwrite"})
            assert_status(status, 409, body)

            status, _, body = http("/?api=rmas")
            assert_status(status, 200)
            records = json.loads(body)["records"]
            assert len(records) == 1
            assert records[0]["notes"] == "Updated note"
            assert records[0]["status"] == "Completed"
            assert records[0]["extraDetails"] == example["extraDetails"], "Extra details were lost"
            assert records[0]["updatedAt"] != first_version

            # Snapshot a running database with an open HTTP session.
            backup = subprocess.run(
                ["php", "scripts/backup.php"], cwd=ROOT, env=env,
                check=True, capture_output=True, text=True
            )
            files = list((Path(data_dir) / "backups").glob("rma-*.sqlite"))
            assert len(files) == 1, "Expected exactly one SQLite backup"
            import sqlite3
            with sqlite3.connect(files[0]) as snapshot:
                assert snapshot.execute("SELECT COUNT(*) FROM rmas").fetchone()[0] == 1
                assert snapshot.execute("SELECT COUNT(*) FROM rma_history").fetchone()[0] == 2

            status, _, body = http("/?api=logout", "POST", {})
            assert_status(status, 200, body)
            status, _, body = http("/?api=rmas")
            assert_status(status, 401, body)
            for _ in range(10):
                status, _, body = http("/?api=auth", "POST", {"code": "wrong"})
                assert_status(status, 401, body)
            status, _, body = http("/?api=auth", "POST", {"code": "wrong"})
            assert_status(status, 429, body)
            print("RMA tracker: all HTTP smoke checks passed.")
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
            log.close()
            if config.exists():
                config.unlink()

if __name__ == "__main__":
    run()
