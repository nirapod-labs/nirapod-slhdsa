# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/tests/fakeapi.py
# =========================
#
# A stand-in for the GitHub REST API, for the tests: an HTTP server on the
# loopback interface that answers each path from `routes` and records
# every request. A route is looked up first with its query string, then
# without. Its value is JSON data, bytes (served as they are), or a
# function of the request that returns either. A path without a route
# answers 404.

import http.server
import json
import threading
import urllib.parse


class Server:
    def __init__(self):
        self.routes = {}
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append((method, self.path, self.headers.get("Authorization"), body))
                parsed = urllib.parse.urlsplit(self.path)
                route = outer.routes.get(self.path, outer.routes.get(parsed.path))
                if callable(route):
                    route = route(method, self.path, body)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                data = route if isinstance(route, bytes) else json.dumps(route).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.answer("GET")

            def do_POST(self):
                self.answer("POST")

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
