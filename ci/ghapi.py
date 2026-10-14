# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/ghapi.py
# =================
#
# A small client for the GitHub REST API, for the CI scripts that read runs,
# jobs and artifacts of this repository. Standard library only. The token
# comes from GH_TOKEN (the workflow's GITHUB_TOKEN); the API root from
# GITHUB_API_URL, as GitHub sets it on its runners.
#
# Every failure raises ApiError: an HTTP error, a network error that
# persists after one retry, or an answer that is not what the endpoint
# returns. Callers decide what an error means for them; none of them reads
# an error as "nothing found".
#
# The token is sent to the API host only. Artifact downloads answer with a
# redirect to a storage URL that carries its own signature; the token is
# not forwarded there (urllib drops headers added as "unredirected").

import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


class ApiError(Exception):
    pass


class Api:
    def __init__(self, repository, token=None, root=None, timeout=60, pause=5):
        if not repository or repository.count("/") != 1:
            raise ApiError(f"repository must be owner/name, not {repository!r}")
        self.repository = repository
        self.token = token if token is not None else os.environ.get("GH_TOKEN", "")
        self.root = (root or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        self.timeout = timeout
        self.pause = pause
        self.calls = 0

    def _request(self, method, url, data=None):
        req = urllib.request.Request(url, method=method, data=data)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "nirapod-slhdsa-ci")
        if self.token:
            req.add_unredirected_header("Authorization", f"Bearer {self.token}")
        # A GET that meets a server error or a lost connection is tried once
        # more after a pause; a client error (4xx), and any POST, is not.
        last = 2 if method == "GET" else 1
        for attempt in range(1, last + 1):
            self.calls += 1
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                e.close()
                if e.code < 500 or attempt == last:
                    raise ApiError(f"{method} {url}: HTTP {e.code} {e.reason}") from None
            except (urllib.error.URLError, OSError) as e:
                if attempt == last:
                    raise ApiError(f"{method} {url}: {e}") from None
            time.sleep(self.pause)

    def url(self, path, **query):
        q = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        return f"{self.root}/repos/{self.repository}/{path}" + (f"?{q}" if q else "")

    def get(self, path, **query):
        _, body = self._request("GET", self.url(path, **query))
        try:
            return json.loads(body)
        except ValueError:
            raise ApiError(f"GET {path}: the answer is not JSON") from None

    def post(self, path, payload=None):
        data = json.dumps(payload or {}).encode()
        status, _ = self._request("POST", self.url(path), data=data)
        return status

    def pages(self, path, key, limit=None, **query):
        """The items under KEY of every page of PATH, at most LIMIT of them."""
        items, page = [], 1
        while True:
            body = self.get(path, per_page=100, page=page, **query)
            if not isinstance(body, dict) or not isinstance(body.get(key), list):
                raise ApiError(f"GET {path}: no list '{key}' in the answer")
            items.extend(body[key])
            if len(body[key]) < 100 or (limit is not None and len(items) >= limit):
                return items[:limit] if limit is not None else items
            page += 1

    def artifact_zip(self, artifact_id):
        """The members of an artifact, as a ZipFile in memory."""
        _, body = self._request("GET", self.url(f"actions/artifacts/{int(artifact_id)}/zip"))
        try:
            return zipfile.ZipFile(io.BytesIO(body))
        except zipfile.BadZipFile:
            raise ApiError(f"artifact {artifact_id}: not a zip archive") from None
