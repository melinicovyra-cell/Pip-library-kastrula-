"""
kastrula.http — HTTP-клиент с кастомным TLS fingerprint.
"""

from __future__ import annotations

import ssl
import random
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


# ---------------------------------------------------------------------------
# Preset fingerprint profiles
# ---------------------------------------------------------------------------

PROFILES: dict[str, dict] = {
    "chrome_120": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "headers_order": [
            "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "upgrade-insecure-requests",
            "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
            "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
            "accept-language",
        ],
        "extra_headers": {
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "upgrade-insecure-requests": "1",
            "connection": "keep-alive",
        },
        "http2": True,
    },
    "firefox_121": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
            "Gecko/20100101 Firefox/121.0"
        ),
        "headers_order": [
            "host", "user-agent", "accept", "accept-language",
            "accept-encoding", "connection", "upgrade-insecure-requests",
            "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
            "sec-fetch-user",
        ],
        "extra_headers": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "accept-encoding": "gzip, deflate, br",
            "connection": "keep-alive",
            "upgrade-insecure-requests": "1",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
        },
        "http2": True,
    },
    "safari_17": {
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.2 Safari/605.1.15"
        ),
        "headers_order": [
            "host", "accept", "sec-fetch-site", "sec-fetch-dest",
            "accept-language", "sec-fetch-mode", "user-agent",
            "accept-encoding",
        ],
        "extra_headers": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
        },
        "http2": True,
    },
    "curl": {
        "user_agent": "curl/8.4.0",
        "headers_order": ["host", "user-agent", "accept"],
        "extra_headers": {"accept": "*/*"},
        "http2": False,
    },
}


# ---------------------------------------------------------------------------
# Response wrapper
# ---------------------------------------------------------------------------

@dataclass
class KastResponse:
    """Обёртка над HTTP-ответом с удобными методами."""
    status_code: int
    headers: dict
    text: str
    content: bytes
    url: str
    elapsed_ms: float
    http_version: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> Any:
        import json
        return json.loads(self.text)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def server(self) -> str:
        return self.headers.get("server", "unknown")

    def __repr__(self) -> str:
        return f"<KastResponse [{self.status_code}] {self.url}>"


# ---------------------------------------------------------------------------
# Main HTTP Client
# ---------------------------------------------------------------------------

class KastClient:
    """
    HTTP-клиент с имитацией браузерного fingerprint.

    >>> client = KastClient(profile="chrome_120")
    >>> resp = client.get("https://httpbin.org/headers")
    >>> print(resp.json())

    >>> # Кастомный профиль
    >>> client = KastClient(user_agent="MyBot/1.0", http2=True)
    >>> resp = client.get("https://example.com")
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        user_agent: Optional[str] = None,
        http2: bool = True,
        proxy: Optional[str] = None,
        timeout: float = 30.0,
        follow_redirects: bool = True,
        extra_headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ):
        self.profile_name = profile
        self._profile = PROFILES.get(profile, {}) if profile else {}
        self._custom_ua = user_agent
        self._http2 = self._profile.get("http2", http2)
        self._proxy = proxy
        self._timeout = timeout
        self._follow_redirects = follow_redirects
        self._extra_headers = extra_headers or {}
        self._cookies = cookies or {}
        self._client: Optional[httpx.Client] = None

    def _build_headers(self, extra: Optional[dict] = None) -> dict:
        """Build headers matching the browser profile."""
        headers = {}

        # Start with profile headers
        if self._profile.get("extra_headers"):
            headers.update(self._profile["extra_headers"])

        # Set UA
        ua = self._custom_ua or self._profile.get("user_agent", f"kastrula/{__import__('kastrula').__version__}")
        headers["user-agent"] = ua

        # User overrides
        headers.update(self._extra_headers)
        if extra:
            headers.update(extra)

        return headers

    def _get_client(self) -> httpx.Client:
        """Lazy-init httpx client."""
        if self._client is None:
            self._client = httpx.Client(
                http2=self._http2,
                proxy=self._proxy,
                timeout=self._timeout,
                follow_redirects=self._follow_redirects,
                cookies=self._cookies,
            )
        return self._client

    def _wrap_response(self, resp: httpx.Response) -> KastResponse:
        """Convert httpx response to KastResponse."""
        return KastResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            content=resp.content,
            url=str(resp.url),
            elapsed_ms=resp.elapsed.total_seconds() * 1000,
            http_version=resp.http_version or "HTTP/1.1",
        )

    def get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> KastResponse:
        """GET-запрос."""
        client = self._get_client()
        h = self._build_headers(headers)
        resp = client.get(url, params=params, headers=h)
        return self._wrap_response(resp)

    def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[dict] = None,
    ) -> KastResponse:
        """POST-запрос."""
        client = self._get_client()
        h = self._build_headers(headers)
        resp = client.post(url, data=data, json=json, headers=h)
        return self._wrap_response(resp)

    def head(self, url: str, headers: Optional[dict] = None) -> KastResponse:
        """HEAD-запрос."""
        client = self._get_client()
        h = self._build_headers(headers)
        resp = client.head(url, headers=h)
        return self._wrap_response(resp)

    def put(self, url: str, data: Optional[Any] = None, json: Optional[Any] = None, headers: Optional[dict] = None) -> KastResponse:
        """PUT-запрос."""
        client = self._get_client()
        h = self._build_headers(headers)
        resp = client.put(url, data=data, json=json, headers=h)
        return self._wrap_response(resp)

    def delete(self, url: str, headers: Optional[dict] = None) -> KastResponse:
        """DELETE-запрос."""
        client = self._get_client()
        h = self._build_headers(headers)
        resp = client.delete(url, headers=h)
        return self._wrap_response(resp)

    def close(self):
        """Закрыть клиент."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        name = self.profile_name or "custom"
        return f"<KastClient profile={name} http2={self._http2}>"

    @staticmethod
    def available_profiles() -> list[str]:
        """Список доступных профилей."""
        return list(PROFILES.keys())


# ---------------------------------------------------------------------------
# Retry wrapper
# ---------------------------------------------------------------------------

import time as _time
import random as _random


class RetryClient(KastClient):
    """
    HTTP-клиент с автоматическим retry и exponential backoff.

    >>> client = RetryClient(profile="chrome_120", retries=3, backoff=1.0)
    >>> resp = client.get("https://flaky-api.com/data")
    """

    def __init__(
        self,
        retries: int = 3,
        backoff: float = 1.0,
        retry_statuses: tuple = (429, 500, 502, 503, 504),
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._retries = retries
        self._backoff = backoff
        self._retry_statuses = retry_statuses

    def _with_retry(self, method, *args, **kwargs):
        last_exc = None
        for attempt in range(self._retries + 1):
            try:
                resp = method(*args, **kwargs)
                if resp.status_code not in self._retry_statuses:
                    return resp
                if attempt < self._retries:
                    delay = self._backoff * (2 ** attempt) + _random.uniform(0, 0.5)
                    _time.sleep(delay)
                else:
                    return resp
            except Exception as e:
                last_exc = e
                if attempt < self._retries:
                    delay = self._backoff * (2 ** attempt)
                    _time.sleep(delay)
                else:
                    raise last_exc

    def get(self, url, **kwargs):
        return self._with_retry(super().get, url, **kwargs)

    def post(self, url, **kwargs):
        return self._with_retry(super().post, url, **kwargs)

    def head(self, url, **kwargs):
        return self._with_retry(super().head, url, **kwargs)

    def put(self, url, **kwargs):
        return self._with_retry(super().put, url, **kwargs)

    def delete(self, url, **kwargs):
        return self._with_retry(super().delete, url, **kwargs)


# ---------------------------------------------------------------------------
# Session with cookie jar & history
# ---------------------------------------------------------------------------

@dataclass
class KastCookieJar:
    """Простой cookie jar с экспортом/импортом."""
    _cookies: dict = None

    def __post_init__(self):
        if self._cookies is None:
            self._cookies = {}

    def set(self, name: str, value: str, domain: str = "") -> None:
        self._cookies[name] = {"value": value, "domain": domain}

    def get(self, name: str) -> Optional[str]:
        c = self._cookies.get(name)
        return c["value"] if c else None

    def delete(self, name: str) -> None:
        self._cookies.pop(name, None)

    def clear(self) -> None:
        self._cookies.clear()

    def to_dict(self) -> dict:
        return {k: v["value"] for k, v in self._cookies.items()}

    def to_header(self) -> str:
        return "; ".join(f"{k}={v['value']}" for k, v in self._cookies.items())

    @classmethod
    def from_dict(cls, d: dict) -> 'KastCookieJar':
        jar = cls()
        for k, v in d.items():
            jar.set(k, v)
        return jar

    def __len__(self) -> int:
        return len(self._cookies)

    def __repr__(self) -> str:
        return f"<KastCookieJar cookies={len(self._cookies)}>"


class KastSession(KastClient):
    """
    HTTP-сессия с persistent cookies, историей и retry.

    >>> session = KastSession(profile="chrome_120")
    >>> session.get("https://httpbin.org/cookies/set?name=value")
    >>> print(session.cookies)
    >>> resp = session.get("https://httpbin.org/cookies")
    >>> print(resp.json())  # покажет сохранённые cookies
    """

    def __init__(self, retries: int = 0, backoff: float = 1.0, **kwargs):
        super().__init__(**kwargs)
        self.cookies = KastCookieJar()
        self.history: list[KastResponse] = []
        self._retries = retries
        self._backoff = backoff

    def _update_cookies_from_response(self, resp: KastResponse) -> None:
        """Extract Set-Cookie headers and update jar."""
        import re
        for key in ("set-cookie", "Set-Cookie"):
            val = resp.headers.get(key, "")
            if val:
                # Parse simple cookie
                match = re.match(r"([^=]+)=([^;]*)", val)
                if match:
                    self.cookies.set(match.group(1).strip(), match.group(2).strip())

    def _inject_cookies(self, headers: Optional[dict]) -> dict:
        """Add cookies to headers."""
        h = headers or {}
        if self.cookies:
            existing = h.get("cookie", "")
            jar_cookies = self.cookies.to_header()
            if existing:
                h["cookie"] = f"{existing}; {jar_cookies}"
            else:
                h["cookie"] = jar_cookies
        return h

    def _request_with_session(self, method, url, **kwargs):
        """Make request with session cookies and retry."""
        kwargs["headers"] = self._inject_cookies(kwargs.get("headers"))

        last_exc = None
        for attempt in range(self._retries + 1):
            try:
                resp = method(url, **kwargs)
                self._update_cookies_from_response(resp)
                self.history.append(resp)

                if resp.status_code not in (429, 500, 502, 503, 504):
                    return resp
                if attempt < self._retries:
                    _time.sleep(self._backoff * (2 ** attempt))
                else:
                    return resp
            except Exception as e:
                last_exc = e
                if attempt < self._retries:
                    _time.sleep(self._backoff * (2 ** attempt))
                else:
                    raise

    def get(self, url, **kwargs):
        return self._request_with_session(super().get, url, **kwargs)

    def post(self, url, **kwargs):
        return self._request_with_session(super().post, url, **kwargs)

    def head(self, url, **kwargs):
        return self._request_with_session(super().head, url, **kwargs)
