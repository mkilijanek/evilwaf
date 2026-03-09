from __future__ import annotations

import ssl
import threading
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional

from chemistry.tcp_options import TCPOptionsManipulator
from chemistry.tls_rotator import TLSFingerprinter
from chemistry.tor_rotator import TorRotator
from core.models import (
    AdvisorDecision,
    InterceptedRequest,
    InterceptedResponse,
    ProxyRecord,
)


class ResponseAdvisor:
    ROTATE_ON = (429, 503, 509)
    RETRY_TECH = (403, 406, 418)
    PASS = (200, 201, 204, 301, 302, 304, 404)

    def __init__(self, magic: "Magic", max_retries: int = 3, retry_delay: float = 1.5):
        self._magic = magic
        self._max = max_retries
        self._delay = retry_delay
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()

    def advise(
        self,
        response: InterceptedResponse,
        request: InterceptedRequest,
        record: ProxyRecord,
    ) -> AdvisorDecision:
        code = response.status_code
        if code in self.PASS:
            self._reset(request.host)
            return AdvisorDecision(action="forward", reason=f"{code} pass")
        if code in self.RETRY_TECH:
            return self._retry(request, record, reason=f"{code} waf block")
        if code in self.ROTATE_ON:
            return self._rotate_and_retry(response, request, record)
        return AdvisorDecision(action="forward", reason=f"{code} default")

    def _retry(
        self, request: InterceptedRequest, record: ProxyRecord, reason: str
    ) -> AdvisorDecision:
        if not self._has_left(request.host):
            return AdvisorDecision(action="forward", reason="max retries")
        self._inc(request.host)
        return AdvisorDecision(
            action="retry", delay=self._delay, reason=reason, forward_response=False
        )

    def _rotate_and_retry(
        self,
        response: InterceptedResponse,
        request: InterceptedRequest,
        record: ProxyRecord,
    ) -> AdvisorDecision:
        if not self._has_left(request.host):
            return AdvisorDecision(action="forward", reason="max retries")
        delay = self._get_delay(response)
        self._inc(request.host)
        return AdvisorDecision(
            action="rotate_and_retry",
            delay=delay,
            rotate_ip=True,
            reason="rate limited",
            forward_response=False,
        )

    def _has_left(self, host: str) -> bool:
        with self._lock:
            return self._counts.get(host, 0) < self._max

    def _inc(self, host: str) -> None:
        with self._lock:
            self._counts[host] = self._counts.get(host, 0) + 1

    def _reset(self, host: str) -> None:
        with self._lock:
            self._counts.pop(host, None)

    def _get_delay(self, response: InterceptedResponse) -> float:
        ra = response.headers.get("retry-after", "").strip()
        if ra.isdigit():
            return min(float(ra), 60.0)
        return self._delay


class Magic:
    def __init__(
        self,
        tcp: Optional[TCPOptionsManipulator] = None,
        tls: Optional[TLSFingerprinter] = None,
        tor: Optional[TorRotator] = None,
        rotate_every: int = 1,
    ):
        self._tcp = tcp or TCPOptionsManipulator()
        self._tls = tls or TLSFingerprinter()
        self._tor = tor or TorRotator()
        self._lock = threading.Lock()
        self._request_count = 0
        self._rotate_every = max(1, rotate_every)

    def apply(self, technique: str = "") -> Dict[str, Any]:
        with self._lock:
            self._request_count += 1
        tcp_opts = self._tcp.per_request_options()
        tls_sess, tls_id = self._tls.paired_with_tcp(tcp_opts.get("profile", ""))
        result = {
            "tcp": tcp_opts,
            "tls": {"session": tls_sess, "identifier": tls_id},
            "tor": {},
        }
        if technique == "ip_rotation" or self._tor.should_rotate(
            self._request_count, self._rotate_every
        ):
            if self._tor.is_tor_alive():
                ok, ip = self._tor.rotate_and_verify()
                result["tor"] = {
                    "active": ok,
                    "ip": ip,
                    "proxies": self._tor.get_proxy_dict(),
                }
        return result

    def _bind_to_tor(self) -> Dict[str, Any]:
        if not self._tor.is_tor_alive():
            return {"active": False}
        ok, ip = self._tor.rotate_and_verify()
        return {"active": ok, "ip": ip, "proxies": self._tor.get_proxy_dict()}

    def error_solver(self, error: Exception, context: str = "") -> bool:
        if isinstance(error, ssl.SSLError):
            try:
                self._tls.rotate()
            except Exception:
                pass
        if isinstance(error, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            try:
                self._tcp.rotate()
            except Exception:
                pass
        return True


class Forwarder:
    def forward(
        self, response: InterceptedResponse, handler: BaseHTTPRequestHandler
    ) -> bool:
        try:
            if response.status_code == 0:
                response.status_code = 502
                response.status_text = "Bad Gateway"
            handler.send_response(response.status_code, response.status_text)
            skip = {"transfer-encoding", "connection", "keep-alive"}
            for k, v in response.headers.items():
                if k.lower() not in skip:
                    handler.send_header(k, v)
            handler.send_header("Connection", "close")
            if response.body:
                handler.send_header("Content-Length", str(len(response.body)))
            handler.end_headers()
            if response.body and handler.command != "HEAD":
                handler.wfile.write(response.body)
            return True
        except Exception:
            return False
