from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class InterceptedRequest:
    method: str = "GET"
    url: str = ""
    path: str = ""
    host: str = ""
    port: int = 80
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    cookies: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, object] = field(default_factory=dict)
    timestamp: float = 0.0
    source_pid: Optional[int] = None
    source_tool: Optional[str] = None
    is_tunnel: bool = False
    is_https: bool = False
    sni_hostname: Optional[str] = None
    tls_version: Optional[str] = None
    http_version: str = "1.1"


@dataclass
class InterceptedResponse:
    status_code: int = 0
    status_text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    cookies: Dict[str, str] = field(default_factory=dict)
    response_time: float = 0.0
    timestamp: float = 0.0
    is_https: bool = False
    tls_version: Optional[str] = None
    http_version: str = "1.1"


@dataclass
class ProxyRecord:
    request: InterceptedRequest = field(default_factory=InterceptedRequest)
    response: InterceptedResponse = field(default_factory=InterceptedResponse)
    technique_applied: str = ""
    passed: bool = False
    blocked: bool = False
    total_time: float = 0.0
    intercepted_https: bool = False
    decryption_successful: bool = False


@dataclass
class AdvisorDecision:
    action: str = "forward"
    technique: str = ""
    delay: float = 0.0
    rotate_ip: bool = False
    reason: str = ""
    forward_response: bool = True
    next_protocol: Optional[str] = None
