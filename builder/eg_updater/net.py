"""HTTPS for EagleGuard's downloads.

Python checks certificates against its own view of trusted roots and does not
download missing intermediate certificates the way Windows and browsers do. Some
servers (e.g. urlhaus-api.abuse.ch) send an incomplete chain, so Python fails with
CERTIFICATE_VERIFY_FAILED "unable to get local issuer certificate" while the
browser opens the same site fine. ``truststore`` hands the check to Windows itself
(same verification as Edge/Chrome, including fetching intermediates). Without it,
Python's default verification is used. Verification is never switched off.
"""
from __future__ import annotations

import ssl
import urllib.request

_CONTEXT: ssl.SSLContext | None = None


def tls_context() -> ssl.SSLContext:
    global _CONTEXT
    if _CONTEXT is None:
        try:
            import truststore  # type: ignore
            _CONTEXT = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception:  # not installed / unsupported platform
            _CONTEXT = ssl.create_default_context()
    return _CONTEXT


def backend() -> str:
    return "system (truststore)" if type(tls_context()).__module__.startswith("truststore") else "python"


def urlopen(request, timeout: float):
    return urllib.request.urlopen(request, timeout=timeout, context=tls_context())
