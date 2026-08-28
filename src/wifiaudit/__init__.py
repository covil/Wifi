"""wifiaudit — an authorized-use WiFi security auditing toolkit.

Stages: discovery (implemented), capture, crack, report (planned).
Every stage runs behind the authorization gate in :mod:`wifiaudit.core.authorization`
and records to the tamper-evident log in :mod:`wifiaudit.core.audit`.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
