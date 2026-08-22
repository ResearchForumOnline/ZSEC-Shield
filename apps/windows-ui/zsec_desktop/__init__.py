"""Unprivileged ZSEC Antivirus desktop client.

The Community package consumes versioned CLI contracts.  It deliberately contains no
antivirus-provider, service-installation, exclusion, or provider-removal code.
"""

from zsec_desktop.bridge import ZsecBridge

__all__ = ["ZsecBridge"]
