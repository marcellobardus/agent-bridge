"""Enrollment result page: the otpauth URI as an inline SVG QR code plus the secret as text, shown once."""
import urllib.parse

import segno
from markupsafe import Markup

from .render import render


def qr_svg(uri: str) -> Markup:
    """segno emits only attributes (no inline style/script), so the strict CSP holds. Input is server-generated."""
    return Markup(segno.make(uri, error="m").svg_inline(scale=5, border=4, dark="#000", light="#fff",
                                                        title="TOTP enrollment QR code"))


def enrolled_page(request, res: dict):
    uri = res["otpauth_uri"]
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)["secret"][0]
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render(request, "enrolled.html", qr=qr_svg(uri), secret=grouped)
