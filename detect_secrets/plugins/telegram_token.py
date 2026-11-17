"""
This plugin searches for Telegram bot tokens
"""
import re

import requests

from ..constants import VerifiedResult
from detect_secrets.plugins.base import RegexBasedDetector


class TelegramBotTokenDetector(RegexBasedDetector):
    """Scans for Telegram bot tokens."""
    secret_type = 'Telegram Bot Token'

    denylist = [
        # refs https://core.telegram.org/bots/api#authorizing-your-bot
        #
        # The token body is ``<8-10 digits>:<35 chars of [0-9A-Za-z_-]>``. Rather than
        # anchoring the pattern to a whole line (``^...$``), we delimit it with
        # zero-width lookarounds so that the same body is still detected when it is
        # embedded in assignments, YAML values, URLs or shell exports. The boundary
        # character class mirrors the token alphabet, which keeps the historical
        # false-positive constraints intact:
        #   * the leading ``(?<![0-9A-Za-z_-])`` rejects a token glued to an identifier
        #     (e.g. the ``bot`` prefix in ``bot<token>`` or ``/bot<token>`` API URLs)
        #     and a longer digit run (e.g. the 12-digit number inside an AWS ARN, where
        #     an internal offset would otherwise satisfy the 8-10 digit quantifier);
        #   * the trailing ``(?![0-9A-Za-z_-])`` rejects a token that is only a prefix
        #     of a longer identifier (e.g. the 38-char suffix of an AWS ARN).
        # Whitespace, quotes and the ``= : / ? &`` separators used by real embedding
        # contexts are all outside the token alphabet, so they delimit a valid match.
        re.compile(
            r'(?<![0-9A-Za-z_-])\d{8,10}:[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])',
        ),
    ]

    def verify(self, secret: str) -> VerifiedResult:  # pragma: no cover
        response = requests.get(
            'https://api.telegram.org/bot{}/getMe'.format(
                secret,
            ),
        )
        return (
            VerifiedResult.VERIFIED_TRUE
            if response.status_code == 200
            else VerifiedResult.VERIFIED_FALSE
        )
