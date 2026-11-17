import pytest

from detect_secrets.plugins.telegram_token import TelegramBotTokenDetector


# Two well-formed tokens used as fixtures: a 9-digit and a 10-digit bot id.
TOKEN_9_DIGITS = '110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw'
TOKEN_10_DIGITS = '7213808860:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM'


class TestTelegramTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('bot110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw', False),
            ('110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw', True),
            ('7213808860:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM', True),
            ('foo:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM', False),
            ('foo', False),
            ('arn:aws:sns:aaa:111122223333:aaaaaaaaaaaaaaaaaaassssssddddddddddddd', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = TelegramBotTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, expected_token',
        [
            # Assignment: keyword = value, with and without surrounding quotes.
            ('TELEGRAM_TOKEN = "{}"'.format(TOKEN_9_DIGITS), TOKEN_9_DIGITS),
            ('token={}'.format(TOKEN_10_DIGITS), TOKEN_10_DIGITS),
            # YAML mapping value, bare and quoted.
            ('telegram_bot_token: {}'.format(TOKEN_9_DIGITS), TOKEN_9_DIGITS),
            ('telegram_bot_token: "{}"'.format(TOKEN_10_DIGITS), TOKEN_10_DIGITS),
            # URL: carried as a query parameter or as a non-``bot`` path segment.
            ('https://example.com/relay?token={}'.format(TOKEN_9_DIGITS), TOKEN_9_DIGITS),
            ('https://example.com/webhook/{}/update'.format(TOKEN_10_DIGITS), TOKEN_10_DIGITS),
            # Shell export, bare and quoted.
            ('export TELEGRAM_BOT_TOKEN={}'.format(TOKEN_9_DIGITS), TOKEN_9_DIGITS),
            ('export TELEGRAM_BOT_TOKEN="{}"'.format(TOKEN_10_DIGITS), TOKEN_10_DIGITS),
        ],
    )
    def test_detects_embedded_token(self, payload, expected_token):
        logic = TelegramBotTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        # Each embedded form must produce exactly one finding, whose value is the
        # token itself rather than a surrounding fragment of the line.
        assert len(output) == 1
        assert {secret.secret_value for secret in output} == {expected_token}

    @pytest.mark.parametrize(
        'payload',
        [
            # Whole-line ``bot``-prefixed form stays a negative (historical constraint).
            'bot110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw',
            # Telegram getMe API URL: the token is glued to the ``bot`` path segment.
            'https://api.telegram.org/bot{}/getMe'.format(TOKEN_9_DIGITS),
            # Token glued to a leading identifier / digit (no delimiter).
            'abc{}'.format(TOKEN_9_DIGITS),
            '0{}'.format(TOKEN_10_DIGITS),
            # Token that is only a prefix of a longer identifier on the right.
            '{}A'.format(TOKEN_9_DIGITS),
            '{}_extra'.format(TOKEN_10_DIGITS),
            '{}-more'.format(TOKEN_10_DIGITS),
        ],
    )
    def test_ignores_false_positive_boundaries(self, payload):
        logic = TelegramBotTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        assert output == set()
