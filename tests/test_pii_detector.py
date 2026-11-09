import pytest
from app.services.pii_detector import detect_pii, mask_text


@pytest.mark.parametrize("card", [
    "4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111",
    "5555 5555 5555 4444", "3782 822463 10005", "6011111111111117",
])
def test_detects_luhn_valid_cards(card):
    text = f"my card is {card} thanks"
    findings = detect_pii(text)
    assert [f.detector for f in findings] == ["CREDIT_CARD"]
    assert mask_text(text, findings) == "my card is [CARD_REDACTED] thanks"


@pytest.mark.parametrize("not_card", ["4111 1111 1111 1112", "1234 5678 9012 3456", "order 20240101123456"])
def test_ignores_non_luhn_or_non_card_numbers(not_card):
    assert not any(f.detector == "CREDIT_CARD" for f in detect_pii(not_card))


def test_other_detectors():
    text = "mail a.b@example.com ssn 123-45-6789 aws AKIAIOSFODNN7EXAMPLE"
    masked = mask_text(text, detect_pii(text))
    assert masked == "mail [EMAIL_REDACTED] ssn [SSN_REDACTED] aws [AWS_KEY_REDACTED]"
