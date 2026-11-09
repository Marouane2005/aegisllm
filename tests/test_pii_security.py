import pytest
from app.services.pii_detector import detect_pii, mask_text


def _kinds(text):
    return [f.detector for f in detect_pii(text)]


@pytest.mark.parametrize("text,detector,secret", [
    ("mail me at jane.doe@example.com today", "EMAIL", "jane.doe@example.com"),
    ("call 415-555-2671 please", "PHONE", "415-555-2671"),
    ("or (415) 555-2671", "PHONE", "(415) 555-2671"),
    ("intl +1 415 555 2671", "PHONE", "+1 415 555 2671"),
    ("uk +44 20 7946 0958", "PHONE", "+44 20 7946 0958"),
    ("visa 4111111111111111", "CREDIT_CARD", "4111111111111111"),
    ("visa 4111 1111 1111 1111", "CREDIT_CARD", "4111 1111 1111 1111"),
    ("visa 4111-1111-1111-1111", "CREDIT_CARD", "4111-1111-1111-1111"),
    ("mc 5555 5555 5555 4444", "CREDIT_CARD", "5555 5555 5555 4444"),
    ("mc2 2223000048400011", "CREDIT_CARD", "2223000048400011"),
    ("amex 3782 822463 10005", "CREDIT_CARD", "3782 822463 10005"),
    ("disc 6011111111111117", "CREDIT_CARD", "6011111111111117"),
    ("diners 30569309025904", "CREDIT_CARD", "30569309025904"),
    ("iban GB82WEST12345698765432", "IBAN", "GB82WEST12345698765432"),
    ("iban GB82 WEST 1234 5698 7654 32", "IBAN", "GB82 WEST 1234 5698 7654 32"),
    ("ssn 123-45-6789", "SSN", "123-45-6789"),
    ("nino AB 12 34 56 C", "NINO", "AB 12 34 56 C"),
    ("dni 12345678Z", "ES_DNI", "12345678Z"),
    ("from 8.8.8.8", "IP_ADDRESS", "8.8.8.8"),
    ("key AKIAIOSFODNN7EXAMPLE", "AWS_KEY", "AKIAIOSFODNN7EXAMPLE"),
])
def test_detects_labeled_pii(text, detector, secret):
    findings = detect_pii(text)
    matched = [f for f in findings if f.detector == detector]
    assert matched, findings
    assert matched[0].original == secret
    masked = mask_text(text, findings)
    assert secret not in masked


@pytest.mark.parametrize("text", [
    "order 20240101123456",
    "4111 1111 1111 1112",
    "1234 5678 9012 3456",
    "not a card 1234567890123",
    "bad iban GB00WEST12345698765432",
    "ssn 000-12-3456",
    "ssn 666-12-3456",
    "ssn 123-45-0000",
    "ssn 900-12-3456",
    "nino BG123456A",
    "nino ZZ123456A",
    "dni 12345678A",
    "version 1.2.3",
    "total $19.99 on 2024-11-09",
    "user@localhost",
    "port 8080",
    "build 415555",
    "uuid 550e8400-e29b-41d4-a716-446655440000",
    "see section 4.1.1 of the rfc",
    "the meeting is at 4",
    "sku AB12",
])
def test_pii_false_positives(text):
    assert detect_pii(text) == []


def test_card_does_not_swallow_a_nearby_phone():
    text = "card 4111111111111111 and phone 415-555-2671"
    kinds = _kinds(text)
    assert kinds == ["CREDIT_CARD", "PHONE"]
    masked = mask_text(text, detect_pii(text))
    assert "4111111111111111" not in masked
    assert "415-555-2671" not in masked


def test_mixed_message_masks_every_kind():
    text = "mail a@b.co phone +44 20 7946 0958 iban DE89370400440532013000"
    # DE89 is a well-known valid IBAN.
    findings = detect_pii(text)
    masked = mask_text(text, findings)
    assert "a@b.co" not in masked
    assert "7946" not in masked
    assert "DE89370400440532013000" not in masked
