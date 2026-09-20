"""Pytest Test Suite for Kerberos AS Exchange Backend.

Covers the 10 required test scenarios:
1. Valid AS exchange
2. Unknown principal
3. Unsupported service
4. Stale timestamp
5. Invalid request schema
6. Correct-key decryption
7. Incorrect-key decryption failure
8. Unique session keys for separate requests
9. No sensitive values in API responses
10. Existing health-check endpoint
"""

from datetime import datetime, timedelta, timezone
import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from app.core.crypto import (
    decrypt_aes_gcm,
    derive_key_from_password,
)
from app.main import app
from app.services.kdc import kdc_service

client = TestClient(app)


def get_fresh_timestamp(offset_seconds: int = 0) -> str:
    """Helper to generate ISO 8601 UTC timestamp."""
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.isoformat()


# --------------------------------------------------------------------------
# Test 1: Valid AS Exchange
# --------------------------------------------------------------------------
def test_valid_as_exchange():
    payload = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 98765432,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    response = client.post("/api/kerberos/as-request", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["msg_type"] == "KRB_AS_REP"
    assert data["pvno"] == 5
    assert data["cname"] == "alice@CANARA.EDU"
    assert data["crealm"] == "CANARA.EDU"

    # Ticket assertions
    ticket = data["ticket"]
    assert ticket["sname"] == "krbtgt/CANARA.EDU"
    assert "cipher_b64" in ticket and len(ticket["cipher_b64"]) > 0
    assert "nonce_b64" in ticket and len(ticket["nonce_b64"]) > 0
    assert ticket["encryption_type"] == "AES-256-GCM"

    # Client encrypted part assertions
    enc_part = data["enc_part"]
    assert "cipher_b64" in enc_part and len(enc_part["cipher_b64"]) > 0
    assert "nonce_b64" in enc_part and len(enc_part["nonce_b64"]) > 0
    assert enc_part["encryption_type"] == "AES-256-GCM"

    # Telemetry assertions (8 standard steps)
    telemetry = data["telemetry"]
    assert len(telemetry) == 8
    step_names = [s["name"] for s in telemetry]
    assert "Request received." in step_names
    assert "Principal validated." in step_names
    assert "KDC lookup completed." in step_names
    assert "Session key generated." in step_names
    assert "TGT constructed." in step_names
    assert "TGT encrypted." in step_names
    assert "Client response encrypted." in step_names
    assert "AS response generated." in step_names


# --------------------------------------------------------------------------
# Test 2: Unknown Principal
# --------------------------------------------------------------------------
def test_unknown_principal():
    payload = {
        "cname": "unknown_user@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 11223344,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    response = client.post("/api/kerberos/as-request", json=payload)
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "KDC_ERR_C_PRINCIPAL_UNKNOWN"
    assert "not registered" in data["message"].lower() or "not found" in data["message"].lower()


# --------------------------------------------------------------------------
# Test 3: Unsupported Service
# --------------------------------------------------------------------------
def test_unsupported_service():
    payload = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "ldap/CANARA.EDU",  # AS only accepts krbtgt
        "nonce": 22334455,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    response = client.post("/api/kerberos/as-request", json=payload)
    # Pydantic validation rejects it with 422
    assert response.status_code in [400, 422]
    content = response.text
    assert "Unsupported service" in content or "krbtgt" in content


# --------------------------------------------------------------------------
# Test 4: Stale Timestamp
# --------------------------------------------------------------------------
def test_stale_timestamp():
    # 15 minutes in the past (> 300s skew window)
    stale_time = get_fresh_timestamp(-900)
    payload = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 33445566,
        "timestamp": stale_time,
        "lifetime": 36000,
    }
    response = client.post("/api/kerberos/as-request", json=payload)
    assert response.status_code in [400, 422]
    content = response.text
    assert "clock skew" in content.lower() or "skew" in content.lower()


# --------------------------------------------------------------------------
# Test 5: Invalid Request Schema
# --------------------------------------------------------------------------
def test_invalid_request_schema():
    # Lifetime below minimum (50 seconds < 300 seconds)
    payload_bad_lifetime = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 44556677,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 50,
    }
    r1 = client.post("/api/kerberos/as-request", json=payload_bad_lifetime)
    assert r1.status_code == 422

    # Negative nonce
    payload_bad_nonce = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": -10,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    r2 = client.post("/api/kerberos/as-request", json=payload_bad_nonce)
    assert r2.status_code == 422

    # Missing cname
    payload_missing = {
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 12345,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    r3 = client.post("/api/kerberos/as-request", json=payload_missing)
    assert r3.status_code == 422


# --------------------------------------------------------------------------
# Test 6: Correct-Key Decryption
# --------------------------------------------------------------------------
def test_correct_key_decryption():
    test_nonce = 55667788
    payload = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": test_nonce,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    response = client.post("/api/kerberos/as-request", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Derive Alice's key from known password
    alice_key = derive_key_from_password("AlicePassword123!", "CANARA.EDUalice")

    # Decrypt client encrypted part
    decrypted_client_part = decrypt_aes_gcm(
        key=alice_key,
        ciphertext_b64=data["enc_part"]["cipher_b64"],
        nonce_b64=data["enc_part"]["nonce_b64"],
    )

    assert "session_key" in decrypted_client_part
    assert decrypted_client_part["nonce"] == test_nonce
    assert decrypted_client_part["sname"] == "krbtgt/CANARA.EDU"

    # Decrypt TGT using TGS master key
    tgs_key = kdc_service.get_tgs_key()
    decrypted_tgt = decrypt_aes_gcm(
        key=tgs_key,
        ciphertext_b64=data["ticket"]["cipher_b64"],
        nonce_b64=data["ticket"]["nonce_b64"],
    )

    assert decrypted_tgt["cname"] == "alice@CANARA.EDU"
    # The session key in the TGT must match the session key delivered to client!
    assert decrypted_tgt["session_key"] == decrypted_client_part["session_key"]


# --------------------------------------------------------------------------
# Test 7: Incorrect-Key Decryption Failure
# --------------------------------------------------------------------------
def test_incorrect_key_decryption_failure():
    payload = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 66778899,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    response = client.post("/api/kerberos/as-request", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Wrong password key derivation
    wrong_key = derive_key_from_password("WrongAttackerPassword!", "CANARA.EDUalice")

    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(
            key=wrong_key,
            ciphertext_b64=data["enc_part"]["cipher_b64"],
            nonce_b64=data["enc_part"]["nonce_b64"],
        )


# --------------------------------------------------------------------------
# Test 8: Unique Session Keys for Separate Requests
# --------------------------------------------------------------------------
def test_unique_session_keys_for_separate_requests():
    alice_key = derive_key_from_password("AlicePassword123!", "CANARA.EDUalice")

    p1 = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 77889900,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    r1 = client.post("/api/kerberos/as-request", json=p1)
    data1 = r1.json()

    p2 = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 77889901,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    r2 = client.post("/api/kerberos/as-request", json=p2)
    data2 = r2.json()

    dec1 = decrypt_aes_gcm(
        key=alice_key,
        ciphertext_b64=data1["enc_part"]["cipher_b64"],
        nonce_b64=data1["enc_part"]["nonce_b64"],
    )
    dec2 = decrypt_aes_gcm(
        key=alice_key,
        ciphertext_b64=data2["enc_part"]["cipher_b64"],
        nonce_b64=data2["enc_part"]["nonce_b64"],
    )

    # Every request MUST receive a distinct, freshly generated session key
    assert dec1["session_key"] != dec2["session_key"]

    # Nonces for ciphertext operations must also be distinct
    assert data1["ticket"]["nonce_b64"] != data2["ticket"]["nonce_b64"]
    assert data1["enc_part"]["nonce_b64"] != data2["enc_part"]["nonce_b64"]


# --------------------------------------------------------------------------
# Test 9: No Sensitive Values in API Responses
# --------------------------------------------------------------------------
def test_no_sensitive_values_in_api_responses():
    payload = {
        "cname": "alice@CANARA.EDU",
        "realm": "CANARA.EDU",
        "sname": "krbtgt/CANARA.EDU",
        "nonce": 88990011,
        "timestamp": get_fresh_timestamp(0),
        "lifetime": 36000,
    }
    response = client.post("/api/kerberos/as-request", json=payload)
    assert response.status_code == 200

    raw_text = response.text

    # Never expose plaintext passwords or internal passphrases
    assert "AlicePassword123!" not in raw_text
    assert "BobPassword456!" not in raw_text
    assert "kdc_master_tgs_passphrase" not in raw_text

    # Ensure principals endpoint also never leaks secrets
    principals_resp = client.get("/api/kerberos/principals")
    assert principals_resp.status_code == 200
    p_text = principals_resp.text
    assert "password" not in p_text.lower()
    assert "salt" not in p_text.lower()
    assert "key" not in p_text.lower()


# --------------------------------------------------------------------------
# Test 10: Existing Health-Check Endpoint
# --------------------------------------------------------------------------
def test_existing_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert "BCS703" in data["course"]
    assert data["college"] == "Canara Engineering College"
    assert "4CB23CS160" in data["team_members"]
    assert "4CB23CS161" in data["team_members"]
    assert data["ready_for_kerberos"] is True
