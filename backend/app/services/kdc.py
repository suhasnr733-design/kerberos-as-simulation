"""Kerberos Key Distribution Center (KDC) and Authentication Server (AS) Engine.

Manages:
- In-memory mock database of Kerberos principals (Alice and Bob)
- Master service key K_TGS for ticket issuance
- Client key derivation via PBKDF2
- Complete 11-step Kerberos AS Exchange pipeline
- Educational telemetry generation (without leaking secrets)
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from app.core.crypto import (
    derive_key_from_password,
    encrypt_aes_gcm,
    generate_session_key,
)
from app.models.kerberos import (
    ClientEncPartContent,
    PrincipalRecord,
    TelemetryStep,
    TGTContent,
)
from app.schemas.kerberos import (
    EncryptedClientPartSchema,
    EncryptedTicketSchema,
    KrbAsRep,
    KrbAsReq,
    SUPPORTED_REALM,
    SUPPORTED_SERVICE,
    TelemetryStepSchema,
)


class KerberosPrincipalNotFoundError(Exception):
    """Raised when client principal is not registered in the KDC database."""

    pass


class KerberosUnsupportedServiceError(Exception):
    """Raised when the requested service principal is unsupported."""

    pass


class KdcService:
    """Authentication Server (AS) and Key Distribution Center (KDC) Service."""

    def __init__(self):
        # Master TGS key used by KDC to encrypt TGTs (K_TGS)
        # In a real KDC this is kept in the master key stash; here derived securely
        self._k_tgs: bytes = derive_key_from_password(
            password="kdc_master_tgs_passphrase_secret_bcs703",
            salt=f"{SUPPORTED_REALM}krbtgt",
        )

        # In-memory development database of authorized principals
        # Passwords are stored in memory for educational key derivation only,
        # never exposed via API responses or logs
        self._user_db: Dict[str, Dict[str, str]] = {
            f"alice@{SUPPORTED_REALM}": {
                "username": "alice",
                "realm": SUPPORTED_REALM,
                "password": "AlicePassword123!",
                "salt": f"{SUPPORTED_REALM}alice",
            },
            f"bob@{SUPPORTED_REALM}": {
                "username": "bob",
                "realm": SUPPORTED_REALM,
                "password": "BobPassword456!",
                "salt": f"{SUPPORTED_REALM}bob",
            },
        }

    def normalize_principal(self, cname: str) -> str:
        """Normalizes principal name to standard form 'username@REALM'."""
        clean = cname.strip()
        if "@" not in clean:
            return f"{clean}@{SUPPORTED_REALM}"
        parts = clean.split("@", 1)
        return f"{parts[0]}@{parts[1].upper()}"

    def get_available_principals(self) -> List[str]:
        """Returns public list of available sample principal names."""
        return sorted(list(self._user_db.keys()))

    def get_client_key(self, cname: str) -> bytes:
        """Derives and retrieves the 256-bit client secret key K_C for a registered principal.

        Internal KDC helper: Never exposed through API responses.
        """
        normalized_cname = self.normalize_principal(cname)
        if normalized_cname not in self._user_db:
            raise KerberosPrincipalNotFoundError(
                f"Client principal '{cname}' not found in KDC database."
            )

        user_info = self._user_db[normalized_cname]
        return derive_key_from_password(
            password=user_info["password"],
            salt=user_info["salt"],
        )

    def get_tgs_key(self) -> bytes:
        """Returns the internal K_TGS master key.

        Used for test verification and TGS processing. Never exposed in API payloads.
        """
        return self._k_tgs

    def process_as_request(self, req: KrbAsReq) -> KrbAsRep:
        """Executes the complete Kerberos Authentication Server (AS) Exchange flow.

        Flow:
        1. Receive KRB_AS_REQ.
        2. Validate client principal.
        3. Validate realm and service.
        4. Check timestamp freshness (validated by schema).
        5. Look up client in KDC database.
        6. Generate session key K_C,TGS.
        7. Construct TGT with client/service details, session key, issue/expiry times.
        8. Encrypt TGT using KDC/TGS key (K_TGS).
        9. Construct client encrypted response part.
        10. Encrypt client response using derived client key (K_C).
        11. Return structured KRB_AS_REP with safe telemetry.
        """
        telemetry: List[TelemetryStep] = []

        # Step 1: Request received
        telemetry.append(
            TelemetryStep(
                step_number=1,
                name="Request received.",
                description=f"Received KRB_AS_REQ for client '{req.cname}' requesting service '{req.sname}'.",
            )
        )

        # Step 2 & 3: Validate realm, service, and principal format
        if req.realm != SUPPORTED_REALM:
            raise ValueError(f"Unsupported realm '{req.realm}'.")

        if req.sname != SUPPORTED_SERVICE:
            raise KerberosUnsupportedServiceError(
                f"Unsupported service principal '{req.sname}'. Only '{SUPPORTED_SERVICE}' supported."
            )

        telemetry.append(
            TelemetryStep(
                step_number=2,
                name="Principal validated.",
                description=f"Validated request syntax, realm '{req.realm}', and service '{req.sname}'.",
            )
        )

        # Step 4 & 5: KDC lookup
        normalized_cname = self.normalize_principal(req.cname)
        if normalized_cname not in self._user_db:
            raise KerberosPrincipalNotFoundError(
                f"Client principal '{req.cname}' (normalized: '{normalized_cname}') not registered in KDC database."
            )

        client_key = self.get_client_key(normalized_cname)

        telemetry.append(
            TelemetryStep(
                step_number=3,
                name="KDC lookup completed.",
                description=f"Found principal '{normalized_cname}' in KDC database. Derived client key K_C successfully.",
            )
        )

        # Step 6: Generate session key K_C,TGS
        session_key = generate_session_key()

        telemetry.append(
            TelemetryStep(
                step_number=4,
                name="Session key generated.",
                description="Generated cryptographically secure random 256-bit session key K_C,TGS.",
            )
        )

        # Step 7: Construct TGT
        now = datetime.now(timezone.utc)
        issue_time = now.isoformat()
        expiry_time = (now + timedelta(seconds=req.lifetime)).isoformat()

        tgt_content = TGTContent(
            cname=normalized_cname,
            crealm=req.realm,
            sname=req.sname,
            srealm=req.realm,
            session_key=session_key,
            authtime=issue_time,
            starttime=issue_time,
            endtime=expiry_time,
        )

        telemetry.append(
            TelemetryStep(
                step_number=5,
                name="TGT constructed.",
                description=f"Constructed TGT with client '{normalized_cname}', session key, and lifetime {req.lifetime}s.",
            )
        )

        # Step 8: Encrypt TGT using K_TGS
        # Nonce is unique for every encryption operation
        tgt_cipher_b64, tgt_nonce_b64 = encrypt_aes_gcm(
            key=self._k_tgs,
            plaintext_data=tgt_content.to_dict(),
        )

        telemetry.append(
            TelemetryStep(
                step_number=6,
                name="TGT encrypted.",
                description="TGT encrypted with master KDC/TGS key (K_TGS) using AES-256-GCM with unique 96-bit nonce.",
            )
        )

        # Step 9: Construct client encrypted response part
        client_part = ClientEncPartContent(
            session_key=session_key,
            sname=req.sname,
            srealm=req.realm,
            nonce=req.nonce,  # Echo client's nonce to confirm message matches their request
            authtime=issue_time,
            endtime=expiry_time,
            lifetime=req.lifetime,
        )

        telemetry.append(
            TelemetryStep(
                step_number=7,
                name="Client response encrypted.",
                description="Encrypted session key, sname, and nonce using derived client key (K_C) via AES-256-GCM.",
            )
        )

        # Step 10: Encrypt client response using K_C
        client_cipher_b64, client_nonce_b64 = encrypt_aes_gcm(
            key=client_key,
            plaintext_data=client_part.to_dict(),
        )

        # Step 11: Return structured KRB_AS_REP
        telemetry.append(
            TelemetryStep(
                step_number=8,
                name="AS response generated.",
                description="Constructed final KRB_AS_REP containing opaque encrypted TGT and encrypted client package.",
            )
        )

        return KrbAsRep(
            msg_type="KRB_AS_REP",
            pvno=5,
            cname=normalized_cname,
            crealm=req.realm,
            ticket=EncryptedTicketSchema(
                sname=req.sname,
                srealm=req.realm,
                cipher_b64=tgt_cipher_b64,
                nonce_b64=tgt_nonce_b64,
                encryption_type="AES-256-GCM",
            ),
            enc_part=EncryptedClientPartSchema(
                cipher_b64=client_cipher_b64,
                nonce_b64=client_nonce_b64,
                encryption_type="AES-256-GCM",
            ),
            telemetry=[
                TelemetryStepSchema(**step.to_dict()) for step in telemetry
            ],
        )


# Global singleton instance for KDC service
kdc_service = KdcService()
