"""Domain and In-Memory Data Models for Kerberos AS Exchange Simulation.

These models represent internal structures for Kerberos principals, tickets,
and educational protocol telemetry. Sensitive keys/passwords are kept strictly
within internal processing structures and are never serialized to public APIs.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class PrincipalRecord:
    """Internal KDC database record for a Kerberos principal."""

    cname: str  # e.g., "alice@CANARA.EDU"
    username: str  # e.g., "alice"
    realm: str  # e.g., "CANARA.EDU"
    salt: str  # e.g., "CANARA.EDUalice"
    password_hash_dummy: str  # Simulated hash identifier (not real production hash)
    is_active: bool = True
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TGTContent:
    """Plaintext contents of a Ticket Granting Ticket (TGT) before encryption with K_TGS."""

    cname: str
    crealm: str
    sname: str
    srealm: str
    session_key: str  # K_C,TGS (base64)
    authtime: str
    starttime: str
    endtime: str
    flags: List[str] = field(default_factory=lambda: ["INITIAL", "PRE-AUTHENT"])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cname": self.cname,
            "crealm": self.crealm,
            "sname": self.sname,
            "srealm": self.srealm,
            "session_key": self.session_key,
            "authtime": self.authtime,
            "starttime": self.starttime,
            "endtime": self.endtime,
            "flags": self.flags,
        }


@dataclass
class ClientEncPartContent:
    """Plaintext contents of the client-encrypted response part before encryption with K_C."""

    session_key: str  # K_C,TGS (base64)
    sname: str
    srealm: str
    nonce: int  # Echoed client nonce to prevent replay
    authtime: str
    endtime: str
    lifetime: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_key": self.session_key,
            "sname": self.sname,
            "srealm": self.srealm,
            "nonce": self.nonce,
            "authtime": self.authtime,
            "endtime": self.endtime,
            "lifetime": self.lifetime,
        }


@dataclass
class TelemetryStep:
    """Educational step-by-step trace item for frontend visualization.

    Contains only safe structural information, never secrets or passwords.
    """

    step_number: int
    name: str
    description: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: str = "SUCCESS"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "name": self.name,
            "description": self.description,
            "timestamp": self.timestamp,
            "status": self.status,
        }
