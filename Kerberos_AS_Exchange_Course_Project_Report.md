# Course Project Report: Kerberos AS Exchange Simulation

**Course**: Cryptography & Network Security (BCS703) — Semester VII  
**Department**: Computer Science & Engineering  
**Institution**: Canara Engineering College, Benjanapadavu, Mangaluru  
**Project Group**: G17 | **Project Number**: P17  
**Academic Year**: 2025 – 2026  
**Students**:
- **4CB23CS161** (Member 1 — Backend Architecture, Cryptographic Engineering & Testing)
- **4CB23CS160** (Member 2 — Frontend Architecture, Interactive UI & Integration)

---

> [!NOTE]
> **Academic Scope Notice**: This report documents an educational software simulation developed for the course Cryptography & Network Security (BCS703). The simulation models the initial Authentication Server (AS) exchange of the Kerberos V5 protocol (RFC 4120) using modern REST/JSON transport and standard cryptography (PBKDF2-HMAC-SHA256, AES-256-GCM). It is engineered for transparent classroom demonstration of authentication mechanics and does not claim RFC 4120 binary ASN.1 wire compatibility.

---

## 1. Description of Requirements

### 1.1 Introduction to Kerberos & The Authentication Server (AS) Exchange
Kerberos is a trusted third-party network authentication protocol originated at MIT (RFC 4120). Designed around the classical "three-headed dog" architectural model, Kerberos establishes mutual authentication across three entities:
1. **The Client**: The workstation or user requesting access to network resources.
2. **The Key Distribution Center (KDC)**: The trusted authority comprising the **Authentication Server (AS)** and **Ticket Granting Server (TGS)**.
3. **The Application Server**: The end network service (e.g., File server, Database, Mail).

The **Authentication Server (AS) Exchange** represents Phase 1 of the Kerberos protocol. It is the initial gateway where a client proves its identity without ever transmitting passwords across the network, thereby obtaining a Ticket Granting Ticket (TGT) and an ephemeral session key ($K_{C,TGS}$).

### 1.2 Problem Statement & Motivation
Traditional distributed login mechanisms transmit plain credentials or static hashes over insecure channels, exposing systems to packet sniffing, eavesdropping, pass-the-hash attacks, and credential replay. Enterprise Kerberos implementations (such as Active Directory) provide robust defense but operate as opaque binary black boxes over ASN.1 DER streams on UDP/TCP port 88. For undergraduate computer science students, inspecting individual keys, timestamps, nonces, and ticket structures inside these production streams is extremely challenging.  
**Motivation**: To design and implement a full-stack, transparent, and cryptographically verified educational simulation that visualizes every step of the AS exchange in real time.

### 1.3 Project Objectives
- **Protocol Mechanics**: Simulate RFC 4120 Authentication Server message semantics (`KRB_AS_REQ` and `KRB_AS_REP`).
- **Modern Cryptography**: Integrate PBKDF2-HMAC-SHA256 (100,000 iterations) for string-to-key derivation and authenticated AES-256-GCM with unique 96-bit random IVs for ticket confidentiality and tamper-evident integrity.
- **Replay & Request Correlation**: Enforce client nonces ($N_1$) for request-response matching and server-side UTC clock-skew validation ($\pm 300\text{s}$).
- **Interactive Visual Telemetry**: Construct a responsive React dashboard demonstrating 8-step live telemetry progression.
- **Formal Verification**: Provide automated test coverage across frontend and backend tiers (21 verified automated tests).

### 1.4 Functional Requirements (FR)
- **FR-1 (Request Formulation)**: The client must construct and submit a valid `KRB_AS_REQ` containing `cname`, `realm`, `sname`, `nonce`, `timestamp`, and requested `lifetime`.
- **FR-2 (Boundary Validation)**: The server must validate the realm (`CANARA.EDU`), service (`krbtgt/CANARA.EDU`), and enforce UTC clock skew freshness within $\pm 300$ seconds.
- **FR-3 (Principal Lookup & Key Derivation)**: The KDC must search its database for the client. If found, it derives $K_C$ via PBKDF2; if unknown, it halts with `KDC_ERR_C_PRINCIPAL_UNKNOWN`.
- **FR-4 (TGT Construction & Encryption)**: The KDC must assemble a plaintext TGT and seal it using the master key $K_{TGS}$ via AES-256-GCM.
- **FR-5 (Client Package Encryption)**: The KDC must assemble a client response containing $K_{C,TGS}$, nonce echo $N_1$, and lifetime, encrypting it under $K_C$ via AES-256-GCM.
- **FR-6 (RFC Error Mapping)**: The system must map validation errors to standard Kerberos RFC error codes.

### 1.5 Non-Functional Requirements (NFR)
- **NFR-1 (Confidentiality)**: Passwords, password salts, and server master keys must never be exposed in public API responses or client logs.
- **NFR-2 (Integrity)**: Authenticated encryption must guarantee that modified ciphertexts fail with an `InvalidTag` exception.
- **NFR-3 (Replay Mitigation)**: Multi-layered defense using nonces, timestamps, and ticket lifetimes.
- **NFR-4 (Performance)**: Sub-50ms cryptographic processing latency.
- **NFR-5 (Testability)**: Fully automated test suites with 100% pass rates.

### 1.6 Hardware and Software Specifications
- **Hardware**: Standard x86-64 PC (Dual-core CPU, 4GB RAM).
- **Backend Stack**: Python 3.12, FastAPI (ASGI), Pydantic V2, PyCA Cryptography, Pytest.
- **Frontend Stack**: Node.js v18+, React 18, Vite, Vanilla CSS Glassmorphism, Vitest.

### 1.7 Project Limitations
The simulation focuses strictly on the initial AS Exchange (Phase 1). Subsequent TGS ticket issuance (Phase 2) and AP application authentication (Phase 3) represent future extensions. Communication uses REST/JSON over HTTP rather than binary ASN.1 DER over UDP port 88.

---

## 2. System Design & Architecture

### 2.1 Architectural Overview
The simulation implements a decoupled two-tier client-server architecture with strict cryptographic isolation boundaries:
- **Client Tier (React Workstation)**: Manages user inputs, parameters, and visual telemetry.
- **KDC Server Tier (FastAPI Engine)**: Manages credential verification, key derivation, ticket construction, and authenticated encryption.

### 2.2 System Architecture Component Relationships

```
+-----------------------------------------------------------------------------------+
|                            CLIENT WORKSTATION (React 18)                          |
|  +---------------------------+  +----------------------+  +---------------------+ |
|  |   ClientRequestForm.jsx   |  |  ProtocolSteps.jsx   |  |   PacketViewer.jsx  | |
|  | (Principal, Nonce, Time)  |  |  (8-Step Telemetry)  |  | (TGT & EncPart View)| |
|  +---------------------------+  +----------------------+  +---------------------+ |
|                                |                                                  |
|                                v                                                  |
|                   api.js (REST / Mock Fallback Client)                            |
+--------------------------------|--------------------------------------------------+
                                 |
              HTTP POST /api/kerberos/as-request  (KRB_AS_REQ)
              HTTP 200 OK Response                (KRB_AS_REP)
                                 |
+--------------------------------v--------------------------------------------------+
|                    KDC AUTHENTICATION SERVER (FastAPI Backend)                    |
|  +-----------------------------------------------------------------------------+  |
|  | API Router & Pydantic Schema Validation (KrbAsReq / Clock Skew <= 300s)     |  |
|  +-----------------------------------------------------------------------------+  |
|                                |                                                  |
|                                v                                                  |
|  +-----------------------------------------------------------------------------+  |
|  | KDC Core Service (KdcService in kdc.py):                                    |  |
|  | - Principal Normalization & Database Verification                           |  |
|  | - Ephemeral 256-bit Session Key Generation (K_C,TGS)                        |  |
|  | - Plaintext TGT Assembly & Sealing via K_TGS                                |  |
|  | - Client Response Assembly & Sealing via K_C                                |  |
|  | - Sanitized 8-Step Telemetry Dispatch                                       |  |
|  +-----------------------------------------------------------------------------+  |
|                  |                                            |                   |
|                  v                                            v                   |
|  +-------------------------------+            +--------------------------------+  |
|  | Cryptographic Engine          |            | In-Memory Principal Store      |  |
|  | - PBKDF2-HMAC-SHA256 (100k)   |            | - alice@CANARA.EDU (pass+salt) |  |
|  | - AES-256-GCM (128-bit Tag)   |            | - bob@CANARA.EDU (pass+salt)   |  |
|  | - CSPRNG IVs (96-bit random)  |            | - Master TGS Key (K_TGS)       |  |
|  +-------------------------------+            +--------------------------------+  |
+-----------------------------------------------------------------------------------+
```

### 2.3 Component Responsibilities & Trust Domains
- **Client Simulator**: Represents an unprivileged workstation. It has no access to server master keys or user database records.
- **KDC Authentication Server**: The authoritative authentication authority. It maintains user accounts, derives keys from stored secrets, and seals tickets.
- **Ticket Granting Service (TGS)**: Represented conceptually by the master key $K_{TGS}$. The TGT issued by the AS can only be decrypted and verified by the TGS.

---

## 3. Kerberos AS Exchange Workflow

### 3.1 Implemented 8-Step Execution Sequence

| Step | Milestone Name | Technical & Cryptographic Action | Key Used | Security Goal |
|:---:|---|---|---|---|
| **1** | **Request received** | Client transmits `KRB_AS_REQ` containing `cname`, `realm`, `sname`, `nonce` ($N_1$), timestamp ($T$), and `lifetime`. No password or hash is sent. | None (Cleartext) | Identity Assertion |
| **2** | **Principal validated** | KDC validates realm (`CANARA.EDU`), service (`krbtgt`), and checks freshness: $|T_{server} - T_{client}| \le 300\text{s}$. | None | Replay & Bounds Defense |
| **3** | **KDC lookup completed** | KDC queries database. If user exists, it derives client key $K_C$ via PBKDF2. If absent, exchange halts with `KDC_ERR_C_PRINCIPAL_UNKNOWN`. | Derived $K_C$ (PBKDF2) | Identity Verification |
| **4** | **Session key generated** | KDC generates fresh 256-bit ephemeral session key ($K_{C,TGS}$) using `secrets.token_bytes(32)`. | None (Ephemeral) | Key Freshness |
| **5** | **TGT constructed** | Plaintext TGT assembled with `cname`, `sname`, $T_{issue}$, $T_{expire}$, and session key $K_{C,TGS}$. | Plaintext Struct | Ticket Formatting |
| **6** | **TGT encrypted** | TGT encrypted under KDC master key $K_{TGS}$ via AES-256-GCM with fresh 96-bit IV. Produces opaque ciphertext with 128-bit tag. | Master Key $K_{TGS}$ | TGT Tamper-Proofing |
| **7** | **Client response encrypted** | Client package containing $K_{C,TGS}$, nonce echo $N_1$, expiry, and realm encrypted under client key $K_C$ via AES-256-GCM. | Client Key $K_C$ | Confidential Key Delivery |
| **8** | **AS response generated** | Encrypted TGT and encrypted client part packaged into `KRB_AS_REP` and returned to client with HTTP 200. | Structured Transport | Response Dispatch |

### 3.2 Stepped Failure Progression
When an unauthorized principal (`charlie@CANARA.EDU`) initiates an authentication request:
- Steps 1 and 2 evaluate to **COMPLETED** (syntax and realm format are valid).
- Step 3 evaluates to **FAILED** with RFC code `KDC_ERR_C_PRINCIPAL_UNKNOWN` (HTTP 404).
- Steps 4 through 8 remain strictly **PENDING**, proving no session key was minted and no ticket was issued.
- The Packet Inspector immediately purges any prior tickets, preventing stale cache trust.

---

## 4. Cryptographic Implementation & Mathematical Foundations

### 4.1 Key Derivation Function (PBKDF2-HMAC-SHA256)
Kerberos avoids storing cleartext passwords by deriving symmetric keys via a string-to-key function:
$$K_C = \text{PBKDF2}(\text{PRF}=\text{HMAC-SHA256},\; \text{Password},\; \text{Salt}=\text{Realm} \mathbin{\Vert} \text{Username},\; c=100{,}000,\; dkLen=32)$$

The 100,000 iterations introduce a controlled computational delay (work factor) of several milliseconds per derivation. While imperceptible to legitimate users, it renders offline dictionary and brute-force attacks computationally intractable for attackers.

### 4.2 Authenticated Symmetric Encryption (AES-256-GCM)
Our simulation utilizes **AES-256-GCM (Galois/Counter Mode)**, an AEAD cipher specified in NIST SP 800-38D:
- **Confidentiality**: Counter mode provides 256-bit symmetric confidentiality for both ticket and client packages.
- **Tamper-Evident Integrity**: GCM computes a 128-bit GHASH authentication tag over the ciphertext. If any byte is altered, decryption raises an explicit `InvalidTag` exception.
- **Unique IV / Nonce**: A fresh 96-bit (12-byte) random nonce is generated via `secrets.token_bytes(12)` for every single encryption operation, preventing keystream reuse.

### 4.3 Request Matching vs. Replay Protection
- **Client Nonce ($N_1$)**: A 32-bit cryptographically secure random integer generated by the client. Its primary purpose is **request-response matching**—ensuring the returned package corresponds directly to the request just sent.
- **Comprehensive Replay Defense**: Replay protection in Kerberos relies on the combined interplay of client nonces, UTC timestamp clock-skew validation ($\pm 300\text{s}$), ticket validity lifetimes, and authenticators in subsequent phases.

---

## 5. Implementation & Core Code Snippets

### 5.1 Request Validation & Clock-Skew Check (`schemas/kerberos.py`)
```python
class KrbAsReq(BaseModel):
    cname: str; realm: str; sname: str; nonce: int; timestamp: str; lifetime: int
    # Enforces strict 300-second clock skew tolerance at the schema boundary
    @field_validator("timestamp")
    def validate_freshness(cls, v: str) -> str:
        req_time = datetime.fromisoformat(v)
        skew = abs((datetime.now(timezone.utc) - req_time).total_seconds())
        if skew > 300.0:
            raise ValueError(f"Clock skew exceeded: {skew:.1f}s > 300s tolerance")
        return v
```
*Explanation*: Pydantic V2 validator rejects replayed or desynchronized requests before they reach the core service.

### 5.2 Principal Lookup & Key Derivation (`services/kdc.py`)
```python
def get_client_key(self, cname: str) -> bytes:
    normalized = self.normalize_principal(cname)
    if normalized not in self._user_db:
        raise KerberosPrincipalNotFoundError(f"Principal '{cname}' not in KDC database.")
    user = self._user_db[normalized]
    return derive_key_from_password(password=user["password"], salt=user["salt"])
```
*Explanation*: Queries the user store, raises domain errors for unknown principals, and derives $K_C$ via PBKDF2.

### 5.3 Authenticated Encryption with Fresh IV (`core/crypto.py`)
```python
def encrypt_aes_gcm(key: bytes, plaintext_data: Any) -> Tuple[str, str]:
    raw_bytes = json.dumps(plaintext_data).encode("utf-8")
    # Fresh, unique 12-byte random IV for every single encryption
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, raw_bytes, associated_data=None)
    return base64.b64encode(ciphertext_with_tag).decode(), base64.b64encode(nonce).decode()
```
*Explanation*: Encrypts data using AES-256-GCM with a unique 96-bit nonce and 128-bit authentication tag.

### 5.4 Core AS Request Processing Pipeline (`services/kdc.py`)
```python
# Ephemeral session key generated via CSPRNG (256-bit)
session_key = generate_session_key()
# Step 6: Encrypt TGT under master K_TGS key (client cannot decrypt)
tgt_cipher, tgt_iv = encrypt_aes_gcm(self._k_tgs, tgt_content)
# Step 7: Encrypt client response under derived K_C key (contains session key & nonce)
client_cipher, client_iv = encrypt_aes_gcm(client_key, client_enc_content)
return KrbAsRep(ticket=EncryptedTicketSchema(cipher_text=tgt_cipher, nonce=tgt_iv),
                enc_part=EncryptedClientPartSchema(cipher_text=client_cipher, nonce=client_iv))
```
*Explanation*: Demonstrates the central Kerberos duality: the session key is sealed inside the TGT (for TGS) and also sealed inside the client package (for client).

---

## 6. Results, Test Verification & Visual Demonstration

### 6.1 Demonstration Scenarios
1. **Alice Authentication (`alice@CANARA.EDU`)**: All 8 steps completed (green), clean single-realm formatting, valid encrypted TGT and client ticket issued.
2. **Bob Authentication (`bob@CANARA.EDU`)**: Verified independent key derivation, single-realm formatting (`bob@CANARA.EDU`), and unique 256-bit session key ($K_{Bob,TGS}$).
3. **Charlie Rejection (`charlie@CANARA.EDU`)**: Stepped failure (Steps 1–2 completed, Step 3 failed with `KDC_ERR_C_PRINCIPAL_UNKNOWN`, Steps 4–8 pending, prior responses wiped).
4. **Clock Skew Defense**: Timestamps offset $>300\text{s}$ rejected with `KRB_AP_ERR_SKEW`.

### 6.2 Automated Test Suite Results (100% Passing — 21 / 21 Tests)

| Suite | Test Target | Test Assertion / Method | Result |
|---|---|---|:---:|
| **Backend** | Valid AS Exchange | Verifies HTTP 200, ciphertext generation, and 8 telemetry steps | **PASSED** |
| **Backend** | Unknown Principal | Asserts HTTP 404 and `KDC_ERR_C_PRINCIPAL_UNKNOWN` for unregistered user | **PASSED** |
| **Backend** | Unsupported Service | Rejects service principals other than `krbtgt/CANARA.EDU` | **PASSED** |
| **Backend** | Stale Timestamp | Rejects timestamps older than 300 seconds with clock skew error | **PASSED** |
| **Backend** | Schema Validation | Rejects negative nonces, invalid lifetimes, and malformed emails | **PASSED** |
| **Backend** | Decryption Integrity | Verifies client key successfully decrypts client part; matches session key | **PASSED** |
| **Backend** | Tamper Detection | Verifies incorrect key or tampered ciphertext triggers AES `InvalidTag` | **PASSED** |
| **Backend** | Session Key Uniqueness | Verifies subsequent requests receive distinct session keys and IVs | **PASSED** |
| **Backend** | Secret Leakage Check | Scans raw JSON responses to confirm zero passwords/salts leaked | **PASSED** |
| **Backend** | Health Check API | Confirms `/api/health` backward compatibility and course metadata | **PASSED** |
| **Frontend** | Component Rendering (6) | Validates Header, Form, 8-step Timeline, Formatter, and Status alerts | **PASSED** |
| **Frontend** | API Client Service (5) | Verifies health check, principal fetching, AS exchange, and offline mock | **PASSED** |

### 6.3 Proof of Implementation (Live Application Screenshots)
- **Figure 6.1**: Alice Successful Authentication (`http://localhost:5173/`) showing all 8 steps COMPLETED and valid encrypted TGT.
- **Figure 6.2**: Charlie Unknown Principal Rejection showing Step 3 FAILED with `KDC_ERR_C_PRINCIPAL_UNKNOWN` and Steps 4–8 PENDING.

---

## 7. Conclusion & Future Scope

### 7.1 Project Outcomes & Core Achievements
The project successfully realized an educational simulation of the Kerberos AS Exchange. The system demonstrates:
- Complete elimination of cleartext password transmission.
- Work-factor resistance against brute-force attacks via PBKDF2 (100,000 iterations).
- Tamper-evident authenticated encryption via AES-256-GCM.
- Multi-layered replay defense via nonces, timestamps, and lifetimes.
- Transparent stepped failure progression for unauthorized principals.

### 7.2 Educational Scope Limitations
This simulation was developed for Cryptography & Network Security (BCS703). It uses RESTful JSON transport instead of legacy binary ASN.1 DER streams over UDP port 88. User accounts are maintained in memory. It is intended for classroom demonstration rather than enterprise production deployment.

### 7.3 Future Scope
- **Phase 4 (Ticket Granting Server Exchange)**: Implement `KRB_TGS_REQ` and `KRB_TGS_REP` message handlers where the client presents its TGT and an Authenticator to obtain service tickets.
- **Phase 5 (Client/Server AP Exchange)**: Implement mutual application authentication (`KRB_AP_REQ` / `KRB_AP_REP`) between client and target application servers.
- **PKINIT Support**: Extend initial authentication with RFC 4556 (PKINIT) to support X.509 digital certificates and asymmetric key pairs.

### 7.4 References
1. Neuman, C., Yu, T., Hartman, S., & Raeburn, K. (2005). *The Kerberos Network Authentication Service (V5)*. RFC 4120, IETF.
2. National Institute of Standards and Technology (NIST). (2010). *Recommendation for Password-Based Key Derivation (PBKDF2)*. NIST SP 800-132.
3. Dworkin, M. (2007). *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*. NIST SP 800-38D.
4. Stallings, W. (2017). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson Education.
5. FastAPI & Pydantic Documentation. (2024). *Asynchronous REST Framework and Data Validation for Python*. https://fastapi.tiangolo.com
