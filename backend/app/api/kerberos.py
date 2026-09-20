"""Kerberos API Endpoints for Authentication Server (AS) Exchange.

Endpoints:
- POST /api/kerberos/as-request: Process KRB_AS_REQ and return KRB_AS_REP
- GET /api/kerberos/principals: Return available sample principal names
"""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from app.schemas.kerberos import (
    KerberosErrorResponse,
    KrbAsRep,
    KrbAsReq,
    PrincipalsResponse,
    SUPPORTED_REALM,
    SUPPORTED_SERVICE,
)
from app.services.kdc import (
    KerberosPrincipalNotFoundError,
    KerberosUnsupportedServiceError,
    kdc_service,
)

router = APIRouter()


@router.post(
    "/as-request",
    response_model=KrbAsRep,
    summary="Process Kerberos AS Request (KRB_AS_REQ)",
    description="Authenticates client principal, generates session key, issues encrypted TGT, and returns KRB_AS_REP.",
    responses={
        200: {"description": "Successful AS Exchange (KRB_AS_REP issued)"},
        400: {"model": KerberosErrorResponse, "description": "Kerberos protocol or validation error"},
        404: {"model": KerberosErrorResponse, "description": "Principal not found in KDC database"},
    },
)
def process_as_exchange(request: KrbAsReq):
    """Processes incoming KRB_AS_REQ and generates KRB_AS_REP."""
    try:
        response = kdc_service.process_as_request(request)
        return response
    except KerberosPrincipalNotFoundError as e:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=KerberosErrorResponse(
                error_code="KDC_ERR_C_PRINCIPAL_UNKNOWN",
                message=str(e),
                timestamp=datetime.now(timezone.utc).isoformat(),
            ).model_dump(),
        )
    except KerberosUnsupportedServiceError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=KerberosErrorResponse(
                error_code="KDC_ERR_S_PRINCIPAL_UNKNOWN",
                message=str(e),
                timestamp=datetime.now(timezone.utc).isoformat(),
            ).model_dump(),
        )
    except ValueError as e:
        error_msg = str(e)
        code = "KRB_AP_ERR_SKEW" if "skew" in error_msg.lower() else "KDC_ERR_BADOPTION"
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=KerberosErrorResponse(
                error_code=code,
                message=error_msg,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ).model_dump(),
        )
    except Exception as e:
        # Safe fallback preventing secret leakage or internal stack exposure
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=KerberosErrorResponse(
                error_code="KDC_ERR_SVC_UNAVAILABLE",
                message="An unexpected error occurred during AS exchange processing.",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ).model_dump(),
        )


@router.get(
    "/principals",
    response_model=PrincipalsResponse,
    summary="Get Available Kerberos Principals",
    description="Returns list of registered sample principal names for simulation testing. Secrets/passwords are never exposed.",
)
def get_principals():
    """Returns list of public sample principal names only."""
    return PrincipalsResponse(
        realm=SUPPORTED_REALM,
        service_principal=SUPPORTED_SERVICE,
        principals=kdc_service.get_available_principals(),
    )
