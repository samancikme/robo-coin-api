"""
ROBO COIN - RATE LIMITER
API so'rovlar limitlash
"""

import os
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse


def get_client_ip(request: Request) -> str:
    """
    Client IP adresini olish
    Reverse proxy orqali ham ishlaydi
    """
    # X-Forwarded-For header (behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    # X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Direct connection
    if request.client:
        return request.client.host
    
    return "127.0.0.1"


# Redis URL (agar mavjud bo'lsa)
REDIS_URL = os.getenv("REDIS_URL", "")

# Limiter yaratish
if REDIS_URL:
    # Redis bilan (production uchun)
    limiter = Limiter(
        key_func=get_client_ip,
        storage_uri=REDIS_URL
    )
    print("✅ Rate limiter: Redis storage")
else:
    # Memory bilan (development uchun)
    limiter = Limiter(key_func=get_client_ip)
    print("⚠️ Rate limiter: In-memory storage (use Redis in production)")


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """
    Rate limit oshganda xatolik qaytarish
    """
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Juda ko'p so'rov. Biroz kuting.",
            "error": "rate_limit_exceeded",
            "retry_after": str(exc.detail)
        },
        headers={
            "Retry-After": str(60),  # 60 sekund kutish
            "X-RateLimit-Limit": str(exc.detail),
        }
    )


# Rate limit presets
class RateLimits:
    """
    Turli endpointlar uchun limitlar
    """
    # Auth - juda qattiq (brute force himoya)
    LOGIN = "5/minute"
    REGISTER = "3/minute"
    PASSWORD_RESET = "3/minute"
    
    # API - oddiy
    DEFAULT = "100/minute"
    SEARCH = "30/minute"
    
    # Write operations
    CREATE = "20/minute"
    UPDATE = "30/minute"
    DELETE = "10/minute"
    
    # Coins
    GIVE_COINS = "30/minute"
    
    # File upload
    UPLOAD = "10/minute"
    
    # Export
    EXPORT = "5/minute"