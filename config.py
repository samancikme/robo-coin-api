"""
ROBO COIN - CONFIGURATION
Muhit o'zgaruvchilari va sozlamalar
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings"""
    
    # MongoDB
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    
    # JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_DAYS: int = 7
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    
    # CORS
    ALLOWED_ORIGINS: list = os.getenv(
        "ALLOWED_ORIGINS", 
        "http://localhost:5173,http://localhost:3000"
    ).split(",")
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = ENVIRONMENT == "development"
    
    # Rate limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_API: str = "100/minute"
    RATE_LIMIT_COINS: str = "30/minute"
    
    # File upload
    MAX_AVATAR_SIZE: int = 500 * 1024  # 500KB
    AVATAR_MAX_DIMENSION: int = 300  # 300x300 pixels
    
    def validate(self):
        """Validate required settings"""
        errors = []
        
        # MongoDB URI
        if not self.MONGODB_URI:
            errors.append("MONGODB_URI environment variable not set!")
        
        # JWT Secret
        if not self.JWT_SECRET:
            errors.append("JWT_SECRET environment variable not set!")
        elif len(self.JWT_SECRET) < 32:
            errors.append("JWT_SECRET must be at least 32 characters!")
        elif self.JWT_SECRET == "robocoin_secret_2024":
            errors.append("Change default JWT_SECRET in production!")
        
        # Production checks
        if self.ENVIRONMENT == "production":
            if "localhost" in self.MONGODB_URI:
                errors.append("Production MongoDB must not use localhost!")
            
            if "*" in self.ALLOWED_ORIGINS:
                errors.append("Production CORS must not allow all origins!")
            
            if len(self.JWT_SECRET) < 64:
                errors.append("Production JWT_SECRET should be 64+ characters!")
        
        if errors:
            raise ValueError("\n".join(["❌ Configuration errors:"] + errors))
        
        print("✅ Configuration validated successfully")
        print(f"   Environment: {self.ENVIRONMENT}")
        print(f"   MongoDB: {'Connected' if self.MONGODB_URI else 'Not set'}")
        print(f"   Redis: {'Enabled' if self.REDIS_URL else 'Disabled'}")
        print(f"   CORS Origins: {len(self.ALLOWED_ORIGINS)} allowed")


settings = Settings()