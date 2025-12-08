"""
ROBO COIN - SECURITY UTILITIES
Xavfsizlik funksiyalari
"""

import secrets
import string
import base64
import io
from datetime import datetime, timedelta
from typing import Optional
from PIL import Image


# ============================================
# PASSWORD GENERATION
# ============================================

def generate_strong_password(length: int = 12) -> str:
    """
    Kuchli parol generatsiya qilish
    - Kamida 12 belgi
    - Katta/kichik harflar
    - Raqamlar
    - Maxsus belgilar
    """
    if length < 12:
        length = 12
    
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Murakkablikni tekshirish
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%&*" for c in password)
        
        if has_lower and has_upper and has_digit and has_special:
            return password


def generate_passphrase(word_count: int = 4) -> str:
    """
    Eslab qolish oson passphrase generatsiya
    Masalan: robot-moon-fire-sky-42
    """
    words = [
        "robot", "coin", "star", "moon", "fire", "earth", 
        "sky", "sun", "code", "play", "learn", "win",
        "game", "hero", "gold", "blue", "fast", "cool"
    ]
    
    chosen = [secrets.choice(words) for _ in range(word_count)]
    number = secrets.randbelow(100)
    
    return f"{'-'.join(chosen)}-{number}"


def generate_login(name: str) -> str:
    """
    Ismdan login generatsiya qilish
    """
    # Kichik harfga o'tkazish
    login = name.lower().strip()
    
    # Faqat harflar va raqamlarni qoldirish
    login = ''.join(c if c.isalnum() else '_' for c in login)
    
    # Ketma-ket _ larni bitta qilish
    while '__' in login:
        login = login.replace('__', '_')
    
    # Boshi va oxiridagi _ ni olib tashlash
    login = login.strip('_')
    
    # Bo'sh bo'lsa random qo'shish
    if not login:
        login = f"user_{secrets.randbelow(10000)}"
    
    return login


# ============================================
# IMAGE PROCESSING
# ============================================

def optimize_avatar_image(
    base64_data: str, 
    max_size: tuple = (300, 300), 
    quality: int = 85
) -> str:
    """
    Avatar rasmni optimizatsiya qilish
    - Hajmni kichraytirish
    - Sifatni siqish
    - JPEG formatga o'tkazish
    """
    try:
        # Base64 ni ajratish
        if "," in base64_data:
            header, encoded = base64_data.split(",", 1)
        else:
            encoded = base64_data
            header = "data:image/jpeg;base64"
        
        # Decode
        img_data = base64.b64decode(encoded)
        img = Image.open(io.BytesIO(img_data))
        
        # RGBA -> RGB
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'RGBA':
                background.paste(img, mask=img.split()[-1])
            else:
                background.paste(img)
            img = background
        
        # Resize (aspect ratio saqlash)
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # JPEG sifatida compress qilish
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=quality, optimize=True)
        
        # Base64 ga qaytarish
        compressed = base64.b64encode(buffer.getvalue()).decode()
        
        # Log
        original_size = len(base64.b64decode(encoded))
        compressed_size = len(buffer.getvalue())
        ratio = (1 - compressed_size / original_size) * 100
        print(f"📸 Image: {original_size/1024:.1f}KB → {compressed_size/1024:.1f}KB ({ratio:.1f}% smaller)")
        
        return f"data:image/jpeg;base64,{compressed}"
    
    except Exception as e:
        print(f"⚠️ Image optimization error: {e}")
        return base64_data


def validate_image_content(base64_data: str) -> bool:
    """
    Rasm faylini tekshirish (zararli fayl emas ekanligini)
    """
    try:
        if "," in base64_data:
            _, encoded = base64_data.split(",", 1)
        else:
            encoded = base64_data
        
        img_data = base64.b64decode(encoded)
        img = Image.open(io.BytesIO(img_data))
        img.verify()  # Fayl to'g'riligini tekshirish
        
        return True
    except:
        return False


# ============================================
# TOKEN UTILS
# ============================================

def generate_secure_token(length: int = 32) -> str:
    """
    Xavfsiz random token generatsiya
    """
    return secrets.token_urlsafe(length)


def generate_qr_token() -> str:
    """
    QR kod uchun qisqa token
    """
    return secrets.token_urlsafe(16)