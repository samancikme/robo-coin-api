"""
ROBO COIN - PYDANTIC MODELS
Input validation uchun
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List
from bson import ObjectId
from bson.errors import InvalidId
import html
import re


# ============================================
# YORDAMCHI VALIDATORLAR
# ============================================

def validate_object_id(value: str) -> str:
    """MongoDB ObjectId validatsiya"""
    try:
        ObjectId(value)
        return value
    except (InvalidId, TypeError):
        raise ValueError("Noto'g'ri ID formati")


def sanitize_string(value: str) -> str:
    """XSS va injection prevention"""
    if not value:
        return value
    
    # HTML escape
    value = html.escape(value.strip())
    
    # MongoDB operator injection prevention
    dangerous_chars = ['$', '{', '}']
    for char in dangerous_chars:
        if char in value:
            raise ValueError(f"'{char}' belgisi ruxsat etilmagan")
    
    return value


def validate_name(value: str) -> str:
    """Ism validatsiya - faqat harflar"""
    if not value:
        raise ValueError("Ism bo'sh bo'lmasligi kerak")
    
    # Faqat harflar, probel, tire, apostrof
    pattern = r"^[a-zA-ZА-Яа-яЁёʻʼ\s'\-]+$"
    if not re.match(pattern, value):
        raise ValueError("Ismda faqat harflar ruxsat etilgan")
    
    return sanitize_string(value)


# ============================================
# AUTH MODELS
# ============================================

class LoginRequest(BaseModel):
    """Login so'rovi"""
    login: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4, max_length=100)
    
    @validator('login')
    def validate_login(cls, v):
        return sanitize_string(v.lower())
    
    @validator('password')
    def validate_password(cls, v):
        # Parolda maxsus belgilar tekshirish (injection prevention)
        dangerous = ['$', '{', '}', '[', ']']
        for char in dangerous:
            if char in v:
                raise ValueError("Parolda ruxsat etilmagan belgi bor")
        return v


# ============================================
# STUDENT MODELS
# ============================================

class StudentCreate(BaseModel):
    """Yangi o'quvchi yaratish"""
    name: str = Field(..., min_length=2, max_length=50)
    groupId: str
    
    @validator('name')
    def validate_name(cls, v):
        return validate_name(v)
    
    @validator('groupId')
    def validate_group_id(cls, v):
        return validate_object_id(v)


class StudentUpdate(BaseModel):
    """O'quvchi yangilash"""
    name: Optional[str] = Field(None, min_length=2, max_length=50)
    groupId: Optional[str] = None
    
    @validator('name')
    def validate_name(cls, v):
        if v:
            return validate_name(v)
        return v
    
    @validator('groupId')
    def validate_group_id(cls, v):
        if v:
            return validate_object_id(v)
        return v


# ============================================
# COIN MODELS
# ============================================

class CoinTransaction(BaseModel):
    """Coin berish/olish"""
    amount: float = Field(..., ge=-1000, le=1000)  # -1000 dan 1000 gacha
    reason: str = Field(..., min_length=2, max_length=200)
    
    @validator('amount')
    def validate_amount(cls, v):
        if v == 0:
            raise ValueError("Coin miqdori 0 bo'lmasligi kerak")
        # 2 xonagacha aniqlik
        return round(v, 2)
    
    @validator('reason')
    def validate_reason(cls, v):
        return sanitize_string(v)


# ============================================
# GROUP MODELS
# ============================================

class GroupCreate(BaseModel):
    """Yangi guruh yaratish"""
    name: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = Field(None, max_length=200)
    
    @validator('name', 'description')
    def sanitize(cls, v):
        if v:
            return sanitize_string(v)
        return v


class GroupUpdate(BaseModel):
    """Guruh yangilash"""
    name: Optional[str] = Field(None, min_length=2, max_length=50)
    description: Optional[str] = Field(None, max_length=200)
    
    @validator('name', 'description')
    def sanitize(cls, v):
        if v:
            return sanitize_string(v)
        return v


# ============================================
# ASSIGNMENT MODELS
# ============================================

class AssignmentCreate(BaseModel):
    """Yangi topshiriq yaratish"""
    title: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    groupIds: List[str] = Field(..., min_items=1)
    dueDate: Optional[str] = None
    
    @validator('title', 'description')
    def sanitize(cls, v):
        if v:
            return sanitize_string(v)
        return v
    
    @validator('groupIds')
    def validate_group_ids(cls, v):
        for group_id in v:
            validate_object_id(group_id)
        return v


class SubmissionReview(BaseModel):
    """Topshiriq baholash"""
    coinsGiven: int = Field(..., ge=0, le=100)


# ============================================
# REWARD MODELS
# ============================================

class RewardCreate(BaseModel):
    """Yangi sovg'a yaratish"""
    name: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = Field(None, max_length=200)
    price: int = Field(..., ge=1, le=10000)
    category: str = Field(default="kichik")
    icon: str = Field(default="gift", max_length=20)
    
    @validator('name', 'description')
    def sanitize(cls, v):
        if v:
            return sanitize_string(v)
        return v
    
    @validator('category')
    def validate_category(cls, v):
        allowed = ['kichik', 'oqish', 'imtiyoz']
        if v not in allowed:
            raise ValueError(f"Kategoriya {allowed} dan biri bo'lishi kerak")
        return v


# ============================================
# SHOP MODELS
# ============================================

class ShopSettingsUpdate(BaseModel):
    """Do'kon sozlamalari"""
    isOpen: bool
    openDate: Optional[str] = None
    closeDate: Optional[str] = None


# ============================================
# PROFILE MODELS
# ============================================

class ProfileUpdate(BaseModel):
    """O'quvchi profil yangilash"""
    avatarIcon: Optional[str] = Field(None, max_length=20)
    avatarColor: Optional[str] = Field(None, max_length=20)
    bio: Optional[str] = Field(None, max_length=100)
    
    @validator('avatarIcon')
    def validate_icon(cls, v):
        if v:
            allowed = ['robot1', 'robot2', 'rocket', 'star', 'fire', 
                      'lightning', 'gem', 'crown', 'ninja', 'alien', 
                      'ghost', 'dragon']
            if v not in allowed:
                raise ValueError("Noto'g'ri avatar icon")
        return v
    
    @validator('avatarColor')
    def validate_color(cls, v):
        if v:
            allowed = ['blue', 'purple', 'green', 'orange', 
                      'cyan', 'rose', 'amber', 'slate']
            if v not in allowed:
                raise ValueError("Noto'g'ri avatar rang")
        return v
    
    @validator('bio')
    def sanitize_bio(cls, v):
        if v:
            return sanitize_string(v)
        return v


class AvatarUpload(BaseModel):
    """Avatar rasm yuklash"""
    image: str = Field(..., min_length=100)  # Base64 string
    
    @validator('image')
    def validate_image(cls, v):
        if not v.startswith('data:image/'):
            raise ValueError("Faqat rasm fayllari ruxsat etilgan")
        
        # Allowed formats
        allowed_formats = ['data:image/jpeg', 'data:image/png', 
                          'data:image/webp', 'data:image/jpg']
        
        if not any(v.startswith(fmt) for fmt in allowed_formats):
            raise ValueError("Faqat JPEG, PNG, WebP formatlar ruxsat etilgan")
        
        return v


# ============================================
# MESSAGE MODELS
# ============================================

class MessageSend(BaseModel):
    """Xabar yuborish"""
    toUserId: str
    text: str = Field(..., min_length=1, max_length=1000)
    
    @validator('toUserId')
    def validate_user_id(cls, v):
        return validate_object_id(v)
    
    @validator('text')
    def sanitize_text(cls, v):
        return sanitize_string(v)


# ============================================
# ATTENDANCE MODELS
# ============================================

class AttendanceEntry(BaseModel):
    """Davomat yozuvi"""
    studentId: str
    status: str
    
    @validator('studentId')
    def validate_student_id(cls, v):
        return validate_object_id(v)
    
    @validator('status')
    def validate_status(cls, v):
        allowed = ['present', 'absent', 'late']
        if v not in allowed:
            raise ValueError(f"Status {allowed} dan biri bo'lishi kerak")
        return v


class AttendanceSave(BaseModel):
    """Davomat saqlash"""
    groupId: str
    date: str
    entries: List[AttendanceEntry]
    
    @validator('groupId')
    def validate_group_id(cls, v):
        return validate_object_id(v)