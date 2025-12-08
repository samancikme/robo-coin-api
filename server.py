# ============================================
# ROBO COIN - BACKEND (TO'LIQ TUZATILGAN)
# ============================================

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from typing import Optional
from datetime import datetime, timedelta
from bson import ObjectId
from bson.errors import InvalidId
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import random
import base64
import string
import io
import os
from dotenv import load_dotenv

# YANGI IMPORT'LAR
from config import settings
from models import (
    LoginRequest, StudentCreate, CoinTransaction, GroupCreate, GroupUpdate,
    AssignmentCreate, SubmissionReview, RewardCreate, ShopSettingsUpdate,
    ProfileUpdate, AvatarUpload, MessageSend, AttendanceSave
)
from security import (
    generate_strong_password, generate_passphrase, generate_login,
    optimize_avatar_image, validate_image_content
)
from rate_limiter import limiter, rate_limit_exceeded_handler, RateLimits


load_dotenv()

# ============================================
# APP VA CONFIG
# ============================================

app = FastAPI(
    title="Robo Coin API",
    version="2.0.0",
    description="Robototexnika maktabi coin tizimi",
    docs_url="/docs" if settings.DEBUG else None,  # Production'da docs yopiq
    redoc_url="/redoc" if settings.DEBUG else None
)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(429, rate_limit_exceeded_handler)



app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,  # ❌ ["*"] emas!
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    max_age=3600  # Preflight cache 1 soat
)


# Global error handler

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Production'da xatolik tafsilotlarini yashirish
    if settings.ENVIRONMENT == "production":
        return JSONResponse(
            status_code=500,
            content={"detail": "Serverda xatolik yuz berdi"}
        )
    
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)}
    )

# MongoDB
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "robocoin_secret_2024")
ALGORITHM = "HS256"

client = AsyncIOMotorClient(MONGODB_URI)
db = client.robocoin

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)
# ============================================
# YORDAMCHI FUNKSIYALAR
# ============================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except:
        return False

def create_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(days=settings.JWT_EXPIRE_DAYS)
    return jwt.encode(
        {**data, "exp": expire}, 
        settings.JWT_SECRET, 
        algorithm=settings.JWT_ALGORITHM
    )

def calculate_level(coins: int) -> str:
    if coins >= 71: return "Senior Robotsoz"
    if coins >= 31: return "Middle Robotsoz"
    return "Junior Robotsoz"

def coins_to_next_level(coins: int) -> int:
    if coins >= 71: return 0
    if coins >= 31: return 71 - coins
    return 31 - coins

def str_id(doc: dict) -> dict:
    if doc and "_id" in doc:
        doc["id"] = str(doc["_id"])
        del doc["_id"]
    return doc

def to_object_id(id_str: str):
    """String ID ni MongoDB ObjectId ga o'zgartirish"""
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError, Exception):
        raise HTTPException(status_code=400, detail="Noto'g'ri ID formati")
# ============================================
# AUTH MIDDLEWARE
# ============================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Token kerak")
    
    try:
        token = credentials.credentials
        payload = jwt.decode(
            token, 
            settings.JWT_SECRET, 
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        user = await db.users.find_one({"_id": ObjectId(payload["id"])})
        if not user:
            raise HTTPException(status_code=401, detail="Foydalanuvchi topilmadi")
        
        if not user.get("isActive", True):
            raise HTTPException(status_code=401, detail="Akkaunt faol emas")
        
        return {
            "id": str(user["_id"]), 
            "role": user["role"], 
            "name": user["name"], 
            "groupId": str(user.get("groupId", "")) if user.get("groupId") else None
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Yaroqsiz token")

async def require_teacher(user: dict = Depends(get_current_user)):
    if user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Faqat ustozlar uchun")
    return user

async def require_student(user: dict = Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(status_code=403, detail="Faqat o'quvchilar uchun")
    return user


# ============================================
# ROOT ENDPOINT
# ============================================


@app.get("/")
async def root():
    return {
        "message": "Robo Coin API ishlayapti!",
        "version": "2.0.0",
        "docs": "/docs" if settings.DEBUG else "Disabled in production"
    }
# ============================================
# AUTH ROUTES
# ============================================

# ============================================
# LOGIN - KICHIK HARFGA O'ZGARTIRISH
# ============================================


@app.post("/api/auth/login")
@limiter.limit(RateLimits.LOGIN)  # 5 ta urinish / 1 daqiqa
async def login(request: Request, data: LoginRequest):
    """
    Login endpoint - Rate limited
    """
    # Login kichik harfga (model'da qilingan)
    user = await db.users.find_one({
        "login": {"$eq": data.login},  # Explicit equality (injection prevention)
        "isActive": True
    })
    
    if not user:
        raise HTTPException(status_code=400, detail="Login yoki parol noto'g'ri")
    
    if not verify_password(data.password, user["passwordHash"]):
        raise HTTPException(status_code=400, detail="Login yoki parol noto'g'ri")
    
    token = create_token({"id": str(user["_id"]), "role": user["role"]})
    
    return {
        "token": token,
        "user": {
            "id": str(user["_id"]),
            "name": user["name"],
            "role": user["role"],
            "groupId": str(user.get("groupId", "")) if user.get("groupId") else "",
            "avatarIcon": user.get("avatarIcon", "robot1"),
            "avatarColor": user.get("avatarColor", "blue"),
            "avatarImage": user.get("avatarImage"),
            "totalCoins": user.get("totalCoins", 0)
        }
    }


# ============================================
# HAFTALIK REYTING
# ============================================

@app.get("/api/teacher/rankings/weekly")
async def get_weekly_rankings(groupId: Optional[str] = None, user: dict = Depends(require_teacher)):
    try:
        # Hafta boshlanishi
        today = datetime.utcnow()
        week_start = today - timedelta(days=today.weekday())
        week_start = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Haftalik coinlar
        pipeline = [
            {"$match": {
                "createdAt": {"$gte": week_start},
                "amount": {"$gt": 0}
            }},
            {"$group": {
                "_id": "$studentId",
                "weeklyCoins": {"$sum": "$amount"}
            }},
            {"$sort": {"weeklyCoins": -1}}
        ]
        
        weekly_coins = await db.coinTransactions.aggregate(pipeline).to_list(500)
        weekly_map = {str(w["_id"]): w["weeklyCoins"] for w in weekly_coins}
        
        # O'quvchilar
        filter_query = {"role": "student", "isActive": True}
        if groupId:
            filter_query["groupId"] = to_object_id(groupId)
        
        students = await db.users.find(filter_query).sort("totalCoins", -1).to_list(500)
        
        result = []
        for i, s in enumerate(students):
            group = None
            if s.get("groupId"):
                group = await db.groups.find_one({"_id": s.get("groupId")})
            
            result.append({
                "rank": i + 1,
                "id": str(s["_id"]),
                "name": s["name"],
                "groupName": group["name"] if group else "",
                "totalCoins": s.get("totalCoins", 0),
                "weeklyCoins": weekly_map.get(str(s["_id"]), 0),
                "level": calculate_level(s.get("totalCoins", 0))
            })
        
        # Haftalik bo'yicha saralash
        result.sort(key=lambda x: x["weeklyCoins"], reverse=True)
        for i, r in enumerate(result):
            r["weeklyRank"] = i + 1
        
        return {
            "weekStart": week_start.isoformat(),
            "weekEnd": (week_start + timedelta(days=6)).isoformat(),
            "rankings": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# O'QUVCHILAR CREDENTIALS EXPORT
# ============================================

@app.get("/api/teacher/students/export-credentials")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def export_students_credentials(groupId: Optional[str] = None, user: dict = Depends(require_teacher)):
    try:
        filter_query = {"role": "student", "isActive": True}
        if groupId:
            filter_query["groupId"] = to_object_id(groupId)
        
        students = await db.users.find(filter_query).sort("name", 1).to_list(500)
        
        result = []
        for s in students:
            group = None
            if s.get("groupId"):
                group = await db.groups.find_one({"_id": s.get("groupId")})
            
            result.append({
                "name": s["name"],
                "login": s["login"],
                "password": s.get("plainPassword", "********"),
                "groupName": group["name"] if group else ""
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/auth/me")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_me(user: dict = Depends(get_current_user)):
    u = await db.users.find_one({"_id": ObjectId(user["id"])})
    return {
        "id": str(u["_id"]),
        "name": u["name"],
        "role": u["role"],
        "groupId": str(u.get("groupId", "")) if u.get("groupId") else "",
        "avatarIcon": u.get("avatarIcon", "robot1"),
        "totalCoins": u.get("totalCoins", 0),
        "level": calculate_level(u.get("totalCoins", 0))
    }
# ============================================
# USTOZ - DASHBOARD
# ============================================

@app.get("/api/teacher/dashboard")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def teacher_dashboard(user: dict = Depends(require_teacher)):
    try:
        total_students = await db.users.count_documents({"role": "student", "isActive": True})
        
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        pipeline = [
            {"$match": {"createdAt": {"$gte": today}, "amount": {"$gt": 0}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]
        coins_today = await db.coinTransactions.aggregate(pipeline).to_list(1)
        
        top_students = await db.users.find({"role": "student", "isActive": True}).sort("totalCoins", -1).limit(3).to_list(3)
        groups = await db.groups.find().to_list(100)
        
        return {
            "totalStudents": total_students,
            "coinsGivenToday": coins_today[0]["total"] if coins_today else 0,
            "topStudents": [{"name": s["name"], "totalCoins": s.get("totalCoins", 0)} for s in top_students],
            "groups": [str_id(g) for g in groups]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# GURUHLAR
# ============================================

@app.get("/api/teacher/groups")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_groups(user: dict = Depends(require_teacher)):
    try:
        groups = await db.groups.find().to_list(100)
        
        # Har bir guruh uchun o'quvchilar sonini hisoblash
        result = []
        for g in groups:
            student_count = await db.users.count_documents({
                "role": "student", 
                "isActive": True, 
                "groupId": g["_id"]
            })
            result.append({
                "id": str(g["_id"]),
                "name": g["name"],
                "description": g.get("description", ""),
                "studentCount": student_count,
                "maxStudents": 12
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/groups")
@limiter.limit(RateLimits.CREATE)
async def create_group(
    request: Request,
    group: GroupCreate,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Yangi guruh yaratish
    """
    # Max 6 guruh
    group_count = await db.groups.count_documents({})
    if group_count >= 6:
        raise HTTPException(status_code=400, detail="Maksimum 6 ta guruh bo'lishi mumkin")
    
    result = await db.groups.insert_one({
        "name": group.name,
        "description": group.description or "",
        "createdAt": datetime.utcnow()
    })
    
    return {"id": str(result.inserted_id), "name": group.name}


@app.patch("/api/teacher/groups/{group_id}")
@limiter.limit(RateLimits.UPDATE)
async def update_group(
    request: Request,
    group_id: str, 
    data: GroupUpdate,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Guruhni yangilash
    """
    existing = await db.groups.find_one({"_id": to_object_id(group_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Guruh topilmadi")
    
    update_data = {}
    if data.name:
        update_data["name"] = data.name
    if data.description is not None:
        update_data["description"] = data.description
    
    if not update_data:
        raise HTTPException(status_code=400, detail="Yangilanadigan ma'lumot yo'q")
    
    await db.groups.update_one(
        {"_id": to_object_id(group_id)},
        {"$set": update_data}
    )
    
    return {"message": "Guruh yangilandi"}

@app.delete("/api/teacher/groups/{group_id}")
async def delete_group(group_id: str, user: dict = Depends(require_teacher)):
    try:
        # Guruhda o'quvchilar borligini tekshirish
        student_count = await db.users.count_documents({
            "role": "student",
            "isActive": True,
            "groupId": to_object_id(group_id)
        })
        
        if student_count > 0:
            raise HTTPException(
                status_code=400, 
                detail=f"Bu guruhda {student_count} ta o'quvchi bor. Avval ularni boshqa guruhga o'tkazing."
            )
        
        await db.groups.delete_one({"_id": to_object_id(group_id)})
        return {"message": "Guruh o'chirildi"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# O'QUVCHILAR BOSHQARUVI
# ============================================

@app.get("/api/teacher/students")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_students(groupId: Optional[str] = None, user: dict = Depends(require_teacher)):
    try:
        filter_query = {"role": "student", "isActive": True}
        if groupId:
            filter_query["groupId"] = to_object_id(groupId)
        
        students = await db.users.find(filter_query).sort("totalCoins", -1).to_list(500)
        
        result = []
        for s in students:
            total = await db.attendance.count_documents({"studentId": s["_id"]})
            present = await db.attendance.count_documents({"studentId": s["_id"], "status": "present"})
            attendance = round((present / total * 100) if total > 0 else 0)
            
            group = None
            if s.get("groupId"):
                group = await db.groups.find_one({"_id": s.get("groupId")})
            
            result.append({
                "id": str(s["_id"]),
                "name": s["name"],
                "login": s["login"],
                "groupId": str(s.get("groupId", "")) if s.get("groupId") else "",
                "groupName": group["name"] if group else "",
                "totalCoins": s.get("totalCoins", 0),
                "level": calculate_level(s.get("totalCoins", 0)),
                "attendancePercent": attendance
            })
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@app.post("/api/teacher/students")
@limiter.limit(RateLimits.CREATE)
async def create_student(
    request: Request,
    student: StudentCreate,  # ✅ Pydantic validation
    user: dict = Depends(require_teacher)
):
    """
    Yangi o'quvchi yaratish - Validated & Rate Limited
    """
    # Guruhda o'quvchilar sonini tekshirish
    student_count = await db.users.count_documents({
        "role": "student",
        "isActive": True,
        "groupId": to_object_id(student.groupId)
    })
    
    if student_count >= 12:
        raise HTTPException(
            status_code=400, 
            detail="Bu guruhda maksimum 12 ta o'quvchi. Boshqa guruhni tanlang."
        )
    
    # Login generatsiya qilish
    login = generate_login(student.name)
    
    # Login band emasligini tekshirish
    existing = await db.users.find_one({"login": login})
    if existing:
        # Unique qilish
        login = f"{login}_{secrets.randbelow(1000)}"
    
    # Kuchli parol generatsiya
    password = generate_strong_password(12)
    
    # O'quvchini yaratish
    result = await db.users.insert_one({
        "role": "student",
        "login": login,
        "passwordHash": hash_password(password),
        "plainPassword": password,  # Ustozga ko'rsatish uchun
        "name": student.name,
        "groupId": to_object_id(student.groupId),
        "avatarIcon": "robot1",
        "avatarColor": "blue",
        "totalCoins": 0,
        "isActive": True,
        "createdAt": datetime.utcnow()
    })
    
    return {
        "id": str(result.inserted_id), 
        "login": login, 
        "generatedPassword": password, 
        "name": student.name
    }


@app.get("/api/teacher/students/{student_id}")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_student(student_id: str, user: dict = Depends(require_teacher)):
    try:
        student = await db.users.find_one({"_id": to_object_id(student_id)})
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        group = None
        if student.get("groupId"):
            group = await db.groups.find_one({"_id": student.get("groupId")})
        
        coins = await db.coinTransactions.find({"studentId": to_object_id(student_id)}).sort("createdAt", -1).limit(20).to_list(20)
        
        coin_history = []
        for c in coins:
            teacher = await db.users.find_one({"_id": c["teacherId"]})
            coin_history.append({
                "id": str(c["_id"]),
                "amount": c["amount"],
                "reason": c["reason"],
                "teacherName": teacher["name"] if teacher else "",
                "createdAt": c["createdAt"].isoformat() if c.get("createdAt") else ""
            })
        
        total = await db.attendance.count_documents({"studentId": to_object_id(student_id)})
        present = await db.attendance.count_documents({"studentId": to_object_id(student_id), "status": "present"})
        
        return {
            "id": str(student["_id"]),
            "name": student["name"],
            "login": student["login"],
            "groupId": str(student.get("groupId", "")) if student.get("groupId") else "",
            "groupName": group["name"] if group else "",
            "avatarIcon": student.get("avatarIcon", "robot1"),
            "totalCoins": student.get("totalCoins", 0),
            "level": calculate_level(student.get("totalCoins", 0)),
            "coinsToNextLevel": coins_to_next_level(student.get("totalCoins", 0)),
            "coinHistory": coin_history,
            "attendancePercent": round((present / total * 100) if total > 0 else 0),
            "totalClasses": total,
            "presentClasses": present
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/teacher/students/{student_id}")
async def delete_student(student_id: str, user: dict = Depends(require_teacher)):
    try:
        student_oid = to_object_id(student_id)
        
        # O'quvchi borligini tekshirish
        student = await db.users.find_one({"_id": student_oid})
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        # O'quvchini o'chirish
        await db.users.delete_one({"_id": student_oid})
        
        # Tegishli ma'lumotlarni o'chirish
        await db.coinTransactions.delete_many({"studentId": student_oid})
        await db.attendance.delete_many({"studentId": student_oid})
        await db.submissions.delete_many({"studentId": student_oid})
        await db.messages.delete_many({
            "$or": [
                {"fromUserId": student_oid}, 
                {"toUserId": student_oid}
            ]
        })
        
        return {"message": "O'quvchi va uning barcha ma'lumotlari o'chirildi"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# PAROL BOSHQARUVI
# ============================================

@app.get("/api/teacher/students/{student_id}/password")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_student_password(student_id: str, user: dict = Depends(require_teacher)):
    try:
        student = await db.users.find_one({"_id": to_object_id(student_id)})
        
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        password = student.get("plainPassword", "")
        if not password:
            password = "Parol topilmadi - Yangi parol yarating"
        
        return {
            "name": student["name"],
            "login": student["login"],
            "password": password
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/students/{student_id}/reset-password")
async def reset_student_password(student_id: str, user: dict = Depends(require_teacher)):
    try:
        student = await db.users.find_one({"_id": to_object_id(student_id)})
        
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        # Yangi parol yaratish
        new_password = generate_password(8)
        
        # Parolni yangilash
        await db.users.update_one(
            {"_id": to_object_id(student_id)},
            {"$set": {
                "passwordHash": hash_password(new_password),
                "plainPassword": new_password
            }}
        )
        
        return {
            "message": "Parol yangilandi",
            "name": student["name"],
            "login": student["login"],
            "newPassword": new_password
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# COIN OPERATSIYALARI
# ============================================

@app.post("/api/teacher/students/{student_id}/coins")
@limiter.limit(RateLimits.GIVE_COINS)
async def give_coins(
    request: Request,
    student_id: str, 
    transaction: CoinTransaction,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Coin berish/olish - Validated & Rate Limited
    """
    student = await db.users.find_one({"_id": to_object_id(student_id)})
    if not student:
        raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
    
    # Transaction yaratish
    await db.coinTransactions.insert_one({
        "studentId": to_object_id(student_id),
        "teacherId": to_object_id(user["id"]),
        "amount": transaction.amount,
        "reason": transaction.reason,
        "createdAt": datetime.utcnow()
    })
    
    # Balansni yangilash
    current_balance = student.get("totalCoins", 0)
    new_balance = round(current_balance + transaction.amount, 2)
    
    await db.users.update_one(
        {"_id": to_object_id(student_id)}, 
        {"$set": {"totalCoins": new_balance}}
    )
    
    return {
        "message": "Coin berildi" if transaction.amount > 0 else "Coin olindi", 
        "newBalance": new_balance
    }

# ============================================
# DAVOMAT
# ============================================

@app.get("/api/teacher/attendance")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_attendance(groupId: Optional[str] = None, date: Optional[str] = None, user: dict = Depends(require_teacher)):
    try:
        filter_query = {}
        if groupId:
            filter_query["groupId"] = to_object_id(groupId)
        if date:
            d = datetime.fromisoformat(date.replace("Z", ""))
            filter_query["date"] = {"$gte": d, "$lt": d + timedelta(days=1)}
        
        records = await db.attendance.find(filter_query).sort("date", -1).to_list(500)
        
        result = []
        for r in records:
            student = await db.users.find_one({"_id": r["studentId"]})
            group = await db.groups.find_one({"_id": r["groupId"]})
            result.append({
                "id": str(r["_id"]),
                "studentId": str(r["studentId"]),
                "studentName": student["name"] if student else "",
                "groupName": group["name"] if group else "",
                "date": r["date"].isoformat() if r.get("date") else "",
                "status": r["status"]
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/attendance")
@limiter.limit(RateLimits.UPDATE)
async def save_attendance(
    request: Request,
    data: AttendanceSave,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Davomat saqlash
    """
    d = datetime.fromisoformat(data.date.replace("Z", "")).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    
    # Avvalgi davomatni tekshirish
    existing_attendance = await db.attendance.find({
        "groupId": to_object_id(data.groupId), 
        "date": d
    }).to_list(100)
    
    existing_student_ids = {str(a["studentId"]) for a in existing_attendance}
    
    # Eski davomatni o'chirish
    await db.attendance.delete_many({
        "groupId": to_object_id(data.groupId), 
        "date": d
    })
    
    coins_given = 0
    records = []
    
    for entry in data.entries:
        records.append({
            "studentId": to_object_id(entry.studentId),
            "groupId": to_object_id(data.groupId),
            "date": d,
            "status": entry.status,
            "createdAt": datetime.utcnow()
        })
        
        # Auto coin for "present"
        if entry.status == "present" and entry.studentId not in existing_student_ids:
            await db.coinTransactions.insert_one({
                "studentId": to_object_id(entry.studentId),
                "teacherId": to_object_id(user["id"]),
                "amount": 1.0,
                "reason": "Darsga kelish",
                "createdAt": datetime.utcnow()
            })
            
            await db.users.update_one(
                {"_id": to_object_id(entry.studentId)},
                {"$inc": {"totalCoins": 1.0}}
            )
            coins_given += 1
    
    if records:
        await db.attendance.insert_many(records)
    
    return {
        "message": f"Davomat saqlandi. {coins_given} ta o'quvchiga coin berildi.", 
        "count": len(records),
        "coinsGiven": coins_given
    }        


@app.get("/api/teacher/attendance/export")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def export_attendance(groupId: str, fromDate: str, toDate: str, user: dict = Depends(require_teacher)):
    try:
        filter_query = {
            "groupId": to_object_id(groupId),
            "date": {"$gte": datetime.fromisoformat(fromDate), "$lte": datetime.fromisoformat(toDate)}
        }
        
        records = await db.attendance.find(filter_query).sort("date", -1).to_list(1000)
        
        csv = "Sana,O'quvchi,Holat\n"
        for r in records:
            student = await db.users.find_one({"_id": r["studentId"]})
            status = {"present": "Keldi", "absent": "Kelmadi", "late": "Kechikdi"}.get(r["status"], r["status"])
            csv += f"{r['date'].strftime('%Y-%m-%d')},{student['name'] if student else '-'},{status}\n"
        
        return StreamingResponse(
            io.StringIO(csv), 
            media_type="text/csv", 
            headers={"Content-Disposition": "attachment; filename=davomat.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# RASM YUKLASH (Base64)
# ============================================


@app.post("/api/student/profile/avatar")
@limiter.limit(RateLimits.UPLOAD)
async def upload_avatar(
    request: Request,
    data: AvatarUpload,  # ✅ Validated
    user: dict = Depends(require_student)
):
    """
    Avatar rasm yuklash - Validated, Optimized, Rate Limited
    """
    # Rasm validatsiya
    if not validate_image_content(data.image):
        raise HTTPException(status_code=400, detail="Noto'g'ri rasm fayli")
    
    # Original hajmni tekshirish
    try:
        _, encoded = data.image.split(",", 1)
        original_size = len(base64.b64decode(encoded))
        
        if original_size > 5 * 1024 * 1024:  # 5MB limit
            raise HTTPException(status_code=400, detail="Rasm 5MB dan katta bo'lmasligi kerak")
    except:
        raise HTTPException(status_code=400, detail="Noto'g'ri rasm formati")
    
    # Optimizatsiya
    optimized = optimize_avatar_image(
        data.image,
        max_size=(settings.AVATAR_MAX_DIMENSION, settings.AVATAR_MAX_DIMENSION),
        quality=85
    )
    
    # Optimizatsiyadan keyingi hajm
    try:
        _, encoded = optimized.split(",", 1)
        final_size = len(base64.b64decode(encoded))
        
        if final_size > settings.MAX_AVATAR_SIZE:
            raise HTTPException(
                status_code=400, 
                detail=f"Rasm juda katta: {final_size/1024:.1f}KB (max {settings.MAX_AVATAR_SIZE/1024}KB)"
            )
    except HTTPException:
        raise
    except:
        raise HTTPException(status_code=400, detail="Rasmni qayta ishlashda xatolik")
    
    # Saqlash
    await db.users.update_one(
        {"_id": to_object_id(user["id"])},
        {"$set": {"avatarImage": optimized}}
    )
    
    return {"message": "Rasm yuklandi"}


# ============================================
# BOSHQA O'QUVCHILARNING PROFILLARI
# ============================================

@app.get("/api/students/public")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_all_students_public(user: dict = Depends(get_current_user)):
    """Barcha o'quvchilarning umumiy ma'lumotlari"""
    try:
        students = await db.users.find(
            {"role": "student", "isActive": True}
        ).sort("totalCoins", -1).to_list(500)
        
        result = []
        for i, s in enumerate(students):
            group = None
            if s.get("groupId"):
                group = await db.groups.find_one({"_id": s.get("groupId")})
            
            result.append({
                "id": str(s["_id"]),
                "name": s["name"],
                "avatarIcon": s.get("avatarIcon", "robot1"),
                "avatarColor": s.get("avatarColor", "blue"),
                "avatarImage": s.get("avatarImage"),
                "bio": s.get("bio", ""),
                "totalCoins": s.get("totalCoins", 0),
                "level": calculate_level(s.get("totalCoins", 0)),
                "groupName": group["name"] if group else "",
                "rank": i + 1
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/students/public/{student_id}")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_student_public_profile(student_id: str, user: dict = Depends(get_current_user)):
    """Bitta o'quvchining umumiy profili"""
    try:
        student = await db.users.find_one({
            "_id": to_object_id(student_id),
            "role": "student",
            "isActive": True
        })
        
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        # Reyting hisoblash
        all_students = await db.users.find(
            {"role": "student", "isActive": True}
        ).sort("totalCoins", -1).to_list(500)
        
        global_rank = next((i + 1 for i, s in enumerate(all_students) if str(s["_id"]) == student_id), 0)
        
        # Guruh va guruh reytingi
        group = None
        group_rank = 0
        group_total = 0
        if student.get("groupId"):
            group = await db.groups.find_one({"_id": student.get("groupId")})
            group_students = [s for s in all_students if s.get("groupId") == student.get("groupId")]
            group_rank = next((i + 1 for i, s in enumerate(group_students) if str(s["_id"]) == student_id), 0)
            group_total = len(group_students)
        
        # Davomat
        total_classes = await db.attendance.count_documents({"studentId": to_object_id(student_id)})
        present_classes = await db.attendance.count_documents({"studentId": to_object_id(student_id), "status": "present"})
        attendance_percent = round((present_classes / total_classes * 100) if total_classes > 0 else 0)
        
        # So'nggi coinlar
        recent_coins = await db.coinTransactions.find(
            {"studentId": to_object_id(student_id)}
        ).sort("createdAt", -1).limit(5).to_list(5)
        
        coin_history = []
        for c in recent_coins:
            coin_history.append({
                "amount": c["amount"],
                "reason": c["reason"],
                "createdAt": c["createdAt"].isoformat() if c.get("createdAt") else ""
            })
        
        return {
            "id": str(student["_id"]),
            "name": student["name"],
            "avatarIcon": student.get("avatarIcon", "robot1"),
            "avatarColor": student.get("avatarColor", "blue"),
            "avatarImage": student.get("avatarImage"),
            "bio": student.get("bio", ""),
            "totalCoins": student.get("totalCoins", 0),
            "level": calculate_level(student.get("totalCoins", 0)),
            "groupName": group["name"] if group else "",
            "globalRank": global_rank,
            "globalTotal": len(all_students),
            "groupRank": group_rank,
            "groupTotal": group_total,
            "attendancePercent": attendance_percent,
            "recentCoins": coin_history
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/students/compare/{student_id}")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def compare_with_student(student_id: str, user: dict = Depends(require_student)):
    """O'zini boshqa o'quvchi bilan solishtirish"""
    try:
        my_id = user["id"]
        
        # O'zim
        me = await db.users.find_one({"_id": to_object_id(my_id)})
        # Boshqa o'quvchi
        other = await db.users.find_one({"_id": to_object_id(student_id)})
        
        if not other:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        # Reytinglar
        all_students = await db.users.find(
            {"role": "student", "isActive": True}
        ).sort("totalCoins", -1).to_list(500)
        
        my_rank = next((i + 1 for i, s in enumerate(all_students) if str(s["_id"]) == my_id), 0)
        other_rank = next((i + 1 for i, s in enumerate(all_students) if str(s["_id"]) == student_id), 0)
        
        # Davomat
        my_total = await db.attendance.count_documents({"studentId": to_object_id(my_id)})
        my_present = await db.attendance.count_documents({"studentId": to_object_id(my_id), "status": "present"})
        
        other_total = await db.attendance.count_documents({"studentId": to_object_id(student_id)})
        other_present = await db.attendance.count_documents({"studentId": to_object_id(student_id), "status": "present"})
        
        return {
            "me": {
                "name": me["name"],
                "totalCoins": me.get("totalCoins", 0),
                "rank": my_rank,
                "attendancePercent": round((my_present / my_total * 100) if my_total > 0 else 0),
                "level": calculate_level(me.get("totalCoins", 0))
            },
            "other": {
                "name": other["name"],
                "totalCoins": other.get("totalCoins", 0),
                "rank": other_rank,
                "attendancePercent": round((other_present / other_total * 100) if other_total > 0 else 0),
                "level": calculate_level(other.get("totalCoins", 0))
            },
            "coinDifference": me.get("totalCoins", 0) - other.get("totalCoins", 0),
            "rankDifference": other_rank - my_rank
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Profil endpoint yangilash (avatarImage qo'shish)
@app.get("/api/student/profile")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_student_profile(user: dict = Depends(require_student)):
    try:
        student = await db.users.find_one({"_id": to_object_id(user["id"])})
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        return {
            "id": str(student["_id"]),
            "name": student["name"],
            "login": student["login"],
            "avatarIcon": student.get("avatarIcon", "robot1"),
            "avatarColor": student.get("avatarColor", "blue"),
            "avatarImage": student.get("avatarImage"),  # YANGI
            "bio": student.get("bio", ""),
            "totalCoins": student.get("totalCoins", 0),
            "level": calculate_level(student.get("totalCoins", 0))
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# TOPSHIRIQLAR
# ============================================

@app.get("/api/teacher/assignments")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_assignments(user: dict = Depends(require_teacher)):
    try:
        assignments = await db.assignments.find().sort("createdAt", -1).to_list(100)
        
        result = []
        for a in assignments:
            group_ids = a.get("groupIds", [])
            groups = await db.groups.find({"_id": {"$in": group_ids}}).to_list(10) if group_ids else []
            result.append({
                "id": str(a["_id"]),
                "title": a["title"],
                "description": a.get("description", ""),
                "groupIds": [str(g) for g in group_ids],
                "groupNames": [g["name"] for g in groups],
                "startDate": a.get("startDate", a.get("createdAt")).isoformat() if a.get("startDate") or a.get("createdAt") else "",
                "dueDate": a["dueDate"].isoformat() if a.get("dueDate") else None,
                "isActive": a.get("isActive", True)
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/assignments")
@limiter.limit(RateLimits.CREATE)
async def create_assignment(
    request: Request,
    assignment: AssignmentCreate,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Yangi topshiriq yaratish
    """
    group_ids = [to_object_id(g) for g in assignment.groupIds]
    
    result = await db.assignments.insert_one({
        "title": assignment.title,
        "description": assignment.description or "",
        "groupIds": group_ids,
        "startDate": datetime.utcnow(),
        "dueDate": datetime.fromisoformat(assignment.dueDate) if assignment.dueDate else None,
        "isActive": True,
        "createdAt": datetime.utcnow()
    })
    
    return {"id": str(result.inserted_id), "message": "Topshiriq yaratildi"}

@app.delete("/api/teacher/assignments/{assignment_id}")
async def delete_assignment(assignment_id: str, user: dict = Depends(require_teacher)):
    try:
        await db.assignments.delete_one({"_id": to_object_id(assignment_id)})
        await db.submissions.delete_many({"assignmentId": to_object_id(assignment_id)})
        return {"message": "Topshiriq o'chirildi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/teacher/assignments/{assignment_id}/submissions")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_submissions(assignment_id: str, user: dict = Depends(require_teacher)):
    try:
        subs = await db.submissions.find({"assignmentId": to_object_id(assignment_id)}).to_list(100)
        
        result = []
        for s in subs:
            student = await db.users.find_one({"_id": s["studentId"]})
            result.append({
                "id": str(s["_id"]),
                "studentId": str(s["studentId"]),
                "studentName": student["name"] if student else "",
                "status": s["status"],
                "submittedAt": s.get("submittedAt").isoformat() if s.get("submittedAt") else None,
                "coinsGiven": s.get("coinsGiven", 0)
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/submissions/{submission_id}/coins")
@limiter.limit(RateLimits.GIVE_COINS)
async def review_submission(
    request: Request,
    submission_id: str, 
    review: SubmissionReview,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Topshiriqni baholash
    """
    sub = await db.submissions.find_one({"_id": to_object_id(submission_id)})
    if not sub:
        raise HTTPException(status_code=404, detail="Javob topilmadi")
    
    await db.submissions.update_one(
        {"_id": to_object_id(submission_id)}, 
        {"$set": {
            "status": "reviewed",
            "reviewedAt": datetime.utcnow(),
            "teacherId": to_object_id(user["id"]),
            "coinsGiven": review.coinsGiven
        }}
    )
    
    if review.coinsGiven > 0:
        await db.coinTransactions.insert_one({
            "studentId": sub["studentId"],
            "teacherId": to_object_id(user["id"]),
            "amount": review.coinsGiven,
            "reason": "Topshiriq uchun",
            "createdAt": datetime.utcnow()
        })
        await db.users.update_one(
            {"_id": sub["studentId"]}, 
            {"$inc": {"totalCoins": review.coinsGiven}}
        )
    
    return {"message": "Coin berildi"}

# ============================================
# SOVG'ALAR VA DO'KON
# ============================================

@app.get("/api/teacher/rewards")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_rewards(user: dict = Depends(require_teacher)):
    try:
        rewards = await db.rewards.find().sort("price", 1).to_list(100)
        return [str_id(r) for r in rewards]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/rewards")
@limiter.limit(RateLimits.CREATE)
async def create_reward(
    request: Request,
    reward: RewardCreate,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Yangi sovg'a yaratish
    """
    result = await db.rewards.insert_one({
        "name": reward.name,
        "description": reward.description or "",
        "price": reward.price,
        "category": reward.category,
        "icon": reward.icon,
        "createdAt": datetime.utcnow()
    })
    
    return {"id": str(result.inserted_id), "message": "Sovg'a qo'shildi"}

@app.delete("/api/teacher/rewards/{reward_id}")
async def delete_reward(reward_id: str, user: dict = Depends(require_teacher)):
    try:
        await db.rewards.delete_one({"_id": to_object_id(reward_id)})
        return {"message": "Sovg'a o'chirildi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/teacher/shop-settings")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_shop_settings(user: dict = Depends(require_teacher)):
    try:
        settings = await db.shopSettings.find_one()
        if not settings:
            settings = {"isOpen": False}
        return str_id(settings) if settings.get("_id") else settings
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/teacher/shop-settings")
async def update_shop_settings(request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        await db.shopSettings.update_one({}, {"$set": {
            "isOpen": data.get("isOpen", False),
            "openDate": datetime.fromisoformat(data.get("openDate")) if data.get("openDate") else None,
            "closeDate": datetime.fromisoformat(data.get("closeDate")) if data.get("closeDate") else None
        }}, upsert=True)
        return {"message": "Do'kon sozlamalari yangilandi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# XABARLAR (USTOZ)
# ============================================

@app.get("/api/teacher/messages")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_teacher_messages(studentId: Optional[str] = None, user: dict = Depends(require_teacher)):
    try:
        if studentId:
            msgs = await db.messages.find({"$or": [
                {"fromUserId": to_object_id(user["id"]), "toUserId": to_object_id(studentId)},
                {"fromUserId": to_object_id(studentId), "toUserId": to_object_id(user["id"])}
            ]}).sort("createdAt", 1).to_list(100)
            
            result = []
            for m in msgs:
                result.append({
                    "id": str(m["_id"]),
                    "fromUserId": str(m["fromUserId"]),
                    "toUserId": str(m["toUserId"]),
                    "text": m["text"],
                    "createdAt": m["createdAt"].isoformat() if m.get("createdAt") else ""
                })
            return result
        
        students = await db.users.find({"role": "student", "isActive": True}).to_list(500)
        return [{"id": str(s["_id"]), "name": s["name"]} for s in students]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/messages")
@limiter.limit(RateLimits.CREATE)
async def send_teacher_message(
    request: Request,
    message: MessageSend,  # ✅ Validated
    user: dict = Depends(require_teacher)
):
    """
    Ustoz xabar yuborish
    """
    # Qabul qiluvchi mavjudligini tekshirish
    recipient = await db.users.find_one({"_id": to_object_id(message.toUserId)})
    if not recipient:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    
    await db.messages.insert_one({
        "fromUserId": to_object_id(user["id"]),
        "toUserId": to_object_id(message.toUserId),
        "text": message.text,
        "createdAt": datetime.utcnow()
    })
    
    return {"message": "Xabar yuborildi"}
# ============================================
# O'QUVCHI PROFIL SOZLAMALARI
# ============================================

@app.get("/api/student/profile")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def get_student_profile(user: dict = Depends(require_student)):
    try:
        student = await db.users.find_one({"_id": to_object_id(user["id"])})
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        return {
            "id": str(student["_id"]),
            "name": student["name"],
            "login": student["login"],
            "avatarIcon": student.get("avatarIcon", "robot1"),
            "avatarColor": student.get("avatarColor", "blue"),
            "bio": student.get("bio", ""),
            "totalCoins": student.get("totalCoins", 0),
            "level": calculate_level(student.get("totalCoins", 0))
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/api/student/profile")
@limiter.limit(RateLimits.UPDATE)
async def update_student_profile(
    request: Request,
    profile: ProfileUpdate,  # ✅ Validated
    user: dict = Depends(require_student)
):
    """
    O'quvchi profil yangilash
    """
    update_data = {}
    
    if profile.avatarIcon:
        update_data["avatarIcon"] = profile.avatarIcon
    if profile.avatarColor:
        update_data["avatarColor"] = profile.avatarColor
    if profile.bio is not None:
        update_data["bio"] = profile.bio
    
    if not update_data:
        raise HTTPException(status_code=400, detail="Yangilanadigan ma'lumot yo'q")
    
    await db.users.update_one(
        {"_id": to_object_id(user["id"])},
        {"$set": update_data}
    )
    
    return {"message": "Profil yangilandi", "updated": update_data}
# ============================================
# O'QUVCHI ROUTES
# ============================================

@app.get("/api/student/dashboard")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def student_dashboard(user: dict = Depends(require_student)):
    try:
        student = await db.users.find_one({"_id": to_object_id(user["id"])})
        
        group = None
        if student.get("groupId"):
            group = await db.groups.find_one({"_id": student.get("groupId")})
        
        last_tx = await db.coinTransactions.find({"studentId": to_object_id(user["id"])}).sort("createdAt", -1).limit(1).to_list(1)
        last_teacher = None
        if last_tx:
            last_teacher = await db.users.find_one({"_id": last_tx[0]["teacherId"]})
        
        total = await db.attendance.count_documents({"studentId": to_object_id(user["id"])})
        present = await db.attendance.count_documents({"studentId": to_object_id(user["id"]), "status": "present"})
        
        all_students = await db.users.find({"role": "student", "isActive": True}).sort("totalCoins", -1).to_list(500)
        global_rank = next((i + 1 for i, s in enumerate(all_students) if str(s["_id"]) == user["id"]), 0)
        
        group_students = [s for s in all_students if str(s.get("groupId", "")) == str(student.get("groupId", ""))]
        group_rank = next((i + 1 for i, s in enumerate(group_students) if str(s["_id"]) == user["id"]), 0)
        
        return {
            "user": {
                "id": user["id"], 
                "name": student["name"], 
                "groupName": group["name"] if group else "", 
                "avatarIcon": student.get("avatarIcon", "robot1")
            },
            "totalCoins": student.get("totalCoins", 0),
            "level": calculate_level(student.get("totalCoins", 0)),
            "coinsToNextLevel": coins_to_next_level(student.get("totalCoins", 0)),
            "lastTransaction": {
                "date": last_tx[0]["createdAt"].isoformat(), 
                "amount": last_tx[0]["amount"], 
                "reason": last_tx[0]["reason"], 
                "teacherName": last_teacher["name"] if last_teacher else ""
            } if last_tx else None,
            "attendancePercent": round((present / total * 100) if total > 0 else 0),
            "globalRank": global_rank,
            "globalTotal": len(all_students),
            "groupRank": group_rank,
            "groupTotal": len(group_students),
            "topGlobal": [{"name": s["name"], "totalCoins": s.get("totalCoins", 0)} for s in all_students[:5]],
            "topGroup": [{"name": s["name"], "totalCoins": s.get("totalCoins", 0)} for s in group_students[:5]]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/student/coins")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def student_coins(user: dict = Depends(require_student)):
    try:
        txs = await db.coinTransactions.find({"studentId": to_object_id(user["id"])}).sort("createdAt", -1).limit(50).to_list(50)
        
        result = []
        for t in txs:
            teacher = await db.users.find_one({"_id": t["teacherId"]})
            result.append({
                "id": str(t["_id"]),
                "amount": t["amount"],
                "reason": t["reason"],
                "teacherName": teacher["name"] if teacher else "",
                "createdAt": t["createdAt"].isoformat() if t.get("createdAt") else ""
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/student/assignments")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def student_assignments(status: Optional[str] = None, user: dict = Depends(require_student)):
    try:
        student = await db.users.find_one({"_id": to_object_id(user["id"])})
        
        if not student.get("groupId"):
            return []
        
        assignments = await db.assignments.find({
            "groupIds": student.get("groupId"), 
            "isActive": True
        }).sort("createdAt", -1).to_list(100)
        
        result = []
        for a in assignments:
            sub = await db.submissions.find_one({
                "assignmentId": a["_id"], 
                "studentId": to_object_id(user["id"])
            })
            sub_status = sub["status"] if sub else "not_started"
            
            if status == "active" and sub_status == "reviewed":
                continue
            if status == "completed" and sub_status != "reviewed":
                continue
            
            result.append({
                "id": str(a["_id"]),
                "title": a["title"],
                "description": a.get("description", ""),
                "startDate": a.get("startDate", a.get("createdAt")).isoformat() if a.get("startDate") or a.get("createdAt") else "",
                "dueDate": a["dueDate"].isoformat() if a.get("dueDate") else None,
                "submission": {
                    "status": sub_status,
                    "submittedAt": sub.get("submittedAt").isoformat() if sub and sub.get("submittedAt") else None,
                    "coinsGiven": sub.get("coinsGiven", 0) if sub else 0
                }
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/student/assignments/{assignment_id}/start")
async def start_assignment(assignment_id: str, user: dict = Depends(require_student)):
    try:
        await db.submissions.update_one(
            {"assignmentId": to_object_id(assignment_id), "studentId": to_object_id(user["id"])},
            {"$set": {"status": "in_progress"}, "$setOnInsert": {"createdAt": datetime.utcnow()}},
            upsert=True
        )
        return {"message": "Topshiriq boshlandi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/student/assignments/{assignment_id}/complete")
async def complete_assignment(assignment_id: str, user: dict = Depends(require_student)):
    try:
        await db.submissions.update_one(
            {"assignmentId": to_object_id(assignment_id), "studentId": to_object_id(user["id"])},
            {"$set": {"status": "submitted", "submittedAt": datetime.utcnow()}, "$setOnInsert": {"createdAt": datetime.utcnow()}},
            upsert=True
        )
        return {"message": "Topshiriq yuborildi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/student/shop")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def student_shop(user: dict = Depends(require_student)):
    try:
        settings = await db.shopSettings.find_one() or {"isOpen": False}
        rewards = await db.rewards.find().sort("price", 1).to_list(100)
        student = await db.users.find_one({"_id": to_object_id(user["id"])})
        
        return {
            "isOpen": settings.get("isOpen", False),
            "openDate": settings.get("openDate").isoformat() if settings.get("openDate") else None,
            "closeDate": settings.get("closeDate").isoformat() if settings.get("closeDate") else None,
            "totalCoins": student.get("totalCoins", 0),
            "rewards": [str_id(r) for r in rewards]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/student/shop/redeem/{reward_id}")
async def redeem_reward(reward_id: str, user: dict = Depends(require_student)):
    try:
        settings = await db.shopSettings.find_one()
        if not settings or not settings.get("isOpen"):
            raise HTTPException(status_code=400, detail="Do'kon hozir yopiq")
        
        reward = await db.rewards.find_one({"_id": to_object_id(reward_id)})
        if not reward:
            raise HTTPException(status_code=404, detail="Sovg'a topilmadi")
        
        student = await db.users.find_one({"_id": to_object_id(user["id"])})
        if student.get("totalCoins", 0) < reward["price"]:
            raise HTTPException(status_code=400, detail="Coin yetarli emas")
        
        new_balance = student["totalCoins"] - reward["price"]
        await db.users.update_one({"_id": to_object_id(user["id"])}, {"$set": {"totalCoins": new_balance}})
        
        await db.coinTransactions.insert_one({
            "studentId": to_object_id(user["id"]),
            "teacherId": to_object_id(user["id"]),
            "amount": -reward["price"],
            "reason": f"Sovg'a: {reward['name']}",
            "createdAt": datetime.utcnow()
        })
        
        return {"message": "Sovg'a olindi!", "reward": reward["name"], "newBalance": new_balance}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/student/messages")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def student_messages(user: dict = Depends(require_student)):
    try:
        msgs = await db.messages.find({
            "$or": [
                {"fromUserId": to_object_id(user["id"])}, 
                {"toUserId": to_object_id(user["id"])}
            ]
        }).sort("createdAt", 1).to_list(100)
        
        result = []
        for m in msgs:
            result.append({
                "id": str(m["_id"]),
                "fromUserId": str(m["fromUserId"]),
                "toUserId": str(m["toUserId"]),
                "text": m["text"],
                "createdAt": m["createdAt"].isoformat() if m.get("createdAt") else ""
            })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/student/messages")
@limiter.limit(RateLimits.CREATE)
async def send_student_message(
    request: Request,
    message: MessageSend,  # ✅ Validated
    user: dict = Depends(require_student)
):
    """
    O'quvchi xabar yuborish - faqat ustozlarga
    """
    teacher = await db.users.find_one({
        "_id": to_object_id(message.toUserId), 
        "role": "teacher"
    })
    if not teacher:
        raise HTTPException(status_code=400, detail="Faqat ustozga xabar yuborish mumkin")
    
    await db.messages.insert_one({
        "fromUserId": to_object_id(user["id"]),
        "toUserId": to_object_id(message.toUserId),
        "text": message.text,
        "createdAt": datetime.utcnow()
    })
    
    return {"message": "Xabar yuborildi"}

# ============================================
# REYTINGLAR
# ============================================

@app.get("/api/rankings/global")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def global_rankings(user: dict = Depends(get_current_user)):
    try:
        students = await db.users.find({"role": "student", "isActive": True}).sort("totalCoins", -1).to_list(500)
        return [
            {
                "rank": i + 1, 
                "name": s["name"], 
                "totalCoins": s.get("totalCoins", 0), 
                "level": calculate_level(s.get("totalCoins", 0))
            } 
            for i, s in enumerate(students)
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/rankings/group/{group_id}")
@limiter.limit(RateLimits.DEFAULT)  # 100/minute
async def group_rankings(group_id: str, user: dict = Depends(get_current_user)):
    try:
        students = await db.users.find({
            "role": "student", 
            "isActive": True, 
            "groupId": to_object_id(group_id)
        }).sort("totalCoins", -1).to_list(100)
        return [
            {
                "rank": i + 1, 
                "name": s["name"], 
                "totalCoins": s.get("totalCoins", 0), 
                "level": calculate_level(s.get("totalCoins", 0))
            } 
            for i, s in enumerate(students)
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# SEED DATA
# ============================================

@app.on_event("startup")
async def startup_event():
    """
    Server ishga tushganda:
    1. Konfiguratsiyani tekshirish
    2. Database indexlarni yaratish
    """
    # Config validation
    settings.validate()
    
    # Database indexes
    await create_indexes()
    
    # Seed data (agar kerak bo'lsa)
    await seed_data()
    
    print("🚀 Robo Coin API ishga tushdi!")

async def create_indexes():
    """Database indexlarni yaratish"""
    try:
        # Users
        await db.users.create_index([("login", 1)], unique=True)
        await db.users.create_index([("role", 1), ("isActive", 1)])
        await db.users.create_index([("groupId", 1)])
        await db.users.create_index([("totalCoins", -1)])
        
        # Coin Transactions
        await db.coinTransactions.create_index([("studentId", 1), ("createdAt", -1)])
        await db.coinTransactions.create_index([("createdAt", -1)])
        
        # Attendance
        await db.attendance.create_index([("studentId", 1), ("date", -1)])
        await db.attendance.create_index([("groupId", 1), ("date", -1)])
        
        # Assignments
        await db.assignments.create_index([("groupIds", 1)])
        await db.assignments.create_index([("isActive", 1)])
        
        # Submissions
        await db.submissions.create_index(
            [("assignmentId", 1), ("studentId", 1)], 
            unique=True
        )
        
        print("✅ Database indexes created")
    except Exception as e:
        print(f"⚠️ Index creation warning: {e}")



async def seed_data():
    """Boshlang'ich ma'lumotlar"""
    try:
        existing = await db.users.find_one({"role": "teacher"})
        if existing:
            print("✅ Ma'lumotlar allaqachon mavjud")
            return
        
        # Ustozlar - KUCHLI PAROLLAR
        await db.users.insert_many([
            {
                "role": "teacher", 
                "login": "lord", 
                "passwordHash": hash_password("samancikme"), 
                "name": "Samandar", 
                "isActive": True, 
                "createdAt": datetime.utcnow()
            },
            {
                "role": "teacher", 
                "login": "saatbaeva", 
                "passwordHash": hash_password("shahlo000"), 
                "name": "Shahlo", 
                "isActive": True, 
                "createdAt": datetime.utcnow()
            }
        ])
        
        # Guruhlar
        await db.groups.insert_many([
            {"name": f"Guruh {i}", "description": "", "createdAt": datetime.utcnow()}
            for i in range(1, 7)
        ])
        
        # Shop settings
        await db.shopSettings.insert_one({"isOpen": False})
        
        # Default rewards
        await db.rewards.insert_many([
            {"name": "Konfet", "description": "Shirin konfet", "price": 5, "category": "kichik", "icon": "candy", "createdAt": datetime.utcnow()},
            {"name": "Ruchka", "description": "Chiroyli ruchka", "price": 10, "category": "kichik", "icon": "pen", "createdAt": datetime.utcnow()},
            {"name": "Daftar", "description": "Katta daftar", "price": 20, "category": "oqish", "icon": "notebook", "createdAt": datetime.utcnow()},
        ])
        
        print("✅ Boshlang'ich ma'lumotlar yaratildi")
    except Exception as e:
        print(f"⚠️ Seed error: {e}")

# ============================================
# SERVER
# ============================================


if __name__ == "__main__":
    import uvicorn
    print("🚀 Server ishga tushmoqda...")
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=int(os.getenv("PORT", 4000))
    )