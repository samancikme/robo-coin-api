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
import string
import io
import os
from dotenv import load_dotenv

load_dotenv()

# ============================================
# APP VA CONFIG
# ============================================

app = FastAPI(title="Robo Coin API", version="1.0.0")

# CORS - MUHIM!
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*"
        }
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
    return pwd_context.verify(plain, hashed)

def create_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(days=7)
    return jwt.encode({**data, "exp": expire}, JWT_SECRET, algorithm=ALGORITHM)

def generate_password(length: int = 8) -> str:
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

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

async def parse_json(request: Request) -> dict:
    """JSON body ni xavfsiz parse qilish"""
    try:
        body = await request.body()
        if not body:
            raise HTTPException(status_code=400, detail="So'rov tanasi bo'sh")
        return await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"JSON formati noto'g'ri: {str(e)}")

# ============================================
# AUTH MIDDLEWARE
# ============================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Token kerak")
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user = await db.users.find_one({"_id": ObjectId(payload["id"])})
        if not user:
            raise HTTPException(status_code=401, detail="Foydalanuvchi topilmadi")
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
        "version": "1.0.0",
        "docs": "/docs"
    }

# ============================================
# AUTH ROUTES
# ============================================

@app.post("/api/auth/login")
async def login(request: Request):
    try:
        data = await parse_json(request)
        
        login_name = data.get("login")
        password = data.get("password")
        
        if not login_name or not password:
            raise HTTPException(status_code=400, detail="Login va parol kerak")
        
        user = await db.users.find_one({"login": login_name, "isActive": True})
        if not user:
            raise HTTPException(status_code=400, detail="Login yoki parol noto'g'ri")
        
        if not verify_password(password, user["passwordHash"]):
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
                "totalCoins": user.get("totalCoins", 0)
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    try:
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# USTOZ - DASHBOARD
# ============================================

@app.get("/api/teacher/dashboard")
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
async def create_group(request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        
        if not data.get("name"):
            raise HTTPException(status_code=400, detail="Guruh nomi kerak")
        
        # Guruhlar soni 6 tadan oshmasligi kerak
        group_count = await db.groups.count_documents({})
        if group_count >= 6:
            raise HTTPException(status_code=400, detail="Maksimum 6 ta guruh bo'lishi mumkin")
        
        result = await db.groups.insert_one({
            "name": data.get("name"),
            "description": data.get("description", ""),
            "createdAt": datetime.utcnow()
        })
        return {"id": str(result.inserted_id), "name": data.get("name")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/teacher/groups/{group_id}")
async def update_group(group_id: str, request: Request, user: dict = Depends(require_teacher)):
    """Guruh nomini o'zgartirish"""
    try:
        data = await parse_json(request)
        
        if not data.get("name"):
            raise HTTPException(status_code=400, detail="Guruh nomi kerak")
        
        group = await db.groups.find_one({"_id": to_object_id(group_id)})
        if not group:
            raise HTTPException(status_code=404, detail="Guruh topilmadi")
        
        await db.groups.update_one(
            {"_id": to_object_id(group_id)},
            {"$set": {
                "name": data.get("name"),
                "description": data.get("description", group.get("description", ""))
            }}
        )
        
        return {"message": "Guruh yangilandi", "name": data.get("name")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
async def create_student(request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        
        name = data.get("name")
        groupId = data.get("groupId")
        
        if not name:
            raise HTTPException(status_code=400, detail="Ism kerak")
        if not groupId:
            raise HTTPException(status_code=400, detail="Guruh kerak")
        
        # Guruhda o'quvchilar sonini tekshirish (maksimum 12)
        student_count = await db.users.count_documents({
            "role": "student",
            "isActive": True,
            "groupId": to_object_id(groupId)
        })
        
        if student_count >= 12:
            raise HTTPException(
                status_code=400, 
                detail="Bu guruhda maksimum 12 ta o'quvchi bo'lishi mumkin. Boshqa guruhni tanlang."
            )
        
        # Login yaratish
        login = data.get("login") or name.lower().replace(" ", "_").replace("'", "").replace(".", "").replace(",", "")
        
        # Loginni tekshirish
        existing = await db.users.find_one({"login": login})
        if existing:
            raise HTTPException(status_code=400, detail="Bu login allaqachon mavjud. Boshqa ism kiriting.")
        
        # Tasodifiy parol yaratish
        password = generate_password(8)
        
        # O'quvchini yaratish
        result = await db.users.insert_one({
            "role": "student",
            "login": login,
            "passwordHash": hash_password(password),
            "plainPassword": password,
            "name": name,
            "groupId": to_object_id(groupId),
            "avatarIcon": "robot1",
            "totalCoins": 0,
            "isActive": True,
            "createdAt": datetime.utcnow()
        })
        
        return {
            "id": str(result.inserted_id), 
            "login": login, 
            "generatedPassword": password, 
            "name": name
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/teacher/students/{student_id}")
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
async def give_coins(student_id: str, request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        
        amount = data.get("amount")
        reason = data.get("reason")
        
        if amount is None:
            raise HTTPException(status_code=400, detail="Coin miqdori kerak")
        if not reason:
            raise HTTPException(status_code=400, detail="Sabab kerak")
        
        student = await db.users.find_one({"_id": to_object_id(student_id)})
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        # Float qiymatni qabul qilish
        coin_amount = float(amount)
        
        await db.coinTransactions.insert_one({
            "studentId": to_object_id(student_id),
            "teacherId": to_object_id(user["id"]),
            "amount": coin_amount,  # Float sifatida saqlash
            "reason": reason,
            "createdAt": datetime.utcnow()
        })
        
        # Manfiy balansga ruxsat berish
        current_balance = student.get("totalCoins", 0)
        new_balance = current_balance + coin_amount  # Manfiy bo'lishi mumkin
        
        await db.users.update_one(
            {"_id": to_object_id(student_id)}, 
            {"$set": {"totalCoins": round(new_balance, 2)}}  # 2 xonagacha yaxlitlash
        )
        
        return {
            "message": "Coin berildi" if coin_amount > 0 else "Coin olindi", 
            "newBalance": round(new_balance, 2)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# DAVOMAT
# ============================================

@app.get("/api/teacher/attendance")
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
async def save_attendance(request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        
        groupId = data.get("groupId")
        date = data.get("date")
        entries = data.get("entries", [])
        
        if not groupId or not date:
            raise HTTPException(status_code=400, detail="Guruh va sana kerak")
        
        d = datetime.fromisoformat(date.replace("Z", "")).replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Avvalgi davomatni tekshirish (takroriy coin berilmasligi uchun)
        existing_attendance = await db.attendance.find({
            "groupId": to_object_id(groupId), 
            "date": d
        }).to_list(100)
        
        existing_student_ids = {str(a["studentId"]) for a in existing_attendance}
        
        # Eski davomatni o'chirish
        await db.attendance.delete_many({"groupId": to_object_id(groupId), "date": d})
        
        coins_given = 0
        
        if entries:
            records = []
            for e in entries:
                student_id = e["studentId"]
                status = e["status"]
                
                records.append({
                    "studentId": to_object_id(student_id),
                    "groupId": to_object_id(groupId),
                    "date": d,
                    "status": status,
                    "createdAt": datetime.utcnow()
                })
                
                # Agar "present" bo'lsa va avval bu sana uchun coin berilmagan bo'lsa
                if status == "present" and student_id not in existing_student_ids:
                    # Avtomatik 1 coin berish
                    await db.coinTransactions.insert_one({
                        "studentId": to_object_id(student_id),
                        "teacherId": to_object_id(user["id"]),
                        "amount": 1.0,
                        "reason": "Darsga kelish",
                        "createdAt": datetime.utcnow()
                    })
                    
                    # Balansni yangilash
                    await db.users.update_one(
                        {"_id": to_object_id(student_id)},
                        {"$inc": {"totalCoins": 1.0}}
                    )
                    coins_given += 1
            
            await db.attendance.insert_many(records)
        
        return {
            "message": f"Davomat saqlandi. {coins_given} ta o'quvchiga coin berildi.", 
            "count": len(entries),
            "coinsGiven": coins_given
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
@app.get("/api/teacher/attendance/export")
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
# TOPSHIRIQLAR
# ============================================

@app.get("/api/teacher/assignments")
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
async def create_assignment(request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        
        if not data.get("title"):
            raise HTTPException(status_code=400, detail="Topshiriq nomi kerak")
        
        group_ids = [to_object_id(g) for g in data.get("groupIds", [])]
        
        result = await db.assignments.insert_one({
            "title": data.get("title"),
            "description": data.get("description", ""),
            "groupIds": group_ids,
            "startDate": datetime.utcnow(),
            "dueDate": datetime.fromisoformat(data.get("dueDate")) if data.get("dueDate") else None,
            "isActive": True,
            "createdAt": datetime.utcnow()
        })
        return {"id": str(result.inserted_id), "message": "Topshiriq yaratildi"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/teacher/assignments/{assignment_id}")
async def delete_assignment(assignment_id: str, user: dict = Depends(require_teacher)):
    try:
        await db.assignments.delete_one({"_id": to_object_id(assignment_id)})
        await db.submissions.delete_many({"assignmentId": to_object_id(assignment_id)})
        return {"message": "Topshiriq o'chirildi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/teacher/assignments/{assignment_id}/submissions")
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
async def review_submission(submission_id: str, request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        coinsGiven = data.get("coinsGiven", 0)
        
        sub = await db.submissions.find_one({"_id": to_object_id(submission_id)})
        if not sub:
            raise HTTPException(status_code=404, detail="Javob topilmadi")
        
        await db.submissions.update_one({"_id": to_object_id(submission_id)}, {"$set": {
            "status": "reviewed",
            "reviewedAt": datetime.utcnow(),
            "teacherId": to_object_id(user["id"]),
            "coinsGiven": coinsGiven
        }})
        
        if coinsGiven > 0:
            await db.coinTransactions.insert_one({
                "studentId": sub["studentId"],
                "teacherId": to_object_id(user["id"]),
                "amount": coinsGiven,
                "reason": "Topshiriq uchun",
                "createdAt": datetime.utcnow()
            })
            await db.users.update_one({"_id": sub["studentId"]}, {"$inc": {"totalCoins": coinsGiven}})
        
        return {"message": "Coin berildi"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# SOVG'ALAR VA DO'KON
# ============================================

@app.get("/api/teacher/rewards")
async def get_rewards(user: dict = Depends(require_teacher)):
    try:
        rewards = await db.rewards.find().sort("price", 1).to_list(100)
        return [str_id(r) for r in rewards]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/teacher/rewards")
async def create_reward(request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        
        if not data.get("name") or data.get("price") is None:
            raise HTTPException(status_code=400, detail="Sovg'a nomi va narxi kerak")
        
        result = await db.rewards.insert_one({
            "name": data.get("name"),
            "description": data.get("description", ""),
            "price": int(data.get("price")),
            "category": data.get("category", "kichik"),
            "icon": data.get("icon", "gift"),
            "createdAt": datetime.utcnow()
        })
        return {"id": str(result.inserted_id), "message": "Sovg'a qo'shildi"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/teacher/rewards/{reward_id}")
async def delete_reward(reward_id: str, user: dict = Depends(require_teacher)):
    try:
        await db.rewards.delete_one({"_id": to_object_id(reward_id)})
        return {"message": "Sovg'a o'chirildi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/teacher/shop-settings")
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
async def send_teacher_message(request: Request, user: dict = Depends(require_teacher)):
    try:
        data = await parse_json(request)
        
        if not data.get("toUserId") or not data.get("text"):
            raise HTTPException(status_code=400, detail="Qabul qiluvchi va xabar matni kerak")
        
        await db.messages.insert_one({
            "fromUserId": to_object_id(user["id"]),
            "toUserId": to_object_id(data.get("toUserId")),
            "text": data.get("text"),
            "createdAt": datetime.utcnow()
        })
        return {"message": "Xabar yuborildi"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# O'QUVCHI PROFIL SOZLAMALARI
# ============================================

@app.get("/api/student/profile")
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
async def update_student_profile(request: Request, user: dict = Depends(require_student)):
    try:
        data = await parse_json(request)
        
        # Faqat ruxsat berilgan maydonlarni yangilash
        allowed_fields = ["avatarIcon", "avatarColor", "bio"]
        update_data = {}
        
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        if not update_data:
            raise HTTPException(status_code=400, detail="Yangilanadigan ma'lumot yo'q")
        
        # Bio uchun limit
        if "bio" in update_data and len(update_data["bio"]) > 100:
            raise HTTPException(status_code=400, detail="Bio 100 ta belgidan oshmasligi kerak")
        
        await db.users.update_one(
            {"_id": to_object_id(user["id"])},
            {"$set": update_data}
        )
        
        return {"message": "Profil yangilandi", "updated": update_data}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# O'QUVCHI ROUTES
# ============================================

@app.get("/api/student/dashboard")
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
async def send_student_message(request: Request, user: dict = Depends(require_student)):
    try:
        data = await parse_json(request)
        
        if not data.get("toUserId") or not data.get("text"):
            raise HTTPException(status_code=400, detail="Qabul qiluvchi va xabar matni kerak")
        
        teacher = await db.users.find_one({"_id": to_object_id(data.get("toUserId")), "role": "teacher"})
        if not teacher:
            raise HTTPException(status_code=400, detail="Faqat ustozga xabar yuborish mumkin")
        
        await db.messages.insert_one({
            "fromUserId": to_object_id(user["id"]),
            "toUserId": to_object_id(data.get("toUserId")),
            "text": data.get("text"),
            "createdAt": datetime.utcnow()
        })
        return {"message": "Xabar yuborildi"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# REYTINGLAR
# ============================================

@app.get("/api/rankings/global")
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
async def seed_data():
    try:
        existing = await db.users.find_one({"role": "teacher"})
        if existing:
            print("✅ Ma'lumotlar allaqachon mavjud")
            return
        
        # Ustozlar
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
        
        # 6 ta guruh
        await db.groups.insert_many([
            {"name": "Guruh 1", "description": "Birinchi guruh", "createdAt": datetime.utcnow()},
            {"name": "Guruh 2", "description": "Ikkinchi guruh", "createdAt": datetime.utcnow()},
            {"name": "Guruh 3", "description": "Uchinchi guruh", "createdAt": datetime.utcnow()},
            {"name": "Guruh 4", "description": "To'rtinchi guruh", "createdAt": datetime.utcnow()},
            {"name": "Guruh 5", "description": "Beshinchi guruh", "createdAt": datetime.utcnow()},
            {"name": "Guruh 6", "description": "Oltinchi guruh", "createdAt": datetime.utcnow()}
        ])
        
        await db.shopSettings.insert_one({"isOpen": False})
        
        await db.rewards.insert_many([
            {"name": "Konfet", "description": "Shirin konfet", "price": 5, "category": "kichik", "icon": "candy", "createdAt": datetime.utcnow()},
            {"name": "Ruchka", "description": "Chiroyli ruchka", "price": 10, "category": "kichik", "icon": "pen", "createdAt": datetime.utcnow()},
            {"name": "Daftar", "description": "Katta daftar", "price": 20, "category": "oqish", "icon": "notebook", "createdAt": datetime.utcnow()},
            {"name": "Mentor Assistant", "description": "Bir dars mentor yordamchisi", "price": 30, "category": "imtiyoz", "icon": "star", "createdAt": datetime.utcnow()}
        ])
        
        print("=" * 50)
        print("✅ Boshlang'ich ma'lumotlar yaratildi")
        print("👨‍🏫 Ustoz 1: login=ustoz1, parol=ustoz123")
        print("👨‍🏫 Ustoz 2: login=ustoz2, parol=ustoz456")
        print("📚 6 ta guruh yaratildi (har birida max 12 o'quvchi)")
        print("=" * 50)
    except Exception as e:
        print(f"Seed xatosi: {e}")


# ============================================
# SERVER
# ============================================


if __name__ == "__main__":
    import uvicorn
    print("🚀 Server ishga tushmoqda...")
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 4000)))