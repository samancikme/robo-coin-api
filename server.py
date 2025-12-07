# ============================================
# ROBO COIN - BACKEND (PYDANTIC'SIZ)
# ============================================

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from typing import Optional, List
from datetime import datetime, timedelta
from bson import ObjectId
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "robocoin_secret_2024")
ALGORITHM = "HS256"

client = AsyncIOMotorClient(MONGODB_URI)
db = client.robocoin

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

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

# ============================================
# AUTH MIDDLEWARE
# ============================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user = await db.users.find_one({"_id": ObjectId(payload["id"])})
        if not user:
            raise HTTPException(status_code=401, detail="Foydalanuvchi topilmadi")
        return {"id": str(user["_id"]), "role": user["role"], "name": user["name"], "groupId": user.get("groupId")}
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
# AUTH ROUTES
# ============================================

@app.post("/api/auth/login")
async def login(request: Request):
    data = await request.json()
    login = data.get("login")
    password = data.get("password")
    
    user = await db.users.find_one({"login": login, "isActive": True})
    if not user or not verify_password(password, user["passwordHash"]):
        raise HTTPException(status_code=400, detail="Login yoki parol noto'g'ri")
    
    token = create_token({"id": str(user["_id"]), "role": user["role"]})
    return {
        "token": token,
        "user": {
            "id": str(user["_id"]),
            "name": user["name"],
            "role": user["role"],
            "groupId": str(user.get("groupId", "")),
            "avatarIcon": user.get("avatarIcon", "robot1"),
            "totalCoins": user.get("totalCoins", 0)
        }
    }

@app.get("/api/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    u = await db.users.find_one({"_id": ObjectId(user["id"])})
    return {
        "id": str(u["_id"]),
        "name": u["name"],
        "role": u["role"],
        "groupId": str(u.get("groupId", "")),
        "avatarIcon": u.get("avatarIcon", "robot1"),
        "totalCoins": u.get("totalCoins", 0),
        "level": calculate_level(u.get("totalCoins", 0))
    }

# ============================================
# USTOZ - DASHBOARD
# ============================================

@app.get("/api/teacher/dashboard")
async def teacher_dashboard(user: dict = Depends(require_teacher)):
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

# ============================================
# GURUHLAR
# ============================================

@app.get("/api/teacher/groups")
async def get_groups(user: dict = Depends(require_teacher)):
    groups = await db.groups.find().to_list(100)
    return [str_id(g) for g in groups]

@app.post("/api/teacher/groups")
async def create_group(request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    result = await db.groups.insert_one({
        "name": data.get("name"),
        "description": data.get("description"),
        "createdAt": datetime.utcnow()
    })
    return {"id": str(result.inserted_id), "name": data.get("name")}

@app.delete("/api/teacher/groups/{group_id}")
async def delete_group(group_id: str, user: dict = Depends(require_teacher)):
    await db.groups.delete_one({"_id": ObjectId(group_id)})
    return {"message": "Guruh o'chirildi"}

# ============================================
# O'QUVCHILAR BOSHQARUVI
# ============================================

@app.get("/api/teacher/students")
async def get_students(groupId: Optional[str] = None, user: dict = Depends(require_teacher)):
    filter = {"role": "student", "isActive": True}
    if groupId:
        filter["groupId"] = ObjectId(groupId)
    
    students = await db.users.find(filter).sort("totalCoins", -1).to_list(500)
    
    result = []
    for s in students:
        total = await db.attendance.count_documents({"studentId": s["_id"]})
        present = await db.attendance.count_documents({"studentId": s["_id"], "status": "present"})
        attendance = round((present / total * 100) if total > 0 else 0)
        
        group = await db.groups.find_one({"_id": s.get("groupId")}) if s.get("groupId") else None
        
        result.append({
            "id": str(s["_id"]),
            "name": s["name"],
            "login": s["login"],
            "groupId": str(s.get("groupId", "")),
            "groupName": group["name"] if group else "",
            "totalCoins": s.get("totalCoins", 0),
            "level": calculate_level(s.get("totalCoins", 0)),
            "attendancePercent": attendance
        })
    
    return result

@app.post("/api/teacher/students")
async def create_student(request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    name = data.get("name")
    groupId = data.get("groupId")
    login = data.get("login") or name.lower().replace(" ", "_")
    
    existing = await db.users.find_one({"login": login})
    if existing:
        raise HTTPException(status_code=400, detail="Bu login allaqachon mavjud")
    
    password = generate_password()
    
    result = await db.users.insert_one({
        "role": "student",
        "login": login,
        "passwordHash": hash_password(password),
        "name": name,
        "groupId": ObjectId(groupId),
        "avatarIcon": "robot1",
        "totalCoins": 0,
        "isActive": True,
        "createdAt": datetime.utcnow()
    })
    
    return {"id": str(result.inserted_id), "login": login, "generatedPassword": password, "name": name}

@app.get("/api/teacher/students/{student_id}")
async def get_student(student_id: str, user: dict = Depends(require_teacher)):
    student = await db.users.find_one({"_id": ObjectId(student_id)})
    if not student:
        raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
    
    group = await db.groups.find_one({"_id": student.get("groupId")}) if student.get("groupId") else None
    
    coins = await db.coinTransactions.find({"studentId": ObjectId(student_id)}).sort("createdAt", -1).limit(20).to_list(20)
    
    for c in coins:
        teacher = await db.users.find_one({"_id": c["teacherId"]})
        c["teacherName"] = teacher["name"] if teacher else ""
        c["id"] = str(c["_id"])
        c["studentId"] = str(c["studentId"])
        c["teacherId"] = str(c["teacherId"])
        del c["_id"]
    
    total = await db.attendance.count_documents({"studentId": ObjectId(student_id)})
    present = await db.attendance.count_documents({"studentId": ObjectId(student_id), "status": "present"})
    
    return {
        "id": str(student["_id"]),
        "name": student["name"],
        "login": student["login"],
        "groupId": str(student.get("groupId", "")),
        "groupName": group["name"] if group else "",
        "avatarIcon": student.get("avatarIcon", "robot1"),
        "totalCoins": student.get("totalCoins", 0),
        "level": calculate_level(student.get("totalCoins", 0)),
        "coinsToNextLevel": coins_to_next_level(student.get("totalCoins", 0)),
        "coinHistory": coins,
        "attendancePercent": round((present / total * 100) if total > 0 else 0),
        "totalClasses": total,
        "presentClasses": present
    }


# O'quvchini TO'LIQ o'chirish
@app.delete("/api/teacher/students/{student_id}")
async def delete_student(student_id: str, user: dict = Depends(require_teacher)):
    try:
        student_oid = to_object_id(student_id)
        
        # Avval o'quvchi borligini tekshirish
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# COIN OPERATSIYALARI
# ============================================

@app.post("/api/teacher/students/{student_id}/coins")
async def give_coins(student_id: str, request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    amount = data.get("amount")
    reason = data.get("reason")
    
    student = await db.users.find_one({"_id": ObjectId(student_id)})
    if not student:
        raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
    
    await db.coinTransactions.insert_one({
        "studentId": ObjectId(student_id),
        "teacherId": ObjectId(user["id"]),
        "amount": amount,
        "reason": reason,
        "createdAt": datetime.utcnow()
    })
    
    new_balance = max(0, student.get("totalCoins", 0) + amount)
    await db.users.update_one({"_id": ObjectId(student_id)}, {"$set": {"totalCoins": new_balance}})
    
    return {"message": "Coin berildi" if amount > 0 else "Coin olindi", "newBalance": new_balance}

# ============================================
# DAVOMAT
# ============================================

@app.get("/api/teacher/attendance")
async def get_attendance(groupId: Optional[str] = None, date: Optional[str] = None, user: dict = Depends(require_teacher)):
    filter = {}
    if groupId:
        filter["groupId"] = ObjectId(groupId)
    if date:
        d = datetime.fromisoformat(date.replace("Z", ""))
        filter["date"] = {"$gte": d, "$lt": d + timedelta(days=1)}
    
    records = await db.attendance.find(filter).sort("date", -1).to_list(500)
    
    result = []
    for r in records:
        student = await db.users.find_one({"_id": r["studentId"]})
        group = await db.groups.find_one({"_id": r["groupId"]})
        result.append({
            "id": str(r["_id"]),
            "studentId": str(r["studentId"]),
            "studentName": student["name"] if student else "",
            "groupName": group["name"] if group else "",
            "date": r["date"].isoformat(),
            "status": r["status"]
        })
    
    return result

@app.post("/api/teacher/attendance")
async def save_attendance(request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    groupId = data.get("groupId")
    date = data.get("date")
    entries = data.get("entries", [])
    
    d = datetime.fromisoformat(date.replace("Z", "")).replace(hour=0, minute=0, second=0, microsecond=0)
    
    await db.attendance.delete_many({"groupId": ObjectId(groupId), "date": d})
    
    records = [{
        "studentId": ObjectId(e["studentId"]),
        "groupId": ObjectId(groupId),
        "date": d,
        "status": e["status"],
        "createdAt": datetime.utcnow()
    } for e in entries]
    
    if records:
        await db.attendance.insert_many(records)
    
    return {"message": "Davomat saqlandi", "count": len(records)}

@app.get("/api/teacher/attendance/export")
async def export_attendance(groupId: str, fromDate: str, toDate: str, user: dict = Depends(require_teacher)):
    filter = {
        "groupId": ObjectId(groupId),
        "date": {"$gte": datetime.fromisoformat(fromDate), "$lte": datetime.fromisoformat(toDate)}
    }
    
    records = await db.attendance.find(filter).sort("date", -1).to_list(1000)
    
    csv = "Sana,O'quvchi,Holat\n"
    for r in records:
        student = await db.users.find_one({"_id": r["studentId"]})
        status = {"present": "Keldi", "absent": "Kelmadi", "late": "Kechikdi"}.get(r["status"], r["status"])
        csv += f"{r['date'].strftime('%Y-%m-%d')},{student['name'] if student else '-'},{status}\n"
    
    return StreamingResponse(io.StringIO(csv), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=davomat.csv"})

# ============================================
# TOPSHIRIQLAR
# ============================================

@app.get("/api/teacher/assignments")
async def get_assignments(user: dict = Depends(require_teacher)):
    assignments = await db.assignments.find().sort("createdAt", -1).to_list(100)
    
    result = []
    for a in assignments:
        groups = await db.groups.find({"_id": {"$in": a.get("groupIds", [])}}).to_list(10)
        result.append({
            "id": str(a["_id"]),
            "title": a["title"],
            "description": a.get("description", ""),
            "groupIds": [str(g) for g in a.get("groupIds", [])],
            "groupNames": [g["name"] for g in groups],
            "startDate": a.get("startDate", a["createdAt"]).isoformat(),
            "dueDate": a["dueDate"].isoformat() if a.get("dueDate") else None,
            "isActive": a.get("isActive", True)
        })
    
    return result

@app.post("/api/teacher/assignments")
async def create_assignment(request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    result = await db.assignments.insert_one({
        "title": data.get("title"),
        "description": data.get("description"),
        "groupIds": [ObjectId(g) for g in data.get("groupIds", [])],
        "startDate": datetime.utcnow(),
        "dueDate": datetime.fromisoformat(data.get("dueDate")) if data.get("dueDate") else None,
        "isActive": True,
        "createdAt": datetime.utcnow()
    })
    return {"id": str(result.inserted_id), "message": "Topshiriq yaratildi"}

@app.delete("/api/teacher/assignments/{assignment_id}")
async def delete_assignment(assignment_id: str, user: dict = Depends(require_teacher)):
    await db.assignments.delete_one({"_id": ObjectId(assignment_id)})
    await db.submissions.delete_many({"assignmentId": ObjectId(assignment_id)})
    return {"message": "Topshiriq o'chirildi"}

@app.get("/api/teacher/assignments/{assignment_id}/submissions")
async def get_submissions(assignment_id: str, user: dict = Depends(require_teacher)):
    subs = await db.submissions.find({"assignmentId": ObjectId(assignment_id)}).to_list(100)
    
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

@app.post("/api/teacher/submissions/{submission_id}/coins")
async def review_submission(submission_id: str, request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    coinsGiven = data.get("coinsGiven", 0)
    
    sub = await db.submissions.find_one({"_id": ObjectId(submission_id)})
    if not sub:
        raise HTTPException(status_code=404, detail="Javob topilmadi")
    
    await db.submissions.update_one({"_id": ObjectId(submission_id)}, {"$set": {
        "status": "reviewed",
        "reviewedAt": datetime.utcnow(),
        "teacherId": ObjectId(user["id"]),
        "coinsGiven": coinsGiven
    }})
    
    if coinsGiven > 0:
        await db.coinTransactions.insert_one({
            "studentId": sub["studentId"],
            "teacherId": ObjectId(user["id"]),
            "amount": coinsGiven,
            "reason": "Topshiriq uchun",
            "createdAt": datetime.utcnow()
        })
        await db.users.update_one({"_id": sub["studentId"]}, {"$inc": {"totalCoins": coinsGiven}})
    
    return {"message": "Coin berildi"}

# ============================================
# SOVG'ALAR VA DO'KON
# ============================================

@app.get("/api/teacher/rewards")
async def get_rewards(user: dict = Depends(require_teacher)):
    rewards = await db.rewards.find().sort("price", 1).to_list(100)
    return [str_id(r) for r in rewards]

@app.post("/api/teacher/rewards")
async def create_reward(request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    result = await db.rewards.insert_one({
        "name": data.get("name"),
        "description": data.get("description"),
        "price": data.get("price"),
        "category": data.get("category", "kichik"),
        "icon": data.get("icon", "gift"),
        "createdAt": datetime.utcnow()
    })
    return {"id": str(result.inserted_id), "message": "Sovg'a qo'shildi"}

@app.delete("/api/teacher/rewards/{reward_id}")
async def delete_reward(reward_id: str, user: dict = Depends(require_teacher)):
    await db.rewards.delete_one({"_id": ObjectId(reward_id)})
    return {"message": "Sovg'a o'chirildi"}

@app.get("/api/teacher/shop-settings")
async def get_shop_settings(user: dict = Depends(require_teacher)):
    settings = await db.shopSettings.find_one()
    if not settings:
        settings = {"isOpen": False}
    return str_id(settings) if settings.get("_id") else settings

@app.patch("/api/teacher/shop-settings")
async def update_shop_settings(request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    await db.shopSettings.update_one({}, {"$set": {
        "isOpen": data.get("isOpen", False),
        "openDate": datetime.fromisoformat(data.get("openDate")) if data.get("openDate") else None,
        "closeDate": datetime.fromisoformat(data.get("closeDate")) if data.get("closeDate") else None
    }}, upsert=True)
    return {"message": "Do'kon sozlamalari yangilandi"}

# ============================================
# XABARLAR (USTOZ)
# ============================================

@app.get("/api/teacher/messages")
async def get_teacher_messages(studentId: Optional[str] = None, user: dict = Depends(require_teacher)):
    if studentId:
        msgs = await db.messages.find({"$or": [
            {"fromUserId": ObjectId(user["id"]), "toUserId": ObjectId(studentId)},
            {"fromUserId": ObjectId(studentId), "toUserId": ObjectId(user["id"])}
        ]}).sort("createdAt", 1).to_list(100)
        return [str_id(m) for m in msgs]
    
    students = await db.users.find({"role": "student", "isActive": True}).to_list(500)
    return [{"id": str(s["_id"]), "name": s["name"]} for s in students]

@app.post("/api/teacher/messages")
async def send_teacher_message(request: Request, user: dict = Depends(require_teacher)):
    data = await request.json()
    await db.messages.insert_one({
        "fromUserId": ObjectId(user["id"]),
        "toUserId": ObjectId(data.get("toUserId")),
        "text": data.get("text"),
        "createdAt": datetime.utcnow()
    })
    return {"message": "Xabar yuborildi"}

# ============================================
# O'QUVCHI ROUTES
# ============================================

@app.get("/api/student/dashboard")
async def student_dashboard(user: dict = Depends(require_student)):
    student = await db.users.find_one({"_id": ObjectId(user["id"])})
    group = await db.groups.find_one({"_id": student.get("groupId")}) if student.get("groupId") else None
    
    last_tx = await db.coinTransactions.find({"studentId": ObjectId(user["id"])}).sort("createdAt", -1).limit(1).to_list(1)
    last_teacher = await db.users.find_one({"_id": last_tx[0]["teacherId"]}) if last_tx else None
    
    total = await db.attendance.count_documents({"studentId": ObjectId(user["id"])})
    present = await db.attendance.count_documents({"studentId": ObjectId(user["id"]), "status": "present"})
    
    all_students = await db.users.find({"role": "student", "isActive": True}).sort("totalCoins", -1).to_list(500)
    global_rank = next((i + 1 for i, s in enumerate(all_students) if str(s["_id"]) == user["id"]), 0)
    
    group_students = [s for s in all_students if str(s.get("groupId", "")) == str(student.get("groupId", ""))]
    group_rank = next((i + 1 for i, s in enumerate(group_students) if str(s["_id"]) == user["id"]), 0)
    
    return {
        "user": {"id": user["id"], "name": student["name"], "groupName": group["name"] if group else "", "avatarIcon": student.get("avatarIcon", "robot1")},
        "totalCoins": student.get("totalCoins", 0),
        "level": calculate_level(student.get("totalCoins", 0)),
        "coinsToNextLevel": coins_to_next_level(student.get("totalCoins", 0)),
        "lastTransaction": {"date": last_tx[0]["createdAt"].isoformat(), "amount": last_tx[0]["amount"], "reason": last_tx[0]["reason"], "teacherName": last_teacher["name"] if last_teacher else ""} if last_tx else None,
        "attendancePercent": round((present / total * 100) if total > 0 else 0),
        "globalRank": global_rank,
        "globalTotal": len(all_students),
        "groupRank": group_rank,
        "groupTotal": len(group_students),
        "topGlobal": [{"name": s["name"], "totalCoins": s.get("totalCoins", 0)} for s in all_students[:5]],
        "topGroup": [{"name": s["name"], "totalCoins": s.get("totalCoins", 0)} for s in group_students[:5]]
    }

@app.get("/api/student/coins")
async def student_coins(user: dict = Depends(require_student)):
    txs = await db.coinTransactions.find({"studentId": ObjectId(user["id"])}).sort("createdAt", -1).limit(50).to_list(50)
    
    result = []
    for t in txs:
        teacher = await db.users.find_one({"_id": t["teacherId"]})
        result.append({
            "id": str(t["_id"]),
            "amount": t["amount"],
            "reason": t["reason"],
            "teacherName": teacher["name"] if teacher else "",
            "createdAt": t["createdAt"].isoformat()
        })
    
    return result

@app.get("/api/student/assignments")
async def student_assignments(status: Optional[str] = None, user: dict = Depends(require_student)):
    student = await db.users.find_one({"_id": ObjectId(user["id"])})
    
    assignments = await db.assignments.find({"groupIds": student.get("groupId"), "isActive": True}).sort("createdAt", -1).to_list(100)
    
    result = []
    for a in assignments:
        sub = await db.submissions.find_one({"assignmentId": a["_id"], "studentId": ObjectId(user["id"])})
        sub_status = sub["status"] if sub else "not_started"
        
        if status == "active" and sub_status == "reviewed":
            continue
        if status == "completed" and sub_status != "reviewed":
            continue
        
        result.append({
            "id": str(a["_id"]),
            "title": a["title"],
            "description": a.get("description", ""),
            "startDate": a.get("startDate", a["createdAt"]).isoformat(),
            "dueDate": a["dueDate"].isoformat() if a.get("dueDate") else None,
            "submission": {
                "status": sub_status,
                "submittedAt": sub.get("submittedAt").isoformat() if sub and sub.get("submittedAt") else None,
                "coinsGiven": sub.get("coinsGiven", 0) if sub else 0
            }
        })
    
    return result

@app.post("/api/student/assignments/{assignment_id}/start")
async def start_assignment(assignment_id: str, user: dict = Depends(require_student)):
    await db.submissions.update_one(
        {"assignmentId": ObjectId(assignment_id), "studentId": ObjectId(user["id"])},
        {"$set": {"status": "in_progress"}, "$setOnInsert": {"createdAt": datetime.utcnow()}},
        upsert=True
    )
    return {"message": "Topshiriq boshlandi"}

@app.post("/api/student/assignments/{assignment_id}/complete")
async def complete_assignment(assignment_id: str, user: dict = Depends(require_student)):
    await db.submissions.update_one(
        {"assignmentId": ObjectId(assignment_id), "studentId": ObjectId(user["id"])},
        {"$set": {"status": "submitted", "submittedAt": datetime.utcnow()}, "$setOnInsert": {"createdAt": datetime.utcnow()}},
        upsert=True
    )
    return {"message": "Topshiriq yuborildi"}

@app.get("/api/student/shop")
async def student_shop(user: dict = Depends(require_student)):
    settings = await db.shopSettings.find_one() or {"isOpen": False}
    rewards = await db.rewards.find().sort("price", 1).to_list(100)
    student = await db.users.find_one({"_id": ObjectId(user["id"])})
    
    return {
        "isOpen": settings.get("isOpen", False),
        "openDate": settings.get("openDate").isoformat() if settings.get("openDate") else None,
        "closeDate": settings.get("closeDate").isoformat() if settings.get("closeDate") else None,
        "totalCoins": student.get("totalCoins", 0),
        "rewards": [str_id(r) for r in rewards]
    }

@app.post("/api/student/shop/redeem/{reward_id}")
async def redeem_reward(reward_id: str, user: dict = Depends(require_student)):
    settings = await db.shopSettings.find_one()
    if not settings or not settings.get("isOpen"):
        raise HTTPException(status_code=400, detail="Do'kon hozir yopiq")
    
    reward = await db.rewards.find_one({"_id": ObjectId(reward_id)})
    if not reward:
        raise HTTPException(status_code=404, detail="Sovg'a topilmadi")
    
    student = await db.users.find_one({"_id": ObjectId(user["id"])})
    if student.get("totalCoins", 0) < reward["price"]:
        raise HTTPException(status_code=400, detail="Coin yetarli emas")
    
    new_balance = student["totalCoins"] - reward["price"]
    await db.users.update_one({"_id": ObjectId(user["id"])}, {"$set": {"totalCoins": new_balance}})
    
    await db.coinTransactions.insert_one({
        "studentId": ObjectId(user["id"]),
        "teacherId": ObjectId(user["id"]),
        "amount": -reward["price"],
        "reason": f"Sovg'a: {reward['name']}",
        "createdAt": datetime.utcnow()
    })
    
    return {"message": "Sovg'a olindi!", "reward": reward["name"], "newBalance": new_balance}

@app.get("/api/student/messages")
async def student_messages(user: dict = Depends(require_student)):
    msgs = await db.messages.find({"$or": [{"fromUserId": ObjectId(user["id"])}, {"toUserId": ObjectId(user["id"])}]}).sort("createdAt", 1).to_list(100)
    return [str_id(m) for m in msgs]

@app.post("/api/student/messages")
async def send_student_message(request: Request, user: dict = Depends(require_student)):
    data = await request.json()
    teacher = await db.users.find_one({"_id": ObjectId(data.get("toUserId")), "role": "teacher"})
    if not teacher:
        raise HTTPException(status_code=400, detail="Faqat ustozga xabar yuborish mumkin")
    
    await db.messages.insert_one({
        "fromUserId": ObjectId(user["id"]),
        "toUserId": ObjectId(data.get("toUserId")),
        "text": data.get("text"),
        "createdAt": datetime.utcnow()
    })
    return {"message": "Xabar yuborildi"}

# ============================================
# REYTINGLAR
# ============================================

@app.get("/api/rankings/global")
async def global_rankings(user: dict = Depends(get_current_user)):
    students = await db.users.find({"role": "student", "isActive": True}).sort("totalCoins", -1).to_list(500)
    return [{"rank": i + 1, "name": s["name"], "totalCoins": s.get("totalCoins", 0), "level": calculate_level(s.get("totalCoins", 0))} for i, s in enumerate(students)]

@app.get("/api/rankings/group/{group_id}")
async def group_rankings(group_id: str, user: dict = Depends(get_current_user)):
    students = await db.users.find({"role": "student", "isActive": True, "groupId": ObjectId(group_id)}).sort("totalCoins", -1).to_list(100)
    return [{"rank": i + 1, "name": s["name"], "totalCoins": s.get("totalCoins", 0), "level": calculate_level(s.get("totalCoins", 0))} for i, s in enumerate(students)]

# ============================================
# SEED DATA
# ============================================

@app.on_event("startup")
async def seed_data():
    existing = await db.users.find_one({"role": "teacher"})
    if existing:
        print("Ma'lumotlar allaqachon mavjud")
        return
    
    await db.users.insert_many([
        {"role": "teacher", "login": "ustoz1", "passwordHash": hash_password("ustoz123"), "name": "Birinchi Ustoz", "isActive": True, "createdAt": datetime.utcnow()},
        {"role": "teacher", "login": "ustoz2", "passwordHash": hash_password("ustoz456"), "name": "Ikkinchi Ustoz", "isActive": True, "createdAt": datetime.utcnow()}
    ])
    
    await db.groups.insert_many([
        {"name": "Guruh A", "description": "Boshlang'ich guruh", "createdAt": datetime.utcnow()},
        {"name": "Guruh B", "description": "O'rta guruh", "createdAt": datetime.utcnow()}
    ])
    
    await db.shopSettings.insert_one({"isOpen": False})
    
    await db.rewards.insert_many([
        {"name": "Konfet", "description": "Shirin konfet", "price": 5, "category": "kichik", "icon": "candy", "createdAt": datetime.utcnow()},
        {"name": "Ruchka", "description": "Chiroyli ruchka", "price": 10, "category": "kichik", "icon": "pen", "createdAt": datetime.utcnow()},
        {"name": "Daftar", "description": "Katta daftar", "price": 20, "category": "oqish", "icon": "notebook", "createdAt": datetime.utcnow()},
        {"name": "Mentor Assistant", "description": "Bir dars mentor yordamchisi", "price": 30, "category": "imtiyoz", "icon": "star", "createdAt": datetime.utcnow()}
    ])
    
    print("=" * 50)
    print("Boshlang'ich ma'lumotlar yaratildi")
    print("Ustoz 1: login=ustoz1, parol=ustoz123")
    print("Ustoz 2: login=ustoz2, parol=ustoz456")
    print("=" * 50)

# ============================================
# SERVER
# ============================================

# ============================================
# PAROLNI YANGILASH
# ============================================

@app.post("/api/teacher/students/{student_id}/reset-password")
async def reset_student_password(student_id: str, user: dict = Depends(require_teacher)):
    try:
        student_oid = to_object_id(student_id)
        
        # O'quvchini topish
        student = await db.users.find_one({"_id": student_oid})
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        # Yangi parol yaratish
        new_password = generate_password(8)
        
        # Parolni hash qilib saqlash
        hashed = hash_password(new_password)
        await db.users.update_one(
            {"_id": student_oid},
            {"$set": {"passwordHash": hashed}}
        )
        
        return {
            "message": "Parol yangilandi",
            "login": student["login"],
            "newPassword": new_password
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/teacher/students/{student_id}/password")
async def get_student_password_info(student_id: str, user: dict = Depends(require_teacher)):
    """O'quvchi login ma'lumotini olish (parolni faqat reset qilish mumkin)"""
    try:
        student_oid = to_object_id(student_id)
        student = await db.users.find_one({"_id": student_oid})
        
        if not student:
            raise HTTPException(status_code=404, detail="O'quvchi topilmadi")
        
        return {
            "login": student["login"],
            "name": student["name"],
            "message": "Parolni ko'rish uchun 'Yangi parol yaratish' tugmasini bosing"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# ROOT ENDPOINT
# ============================================

@app.get("/")
async def root():
    return {
        "message": "Robo Coin API ishlayapti!",
        "version": "1.0.0",
        "docs_url": "/docs"
    }

@app.head("/")
async def root_head():
    return {}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))