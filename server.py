from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import uuid
import logging
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="Nilphamari Content App API")
api_router = APIRouter(prefix="/api")
bearer_scheme = HTTPBearer(auto_error=False)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Password & JWT Helpers
# -----------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> dict:
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def get_optional_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> Optional[dict]:
    if not creds or not creds.credentials:
        return None
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        return user
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Pydantic Models
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: str


class AuthResponse(BaseModel):
    user: UserPublic
    token: str


class Location(BaseModel):
    name: Optional[str] = ""
    lat: Optional[float] = None
    lng: Optional[float] = None


class ContentCreate(BaseModel):
    title: str
    description: str
    category: str  # tourism | history | business | news
    images: List[str] = Field(default_factory=list)  # base64 or URLs
    video_url: Optional[str] = ""
    location: Optional[Location] = None


class ContentOut(BaseModel):
    id: str
    title: str
    description: str
    category: str
    images: List[str]
    video_url: str
    location: Location
    submitted_by: str
    submitter_name: str
    status: str
    is_featured: bool
    created_at: str


VALID_CATEGORIES = {"tourism", "history", "business", "news"}


# -----------------------------------------------------------------------------
# Auth Endpoints
# -----------------------------------------------------------------------------
@api_router.post("/auth/register", response_model=AuthResponse)
async def register(body: RegisterRequest):
    email = body.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="এই ইমেইল ইতিমধ্যে ব্যবহৃত হয়েছে")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে")

    uid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    user_doc = {
        "id": uid,
        "name": body.name.strip(),
        "email": email,
        "password_hash": hash_password(body.password),
        "role": "user",
        "created_at": now,
    }
    await db.users.insert_one(user_doc)
    token = create_access_token(uid, email, "user")
    return AuthResponse(
        user=UserPublic(id=uid, name=user_doc["name"], email=email, role="user", created_at=now),
        token=token,
    )


@api_router.post("/auth/login", response_model=AuthResponse)
async def login(body: LoginRequest):
    email = body.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="ভুল ইমেইল বা পাসওয়ার্ড")
    token = create_access_token(user["id"], user["email"], user["role"])
    return AuthResponse(
        user=UserPublic(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            role=user["role"],
            created_at=user["created_at"],
        ),
        token=token,
    )


@api_router.get("/auth/me", response_model=UserPublic)
async def me(user: dict = Depends(get_current_user)):
    return UserPublic(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        role=user["role"],
        created_at=user["created_at"],
    )


# -----------------------------------------------------------------------------
# Content Endpoints
# -----------------------------------------------------------------------------
def _content_to_out(doc: dict) -> ContentOut:
    return ContentOut(
        id=doc["id"],
        title=doc["title"],
        description=doc["description"],
        category=doc["category"],
        images=doc.get("images", []),
        video_url=doc.get("video_url", ""),
        location=Location(**(doc.get("location") or {})),
        submitted_by=doc.get("submitted_by", ""),
        submitter_name=doc.get("submitter_name", ""),
        status=doc.get("status", "approved"),
        is_featured=doc.get("is_featured", False),
        created_at=doc.get("created_at", ""),
    )


@api_router.get("/content", response_model=List[ContentOut])
async def list_content(
    category: Optional[str] = None,
    status: Optional[str] = None,
    featured: Optional[bool] = None,
    q: Optional[str] = None,
    limit: int = 100,
):
    query: dict = {}
    # Default: only approved for public
    query["status"] = status or "approved"
    if category and category in VALID_CATEGORIES:
        query["category"] = category
    if featured is not None:
        query["is_featured"] = featured
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"location.name": {"$regex": q, "$options": "i"}},
        ]
    cursor = db.content.find(query, {"_id": 0}).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [_content_to_out(d) for d in docs]


@api_router.get("/content/{content_id}", response_model=ContentOut)
async def get_content(content_id: str):
    doc = await db.content.find_one({"id": content_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="কন্টেন্ট পাওয়া যায়নি")
    return _content_to_out(doc)


@api_router.post("/content", response_model=ContentOut)
async def create_content(body: ContentCreate, user: dict = Depends(get_current_user)):
    if body.category not in VALID_CATEGORIES:
        raise HTTPException(status_code=400, detail="অবৈধ ক্যাটাগরি")
    cid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    # Admins can auto-approve, users pending
    status_val = "approved" if user.get("role") == "admin" else "pending"
    doc = {
        "id": cid,
        "title": body.title.strip(),
        "description": body.description.strip(),
        "category": body.category,
        "images": body.images or [],
        "video_url": (body.video_url or "").strip(),
        "location": body.location.dict() if body.location else {"name": "", "lat": None, "lng": None},
        "submitted_by": user["id"],
        "submitter_name": user["name"],
        "status": status_val,
        "is_featured": False,
        "created_at": now,
    }
    await db.content.insert_one(doc)
    return _content_to_out(doc)


@api_router.put("/content/{content_id}", response_model=ContentOut)
async def update_content(content_id: str, body: ContentCreate, user: dict = Depends(require_admin)):
    updates = {
        "title": body.title.strip(),
        "description": body.description.strip(),
        "category": body.category,
        "images": body.images or [],
        "video_url": (body.video_url or "").strip(),
        "location": body.location.dict() if body.location else {"name": "", "lat": None, "lng": None},
    }
    res = await db.content.find_one_and_update(
        {"id": content_id}, {"$set": updates}, return_document=True, projection={"_id": 0}
    )
    if not res:
        raise HTTPException(status_code=404, detail="কন্টেন্ট পাওয়া যায়নি")
    return _content_to_out(res)


@api_router.delete("/content/{content_id}")
async def delete_content(content_id: str, user: dict = Depends(require_admin)):
    res = await db.content.delete_one({"id": content_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="কন্টেন্ট পাওয়া যায়নি")
    await db.favorites.delete_many({"content_id": content_id})
    return {"ok": True}


# -----------------------------------------------------------------------------
# Admin Endpoints
# -----------------------------------------------------------------------------
@api_router.get("/admin/content/pending", response_model=List[ContentOut])
async def admin_pending(user: dict = Depends(require_admin)):
    cursor = db.content.find({"status": "pending"}, {"_id": 0}).sort("created_at", -1)
    docs = await cursor.to_list(length=200)
    return [_content_to_out(d) for d in docs]


@api_router.put("/admin/content/{content_id}/approve", response_model=ContentOut)
async def admin_approve(content_id: str, user: dict = Depends(require_admin)):
    res = await db.content.find_one_and_update(
        {"id": content_id},
        {"$set": {"status": "approved"}},
        return_document=True,
        projection={"_id": 0},
    )
    if not res:
        raise HTTPException(status_code=404, detail="কন্টেন্ট পাওয়া যায়নি")
    return _content_to_out(res)


@api_router.put("/admin/content/{content_id}/reject", response_model=ContentOut)
async def admin_reject(content_id: str, user: dict = Depends(require_admin)):
    res = await db.content.find_one_and_update(
        {"id": content_id},
        {"$set": {"status": "rejected"}},
        return_document=True,
        projection={"_id": 0},
    )
    if not res:
        raise HTTPException(status_code=404, detail="কন্টেন্ট পাওয়া যায়নি")
    return _content_to_out(res)


@api_router.put("/admin/content/{content_id}/feature")
async def admin_toggle_feature(content_id: str, user: dict = Depends(require_admin)):
    doc = await db.content.find_one({"id": content_id})
    if not doc:
        raise HTTPException(status_code=404, detail="কন্টেন্ট পাওয়া যায়নি")
    new_val = not doc.get("is_featured", False)
    await db.content.update_one({"id": content_id}, {"$set": {"is_featured": new_val}})
    return {"is_featured": new_val}


# -----------------------------------------------------------------------------
# Favorites Endpoints
# -----------------------------------------------------------------------------
@api_router.get("/favorites", response_model=List[ContentOut])
async def list_favorites(user: dict = Depends(get_current_user)):
    fav_docs = await db.favorites.find({"user_id": user["id"]}, {"_id": 0}).to_list(length=500)
    content_ids = [f["content_id"] for f in fav_docs]
    if not content_ids:
        return []
    cursor = db.content.find({"id": {"$in": content_ids}, "status": "approved"}, {"_id": 0})
    docs = await cursor.to_list(length=500)
    return [_content_to_out(d) for d in docs]


@api_router.post("/favorites/{content_id}")
async def add_favorite(content_id: str, user: dict = Depends(get_current_user)):
    content = await db.content.find_one({"id": content_id})
    if not content:
        raise HTTPException(status_code=404, detail="কন্টেন্ট পাওয়া যায়নি")
    existing = await db.favorites.find_one({"user_id": user["id"], "content_id": content_id})
    if existing:
        return {"ok": True, "already": True}
    await db.favorites.insert_one(
        {
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "content_id": content_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    return {"ok": True}


@api_router.delete("/favorites/{content_id}")
async def remove_favorite(content_id: str, user: dict = Depends(get_current_user)):
    await db.favorites.delete_one({"user_id": user["id"], "content_id": content_id})
    return {"ok": True}


@api_router.get("/favorites/ids")
async def favorite_ids(user: dict = Depends(get_current_user)):
    fav_docs = await db.favorites.find({"user_id": user["id"]}, {"_id": 0, "content_id": 1}).to_list(length=500)
    return {"ids": [f["content_id"] for f in fav_docs]}


# -----------------------------------------------------------------------------
# Stats
# -----------------------------------------------------------------------------
@api_router.get("/stats")
async def stats():
    counts = {}
    for cat in VALID_CATEGORIES:
        counts[cat] = await db.content.count_documents({"category": cat, "status": "approved"})
    counts["total"] = await db.content.count_documents({"status": "approved"})
    counts["pending"] = await db.content.count_documents({"status": "pending"})
    return counts


@api_router.get("/")
async def root():
    return {"message": "Nilphamari Content App API", "status": "running"}


# -----------------------------------------------------------------------------
# Seed Data
# -----------------------------------------------------------------------------
SAMPLE_CONTENT = [
    {
        "title": "নীলসাগর দিঘী",
        "description": "নীলসাগর নীলফামারী জেলার একটি ঐতিহাসিক ও প্রাকৃতিক দর্শনীয় স্থান। প্রায় ৫৩.৯০ একর জায়গা জুড়ে বিস্তৃত এই দিঘীটি নীলফামারী সদর উপজেলার গোড়গ্রাম ইউনিয়নে অবস্থিত। স্থানীয় জনশ্রুতি অনুযায়ী, রাজা বিরাটের রাজত্বকালে এই দিঘীটি খনন করা হয়েছিল। প্রতি শীতকালে এখানে অসংখ্য পরিযায়ী পাখি আসে যা পর্যটকদের মুগ্ধ করে।",
        "category": "tourism",
        "images": [
            "https://images.unsplash.com/photo-1767154966937-68e31b7825f1?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85",
            "https://images.unsplash.com/photo-1667120205301-a2a3a886886e?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "গোড়গ্রাম, নীলফামারী সদর", "lat": 25.9310, "lng": 88.8560},
        "is_featured": True,
    },
    {
        "title": "তিস্তা ব্যারেজ",
        "description": "তিস্তা ব্যারেজ বাংলাদেশের বৃহত্তম সেচ প্রকল্পগুলোর একটি, যা নীলফামারী জেলার ডিমলা উপজেলায় অবস্থিত। ১৯৭৯ সালে এর নির্মাণ কাজ শুরু হয় এবং ১৯৯০ সালে সম্পন্ন হয়। এই ব্যারেজটি কৃষিক্ষেত্রে সেচের পাশাপাশি একটি জনপ্রিয় পর্যটন কেন্দ্র হিসেবেও গড়ে উঠেছে। তিস্তা নদীর বুকে দাঁড়িয়ে সূর্যাস্তের দৃশ্য দেখা এক অপরূপ অভিজ্ঞতা।",
        "category": "tourism",
        "images": [
            "https://images.unsplash.com/photo-1708943080998-be2a26ec9394?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "ডিমলা, নীলফামারী", "lat": 26.1200, "lng": 88.9500},
        "is_featured": True,
    },
    {
        "title": "চিলাহাটি রেলওয়ে স্টেশন",
        "description": "চিলাহাটি রেলওয়ে স্টেশন নীলফামারী জেলার ডোমার উপজেলায় অবস্থিত একটি ঐতিহাসিক রেলওয়ে স্টেশন। ব্রিটিশ আমলে নির্মিত এই স্টেশনটি বাংলাদেশ ও ভারতের মধ্যে আন্তর্জাতিক ট্রেন চলাচলের একটি গুরুত্বপূর্ণ কেন্দ্র। মিতালী এক্সপ্রেস ট্রেন এই স্টেশন দিয়েই ভারত-বাংলাদেশ যাতায়াত করে।",
        "category": "tourism",
        "images": [
            "https://images.unsplash.com/photo-1706554481074-0fb51d4d0537?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "চিলাহাটি, ডোমার", "lat": 26.2500, "lng": 88.8800},
        "is_featured": False,
    },
    {
        "title": "ধরণীগঞ্জ জমিদার বাড়ি",
        "description": "ধরণীগঞ্জ জমিদার বাড়ি নীলফামারী জেলার একটি অন্যতম ঐতিহাসিক স্থাপনা। ব্রিটিশ আমলে নির্মিত এই জমিদার বাড়িটি তৎকালীন স্থাপত্যশৈলীর এক অনন্য নিদর্শন। বাড়িটির প্রাচীন কারুকাজ এবং স্থাপত্যকৌশল ইতিহাস প্রেমীদের জন্য এক আকর্ষণীয় স্থান।",
        "category": "history",
        "images": [
            "https://images.unsplash.com/photo-1670006589700-0b557c00e609?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "ধরণীগঞ্জ, নীলফামারী", "lat": 25.9800, "lng": 88.9000},
        "is_featured": False,
    },
    {
        "title": "নীলফামারীর ইতিহাস",
        "description": "নীলফামারী জেলার নামকরণের পেছনে রয়েছে এক ঐতিহাসিক ঘটনা। ব্রিটিশ আমলে এই অঞ্চলে ব্যাপকহারে নীল চাষ হতো। 'নীল' মানে নীল গাছ এবং 'ফামারী' অর্থ খামার - অর্থাৎ নীলের খামার থেকেই এসেছে নীলফামারী নাম। ১৯৮৪ সালের ১ ফেব্রুয়ারি নীলফামারীকে স্বতন্ত্র জেলা হিসেবে ঘোষণা করা হয়। এর আগে এটি রংপুর জেলার অন্তর্ভুক্ত ছিল।",
        "category": "history",
        "images": [
            "https://images.unsplash.com/photo-1670006589700-0b557c00e609?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "নীলফামারী সদর", "lat": 25.9310, "lng": 88.8560},
        "is_featured": True,
    },
    {
        "title": "সৈয়দপুর বিমানবন্দর",
        "description": "সৈয়দপুর বিমানবন্দর বাংলাদেশের উত্তরাঞ্চলের একমাত্র সক্রিয় অভ্যন্তরীণ বিমানবন্দর। ১৯৭৯ সালে প্রতিষ্ঠিত এই বিমানবন্দরটি সৈয়দপুর শহরের কেন্দ্রস্থলে অবস্থিত। এটি উত্তরাঞ্চলের যোগাযোগ ব্যবস্থায় গুরুত্বপূর্ণ ভূমিকা পালন করে এবং নিয়মিত ঢাকা থেকে ফ্লাইট পরিচালিত হয়।",
        "category": "history",
        "images": [
            "https://images.unsplash.com/photo-1706554481074-0fb51d4d0537?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "সৈয়দপুর, নীলফামারী", "lat": 25.7575, "lng": 88.9100},
        "is_featured": False,
    },
    {
        "title": "সৈয়দপুর বস্ত্র শিল্প",
        "description": "সৈয়দপুর উপজেলা বাংলাদেশের অন্যতম বস্ত্র উৎপাদন কেন্দ্র হিসেবে পরিচিত। এখানে অসংখ্য ছোট-বড় গার্মেন্টস ও টেক্সটাইল কারখানা রয়েছে। সৈয়দপুরে উৎপাদিত বস্ত্র দেশের বিভিন্ন স্থানে ও বিদেশে রপ্তানি হয়। স্থানীয় অর্থনীতিতে এই শিল্পের অবদান অপরিসীম এবং হাজারো মানুষের কর্মসংস্থান সৃষ্টি করেছে।",
        "category": "business",
        "images": [
            "https://images.unsplash.com/photo-1710458868515-44426e7c565b?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "সৈয়দপুর, নীলফামারী", "lat": 25.7575, "lng": 88.9100},
        "is_featured": False,
    },
    {
        "title": "নীলফামারী কৃষি বাজার",
        "description": "নীলফামারী জেলা একটি কৃষিপ্রধান অঞ্চল। ধান, পাট, গম, ভুট্টা, আলু সহ বিভিন্ন ধরনের ফসল এখানে উৎপাদিত হয়। জেলার বিভিন্ন স্থানে বড় বড় পাইকারি বাজার রয়েছে যেখানে স্থানীয় কৃষকরা তাদের উৎপাদিত ফসল বিক্রি করেন। নীলফামারীর আলু দেশব্যাপী বিখ্যাত।",
        "category": "business",
        "images": [
            "https://images.unsplash.com/photo-1710458868515-44426e7c565b?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "নীলফামারী সদর", "lat": 25.9310, "lng": 88.8560},
        "is_featured": False,
    },
    {
        "title": "তিস্তা প্রকল্প উন্নয়ন",
        "description": "তিস্তা মহাপরিকল্পনা নিয়ে সরকারের নতুন উদ্যোগের খবর। তিস্তা নদী তীরবর্তী এলাকার উন্নয়ন ও বন্যা নিয়ন্ত্রণে বিশেষ প্রকল্প গ্রহণ করা হচ্ছে। এই প্রকল্প বাস্তবায়িত হলে নীলফামারী সহ উত্তরাঞ্চলের লক্ষ লক্ষ মানুষ উপকৃত হবে।",
        "category": "news",
        "images": [
            "https://images.unsplash.com/photo-1767154966937-68e31b7825f1?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "নীলফামারী", "lat": 25.9310, "lng": 88.8560},
        "is_featured": False,
    },
    {
        "title": "নীলফামারী শিক্ষা উন্নয়ন সংবাদ",
        "description": "নীলফামারী জেলার শিক্ষাক্ষেত্রে নতুন বেশ কিছু উন্নয়নমূলক উদ্যোগ গ্রহণ করা হয়েছে। নতুন স্কুল, কলেজ প্রতিষ্ঠা এবং ডিজিটাল শিক্ষা ব্যবস্থা চালুর মাধ্যমে জেলার শিক্ষার মান উন্নয়নে কাজ চলছে। সরকারের এই উদ্যোগ স্থানীয় শিক্ষার্থীদের জন্য অত্যন্ত সুফল বয়ে আনবে।",
        "category": "news",
        "images": [
            "https://images.unsplash.com/photo-1706554481074-0fb51d4d0537?crop=entropy&cs=srgb&fm=jpg&w=1200&q=85"
        ],
        "video_url": "",
        "location": {"name": "নীলফামারী সদর", "lat": 25.9310, "lng": 88.8560},
        "is_featured": False,
    },
]


async def seed_admin():
    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if existing is None:
        uid = str(uuid.uuid4())
        await db.users.insert_one(
            {
                "id": uid,
                "name": "অ্যাডমিন",
                "email": ADMIN_EMAIL,
                "password_hash": hash_password(ADMIN_PASSWORD),
                "role": "admin",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.info(f"Seeded admin: {ADMIN_EMAIL}")
    elif not verify_password(ADMIN_PASSWORD, existing["password_hash"]):
        await db.users.update_one(
            {"email": ADMIN_EMAIL}, {"$set": {"password_hash": hash_password(ADMIN_PASSWORD)}}
        )
        logger.info("Updated admin password")


async def seed_content():
    count = await db.content.count_documents({})
    if count > 0:
        return
    admin = await db.users.find_one({"email": ADMIN_EMAIL})
    admin_id = admin["id"] if admin else "system"
    admin_name = admin["name"] if admin else "Admin"
    for item in SAMPLE_CONTENT:
        doc = {
            "id": str(uuid.uuid4()),
            "title": item["title"],
            "description": item["description"],
            "category": item["category"],
            "images": item["images"],
            "video_url": item.get("video_url", ""),
            "location": item.get("location", {}),
            "submitted_by": admin_id,
            "submitter_name": admin_name,
            "status": "approved",
            "is_featured": item.get("is_featured", False),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.content.insert_one(doc)
    logger.info(f"Seeded {len(SAMPLE_CONTENT)} content items")


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.content.create_index("id", unique=True)
    await db.content.create_index("category")
    await db.content.create_index("status")
    await db.favorites.create_index([("user_id", 1), ("content_id", 1)], unique=True)
    await seed_admin()
    await seed_content()


@app.on_event("shutdown")
async def shutdown():
    client.close()


# Register router & middleware
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Entry Point (Render / Production)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)