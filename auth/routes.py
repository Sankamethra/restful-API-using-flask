from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import bcrypt
from database import db
from jose import jwt
from datetime import datetime, timedelta
from config import Config

auth_router = APIRouter()

class UserRegister(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str

class LoginResponse(BaseModel):
    access_token: str
    user: UserResponse

@auth_router.post("/register", status_code=201, response_model=dict)
async def register(user: UserRegister):
    """Register a new user"""
    try:
        # Check if email exists
        if db.users.find_one({"email": user.email}):
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
        
        # Hash password
        hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
        
        # Create user document
        user_data = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "password": hashed_password
        }
        
        # Insert user
        result = db.users.insert_one(user_data)
        
        if result.inserted_id:
            return {
                "message": "User registered successfully",
                "user_id": str(result.inserted_id)
            }
        
        raise HTTPException(status_code=400, detail="Registration failed")
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@auth_router.post("/login", response_model=LoginResponse)
async def login(user: UserLogin):
    """Login user and return access token"""
    try:
        # Find user
        db_user = db.users.find_one({"email": user.email})
        
        if db_user and bcrypt.checkpw(user.password.encode('utf-8'), db_user['password']):
            # Create access token
            access_token = jwt.encode(
                {
                    "sub": str(db_user['_id']),
                    "exp": datetime.utcnow() + timedelta(days=1)
                },
                Config.JWT_SECRET_KEY,
                algorithm="HS256"
            )
            
            return LoginResponse(
                access_token=access_token,
                user=UserResponse(
                    id=str(db_user['_id']),
                    email=db_user['email'],
                    first_name=db_user['first_name'],
                    last_name=db_user['last_name']
                )
            )
        
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
