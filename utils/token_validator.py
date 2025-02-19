from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from database import db
from bson import ObjectId
from config import Config

security = HTTPBearer()

async def validate_token_and_get_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid user token"
            )
            
        return user_id
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token or expired token"
        )
