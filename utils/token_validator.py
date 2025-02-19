from flask_jwt_extended import decode_token
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from flask_jwt_extended.exceptions import InvalidHeaderError, NoAuthorizationError
from bson import ObjectId
from database import db
import logging

logger = logging.getLogger(__name__)

def validate_token_and_get_user(token):
    try:
        if not token:
            raise NoAuthorizationError("Authorization header is missing")
            
        if not token.startswith('Bearer '):
            raise InvalidHeaderError("Invalid token format")
            
        token = token.split(' ')[1]
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
        
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise InvalidTokenError("Invalid user token")
            
        return user_id
        
    except ExpiredSignatureError:
        logger.error("Token has expired")
        return {'error': 'Token has expired', 'code': 401}
    except (InvalidTokenError, NoAuthorizationError, InvalidHeaderError) as e:
        logger.error(f"Token error: {str(e)}")
        return {'error': str(e), 'code': 401}
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return {'error': 'Invalid token format', 'code': 401}