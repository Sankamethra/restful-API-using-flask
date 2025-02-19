# auth/routes.py
from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import create_access_token
import bcrypt
from database import db
from flasgger import swag_from
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

@auth_bp.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'},
                    'email': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['first_name', 'last_name', 'email', 'password']
            }
        }
    ],
    'responses': {
        201: {'description': 'User registered successfully'},
        400: {'description': 'Invalid request or email already registered'}
    }
})
def register():
    try:
        if not request.is_json:
            logger.error("Request must be JSON")
            return jsonify({'error': 'Request must be JSON'}), 400

        data = request.get_json()
        
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                logger.error(f"Missing required field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Check if email exists
        if db.users.find_one({'email': data['email']}):
            logger.warning(f"Email already registered: {data['email']}")
            return jsonify({'error': 'Email already registered'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        
        # Create user document
        user = {
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'email': data['email'],
            'password': hashed_password
        }
        
        # Insert user
        result = db.users.insert_one(user)
        
        if result.inserted_id:
            logger.info(f"User registered successfully: {data['email']}")
            return jsonify({
                'message': 'User registered successfully',
                'user_id': str(result.inserted_id)
            }), 201
        
        return jsonify({'error': 'Registration failed'}), 400
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Login successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'access_token': {'type': 'string'}
                }
            }
        },
        401: {'description': 'Invalid credentials'}
    }
})
def login():
    try:
        if not request.is_json:
            logger.error("Request must be JSON")
            return jsonify({'error': 'Request must be JSON'}), 400

        data = request.get_json()
        
        # Validate required fields
        if not data.get('email') or not data.get('password'):
            logger.error("Missing email or password")
            return jsonify({'error': 'Email and password are required'}), 400

        # Find user
        user = db.users.find_one({'email': data['email']})
        
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user['password']):
            access_token = create_access_token(identity=str(user['_id']))
            logger.info(f"Login successful: {data['email']}")
            return jsonify({
                'access_token': access_token,
                'user': {
                    'id': str(user['_id']),
                    'email': user['email'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name']
                }
            }), 200
        
        logger.warning(f"Invalid login attempt for email: {data['email']}")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 400