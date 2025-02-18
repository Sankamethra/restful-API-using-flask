from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
from flasgger import Swagger, swag_from
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from flask_jwt_extended.exceptions import InvalidHeaderError, NoAuthorizationError
import logging

load_dotenv()

app = Flask(__name__)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_HEADER_NAME'] = 'Authorization'
jwt = JWTManager(app)

# Swagger Configuration
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

template = {
    "swagger": "2.0",
    "info": {
        "title": "Email Template API",
        "description": "API for managing email templates",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\""
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}

swagger = Swagger(app, config=swagger_config, template=template)

MONGODB_URI = os.getenv('MONGODB_URI', 'your-mongodb-atlas-uri')  
client = MongoClient(MONGODB_URI)
db = client['template_db']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_token_and_get_user(token):
    try:
        if not token:
            raise NoAuthorizationError("Authorization header is missing")
            
        if not token.startswith('Bearer '):
            raise InvalidHeaderError("Invalid token format. Must start with 'Bearer'")
            
        token = token.split(' ')[1]
        
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
        
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            logger.warning(f"Token contains invalid user ID: {user_id}")
            raise InvalidTokenError("Invalid user token")
            
        return user_id
        
    except ExpiredSignatureError:
        logger.error("Token has expired")
        return {'error': 'Token has expired', 'code': 401}
    except InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        return {'error': 'Invalid token', 'code': 401}
    except NoAuthorizationError as e:
        logger.error(f"Missing authorization: {str(e)}")
        return {'error': str(e), 'code': 401}
    except InvalidHeaderError as e:
        logger.error(f"Invalid header: {str(e)}")
        return {'error': str(e), 'code': 401}
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return {'error': 'Invalid token format', 'code': 401}

@app.route('/register', methods=['POST'])
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
        201: {
            'description': 'User registered successfully'
        },
        400: {
            'description': 'Invalid request or email already registered'
        }
    }
})
def register():
    try:
        data = request.get_json()
        

        if db.users.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 400
        

        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        
        user = {
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'email': data['email'],
            'password': hashed_password
        }
        
        db.users.insert_one(user)
        return jsonify({'message': 'User registered successfully'}), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/login', methods=['POST'])
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
        401: {
            'description': 'Invalid credentials'
        }
    }
})
def login():
    try:
        data = request.get_json()
        user = db.users.find_one({'email': data['email']})
        
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user['password']):
            access_token = create_access_token(identity=str(user['_id']))
            return jsonify({
                'access_token': access_token
            }), 200
        
        return jsonify({'error': 'Invalid credentials'}), 401
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# First route decorator for GET method
@app.route('/template', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Templates'],
    'security': [{'Bearer': []}],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer token'
        }
    ],
    'responses': {
        200: {
            'description': 'List of templates',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        '_id': {'type': 'string'},
                        'template_name': {'type': 'string'},
                        'category': {'type': 'string'},
                        'subject': {'type': 'string'},
                        'body': {'type': 'string'},
                        'variables': {
                            'type': 'array',
                            'items': {'type': 'string'}
                        },
                        'created_at': {'type': 'string'},
                        'updated_at': {'type': 'string'},
                        'is_active': {'type': 'boolean'}
                    }
                }
            }
        },
        400: {
            'description': 'Error occurred',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def get_templates():
    return template()

# Second route decorator for POST method
@app.route('/template', methods=['POST'])
@jwt_required()
@swag_from({
    'tags': ['Templates'],
    'security': [{'Bearer': []}],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer token'
        },
        {
            'name': 'template_data',
            'in': 'body',
            'required': True,
            'description': 'Template data',
            'schema': {
                'type': 'object',
                'properties': {
                    'template_name': {
                        'type': 'string',
                        'description': 'Name of the template',
                        'example': 'Welcome Email'
                    },
                    'category': {
                        'type': 'string',
                        'description': 'Category of the template',
                        'example': 'Onboarding',
                        'enum': ['Onboarding', 'Marketing', 'Support', 'Sales', 'HR', 'Other']
                    },
                    'subject': {
                        'type': 'string',
                        'description': 'Email subject line',
                        'example': 'Welcome to our platform!'
                    },
                    'body': {
                        'type': 'string',
                        'description': 'Email body content. Use {variable_name} for variables',
                        'example': 'Hello {name},\n\nWelcome to our platform! We are excited to have you here.\n\nBest regards,\nThe Team'
                    },
                    'variables': {
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'List of variable names used in the template body',
                        'example': ['name', 'company', 'role']
                    }
                },
                'required': ['template_name', 'subject', 'body', 'category']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Template created successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'template': {
                        'type': 'object',
                        'properties': {
                            '_id': {'type': 'string'},
                            'template_name': {'type': 'string'},
                            'category': {'type': 'string'},
                            'subject': {'type': 'string'},
                            'body': {'type': 'string'},
                            'variables': {
                                'type': 'array',
                                'items': {'type': 'string'}
                            },
                            'created_at': {'type': 'string'},
                            'updated_at': {'type': 'string'},
                            'is_active': {'type': 'boolean'}
                        }
                    }
                }
            }
        },
        400: {
            'description': 'Invalid request',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def post_template():
    return template()

# GET single template
@app.route('/template/<template_id>', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Templates'],
    'security': [{'Bearer': []}],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer token'
        },
        {
            'name': 'template_id',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'ID of the template to retrieve'
        }
    ],
    'responses': {
        200: {
            'description': 'Template details',
            'schema': {
                'type': 'object',
                'properties': {
                    '_id': {'type': 'string'},
                    'template_name': {'type': 'string'},
                    'category': {'type': 'string'},
                    'subject': {'type': 'string'},
                    'body': {'type': 'string'},
                    'variables': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    'created_at': {'type': 'string'},
                    'updated_at': {'type': 'string'},
                    'is_active': {'type': 'boolean'}
                }
            }
        },
        404: {
            'description': 'Template not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def get_template(template_id):
    return template_operations(template_id)

# UPDATE single template
@app.route('/template/<template_id>', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Templates'],
    'security': [{'Bearer': []}],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer token'
        },
        {
            'name': 'template_id',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'ID of the template to update'
        },
        {
            'name': 'template_data',
            'in': 'body',
            'required': True,
            'description': 'Updated template data',
            'schema': {
                'type': 'object',
                'properties': {
                    'template_name': {
                        'type': 'string',
                        'description': 'Name of the template',
                        'example': 'Updated Welcome Email'
                    },
                    'category': {
                        'type': 'string',
                        'description': 'Category of the template',
                        'example': 'Marketing',
                        'enum': ['Onboarding', 'Marketing', 'Support', 'Sales', 'HR', 'Other']
                    },
                    'subject': {
                        'type': 'string',
                        'description': 'Email subject line',
                        'example': 'Welcome to our updated platform!'
                    },
                    'body': {
                        'type': 'string',
                        'description': 'Email body content',
                        'example': 'Hello {name},\n\nWelcome to our updated platform!'
                    },
                    'variables': {
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'List of variables used in template',
                        'example': ['name']
                    }
                },
                'required': ['template_name', 'subject', 'body', 'category']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Template updated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'template': {
                        'type': 'object',
                        'properties': {
                            '_id': {'type': 'string'},
                            'template_name': {'type': 'string'},
                            'category': {'type': 'string'},
                            'subject': {'type': 'string'},
                            'body': {'type': 'string'},
                            'variables': {
                                'type': 'array',
                                'items': {'type': 'string'}
                            },
                            'updated_at': {'type': 'string'}
                        }
                    }
                }
            }
        },
        404: {
            'description': 'Template not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def update_template(template_id):
    return template_operations(template_id)

# DELETE single template
@app.route('/template/<template_id>', methods=['DELETE'])
@jwt_required()
@swag_from({
    'tags': ['Templates'],
    'security': [{'Bearer': []}],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer token'
        },
        {
            'name': 'template_id',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'ID of the template to delete'
        }
    ],
    'responses': {
        200: {
            'description': 'Template deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        404: {
            'description': 'Template not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def delete_template(template_id):
    return template_operations(template_id)

# The main handler function
def template():
    try:
        # Get token from header
        auth_header = request.headers.get('Authorization')
        
        # Validate token and get user
        result = validate_token_and_get_user(auth_header)
        if isinstance(result, dict) and 'error' in result:
            return jsonify({
                'error': result['error'],
                'message': 'Authentication failed'
            }), result['code']
            
        current_user_id = result

        if request.method == 'POST':
            try:
                if not request.is_json:
                    return jsonify({
                        'error': 'Content-Type must be application/json'
                    }), 400

                data = request.get_json()
                
                # Validate required fields
                required_fields = ['template_name', 'subject', 'body', 'category']
                for field in required_fields:
                    if field not in data or not data[field]:
                        return jsonify({
                            'error': f'Missing or empty required field: {field}'
                        }), 400
                
                # Validate and sanitize variables if provided
                variables = data.get('variables', [])
                if not isinstance(variables, list):
                    return jsonify({
                        'error': 'variables must be an array of strings'
                    }), 400
                
                # Check if template name already exists for this user
                existing_template = db.templates.find_one({
                    'user_id': current_user_id,
                    'template_name': data['template_name']
                })
                
                if existing_template:
                    return jsonify({
                        'error': 'Template name already exists'
                    }), 400
                
                template_data = {
                    'user_id': current_user_id,
                    'template_name': data['template_name'].strip(),
                    'category': data['category'].strip(),
                    'subject': data['subject'].strip(),
                    'body': data['body'].strip(),
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                    'variables': variables,
                    'is_active': True
                }
                
                result = db.templates.insert_one(template_data)
                
                # Return the created template with its ID
                created_template = template_data.copy()
                created_template['_id'] = str(result.inserted_id)
                created_template['created_at'] = created_template['created_at'].isoformat()
                created_template['updated_at'] = created_template['updated_at'].isoformat()
                
                return jsonify({
                    'message': 'Template created successfully',
                    'template': created_template
                }), 201
            
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        elif request.method == 'GET':
            try:
                # Only get templates belonging to the current user
                templates = list(db.templates.find({'user_id': current_user_id}))
                for template in templates:
                    template['_id'] = str(template['_id'])
                return jsonify(templates), 200
            
            except Exception as e:
                return jsonify({'error': str(e)}), 400

    except Exception as e:
        logger.error(f"Error in template function: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }), 500

def template_operations(template_id):
    try:
        # Get token from header
        auth_header = request.headers.get('Authorization')
        
        # Validate token and get user
        result = validate_token_and_get_user(auth_header)
        if isinstance(result, dict) and 'error' in result:
            return jsonify({
                'error': result['error'],
                'message': 'Authentication failed'
            }), result['code']
            
        current_user_id = result

        # Log the operation attempt
        logger.info(f"User {current_user_id} attempting to access template {template_id}")
        
        try:
            template_obj_id = ObjectId(template_id)
        except:
            return jsonify({
                'error': 'Invalid template ID format',
                'message': 'The provided template ID is not valid'
            }), 400
        
        # First check if template exists
        template = db.templates.find_one({'_id': template_obj_id})
        if not template:
            logger.warning(f"Template {template_id} not found")
            return jsonify({
                'error': 'Template not found',
                'message': 'The requested template does not exist'
            }), 404
            
        # Then check if user owns the template
        if template['user_id'] != current_user_id:
            logger.warning(f"Unauthorized access attempt: User {current_user_id} attempted to access template {template_id} owned by {template['user_id']}")
            return jsonify({
                'error': 'Access denied',
                'message': 'You do not have permission to access this template'
            }), 403

        if request.method == 'GET':
            template['_id'] = str(template['_id'])
            return jsonify(template), 200
        
        elif request.method == 'PUT':
            if not request.is_json:
                return jsonify({
                    'error': 'Content-Type must be application/json'
                }), 400

            data = request.get_json()
            
            # Validate required fields
            required_fields = ['template_name', 'subject', 'body', 'category']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({
                        'error': f'Missing or empty required field: {field}'
                    }), 400

            # Check if new template name conflicts with existing templates
            if data['template_name'] != template['template_name']:
                existing_template = db.templates.find_one({
                    'user_id': current_user_id,
                    'template_name': data['template_name'],
                    '_id': {'$ne': ObjectId(template_id)}
                })
                if existing_template:
                    return jsonify({
                        'error': 'Template name already exists'
                    }), 400

            # Validate variables if provided
            variables = data.get('variables', template.get('variables', []))
            if not isinstance(variables, list):
                return jsonify({
                    'error': 'variables must be an array of strings'
                }), 400

            update_data = {
                'template_name': data['template_name'].strip(),
                'category': data['category'].strip(),
                'subject': data['subject'].strip(),
                'body': data['body'].strip(),
                'variables': variables,
                'updated_at': datetime.utcnow()
            }
            
            # Update only if user owns the template
            result = db.templates.update_one(
                {
                    '_id': ObjectId(template_id),
                    'user_id': current_user_id
                }, 
                {'$set': update_data}
            )
            
            if result.modified_count == 0:
                logger.warning(f"Update failed for template {template_id} by user {current_user_id}")
                return jsonify({
                    'error': 'Template update failed'
                }), 403
            
            logger.info(f"Template {template_id} successfully updated by user {current_user_id}")
            # Get and return updated template
            updated_template = db.templates.find_one({
                '_id': ObjectId(template_id),
                'user_id': current_user_id
            })
            updated_template['_id'] = str(updated_template['_id'])
            updated_template['updated_at'] = updated_template['updated_at'].isoformat()
            
            return jsonify({
                'message': 'Template updated successfully',
                'template': updated_template
            }), 200
        
        elif request.method == 'DELETE':
            # Delete only if user owns the template
            result = db.templates.delete_one({
                '_id': ObjectId(template_id),
                'user_id': current_user_id
            })
            
            if result.deleted_count == 0:
                logger.warning(f"Delete failed for template {template_id} by user {current_user_id}")
                return jsonify({
                    'error': 'Template deletion failed'
                }), 403
            
            logger.info(f"Template {template_id} successfully deleted by user {current_user_id}")
            return jsonify({
                'message': 'Template deleted successfully'
            }), 200
            
    except Exception as e:
        logger.error(f"Error in template_operations: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }), 500

# Add CORS headers
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0') 