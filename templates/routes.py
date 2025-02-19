from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from database import db
from bson import ObjectId
from datetime import datetime
from utils.token_validator import validate_token_and_get_user
from flasgger import swag_from
import logging

# Initialize Blueprint and logger
templates_bp = Blueprint('templates', __name__)
logger = logging.getLogger(__name__)

@templates_bp.route('/', methods=['GET'])
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
                        }
                    }
                }
            }
        },
        401: {'description': 'Authentication failed'},
        400: {'description': 'Bad request'}
    }
})
def get_templates():
    """Get all templates for the current user."""
    try:
        auth_header = request.headers.get('Authorization')
        result = validate_token_and_get_user(auth_header)
        if isinstance(result, dict) and 'error' in result:
            return jsonify({'error': result['error']}), result['code']
            
        current_user_id = result
        templates = list(db.templates.find({'user_id': current_user_id}))
        for template in templates:
            template['_id'] = str(template['_id'])
        return jsonify(templates), 200
            
    except Exception as e:
        logger.error(f"Error in get_templates: {str(e)}")
        return jsonify({'error': str(e)}), 400

@templates_bp.route('/', methods=['POST'])
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
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'template_name': {'type': 'string'},
                    'category': {'type': 'string', 'enum': ['Onboarding', 'Marketing', 'Support', 'Sales', 'HR', 'Other']},
                    'subject': {'type': 'string'},
                    'body': {'type': 'string'},
                    'variables': {'type': 'array', 'items': {'type': 'string'}}
                },
                'required': ['template_name', 'category', 'subject', 'body']
            }
        }
    ],
    'responses': {
        201: {'description': 'Template created successfully'},
        400: {'description': 'Invalid request'},
        401: {'description': 'Authentication failed'}
    }
})
def create_template():
    """Create a new email template."""
    try:
        auth_header = request.headers.get('Authorization')
        result = validate_token_and_get_user(auth_header)
        if isinstance(result, dict) and 'error' in result:
            return jsonify({'error': result['error']}), result['code']
        
        current_user_id = result
        
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
            
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['template_name', 'category', 'subject', 'body']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
                
        # Check for duplicate template name
        if db.templates.find_one({
            'user_id': current_user_id,
            'template_name': data['template_name']
        }):
            return jsonify({'error': 'Template name already exists'}), 400
            
        # Create template document
        template_data = {
            'user_id': current_user_id,
            'template_name': data['template_name'].strip(),
            'category': data['category'].strip(),
            'subject': data['subject'].strip(),
            'body': data['body'].strip(),
            'variables': data.get('variables', []),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_active': True
        }
        
        result = db.templates.insert_one(template_data)
        template_data['_id'] = str(result.inserted_id)
        
        return jsonify({
            'message': 'Template created successfully',
            'template': template_data
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating template: {str(e)}")
        return jsonify({'error': str(e)}), 400

@templates_bp.route('/<template_id>', methods=['GET'])
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
            'description': 'Template ID'
        }
    ],
    'responses': {
        200: {'description': 'Template details'},
        404: {'description': 'Template not found'},
        401: {'description': 'Authentication failed'},
        403: {'description': 'Access denied'}
    }
})
def get_template(template_id):
    """Get a specific template by ID."""
    try:
        auth_header = request.headers.get('Authorization')
        result = validate_token_and_get_user(auth_header)
        if isinstance(result, dict) and 'error' in result:
            return jsonify({'error': result['error']}), result['code']
            
        current_user_id = result
        
        try:
            template = db.templates.find_one({'_id': ObjectId(template_id)})
        except:
            return jsonify({'error': 'Invalid template ID format'}), 400
            
        if not template:
            return jsonify({'error': 'Template not found'}), 404
            
        if template['user_id'] != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
            
        template['_id'] = str(template['_id'])
        return jsonify(template), 200
        
    except Exception as e:
        logger.error(f"Error retrieving template: {str(e)}")
        return jsonify({'error': str(e)}), 400

@templates_bp.route('/<template_id>', methods=['PUT'])
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
            'description': 'Template ID'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'template_name': {'type': 'string'},
                    'category': {'type': 'string'},
                    'subject': {'type': 'string'},
                    'body': {'type': 'string'},
                    'variables': {'type': 'array', 'items': {'type': 'string'}}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'Template updated successfully'},
        404: {'description': 'Template not found'},
        401: {'description': 'Authentication failed'},
        403: {'description': 'Access denied'}
    }
})
def update_template(template_id):
    """Update a specific template."""
    try:
        auth_header = request.headers.get('Authorization')
        result = validate_token_and_get_user(auth_header)
        if isinstance(result, dict) and 'error' in result:
            return jsonify({'error': result['error']}), result['code']
            
        current_user_id = result
        
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
            
        data = request.get_json()
        
        try:
            template = db.templates.find_one({'_id': ObjectId(template_id)})
        except:
            return jsonify({'error': 'Invalid template ID format'}), 400
            
        if not template:
            return jsonify({'error': 'Template not found'}), 404
            
        if template['user_id'] != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
            
        # Check for duplicate template name
        if data.get('template_name') and data['template_name'] != template['template_name']:
            if db.templates.find_one({
                'user_id': current_user_id,
                'template_name': data['template_name'],
                '_id': {'$ne': ObjectId(template_id)}
            }):
                return jsonify({'error': 'Template name already exists'}), 400
                
        # Update template
        update_data = {
            'template_name': data.get('template_name', template['template_name']).strip(),
            'category': data.get('category', template['category']).strip(),
            'subject': data.get('subject', template['subject']).strip(),
            'body': data.get('body', template['body']).strip(),
            'variables': data.get('variables', template.get('variables', [])),
            'updated_at': datetime.utcnow()
        }
        
        db.templates.update_one(
            {'_id': ObjectId(template_id)},
            {'$set': update_data}
        )
        
        updated_template = db.templates.find_one({'_id': ObjectId(template_id)})
        updated_template['_id'] = str(updated_template['_id'])
        
        return jsonify({
            'message': 'Template updated successfully',
            'template': updated_template
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating template: {str(e)}")
        return jsonify({'error': str(e)}), 400

@templates_bp.route('/<template_id>', methods=['DELETE'])
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
            'description': 'Template ID'
        }
    ],
    'responses': {
        200: {'description': 'Template deleted successfully'},
        404: {'description': 'Template not found'},
        401: {'description': 'Authentication failed'},
        403: {'description': 'Access denied'}
    }
})
def delete_template(template_id):
    """Delete a specific template."""
    try:
        auth_header = request.headers.get('Authorization')
        result = validate_token_and_get_user(auth_header)
        if isinstance(result, dict) and 'error' in result:
            return jsonify({'error': result['error']}), result['code']
            
        current_user_id = result
        
        try:
            template = db.templates.find_one({'_id': ObjectId(template_id)})
        except:
            return jsonify({'error': 'Invalid template ID format'}), 400
            
        if not template:
            return jsonify({'error': 'Template not found'}), 404
            
        if template['user_id'] != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
            
        db.templates.delete_one({'_id': ObjectId(template_id)})
        
        return jsonify({
            'message': 'Template deleted successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error deleting template: {str(e)}")
        return jsonify({'error': str(e)}), 400
