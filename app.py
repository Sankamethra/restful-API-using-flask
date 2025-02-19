from flask import Flask
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from config import Config
from auth.routes import auth_bp
from templates.routes import templates_bp
import logging

def create_app():
    app = Flask(__name__)
    
    # Load configurations
    app.config.from_object(Config)
    
    # Initialize extensions
    jwt = JWTManager(app)
    swagger = Swagger(app, config=Config.SWAGGER_CONFIG, template=Config.SWAGGER_TEMPLATE)
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(templates_bp, url_prefix='/template')
    
    # CORS headers
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
        return response
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=3003, host='0.0.0.0')