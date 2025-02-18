# Flask Template API with MongoDB Atlas

A RESTful API built with Flask and MongoDB Atlas for managing templates with JWT authentication.

## Setup

1. Create a MongoDB Atlas account and get your connection string
2. Create a `.env` file with the following variables:
   ```
   JWT_SECRET_KEY=your-super-secret-key
   MONGODB_URI=your-mongodb-atlas-connection-string
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python app.py
   ```

## API Endpoints

### Authentication

#### Register User
- **URL**: `/register`
- **Method**: POST
- **Headers**: 
  ```
  Accept: application/json
  Content-Type: application/json
  ```
- **Body**:
  ```json
  {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "password123"
  }
  ```

#### Login
- **URL**: `/login`
- **Method**: POST
- **Headers**: 
  ```
  Accept: application/json
  Content-Type: application/json
  ```
- **Body**:
  ```json
  {
    "email": "john@example.com",
    "password": "password123"
  }
  ```

### Templates

All template endpoints require JWT authentication. Add the token to the header:
```
Authorization: Bearer <your_access_token>
```

#### Create Template
- **URL**: `/template`
- **Method**: POST
- **Body**:
  ```json
  {
    "template_name": "Welcome Email",
    "subject": "Welcome to our platform",
    "body": "Hello {name}, welcome to our platform!"
  }
  ```

#### Get All Templates
- **URL**: `/template`
- **Method**: GET

#### Get Single Template
- **URL**: `/template/<template_id>`
- **Method**: GET

#### Update Template
- **URL**: `/template/<template_id>`
- **Method**: PUT
- **Body**: Same as Create Template

#### Delete Template
- **URL**: `/template/<template_id>`
- **Method**: DELETE

## Deployment

The application is ready to be deployed on platforms like Render or Heroku. It includes a Procfile for deployment configuration.

## Security Notes

1. Change the JWT_SECRET_KEY in production
2. Use environment variables for sensitive data
3. Implement rate limiting in production
4. Add additional security headers in production 