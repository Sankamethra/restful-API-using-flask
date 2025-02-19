from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime
import uvicorn
from auth.routes import auth_router
from templates.routes import templates_router

app = FastAPI(
    title="Email Template API",
    description="API for managing email templates",
    version="1.0.0",
    docs_url="/",  # Serve Swagger UI at root
    redoc_url="/redoc"  # ReDoc documentation at /redoc
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(templates_router, prefix="/template", tags=["Templates"])

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)