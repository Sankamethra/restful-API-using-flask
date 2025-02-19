from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from bson import ObjectId
from database import db
from utils.token_validator import validate_token_and_get_user

templates_router = APIRouter()

class TemplateBase(BaseModel):
    template_name: str
    category: str
    subject: str
    body: str
    variables: Optional[List[str]] = []

class TemplateResponse(TemplateBase):
    id: str
    user_id: str
    created_at: datetime
    updated_at: datetime
    is_active: bool

    class Config:
        orm_mode = True

@templates_router.get("/", response_model=List[TemplateResponse])
async def get_templates(current_user: str = Depends(validate_token_and_get_user)):
    """Get all templates for the current user."""
    try:
        templates = list(db.templates.find({"user_id": current_user}))
        for template in templates:
            template["id"] = str(template.pop("_id"))
        return templates
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@templates_router.post("/", response_model=TemplateResponse, status_code=201)
async def create_template(
    template: TemplateBase,
    current_user: str = Depends(validate_token_and_get_user)
):
    """Create a new email template."""
    try:
        # Check for duplicate template name
        if db.templates.find_one({
            "user_id": current_user,
            "template_name": template.template_name
        }):
            raise HTTPException(
                status_code=400,
                detail="Template name already exists"
            )

        template_data = template.dict()
        template_data.update({
            "user_id": current_user,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "is_active": True
        })

        result = db.templates.insert_one(template_data)
        template_data["id"] = str(result.inserted_id)
        return template_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@templates_router.put("/{template_id}", response_model=TemplateResponse)
async def update_template(
    template_id: str,
    template: TemplateBase,
    current_user: str = Depends(validate_token_and_get_user)
):
    """Update a specific template."""
    try:
        # Validate template ID format
        try:
            obj_id = ObjectId(template_id)
        except:
            raise HTTPException(status_code=400, detail="Invalid template ID format")

        # Check if template exists and belongs to user
        existing_template = db.templates.find_one({"_id": obj_id})
        if not existing_template:
            raise HTTPException(status_code=404, detail="Template not found")
        
        if existing_template["user_id"] != current_user:
            raise HTTPException(status_code=403, detail="Access denied")

        # Check for duplicate template name
        if template.template_name != existing_template["template_name"]:
            if db.templates.find_one({
                "user_id": current_user,
                "template_name": template.template_name,
                "_id": {"$ne": obj_id}
            }):
                raise HTTPException(
                    status_code=400,
                    detail="Template name already exists"
                )

        # Update template
        update_data = template.dict()
        update_data.update({
            "updated_at": datetime.utcnow()
        })

        db.templates.update_one(
            {"_id": obj_id},
            {"$set": update_data}
        )

        # Get updated template
        updated_template = db.templates.find_one({"_id": obj_id})
        updated_template["id"] = str(updated_template.pop("_id"))
        return updated_template

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@templates_router.delete("/{template_id}")
async def delete_template(
    template_id: str,
    current_user: str = Depends(validate_token_and_get_user)
):
    """Delete a specific template."""
    try:
        # Validate template ID format
        try:
            obj_id = ObjectId(template_id)
        except:
            raise HTTPException(status_code=400, detail="Invalid template ID format")

        # Check if template exists and belongs to user
        template = db.templates.find_one({"_id": obj_id})
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")
        
        if template["user_id"] != current_user:
            raise HTTPException(status_code=403, detail="Access denied")

        # Delete template
        db.templates.delete_one({"_id": obj_id})

        return {"message": "Template deleted successfully"}

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
