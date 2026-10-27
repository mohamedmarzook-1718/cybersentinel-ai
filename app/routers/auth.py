"""Authentication router – login, token refresh, user profile, admin demo user creation."""
from datetime import timedelta, datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import verify_password, hash_password, create_access_token
from app.core.deps import get_current_user, require_admin
from app.core.config import get_settings
from app.models import User
from app.schemas import Token, UserCreate, UserOut, UserUpdate
from app.database import get_db
from sqlalchemy.orm import Session

router = APIRouter(tags=["auth"])

settings = get_settings()

def seed_demo_users_internal(db: Session) -> list[str]:
    """Helper to ensure demo admin and analyst accounts exist."""
    created = []
    for uname, pwd, role in [
        (settings.demo_admin_username, settings.demo_admin_password, "admin"),
        (settings.demo_analyst_username, settings.demo_analyst_password, "analyst"),
    ]:
        existing = db.query(User).filter(User.username == uname).first()
        if not existing:
            user = User(
                username=uname,
                hashed_password=hash_password(pwd),
                role=role,
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            db.add(user)
            created.append(uname)
    if created:
        db.commit()
    return created

@router.post("/token", response_model=Token)
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
):
    # Auto-seed if database is currently empty
    if db.query(User).count() == 0:
        seed_demo_users_internal(db)

    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    token = create_access_token({"sub": str(user.id), "role": user.role, "username": user.username}, expires_delta=access_token_expires)
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    return Token(access_token=token, role=user.role, username=user.username)

@router.get("/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/demo-seed", response_model=dict)
def seed_demo_users(db: Session = Depends(get_db)):
    """Create demo admin and analyst accounts if they don't exist."""
    created = seed_demo_users_internal(db)
    return {"seeded": created}

@router.put("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for attr, value in payload.model_dump(exclude_unset=True).items():
        setattr(user, attr, value)
    db.commit()
    db.refresh(user)
    return user
