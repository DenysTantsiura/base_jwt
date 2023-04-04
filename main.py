# файл застосунку з маршрутами
from pydantic import BaseModel, EmailStr  # poetry add pydantic[email]

from jose import jwt, JWTError
from fastapi import FastAPI, Depends, HTTPException, status, Security
# """клас фреймворку FastAPI для обробки запитів з ім'ям користувача та паролем 
# у форматі OAuth 2.0. Він містить властивості username та password відповідно 
# до формату OAuth 2.0"""
# from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
import uvicorn

from auth import create_access_token, get_current_user, Hash
from db import User, get_db


app = FastAPI()
hash_handler = Hash()  # буде хешувати паролі
# security = HTTPBearer()


class UserModel(BaseModel):
    email: EmailStr
    password: str


@app.post("/signup")
async def signup(body: UserModel, db: Session = Depends(get_db)):
    exist_user = db.query(User).filter(User.email == body.email).first()
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    new_user = User(email=body.email, password=hash_handler.get_password_hash(body.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"id": new_user.id, "new_user": new_user.email}


@app.post("/login")
async def login(body: UserModel, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not hash_handler.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    # Generate JWT (створюємо та повертаємо два токени)
    access_token = await create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/secret")  # закритий маршрут бо добавили Depends(get_current_user):
async def secret(current_user: User = Depends(get_current_user)):
    return {"message": 'secret router', "owner": current_user.email}


if __name__ == "__main__":
    uvicorn.run(app, host='127.0.0.1', port=8000)
