# файл застосунку з маршрутами
from pydantic import BaseModel

from fastapi import FastAPI, Depends, HTTPException, status, Security
"""клас фреймворку FastAPI для обробки запитів з ім'ям користувача та паролем 
у форматі OAuth 2.0. Він містить властивості username та password відповідно 
до формату OAuth 2.0"""
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
import uvicorn

from auth2 import create_access_token, create_refresh_token, get_email_form_refresh_token, get_current_user, Hash
from db import User, get_db


app = FastAPI()
hash_handler = Hash()
security = HTTPBearer()


class UserModel(BaseModel):
    username: str
    password: str


@app.post("/signup")
async def signup(body: UserModel, db: Session = Depends(get_db)):
    exist_user = db.query(User).filter(User.email == body.username).first()
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    new_user = User(email=body.username, password=hash_handler.get_password_hash(body.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"new_user": new_user.email}


@app.post("/login")
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not hash_handler.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    # Generate JWT (створюємо та повертаємо два токени)
    access_token = await create_access_token(data={"sub": user.email})
    refresh_token = await create_refresh_token(data={"sub": user.email})
    user.refresh_token = refresh_token  # поміщаємо refresh_token у базу даних
    db.commit()
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


"""
Функція приймає як параметр заголовок авторизації з /refresh_token, 
використовуючи механізм захисту Security з FastAPI. Використовуючи HTTPAuthorizationCredentials з fastapi.security, 
отримуємо refresh_token із заголовка запиту token=credentials.credentials. 
Потім, використовуючи функцію get_email_form_refresh_token, декодуємо токен і отримуємо email з нього. 
Якщо токен не відповідає токену, збереженому в базі даних, 
функція викликає виняток raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
detail="Invalid refresh token") та 
видаляє поточний refresh_token з бази даних. Можливо, він скомпрометований, 
і тепер клієнт повинен повторити операцію аутентифікації знову. 
Якщо токен є валідним, створюються нові токени доступу та оновлення, 
і старий токен оновлення refresh_token оновлюємо в базі даних.
"""
@app.get('/refresh_token')
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    token = credentials.credentials  # отримуємо refresh_token із заголовка запиту
    email = await get_email_form_refresh_token(token)  # отримуємо email
    user = db.query(User).filter(User.email == email).first()
    if user.refresh_token != token:
        user.refresh_token = None
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await create_access_token(data={"sub": email})
    refresh_token = await create_refresh_token(data={"sub": email})
    user.refresh_token = refresh_token
    db.commit()
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/secret")
async def read_item(current_user: User = Depends(get_current_user)):
    return {"message": 'secret router', "owner": current_user.email}


if __name__ == "__main__":
    uvicorn.run(app, host='127.0.0.1', port=8000)
