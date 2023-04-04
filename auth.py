# методи роботи з аутентифікацією та авторизацією (створення токенів)
# python-jose[cryptography] - пакет для jwt токенів
# passlib[bcrypt] - шоб хешировать пароль
"""Цей код визначає кілька функцій та класів для обробки аутентифікації користувача 
та генерації токенів доступу з використанням JWT та 
класу OAuth2PasswordBearer з бібліотеки FastAPI.

Використовуватимемо пару токенів: access token та refresh token.
access token - використовується для авторизації запитів та зберігання додаткової інформації про користувача.
refresh token - видається сервером за результатами успішної аутентифікації та використовується для отримання нового access/refresh токенів.
"""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
# from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import User, get_db


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
token_schema = HTTPBearer()


class Hash:
    """надає методи для хешування та перевірки паролів з використанням алгоритму bcrypt. 
    Алгоритм bcrypt є функцією хешування паролів, яка вважається безпечною та ефективною
    """
    # Алгоритм bcrypt розроблений таким чином, щоб бути повільним та високо витратним в обчисленнях, 
    # це робить його стійкішим до атак перебором:
    # https://passlib.readthedocs.io/en/stable/narr/context-tutorial.html
    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')  # hash migration features for legacy support

    def verify_password(self, plain_password, hashed_password) -> bool: 
        """повертає булеве значення, що вказує на те, чи збігається"""
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str):
        """пароль користувача хешується, його хеш може бути збережений в базі даних і оригінальний пароль 
        не може бути відновлений з хешованого пароля."""
        return self.pwd_context.hash(password)


# define a function to generate a new access token
async def create_access_token(data: dict, expires_delta: Optional[float] = None):
    """генерує новий access_token з кінцевим часом життя, кодуючи словник даних, так званий 
    to_encode в JWT."""
    to_encode = data.copy()  # копію словника даних, щоб вихідні дані не змінювалися
    if expires_delta: # розраховує час закінчення терміну дії:
        expire = datetime.utcnow() + timedelta(seconds=expires_delta)
    else:  # встановлює час закінчення терміну дії на 15 хвилин:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({'exp': expire})  # додає час закінчення терміну дії
    # для кодування даних у JWT:
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt  # цей токен буде використаний як токен доступу для авторизації


# декоратор Depends 
# щоб передати токен у функцію і перевірити, чи є токен дійсним
async def get_current_user(token: HTTPAuthorizationCredentials = Depends(token_schema), db: Session = Depends(get_db)):
    """для аутентифікації користувача на основі його токена доступу: access_token.
    використовує клас OAuth2PasswordBearer для витягування токена із запиту."""
    credentials_exception = HTTPException(  # виключення HTTP з кодом статусу 401
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        # Decode JWT
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload['sub']  # get email
        if email is None:
            raise credentials_exception
        
    except JWTError as e:
        raise credentials_exception

    # використовує email для запиту інформації про користувача з бази даних.
    user: Optional[User] = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    
    return user
