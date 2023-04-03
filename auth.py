# методи роботи з аутентифікацією та авторизацією (створення токенів)
"""Цей код визначає кілька функцій та класів для обробки аутентифікації користувача 
та генерації токенів доступу з використанням JWT та 
класу OAuth2PasswordBearer з бібліотеки FastAPI."""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException
# клас OAuth2PasswordBearer використовується для захисту маршрутів вашого застосунку перевіркою дійсності токена, 
# переданого в заголовку Authorization запиту:
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext # class
from starlette import status
from sqlalchemy.orm import Session

from db import get_db, User


class Hash:
    """надає методи для хешування та перевірки паролів з використанням алгоритму bcrypt. 
    Алгоритм bcrypt є функцією хешування паролів, яка вважається безпечною та ефективною
    """
    # Алгоритм bcrypt розроблений таким чином, щоб бути повільним та високо витратним в обчисленнях, 
    # це робить його стійкішим до атак перебором:
    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

    def verify_password(self, plain_password, hashed_password) -> bool: 
        """повертає булеве значення, що вказує на те, чи збігається"""
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str):
        """пароль користувача хешується, його хеш може бути збережений в базі даних і оригінальний пароль 
        не може бути відновлений з хешованого пароля."""
        return self.pwd_context.hash(password)


SECRET_KEY = 'secret_key'
ALGORITHM = 'HS256'

# OAuth2PasswordBearer - це клас, який надається бібліотекою FastAPI, 
# який дозволяє легко реалізувати аутентифікацію на основі механізму OAuth2:
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/login')
# часто використовується для входу користувачів з адресою електронної пошти та паролем
'''
потрібно передати URL точки входу, яка оброблятиме видачу токена, зазвичай, 
у документації /token, але ми перейменували його на адекватніший /login. 
Це той маршрут, де наш застосунок буде отримувати електронну пошту та пароль 
користувача та видавати токен доступу клієнту.
OAuth2PasswordBearer автоматично обробляє процес парсингу токена із заголовка Authorization 
запиту та передачі його у функцію обробки маршруту, який захищений цим класом. 
Якщо токен недійсний або його термін дії минув, клас поверне 
HTTPException зі status_code рівним 401. Ми, наприклад, використовуємо 
декоратор Depends(oauth2_scheme) у функції get_current_user, 
щоб передати токен у функцію і перевірити, чи є токен дійсним.'''

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


# декоратор Depends(oauth2_scheme) у функції get_current_user, 
# щоб передати токен у функцію і перевірити, чи є токен дійсним
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """для аутентифікації користувача на основі його токена доступу: access_token.
    використовує клас OAuth2PasswordBearer для витягування токена із запиту."""
    credentials_exception = HTTPException(  # виключення HTTP з кодом статусу 401
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        # Decode JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload['sub']  # get email
        if email is None:
            raise credentials_exception
        
    except JWTError as e:
        raise credentials_exception

    # використовує email для запиту інформації про користувача з бази даних.
    user: User = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    
    return user
