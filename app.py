# файл застосунку з маршрутами
from pydantic import BaseModel

from fastapi import FastAPI, Depends, HTTPException, status
"""клас фреймворку FastAPI для обробки запитів з ім'ям користувача та паролем 
у форматі OAuth 2.0. Він містить властивості username та password відповідно 
до формату OAuth 2.0"""
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import uvicorn

from auth import create_access_token, get_current_user, Hash
from db import User, get_db


app = FastAPI()
hash_handler = Hash()


'''Стандарт OAuth2 вимагає, щоб при використанні "потоку паролів" (який ми використовуємо) 
клієнт/користувач відправив поля у вигляді даних форми: username та password. У нашому застосунку 
ми збираємося використовувати email та password. Тут не варто хвилюватися, оскільки кінцевим 
користувачам на клієнті ми можемо завжди показати, що чекаємо від них поля email та password. 
А наша модель баз даних вже використовує поле email, замість username. Але для операції шляху 
входу нам потрібно використовувати ці імена username та password, щоб бути сумісними зі 
специфікацією та мати можливість використовувати Swagger документацію та 
клас OAuth2PasswordBearer для витягування токена із запиту.'''
class UserModel(BaseModel):
    username: str
    password: str


# маршрут для реєстрації у нашому застосунку
'''Коли користувач надсилає запит POST на цей маршрут, у тілі запиту повинні бути представлені 
дані нового користувача у форматі JSON, і вони будуть перетворені на об'єкт UserModel.'''
@app.post('/signup')
async def signup(body: UserModel, db: Session = Depends(get_db)):
    """приймає дані нового користувача та додає його в базу даних."""
    exist_user = db.query(User).filter(User.email == body.username).first()
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Account already exists')
    # створюється новий об'єкт User з email користувача та хешованим паролем:
    new_user = User(email=body.username, password=hash_handler.get_password_hash(body.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {'new_user': new_user.email} # відповідь з інформацією про нового користувача


# маршрут для аутентифікації: повинен буде приймати email та пароль, та повинен повертати нам JWT токен: access_token
'''Коли користувач надсилає запит POST на цей маршрут /login зі своїм ім'ям користувача 
(у нашому випадку нагадуємо email) та паролем у тілі запиту, вони 
перетворюються на об'єкт OAuth2PasswordRequestForm'''
@app.post('/login')
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """приймає ім'я користувача та пароль та повертає токен JWT для авторизації користувача."""
    user = db.query(User).filter(User.email == body.username).first()
    if user is None:  # недійсне ім'я користувача
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid email')
    if not hash_handler.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid password')
    # Generate JWT
    access_token = await create_access_token(data={'sub': user.email})

    return {'access_token': access_token, 'token_type': 'bearer'}


# можемо потрапити в будь-якому випадку
@app.get('/')
async def root():
    """Загальнодоступний ресурс."""
    return {'message': 'Hello World'}


# можемо потрапити на маршрут /secret - тільки використовуючи access_token
"""current_user: User = Depends(get_current_user) - це аргумент функції, 
який отримує інформацію про поточного користувача з токена доступу access_token, 
який ми повинні надати разом із запитом. Отримуємо ми access_token під час роботи 
з маршрутом /login. Сам процес отримання інформації досягається за допомогою 
залежності Depends(get_current_user), яка викликає безпосередньо функцію get_current_user 
для отримання інформації про користувача з токена"""
@app.get('/secret')
async def read_item(current_user: User = Depends(get_current_user)):
    """вимагає авторизації та повертає захищену інформацію."""
    return {'message': 'secret router', 'owner': current_user.email}


if __name__ == "__main__":
    uvicorn.run(app, host='127.0.0.1', port=8000)
