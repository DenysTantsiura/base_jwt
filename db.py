# підключення до бази даних та моделі
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


# створює базу даних... за допомогою SQLAlchemy:
SQLALCHEMY_DATABASE_URL = 'sqlite:///:memory:'  # 'sqlite:///./sql_app.db'

# створює двигун для бази даних
engine = create_engine( # connect_args...- для зазначення відключити перевірку на той самий потік, бо
    SQLALCHEMY_DATABASE_URL, connect_args={'check_same_thread': False}
)  # SQLite за замовчуванням він дозволяє лише одне з'єднання з базою даних з одного потоку

# створюється як фабрика сесій, яка використовується для створення нових сесій:
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# створює базовий клас Base для оголошених моделей, який використовується для визначення моделі User
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'  # як ім'я таблиці в базі даних
    id = Column(Integer, primary_key=True)
    email = Column(String(150), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
#     refresh_token = Column(String(255), nullable=True)  # поле для зберігання рефреш токена
# '''Зберігання рефреш токенів у базі даних треба, щоб система могла перевіряти їх достовірність та дійсність.
#  для використання можливості аутентифікації на більш ніж одному девайсі, необхідно зберігати 
#  всі рефреш токени для кожного клієнта. А це означає, що для реалізації нам потрібна окрема таблиця 
#  зберігання рефреш токенів для кожного пристрою користувача. У нашій реалізації ми вважаємо, 
#  що у користувача лише один пристрій.'''


# створює таблицю в базі даних із використанням моделі User:
Base.metadata.create_all(bind=engine)

# Для прикладу немає необхідності використовувати механізми міграції.

'''
Функція get_db є залежністю, що дозволяє коду використовувати сесію бази даних. 
Функція створює нову сесію під час її виклику та повертає сесію, потім закриває 
сесію після закінчення роботи.'''
# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
