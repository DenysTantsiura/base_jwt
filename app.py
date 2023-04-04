from jose import jwt, JWTError

# the secret word is not stored here # openssl rand -hex 32
secret_word = '898edeeeac4a61f957ac47f9766ad504626b3e120b77502c3e242f343b484b8b'

# корисне навантаження може містити все, але не має містити секретів:
payload  = {
    'sub': 'test@test.com',
    'username': 'Den',
    'role': 'moderator',
}

# https://jwt.io/libraries?language=Python
token = jwt.encode(payload, secret_word, algorithm='HS256')
print(token)

try:
    r = jwt.decode(token, secret_word, algorithms=['HS256', 'HS512'])
    print(r)

except JWTError as err:
    print(err)
