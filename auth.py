import os
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends, status
from fastapi.security import APIKeyQuery
from starlette.status import HTTP_401_UNAUTHORIZED

# Configuración del secreto y algoritmo de JWT
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS512"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
API_KEY = os.getenv("API_KEY")

# Security para API Key
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

# Configuración para hashear contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Función para crear el token JWT
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Configuración para hashear contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Función para verificar la contraseña
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Función para hashear contraseñas
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Seguridad de API Key (pasada como parámetro)
def validate_api_key(api_key: str = Depends(APIKeyQuery(name="api_key", auto_error=False))):
    if api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")
