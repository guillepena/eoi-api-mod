
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Dict, cast, List
from datetime import timedelta
from jose import JWTError, jwt
from contextlib import asynccontextmanager
import redis
import os
import csv
from starlette.datastructures import State
from classes import UserRegister, Token, Movie
from auth import create_access_token, verify_password, hash_password, validate_api_key



# Configuración del secreto y algoritmo de JWT
SECRET_KEY = os.getenv("SECRET_KEY")
API_KEY = os.getenv("API_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 15


def load_data(redis_client):
    with open('data/rotten_tomatoes_movies.csv', mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["tomatometer_status"] == "Certified-Fresh" and row["content_rating"] != "NR":
                redis_client.set(row["movie_title"], str(row))

def get_redis_client(request: Request):
    return request.app.state.redis_client


# Configuración del cliente Redis
@asynccontextmanager
async def lifespan(_):
    app.state.redis_client = redis.Redis(host='redis', port=6379, db=0)
    app.state = cast(State, app.state) # Usar cast para indicar el tipo de app.state
    load_data(app.state.redis_client) # Cargar las películas en Redis al iniciar la aplicación
    yield
    app.state.redis_client.close() # Cerrar la conexión de Redis al finalizar

# Configuración básica de la aplicación
app = FastAPI(lifespan=lifespan)


# Router para agrupar endpoints
router = APIRouter(prefix="/act4", tags=["movies"])



#Method 1

# Base de datos en memoria para almacenar usuarios
users_db: Dict[str, Dict[str, str]] = {
                                        "Rober": {
                                            "username": "Rober",
                                            "hashed_password": "$2b$12$VcB9fTaK6nViJaDuZseaaefqjHU58OFGVXXYhxOPNqjA3F.tJtDZO",
                                            "content_rating": "G"
                                                },
                                        "Marian": {
                                            "username": "Marian",
                                            "hashed_password": "$2b$12$sbxu21/V135gaLJT2i.YKOap6KvuR0DYwCwWjr.8XqK9rs5FIX99u",
                                            "content_rating": "R"
                                                }
                                        }


# Endpoint para el registro de usuario
@router.post("/register", status_code=status.HTTP_204_NO_CONTENT)
async def register_user(user: UserRegister, api_key: str = Depends(validate_api_key),
                        users_collection=users_db):
    if user.username in users_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario ya está registrado")

    # Almacena el usuario en la "base de datos" con contraseña hasheada
    hashed_password = hash_password(user.password)
    users_db[user.username] = {
        "username": user.username,
        "hashed_password": hashed_password,
        "content_rating": user.content_rating
    }

    return {"message": "Usuario registrado exitosamente"}

# Añadir el router a la aplicación
app.include_router(router)



#Method 2

# Base de datos en memoria para almacenar usuarios
users_db: Dict[str, Dict[str, str]] = {}


# Endpoint para solicitud de token
@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    
    # Verificar si el usuario existe y si la contraseña es válida
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    
    # Generar el token con los claims requeridos
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "cr": user["content_rating"]}, expires_delta=access_token_expires
    )
    
    # Devolver el token
    return {"access_token": access_token, "token_type": "bearer"}



#Method 3

# Endpoint de seguridad OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="act4/token")


# Función para verificar el token y extraer el contenido
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        content_rating: str = payload.get("cr")
        if content_rating is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail="Content rating not found in token",
                                headers={"WWW-Authenticate": "Bearer"})
        return content_rating
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Invalid token",
                            headers={"WWW-Authenticate": "Bearer"})

# Función para obtener las 10 películas mejor valoradas filtradas por calificación de edad
@router.get("/movies-by-content-rating", response_model=List[Movie])
async def get_movies_by_content_rating(content_rating: str = Depends(get_current_user),
                                       redis_client=Depends(get_redis_client)):
    # Obtener todas las películas desde Redis y filtrar por content_rating
    all_movies = []
    for key in redis_client.scan_iter("movie:*"):
        movie_data = redis_client.hgetall(key)
        movie = {
            "movie_title": movie_data.get("movie_title").decode("utf-8"),
            "original_release_date": movie_data.get("original_release_date").decode("utf-8"),
            "genres": movie_data.get("genres").decode("utf-8").split(","),
            "content_rating": movie_data.get("content_rating").decode("utf-8"),
            "tomatometer_rating": float(movie_data.get("tomatometer_rating").decode("utf-8")),
        }
        
        # Filtrar por content_rating
        if movie["content_rating"] == content_rating:
            all_movies.append(movie)

    # Ordenar películas por tomatometer_rating de mayor a menor y limitar a 10
    top_movies = sorted(all_movies, key=lambda x: x["tomatometer_rating"], reverse=True)[:10]
    
    return top_movies



#Method 4

# Endpoint para obtener el número de claves en Redis
@router.get("/key-list-size", status_code=status.HTTP_200_OK)
async def get_key_list_size(api_key: str = Depends(validate_api_key),
                            redis_client=Depends(get_redis_client)):
    # Contar el número de claves en la base de datos Redis
    num_keys = redis_client.dbsize()
    return {"num_keys": num_keys}



# Incluir el router en la aplicación
app.include_router(router)