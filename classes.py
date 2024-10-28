from pydantic import BaseModel, Field, field_validator
from fastapi import HTTPException
from typing import List

# Esquema de datos para el registro de usuario
class UserRegister(BaseModel):
    username: str = Field(..., min_length=4, pattern="^[A-Z][a-zA-Z0-9]*$")
    password: str = Field(..., min_length=8)
    rating: str = Field(...)

    @field_validator("rating")
    def validate_rating(cls, value):
        allowed_ratings = ["G", "PG", "PG-13", "R", "NC-17"]
        if value not in allowed_ratings:
            raise HTTPException(status_code=422, detail=f"Rating no permitido: {value}")
        return value


class UserLogin(BaseModel):
    username: str
    password: str


# Modelo de datos para la respuesta del token
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


# Modelo de respuesta para una película
class Movie(BaseModel):
    movie_title: str
    original_release_date: str
    genres: List[str]
    content_rating: str
    tomatometer_rating: float