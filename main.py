from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import MongoClient
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv, dotenv_values 
load_dotenv() 

MONGODB_URI = os.getenv("MONGODB_URI")
client = MongoClient(MONGODB_URI)
db = client["fastapi_db"]
users_collection = db["FastAPI_Users"]
scripts_collection = db["FastAPI_Scripts"]


app = FastAPI()


SECRET_KEY = "key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel):
    username: str
    password: str
    is_enable: bool
    about: Optional[str] = None

class Script(BaseModel):
    name: str
    description: str
    ltp: float
    is_enable: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = users_collection.find_one({"username": token_data.username})
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user["is_enable"]:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/signup", response_model=Token)
async def signup(user: User):
    user_dict = user.dict()
    user_dict["password"] = get_password_hash(user.password)
    # test_password["password"] = get_password_hash(user.password)
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    # test_password["password"]=create_access_token(data={"sub": user.username})
    users_collection.insert_one(user_dict)
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # access_token = create_access_token(data={"ans": user["username"]})
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


# @app.post("/add-script", response_model=Script)
# async def add_script(script: Script):
#     if scripts_collection.find_one({"name": script.name}):
#         raise HTTPException(status_code=400, detail="Script already exists")
#     scripts_collection.insert_one(script.dict())
#     return script

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/scripts", response_model=List[Script])
async def get_scripts():
    scripts = scripts_collection.find({"is_enable": True})
    return list(scripts)

@app.post("/assign-script/{script_name}")
async def assign_script(script_name: str, current_user: User = Depends(get_current_active_user)):
    script = scripts_collection.find_one({"name": script_name})
    if not script or not script["is_enable"]:
        raise HTTPException(status_code=400, detail="Script not found or not enabled")
    users_collection.update_one(
        {"username": current_user["username"]},
        # {"password": current_user["password"]},
        {"$addToSet": {"scripts": script_name}}
    )
    return {"msg": "Script assigned"}

@app.get("/my-scripts", response_model=List[Script])
async def get_my_scripts(current_user: User = Depends(get_current_active_user)):
    user = users_collection.find_one({"username": current_user["username"]})
    scripts = scripts_collection.find({"name": {"$in": user.get("scripts", [])}})
    return list(scripts)

@app.put("/disable-script/{script_name}")
async def disable_script(script_name: str):
    scripts_collection.update_one({"name": script_name}, {"$set": {"is_enable": False}})
    return {"msg": "Script disabled"}

