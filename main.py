from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
import jwt

app = FastAPI()

SECRET_KEY="your_secret_key"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=1

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_user_db = {
    "john_doe": {
        "username": "john_doe",
        "hashed_password": pwd_context.hash("secret")
    },
}


class User(BaseModel):
    username:str


class Token(BaseModel):
    access_token: str
    token_type:str

class TokenData(BaseModel):
    username:Optional[str] = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authentificate_user(username:str, password:str):
    user = fake_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return True

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authentificate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail="incorrect username or password",
            geaders={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token=create_access_token(data={"sub": user["username"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type":"bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception= HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail="incorrect username or password",
        geaders={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = fake_user_db.get(token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/users/me", response_model=User)
async def read_current_user(current_user: User=Depends(get_current_user)):
    return current_user

@app.post("/users", response_model=User)
def create_user(user:User):
    if user.username in fake_user_db:
        raise HTTPException(status_code=400, detail="username already exist")
    hashed_password = pwd_context.hash("secret")
    user_data=user.dict()
    user_data["hashed_password"]=hashed_password
    fake_user_db[user.username] = user_data
    return user


