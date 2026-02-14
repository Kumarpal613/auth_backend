from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import text
from app.db.base import Base
from app.db.session import engine

from app.routers import users
from app.routers.auth import router as auth_router
from app.core.config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        print("Database connection is stable")
    except Exception as e:
        print("Database connection failed:", e)
        raise e

    yield  # App runs here

    # Shutdown logic
    print("Closing database connections")
    engine.dispose()

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Sparrow API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(users.router)

@app.get("/")
async def root():
    return {"status": "healthy", "message": "API is running"}


