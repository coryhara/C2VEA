import os
from dataclasses import dataclass
from dotenv import load_dotenv
load_dotenv()

@dataclass
class Config:
    SECRET_KEY: str
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASSWORD: str
    DB_NAME: str
    DB_CHARSET: str
    TIMEZONE: str
    ALLOWED_ORIGINS: str
    POLL_INTERVAL_MS: int

def load_config() -> Config:
    required_vars = [
        "SECRET_KEY",
        "DB_HOST",
        "DB_PORT",
        "DB_USER",
        "DB_PASSWORD",
        "DB_NAME",
        "DB_CHARSET",
        "TIMEZONE",
        "ALLOWED_ORIGINS",
        "POLL_INTERVAL_MS",
    ]

    missing = [var for var in required_vars if not (os.getenv(var) and os.getenv(var).strip())]
    if missing:
        raise RuntimeError("필수 환경변수가 누락되었습니다:\n - " + "\n - ".join(missing))

    return Config(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        DB_HOST=os.getenv("DB_HOST"),
        DB_PORT=int(os.getenv("DB_PORT")),
        DB_USER=os.getenv("DB_USER"),
        DB_PASSWORD=os.getenv("DB_PASSWORD"),
        DB_NAME=os.getenv("DB_NAME"),
        DB_CHARSET=os.getenv("DB_CHARSET"),
        TIMEZONE=os.getenv("TIMEZONE"),
        ALLOWED_ORIGINS=os.getenv("ALLOWED_ORIGINS"),
        POLL_INTERVAL_MS=int(os.getenv("POLL_INTERVAL_MS")),
    )
