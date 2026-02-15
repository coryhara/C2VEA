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
    PUBLIC_BASE_URL: str
    POLL_INTERVAL_MS: int
    SMTP_USER: str
    SMTP_PASS: str
    GITHUB_TOKEN_ENCRYPTION_KEY: str

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
        "SMTP_USER",
        "SMTP_PASS"
    ]

    missing = [var for var in required_vars if not (os.getenv(var) and os.getenv(var).strip())]
    if missing:
        raise RuntimeError("필수 환경변수가 누락되었습니다:\n - " + "\n - ".join(missing))

    allowed_origins = os.getenv("ALLOWED_ORIGINS")
    public_base_url = (os.getenv("PUBLIC_BASE_URL") or "").strip()
    if not public_base_url:
        public_base_url = allowed_origins.replace(";", ",").split(",")[0].strip()

    github_token_encryption_key = (os.getenv("GITHUB_TOKEN_ENCRYPTION_KEY") or "").strip()

    return Config(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        DB_HOST=os.getenv("DB_HOST"),
        DB_PORT=int(os.getenv("DB_PORT")),
        DB_USER=os.getenv("DB_USER"),
        DB_PASSWORD=os.getenv("DB_PASSWORD"),
        DB_NAME=os.getenv("DB_NAME"),
        DB_CHARSET=os.getenv("DB_CHARSET"),
        TIMEZONE=os.getenv("TIMEZONE"),
        ALLOWED_ORIGINS=allowed_origins,
        PUBLIC_BASE_URL=public_base_url,
        POLL_INTERVAL_MS=int(os.getenv("POLL_INTERVAL_MS")),
        SMTP_USER=os.getenv("SMTP_USER"),
        SMTP_PASS=os.getenv("SMTP_PASS"),
        GITHUB_TOKEN_ENCRYPTION_KEY=github_token_encryption_key
    )
