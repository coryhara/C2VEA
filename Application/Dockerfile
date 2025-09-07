FROM python:3.11-slim-bullseye

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# wkhtmltopdf + 런타임 라이브러리
RUN apt-get update && apt-get install -y --no-install-recommends \
    wkhtmltopdf \
    fontconfig \
    libfreetype6 \
    libjpeg62-turbo \
    libpng16-16 \
    libx11-6 \
    libxcb1 \
    libxext6 \
    libxrender1 \
    xfonts-75dpi \
    xfonts-base \
 && rm -rf /var/lib/apt/lists/*

# Python 의존성
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- 유저/그룹 보정: 있으면 수정, 없으면 생성 ---
ARG APP_UID=1000
ARG APP_GID=1000
RUN set -eux; \
    if getent group app >/dev/null; then \
        groupmod -g "$APP_GID" app; \
    else \
        addgroup --gid "$APP_GID" app; \
    fi; \
    if id -u app >/dev/null 2>&1; then \
        usermod -u "$APP_UID" -g "$APP_GID" app; \
    else \
        adduser --uid "$APP_UID" --gid "$APP_GID" --disabled-password --gecos "" app; \
    fi

# 앱 소스 복사 (+ 소유권)
COPY --chown=${APP_UID}:${APP_GID} . .

USER app

EXPOSE 8080

# run.py 실행 (python -m app.run)
CMD ["python", "-m", "app.run"]
