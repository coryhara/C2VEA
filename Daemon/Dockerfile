FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends mariadb-client tzdata && \
    ln -snf /usr/share/zoneinfo/Asia/Seoul /etc/localtime && \
    echo "Asia/Seoul" > /etc/timezone && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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

COPY --chown=${APP_UID}:${APP_GID} . .

USER app

CMD ["python", "main.py"]
