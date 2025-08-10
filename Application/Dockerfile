FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# non-root 유저 생성
RUN addgroup --system app && adduser --system --ingroup app app

WORKDIR /app

# 1) 의존성 먼저 설치 (캐시 활용)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2) 앱 소스 복사 (여기서의 '.'은 ../Application 전체)
COPY . .

# 3) 권한 낮추기
USER app

EXPOSE 8080

# Gunicorn을 모듈 방식으로 실행 (PATH 이슈 회피)
CMD ["python", "-m", "gunicorn", "app:create_app()", \
     "--bind", "0.0.0.0:8080", "--worker-class", "eventlet", \
     "--workers", "1", "--threads", "1", "--timeout", "120"]