# 베이스 이미지 설정
FROM python:3.12-slim

# 작업 디렉토리 설정
WORKDIR /app

# 환경 변수 설정 → .pyc 파일 생성 방지 \ 로그를 버퍼링 없이 즉시 출력
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 종속성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 애플리케이션 소스 코드 전체 복사
COPY . .

# 컨테이너 외부에서 접근할 포트 지정
EXPOSE 5001

# 컨테이너 시작 시 실행할 명령
CMD ["python", "app.py"]