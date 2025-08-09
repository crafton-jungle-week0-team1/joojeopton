#!/bin/bash

# EC2 배포 스크립트

echo "🚀 joojeopton 배포 시작..."

# Docker 및 Docker Compose 설치 확인
if ! command -v docker &> /dev/null; then
    echo "Docker 설치 중..."
    sudo yum update -y
    sudo yum install -y docker
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -a -G docker ec2-user
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose 설치 중..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

# 기존 컨테이너 중지 및 제거
echo "기존 컨테이너 정리 중..."
docker-compose down

# 새 이미지 빌드 및 실행
echo "새 이미지 빌드 및 실행 중..."
docker-compose up --build -d

echo "✅ 배포 완료!"
echo "애플리케이션이 http://your-ec2-ip 에서 실행 중입니다."