# joojeopton EC2 배포 가이드

## 1. EC2 인스턴스 준비

### 인스턴스 생성
- AMI: Amazon Linux 2
- 인스턴스 타입: t2.micro (프리티어) 또는 t3.small
- 보안 그룹: HTTP(80), HTTPS(443), SSH(22) 포트 열기

### SSH 접속
```bash
ssh -i your-key.pem ec2-user@your-ec2-ip
```

## 2. 코드 업로드

### Git 사용 (권장)
```bash
git clone https://github.com/your-repo/joojeopton.git
cd joojeopton
```

### SCP 사용
```bash
scp -i your-key.pem -r joojeopton/ ec2-user@your-ec2-ip:~/
```

## 3. 환경 변수 설정

`.env` 파일을 EC2에 생성하고 필요한 환경 변수들을 설정:

```bash
# .env 파일 예시
MONGODB_URL=your_mongodb_connection_string
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
JWT_SECRET=your_jwt_secret
ADMIN_GOOCHUL=admin_user_id_1
ADMIN_HYUNHO=admin_user_id_2
ADMIN_JINYOUNG=admin_user_id_3
```

## 4. 배포 실행

```bash
cd joojeopton
./deploy.sh
```

## 5. 확인

브라우저에서 `http://your-ec2-ip`로 접속하여 애플리케이션이 정상 작동하는지 확인

## 6. 도메인 연결 (선택사항)

### Route 53에서 도메인 설정
1. Route 53에서 호스팅 영역 생성
2. A 레코드로 EC2 IP 연결

### SSL 인증서 (Let's Encrypt)
```bash
sudo yum install -y certbot
sudo certbot --nginx -d your-domain.com
```

## 7. 모니터링

### 로그 확인
```bash
docker-compose logs -f
```

### 컨테이너 상태 확인
```bash
docker-compose ps
```

## 8. 업데이트

코드 변경 후 재배포:
```bash
git pull
./deploy.sh
```