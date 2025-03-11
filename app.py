import datetime
import os
from flask import Flask, redirect, request, jsonify, render_template, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
import jwt
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client.jujeopton
app = Flask(__name__)


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # HTTP에서도 사용 가능하도록 설정
app.secret_key = os.getenv("APP_SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

# 구글 소셜 로그인
google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    redirect_to="google_login",  # 구글 로그인 후 이동할 함수명
)
app.register_blueprint(google_bp, url_prefix="/login")

# 깃허브 소셜 로그인
github_bp = make_github_blueprint(
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    redirect_to="github_login"  # 깃허브 로그인 후 이동할 함수명명
)

app.register_blueprint(github_bp, url_prefix="/login")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")

# demo db
joojeops = [{"id": 1, "content": "김정민 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "김정민"},
            {"id": 2, "content": "김현수 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "김현수"},
            {"id": 3, "content": "방효식 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "방효식"},
            {"id": 4, "content": "백승현 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "백승현"},
            {"id": 5, "content": "안예인 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "안예인"},
            {"id": 6, "content": "유윤선 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "유윤선"},
            {"id": 7, "content": "이동석 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "이동석"},
            {"id": 8, "content": "이승민 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3, "coach_name": "이승민"}]


@app.context_processor
def utility_processor():
    """
    템플릿에서 바로 사용할 수 있는 함수 `for_url` 등록
    """
    def for_url(endpoint, **kwargs):
        """
        1) 현재 request.args(기존 쿼리 파라미터)를 dict로 변환
        2) kwargs(새로 지정할 파라미터)로 update
        3) url_for(...)로 최종 URL 생성
        """
        current_args = request.args.to_dict()  # 현재 쿼리스트링을 dict로
        # kwargs에 같은 key가 있다면 덮어쓰게 됨
        current_args.update(kwargs)
        return url_for(endpoint, **current_args)

    return dict(for_url=for_url)

# 맨 처음 접속하면 띄워지는 페이지. 모든 코치진의 사진과 이름을 보여준다.
# 각 코치진을 클릭하면 그 코치의 주접을 볼 수 있는 페이지로 넘어간다.
@app.route('/', methods=['GET'])
def home():
    user_id = decode_jwt_from_cookie()
    if user_id is None:
        return redirect(url_for("login"))  # jwt가 없을 경우 로그인 페이지로 이동
    user = db.users.find_one({"user_id": user_id})
    # 코치 DB, 픽스 값으로 유지
    coaches = [
        {"name":"김정민", "path":"images/김정민.png"},
        {"name":"김현수", "path":"images/김현수.png"},
        {"name":"방효식", "path":"images/방효식.png"},
        {"name":"백승현", "path":"images/백승현.png"},
        {"name":"안예인", "path":"images/안예인.png"},
        {"name":"유윤선", "path":"images/유윤선.png"},
        {"name":"이동석", "path":"images/이동석.png"},
        {"name":"이승민", "path":"images/이승민.png"},
    ]
    if user:
        order = request.args.get('order', 'newest')  # 기본값 newest
        sorted_joojeops = sort_joojoeps(order=order)
        return render_template("index.html", user=user, coaches=coaches, joojeops=sorted_joojeops)
    else:
        return redirect(url_for("login"))

@app.route("/login")
def login():
    return render_template("login.html")

@app.route('/joojeop/<coach_name>', methods=['GET'])
def joojeop(coach_name):
    # 클라이언트에서 선택한 코치 이름 받아오기 -> path variable로 수정
    # coach_name = request.args.get('coach_name') 

    # 코치 딕셔너리 생성
    coach = {"name": coach_name, "path": f"images/{coach_name}.png"}
    # 해당 코치의 주접 리스트만 표현하도록 업데이트
    filtered_joojeops = [joojeop for joojeop in joojeops if joojeop["coach_name"] == coach_name]
    # 해당 코치의 주접 리스트를 정렬
    order = request.args.get('order', 'newest')
    sorted_joojeops = sort_joojoeps(order=order, joojeops=filtered_joojeops)
    # 코치 데이터 템플릿에 넘겨주기
    return render_template("joojeop.html", coach=coach, joojeops=sorted_joojeops)

def sort_joojoeps(order='newest', joojeops=joojeops):
    if order == 'newest':
        return sorted(joojeops, key=lambda x: x['date'], reverse=True)
    elif order == 'like':
        return sorted(joojeops, key=lambda x: x['like'], reverse=True)
    elif order == 'oldest':
        return sorted(joojeops, key=lambda x: x['date'], reverse=False)

@app.route("/google")  # ✅ Google 로그인 처리
def google_login():

    print("google_login 함수 호출")

    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v1/userinfo")
    if resp.ok:
        user_info = resp.json()
        print(user_info)
        user_id = user_info["id"]
        picture = user_info["picture"]
        name = user_info["name"]

        # 데이터베이스에서 user_id로 사용자 찾기
        user = db.users.find_one({"user_id": user_id})

        # 사용자가 없으면 새로 생성
        if not user:
            new_user = {
                "user_id": user_id,
                "name": name,
                "picture": picture
            }
            db.users.insert_one(new_user)

        # jwt 발급
        jwt_secret = app.config.get("JWT_SECRET", "default_jwt_secret")
        token = generate_jwt(user_id, jwt_secret)

        # ✅ JWT 토큰을 쿠키에 저장
        response = redirect(url_for("home"))
        response.set_cookie("jwt", token, httponly=True)
        return response

    return "Google 로그인 실패", 403


@app.route("/github")  # ✅ GitHub 로그인 처리
def github_login():
    if not github.authorized:
        github_bp.session.token = None  # ✅ 기존 OAuth 토큰 삭제 (강제 재요청)
        return redirect(url_for("github.login"))

    resp = github.get("/user")
    if resp.ok:
        user_info = resp.json()
        print("GitHub 응답 데이터:", user_info)  # ✅ GitHub 응답 데이터 확인

        user_id = str(user_info["id"])
        name = user_info.get("login", "Unknown")
        picture = user_info.get("avatar_url", "")

        # 데이터베이스에서 user_id로 사용자 찾기
        user = db.users.find_one({"user_id": user_id})

        # 사용자가 없으면 새로 생성
        if not user:
            new_user = {
                "user_id": user_id,
                "name": name,
                "picture": picture
            }
            db.users.insert_one(new_user)

        # ✅ 이메일 정보 가져오기
        email_resp = github.get("/user/emails")
        if email_resp.ok:
            emails = email_resp.json()
            primary_email = next(
                (email["email"] for email in emails if email["primary"]
                 and email["verified"]), "no-email@example.com"
            )
        else:
            primary_email = "no-email@example.com"

        # jwt 발급
        jwt_secret = app.config.get("JWT_SECRET", "default_jwt_secret")
        token = generate_jwt(user_id, jwt_secret)

        # ✅ JWT 토큰을 쿠키에 저장
        response = redirect(url_for("home"))
        response.set_cookie("jwt", token, httponly=True)
        return response

    return "GitHub 로그인 실패", 403


def generate_jwt(user_id: str, secret_key: str, expiration_hours: int = 1) -> str:
    """
    주어진 user_id를 포함하는 JWT를 생성합니다.

    :param user_id: JWT에 포함할 사용자 ID
    :param secret_key: JWT 서명에 사용할 비밀키
    :param expiration_hours: JWT 만료 시간(시간 단위)
    :return: JWT 문자열
    """
    payload = {
        "user_id": user_id,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=expiration_hours)
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    # PyJWT의 버전에 따라 bytes가 반환될 수 있으므로 문자열로 변환합니다.
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_jwt_from_cookie():
    """
    쿠키에서 'jwt' 토큰을 읽어 복호화한 후, 
    유효한 토큰이면 payload에서 user_id를 추출하여 반환합니다.
    유효하지 않거나 토큰이 없으면 None을 반환합니다.
    """
    token = request.cookies.get("jwt")
    if not token:
        print("JWT 토큰이 쿠키에 존재하지 않습니다.")
        return None

    jwt_secret = app.config.get("JWT_SECRET", "default_jwt_secret")

    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        user_id = payload.get("user_id")
        return user_id
    except jwt.ExpiredSignatureError:
        print("JWT 토큰이 만료되었습니다.")
    except jwt.InvalidTokenError:
        print("유효하지 않은 JWT 토큰입니다.")

    return None



if __name__ == '__main__':
    app.run(debug=True)