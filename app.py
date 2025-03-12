import datetime
import os
from flask import Flask, redirect, request, jsonify, render_template, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
import jwt
import gpt
from pymongo import MongoClient
from flask_apscheduler import APScheduler
import slack
from bson.objectid import ObjectId

client = MongoClient("mongodb://localhost:27017/")
db = client.jujeopton
app = Flask(__name__)
app.config['SCHEDULER_API_ENABLED'] = True

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # HTTP에서도 사용 가능하도록 설정
app.secret_key = os.urandom(24)
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
        {"name": "김정민", "path": "images/김정민.png"},
        {"name": "김현수", "path": "images/김현수.png"},
        {"name": "방효식", "path": "images/방효식.png"},
        {"name": "백승현", "path": "images/백승현.png"},
        {"name": "안예인", "path": "images/안예인.png"},
        {"name": "유윤선", "path": "images/유윤선.png"},
        {"name": "이동석", "path": "images/이동석.png"},
        {"name": "이승민", "path": "images/이승민.png"},
    ]
    if user:
        order = request.args.get('order', 'newest')  # 기본값 newest
        print
        filter_option = request.args.get('filter', 'all')  # 기본값 all
        sorted_joojeops = get_joojeops(order, filter_option=filter_option)
        return render_template("index.html", user=user, coaches=coaches, joojeops=sorted_joojeops)
    else:
        return redirect(url_for("login"))


@app.route('/joojeop/<coach_name>/<sort_order>', methods=['GET'])
def joojeop(coach_name, sort_order):
    user_id = decode_jwt_from_cookie()
    if user_id is None:
        return redirect(url_for("login"))
    user = get_user_by_user_id(user_id)
    # 클라이언트에서 선택한 코치 이름 path variable로 받아오기
    # 코치 딕셔너리 생성
    coach = {"name": coach_name, "path": f"images/{coach_name}.png"}
    # 해당 코치의 주접 리스트만 표현하도록 업데이트
    filter_option = request.args.get('filter', 'all')  # 기본값 all
    joojeops = get_joojeops_by_coach_name(coach_name, sort_order, filter_option=filter_option)
    
    # get content from query string if exists
    content = request.args.get('content', '')

    # 코치 데이터 템플릿에 넘겨주기
    return render_template("joojeop.html", coach=coach, joojeops=joojeops, sort_order=sort_order, content=content, user=user)


@app.route('/joojeop/<joojeop_id>/like', methods=['POST'])
def like(joojeop_id):
    # 클라이언트에서 선택한 주접의 id를 받아오기
    # 해당 주접의 like 수를 1 증가시키기
    user_id = decode_jwt_from_cookie()
    like_joojeop(joojeop_id, user_id)
    return redirect(url_for("home"))

@app.route('/joojeop/<joojeop_id>/delete', methods=['POST'])
def delete_joojeop(joojeop_id):
    # 클라이언트에서 선택한 주접의 id를 받아오기
    # 해당 주접 삭제
    object_id = ObjectId(joojeop_id)
    db.joojeops.delete_one({"_id": object_id})
    return redirect(url_for("home"))

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

@app.route("/login")
def login():
    return render_template("login.html")

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


@app.route("/logout")  # ✅ 로그아웃 처리
def logout():
    response = redirect(url_for("login"))
    response.set_cookie("jwt", "", expires=0)
    return response


@app.route("/joojeop/<coach_name>/<sort_order>/<keyword>/generate", methods=["POST"])
def generate_joojeop(coach_name, sort_order, keyword):
    print("generate_joojeop 함수 호출")
    user_id = decode_jwt_from_cookie()
    content = gpt.get_gpt_response(
        f"{coach_name}에 대한 주접 하나 만들어줘. 아재개그 스타일 20글자 이내로. 키워드:{keyword}")
    print(content)

    return redirect(url_for("joojeop", coach_name=coach_name, sort_order=sort_order, content=content))


@app.route("/joojeop/<coach_name>/<sort_order>/save", methods=["POST"])
def save_joojeop_route(coach_name, sort_order):
    user_id = decode_jwt_from_cookie()
    user = get_user_by_user_id(user_id)
    content = request.form.get("content")
    save_joojeop(user_id, user["name"], coach_name, content)
    return redirect(url_for("joojeop", coach_name=coach_name, sort_order=sort_order))


def get_user_by_user_id(user_id):
    return db.users.find_one({"user_id": user_id})


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


def save_joojeop(author_id, author_name, coach_name, content):
    """
    주접을 저장하는 함수
    """
    joojeop = {
        "content": content,
        "author_name": author_name,
        "author_id": author_id,
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "like": 0,
        "coach_name": coach_name,
        "liked_by": []
    }
    db.joojeops.insert_one(joojeop)


def like_joojeop(joojeop_id, user_id):
    """
    주접에 좋아요를 누르는 함수
    """
    object_id = ObjectId(joojeop_id)
    joojeop = db.joojeops.find_one({"_id": object_id})
    if user_id in joojeop["liked_by"]:
        db.joojeops.update_one({"_id": object_id}, {"$inc": {"like": -1}})
        db.joojeops.update_one({"_id": object_id}, {
                               "$pull": {"liked_by": user_id}})
    else:
        db.joojeops.update_one({"_id": object_id}, {"$inc": {"like": 1}})
        db.joojeops.update_one({"_id": object_id}, {
                               "$push": {"liked_by": user_id}})
    return True


def get_joojeops_by_coach_name(coach_name, order='newest', limit=None, filter_option='all'):
    """
    주어진 coach_name의 모든 주접을 가져와서 정렬하여 반환하는 함수
    """
    query = {}
    if coach_name:
        query["coach_name"] = coach_name
    query = {}
    if coach_name:
        query["coach_name"] = coach_name

    joojeops = list(db.joojeops.find(query))

    if order == 'newest':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['date'], reverse=True)
    elif order == 'like':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['like'], reverse=True)
    elif order == 'oldest':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['date'], reverse=False)
    else:
        sorted_joojeops = joojeops
    
    # 필터링    
    if filter_option == 'all':  
        pass
    elif filter_option == 'mine':
        sorted_joojeops = [joojeop for joojeop in sorted_joojeops if joojeop['author_id'] == decode_jwt_from_cookie()]

    if limit:
        sorted_joojeops = sorted_joojeops[:limit]

    # _id를 string으로 변환
    for joojeop in sorted_joojeops:
        joojeop['_id'] = str(joojeop['_id'])
        joojeop['isAuthor'] = False if joojeop['author_id'] != decode_jwt_from_cookie() else True
        joojeop['isLiked'] = True if decode_jwt_from_cookie() in joojeop.get('liked_by', []) else False

    return sorted_joojeops


def get_joojeops_by_author_id(author_id, order='newest', limit=None):
    """
    주어진 author_id의 모든 주접을 가져와서 정렬하여 반환하는 함수
    """
    joojeops = list(db.joojeops.find({"author_id": author_id}))

    if order == 'newest':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['date'], reverse=True)
    elif order == 'like':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['like'], reverse=True)
    elif order == 'oldest':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['date'], reverse=False)
    else:
        sorted_joojeops = joojeops

    if limit:
        sorted_joojeops = sorted_joojeops[:limit]

    # id를 string으로 변환
    for joojeop in sorted_joojeops:
        joojeop['_id'] = str(joojeop['_id'])

    return sorted_joojeops


def get_joojeops(order='newest', limit=None, filter_option='all'):
    """
    모든 주접을 가져와서 정렬하여 반환하는 함수
    :param order: 정렬 기준 ('newest', 'like' 또는 'oldest')
    :param limit: 반환할 주접의 최대 개수 (None이면 제한 없음)
    :return: 정렬된 주접 리스트
    """
    joojeops = list(db.joojeops.find())

    if order == 'newest':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['date'], reverse=True)
    elif order == 'like':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['like'], reverse=True)
    elif order == 'oldest':
        sorted_joojeops = sorted(
            joojeops, key=lambda x: x['date'], reverse=False)
    else:
        sorted_joojeops = joojeops

    # 필터링    
    if filter_option == 'all':  
        pass
    elif filter_option == 'mine':
        sorted_joojeops = [joojeop for joojeop in sorted_joojeops if joojeop['author_id'] == decode_jwt_from_cookie()]
    
    if limit:
        sorted_joojeops = sorted_joojeops[:limit]

    # id를 string으로 변환
    for joojeop in sorted_joojeops:
        joojeop['_id'] = str(joojeop['_id'])
        joojeop['isAuthor'] = False if joojeop['author_id'] != decode_jwt_from_cookie() else True
        joojeop['isLiked'] = True if decode_jwt_from_cookie() in joojeop.get('liked_by', []) else False

    return sorted_joojeops


def get_today_joojeops_by_coach_name(coach_name):
    """
    오늘 작성된 주접들을 코치 이름을 입력받아 좋아요 순으로 반환하고, 10개까지만 반환하는 함수
    """
    today = datetime.datetime.now().date()  # 현재 날짜 (시간 제외)
    start_of_day = datetime.datetime.combine(
        today, datetime.time.min)  # 00:00:00
    end_of_day = datetime.datetime.combine(
        today, datetime.time.max)    # 23:59:59.999999

    query = {
        "coach_name": coach_name,
        "date": {"$gte": start_of_day, "$lt": end_of_day}  # 오늘 날짜 범위 조회
    }
    joojeops = list(db.joojeops.find(query))

    sorted_joojeops = sorted(joojeops, key=lambda x: x['like'], reverse=True)
    top_10_joojeops = sorted_joojeops[:10]

    # id를 string으로 변환
    for joojeop in top_10_joojeops:
        joojeop['_id'] = str(joojeop['_id'])

    return top_10_joojeops

# 코치님 이름으로 만들어진 주접 가져와서 메세지 만들기기


def make_joojeop_message_for_coach(coach_name):
    list = get_today_joojeops_by_coach_name(coach_name)
    message = f"오늘 {len(list)}명이 {coach_name}님 주접을 떨었습니다\n-----------------------------------------\n"
    count = 0
    for joojeop in list:
        count += 1
        message += f"{count}. {joojeop['content']} | 작성자 : {joojeop['author_name']} | 좋아요 {joojeop['like']}개\n"
    return message


def scheduled_job():
    slack.send_slack_message(make_joojeop_message_for_coach("이동석"))


scheduler.add_job(id="scheduled_job", func=scheduled_job,
                  trigger="cron", hour=11, minute=9)


if __name__ == '__main__':
    app.run(debug=True)
