import os
from flask import Flask, request, jsonify, render_template, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # HTTP에서도 사용 가능하도록 설정

app = Flask(__name__)

# 맨 처음 접속하면 띄워지는 페이지. 모든 코치진의 사진과 이름을 보여준다.
# 각 코치진을 클릭하면 그 코치의 주접을 볼 수 있는 페이지로 넘어간다.
@app.route('/', methods=['GET'])
def home():
    joojeops = [{"id": 1, "content": "대한민국, 동석 보유국", "author_name": "현호","author_id":'324', "date": "2025-03-10", "like": 2},
                {"id": 2, "content": "동석이 좋아하지마\n그거 어떻게하는데...\n", "author_name": "choi", "author_id":'2344', "date": "2021-07-01", "like": 3}]
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
    return render_template("index.html", coaches=coaches, joojeops=joojeops)


@app.route('/joojeop', methods=['GET'])
def joojeop():
    # 클라이언트에서 선택한 코치 이름 받아오기
    coach_name = request.args.get('coach_name')
    # 코치 딕셔너리 생성
    coach = {"name": coach_name, "path": f"images/{coach_name}.png"}
    print(coach['path'])
    # 코치 데이터 템플릿에 넘겨주기
    return render_template("joojeop.html", coach=coach)

if __name__ == '__main__':
    app.run(debug=True)