import os
from flask import Flask, request, jsonify, render_template, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # HTTP에서도 사용 가능하도록 설정

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    img_url = url_for('static', filename='images/profile_test.png')
    return render_template("index.html", profile_url=img_url)

@app.route('/joojeop', methods=['GET'])
def joojeop():
    img_url = url_for('static', filename='images/profile_test.png')
    return render_template("joojeop.html", profile_url=img_url)

if __name__ == '__main__':
    app.run(debug=True)