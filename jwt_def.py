import jwt
import datetime
from flask import request
from flask import Flask, make_response

jwt_secret = "A2sdasf1w31sfgkaiI"


def generate_jwt(user_id: str) -> str:
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
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }

    token = jwt.encode(payload, jwt_secret, algorithm="HS256")
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
    # Example usage
    user_id = "example_user"
    token = generate_jwt(user_id)
    print(f"Generated JWT: {token}")

    # Simulate setting the token in a cookie for testing

    app = Flask(__name__)

    @app.route('/')
    def index():
        response = make_response("Setting JWT in cookie")
        response.set_cookie("jwt", token)
        return response

    @app.route('/decode')
    def decode():
        user_id_from_cookie = decode_jwt_from_cookie()
        if user_id_from_cookie:
            return f"Decoded user_id from JWT: {user_id_from_cookie}"
        else:
            return "Failed to decode JWT"

    if __name__ == '__main__':
        app.run(debug=True)