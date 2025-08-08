from dotenv import load_dotenv
load_dotenv()

import google.generativeai as genai
# import openai
import os

# 환경 변수에서 API 키를 불러옵니다.
# openai.api_key = os.getenv("OPENAI_API_KEY")
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

def get_gemini_response(prompt):
    """
    주어진 프롬프트를 기반으로 GEMINI API에 요청하여 응답을 반환하는 함수.
    """
    model = genai.GenerativeModel("gemini-2.0-flash-lite")
    try:
        response = model.generate_content(prompt, stream=True)
        # 첫 번째 응답 메시지의 내용을 반환합니다.
        result = ''
        for chunk in response:
            result += chunk.text
        return result
    except Exception as e:
        print("API 호출 중 오류 발생:", e)
        return None


# if __name__ == '__main__':
#     # 사용자로부터 프롬프트 입력을 받습니다.
#     user_prompt = input("프롬프트를 입력하세요: ")
#     reply = get_gpt_response(user_prompt)
#     print("GPT의 답변:", reply)
