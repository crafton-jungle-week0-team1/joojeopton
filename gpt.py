from dotenv import load_dotenv
load_dotenv()

from openai import OpenAI
import os

# 환경 변수에서 API 키를 불러옵니다.
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def get_gpt_response(prompt):
    """
    주어진 프롬프트를 기반으로 GPT API에 요청하여 응답을 반환하는 함수.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "당신은 도움이 되는 어시스턴트입니다."},
                {"role": "user", "content": prompt}
            ]
        )
        # 첫 번째 응답 메시지의 내용을 반환합니다.
        return response.choices[0].message.content
    except Exception as e:
        print("API 호출 중 오류 발생:", e)
        return None


# if __name__ == '__main__':
#     # 사용자로부터 프롬프트 입력을 받습니다.
#     user_prompt = input("프롬프트를 입력하세요: ")
#     reply = get_gpt_response(user_prompt)
#     print("GPT의 답변:", reply)
