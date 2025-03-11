from venv import logger
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
import os

load_dotenv()

SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_SINGING_SECRET = os.environ.get("SLACK_SINGING_SECRET")
CHANNEL_ID = os.environ.get("CHANNEL_ID")

client = WebClient(token=SLACK_BOT_TOKEN)


def send_slack_message(message):
    try:
        result = client.chat_postMessage(
            channel=CHANNEL_ID,
            text=message
        )
        logger.info(result)

    except SlackApiError as e:
        logger.error(f"Error posting message: {e}")


# if __name__ == '__main__':
#     message = input("메시지를 입력하세요: ")
#     send_slack_message(message)
#     print("메시지 전송 완료!")
