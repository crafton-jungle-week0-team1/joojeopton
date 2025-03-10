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

# print(f"SLACK_APP_TOKEN: {SLACK_APP_TOKEN}")
# print(f"SLACK_BOT_TOKEN: {SLACK_BOT_TOKEN}")
# print(f"SLACK_SIGNING_SECRET: {SLACK_SINGING_SECRET}")
# print(f"CHANNEL_ID: {CHANNEL_ID}")

client = WebClient(token=SLACK_BOT_TOKEN)


def send_slack_message(user_id, message):
    try:
        result = client.chat_postMessage(
            channel=user_id,
            text=message
        )
        logger.info(result)

    except SlackApiError as e:
        logger.error(f"Error posting message: {e}")
