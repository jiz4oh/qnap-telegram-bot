import logging
import os
import base64
import re
import requests
from xml.etree import ElementTree as ET
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from dotenv import load_dotenv

load_dotenv()
# 设置日志
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

QNAP_HOST = os.getenv("QNAP_HOST")
QNAP_PORT = os.getenv("QNAP_PORT", 5000)
QNAP_BASE_URL = f"{QNAP_HOST}:{QNAP_PORT}"
LOGIN_URL = f"{QNAP_BASE_URL}/cgi-bin/authLogin.cgi"
ADD_TASK_URL = f"{QNAP_BASE_URL}/downloadstation/V4/Task/AddUrl"

USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
encoded_bytes = base64.b64encode(PASSWORD.encode("utf-8"))
ENCODED_PASSWORD = encoded_bytes.decode("utf-8")

TEMP_DIR = os.getenv("TEMP_DIR", "Downloads")
MOVE_DIR = os.getenv("MOVE_DIR", "Downloads")

# 从环境变量中获取 API Token
TELEGRAM_BOT_TOKEN= os.getenv("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    raise ValueError("No TELEGRAM_BOT_TOKEN found in environment variables")

# 登录 QNAP 获取会话 ID (SID)
def login_qnap():
    payload = {"user": USERNAME, "pwd": ENCODED_PASSWORD}
    response = requests.post(LOGIN_URL, data=payload)
    if response.status_code == 200:
        # 解析失败时，尝试解析 XML 响应
        root = ET.fromstring(response.text)
        auth_sid = root.find("authSid")
        if auth_sid is not None:
            return auth_sid.text
        auth_passed = root.find("authPassed").text
        error_value = root.find("errorValue").text
        username = root.find("username").text
        logger.warn(
            f"XML response: authPassed: {auth_passed}, errorValue: {error_value}, username: {username}"
        )
    return None


# 添加下载任务
def add_download_task(download_url):
    sid = login_qnap()
    if not sid:
        logger.warn("Failed to login to QNAP NAS")
        return False
    headers = {}
    headers = {"Cookie": f"NAS_USER={USERNAME},NAS_SID={sid}"}
    payload = {
        "url": download_url,
        "temp": TEMP_DIR,
        "move": MOVE_DIR,
        "user": USERNAME,
        "pass": ENCODED_PASSWORD,
        "sid": sid,
    }
    response = requests.post(ADD_TASK_URL, headers=headers, data=payload)
    if response.status_code == 200:
        if response.json()["error"] == 0:
            logger.debug(f"Response: {response.status_code}, {response.text}")
            return True
    logger.warn(f"Response: {response.status_code}, {response.text}")
    return False


# 定义 start 命令的回调函数
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Hi!")


async def handle_qnap(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message_text = update.message.text
    urls = extract_urls(message_text)
    if urls:
        for url in urls:
            success = add_download_task(url)
            if success:
                await update.message.reply_text(
                    f"Download task added successfully: {url}"
                )
            else:
                await update.message.reply_text(f"Failed to add download task: {url}")
    else:
        await update.message.reply_text("No valid URL found.")


# 定义处理消息的回调函数
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await handle_qnap(update, context)


# 提取 URL 的函数
def extract_urls(text: str) -> list:
    url_pattern = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
    return url_pattern.findall(text)


def main() -> None:
    # 创建应用程序
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    # 添加命令处理程序
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("qnap", handle_qnap))

    # 添加消息处理程序
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
    )

    # 启动 Bot
    application.run_polling()


if __name__ == "__main__":
    main()
