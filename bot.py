import os
import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart, Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo, FSInputFile
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramConflictError

# ═══════════════════════════════════════════════
# НАСТРОЙКИ
# ═══════════════════════════════════════════════
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8692931256:AAEIIC1zo-iqGgTwDNb0D4uTGKt9CqyYdes")
WEBAPP_URL = os.environ.get("WEBAPP_URL", "https://nebula-app-5.onrender.com")
IMAGE_PATH = "static/welcome.jpg"

WELCOME_TEXT = """Вас приветствует <b>ORION parcer</b> 🚗

Это приложение создано для вас, и для повышения комфорта вашей работы 💻

Приложение абсолютно бесплатное для пользователей которые состоят в команде <b>ORION 7+ дней</b> ⏱

Для остальных есть прайсы на использование 📥
➖ доступ на 24 часа — <b>5$</b>
➖ доступ на 48 часов — <b>9$</b>
➖ доступ на три дня — <b>25$</b>
➖ доступ на две недели — <b>100$</b>
➖ доступ на месяц — <b>300$</b>

Для покупки а также более детальной информации пишите — @dmitryn1

Чтобы вступить в команду ORION пишите этому человеку — @pexaab"""

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()


def get_kb() -> InlineKeyboardMarkup:
    """Главная клавиатура с кнопками"""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚀 Перейти на наш сайт", web_app=WebAppInfo(url=WEBAPP_URL))],
        [
            InlineKeyboardButton(text="💎 Купить доступ", url="https://t.me/dmitryn1"),
            InlineKeyboardButton(text="👥 Вступить в ORION", url="https://t.me/pexaab"),
        ],
    ])


@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    """Приветственное сообщение"""
    try:
        if os.path.exists(IMAGE_PATH):
            photo = FSInputFile(IMAGE_PATH)
            await message.answer_photo(
                photo=photo,
                caption=WELCOME_TEXT,
                reply_markup=get_kb()
            )
        else:
            logger.warning(f"Image not found: {IMAGE_PATH}")
            await message.answer(text=WELCOME_TEXT, reply_markup=get_kb())
        logger.info(f"✅ /start from {message.from_user.id} (@{message.from_user.username})")
    except Exception as e:
        logger.error(f"❌ Error in /start: {e}")
        try:
            await message.answer(text=WELCOME_TEXT, reply_markup=get_kb())
        except Exception as e2:
            logger.error(f"❌ Fallback also failed: {e2}")


@dp.message(Command("app"))
async def cmd_app(message: types.Message):
    """Быстрая ссылка на приложение"""
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🚀 Открыть ORION parcer", web_app=WebAppInfo(url=WEBAPP_URL))
    ]])
    await message.answer("Нажмите кнопку чтобы открыть приложение 👇", reply_markup=kb)


@dp.message(Command("help"))
async def cmd_help(message: types.Message):
    """Помощь"""
    text = (
        "📋 <b>Доступные команды:</b>\n\n"
        "/start — главное меню\n"
        "/app — открыть приложение\n"
        "/help — эта справка\n\n"
        "💎 Купить доступ: @dmitryn1\n"
        "👥 Вступить в ORION: @pexaab"
    )
    await message.answer(text, reply_markup=get_kb())


async def run_bot():
    """Запуск бота с автоповтором при конфликтах"""
    logger.info("🤖 ORION bot starting...")
    logger.info(f"📱 WebApp URL: {WEBAPP_URL}")
    logger.info(f"🖼️ Image path: {IMAGE_PATH} (exists: {os.path.exists(IMAGE_PATH)})")

    # Удаляем webhook и pending updates
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        logger.info("✅ Webhook deleted, pending updates dropped")
    except Exception as e:
        logger.warning(f"⚠️ Delete webhook failed: {e}")

    # Устанавливаем команды
    try:
        await bot.set_my_commands([
            types.
BotCommand(command="start", description="🚀 Главное меню"),
            types.BotCommand(command="app", description="📱 Открыть приложение"),
            types.BotCommand(command="help", description="❓ Помощь"),
        ])
        logger.info("✅ Bot commands set")
    except Exception as e:
        logger.warning(f"⚠️ Set commands failed: {e}")

    # Запуск polling с обработкой конфликтов
    retry_count = 0
    max_retries = 10

    while retry_count < max_retries:
        try:
            logger.info(f"▶️ Starting polling (attempt {retry_count + 1}/{max_retries})...")
            await dp.start_polling(
                bot,
                allowed_updates=dp.resolve_used_update_types(),
                handle_signals=False,
            )
            break  # успешно завершилось
        except TelegramConflictError as e:
            retry_count += 1
            wait = min(30, 5 * retry_count)
            logger.error(f"❌ Conflict detected (attempt {retry_count}): {e}")
            logger.info(f"⏳ Waiting {wait} sec before retry...")
            await asyncio.sleep(wait)
            # Пытаемся ещё раз сбросить webhook
            try:
                await bot.delete_webhook(drop_pending_updates=True)
            except Exception:
                pass
        except Exception as e:
            logger.error(f"❌ Polling error: {type(e).__name__}: {e}")
            await asyncio.sleep(5)
            retry_count += 1

    if retry_count >= max_retries:
        logger.critical("💥 Max retries reached, bot stopped")


if __name__ == "__main__":
    asyncio.run(run_bot())
