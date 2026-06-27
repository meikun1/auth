"""
Telegram MTProto auth — голый скрипт ручной авторизации через Telethon.

Flow:
  1. Юзер вводит номер
  2. Выбираем рандомный SOCKS5 прокси из GERNETh.txt
  3. SendCodeRequest (+ reCAPTCHA solver если телега требует)
  4. Классификация ответа:
       - SetUpEmailRequired → email-флоу (адрес и код с почты — авто через
         Code API при заданном CODEAPI_TOKEN, иначе ручной ввод)
       - App / Call / прочее не-SMS → ResendCodeRequest для форса SMS (без email)
       - SMS → сразу к sign_in
       - EmailCode (чужая почта) → STOP
  5. Юзер вводит SMS-код → sign_in → готово
  6. verify_session_live() — 12 сек пингов на отзыв auth_key

Email-флоу автоматизирован через Code API (mailserver/), без бота. 2FA → фейл.
"""

import asyncio
import os
import random
import re
import sys
import time

import aiohttp
import socks
from telethon import TelegramClient, errors
from telethon.tl.functions import InvokeWithReCaptchaRequest
from telethon.tl.functions.account import (
    SendVerifyEmailCodeRequest,
    VerifyEmailRequest,
)
from telethon.tl.functions.auth import ResendCodeRequest, SendCodeRequest
from telethon.tl.functions.help import GetNearestDcRequest
from telethon.tl.functions.users import GetUsersRequest
from telethon.tl.types import (
    CodeSettings,
    EmailVerificationCode,
    EmailVerifyPurposeLoginSetup,
    InputUserSelf,
)


# ────────────────────────────────────────────────────────
#  .env loader — чтобы не вписывать CODEAPI_* при каждом запуске
# ────────────────────────────────────────────────────────
def _load_dotenv():
    """Подхватывает KEY=VALUE из файла .env рядом со скриптом в os.environ,
    НЕ перетирая уже заданные переменные (реальный env имеет приоритет).
    Формат: по строке KEY=VALUE, # — комментарий, кавычки опциональны."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


_load_dotenv()


# ────────────────────────────────────────────────────────
#  Конфиг
# ────────────────────────────────────────────────────────

API_ID = 21724
API_HASH = "3e0cb5efcd52300aec5994fdfc5bdc16"

NEXTCAPTCHA_KEY = "next_6dffe712892e5ab5799ce1e35625e45a58"
TWOCAPTCHA_KEY = "3318467b70ec8c1f2ff3629c0a92cf40"

CAPTCHA_MAX_RETRIES = 3
CAPTCHA_POLL_INTERVAL = 5
CAPTCHA_POLL_TIMEOUT = 180

# Сколько ждать перед ResendCodeRequest для форса SMS. Telegram отдаёт свой
# анти-флуд timeout (обычно 60s); ждём min(его, RESEND_WAIT_MAX). Слишком
# короткое ожидание → сервер может вернуть фейковый SentCodeTypeSms без реальной SMS.
# Крутится через env: RESEND_WAIT_MAX=30 python auth.py
try:
    RESEND_WAIT_MAX = int(os.environ.get("RESEND_WAIT_MAX", "15"))
except ValueError:
    RESEND_WAIT_MAX = 15

# Сколько раз пробовать авторизацию заново при PhoneHashExpiredError.
# Каждая попытка берёт НОВУЮ рандомную прокси + новый fingerprint + новый
# phone_code_hash — это лечит "плохой IP", из-за которого хэш протухает мгновенно.
# Крутится через env: AUTH_RETRY_MAX=5 python auth.py
try:
    AUTH_RETRY_MAX = int(os.environ.get("AUTH_RETRY_MAX", "3"))
except ValueError:
    AUTH_RETRY_MAX = 3

# Проверка живости сессии после sign_in.
# Делаем N пингов GetUsers(self) с интервалом, ловим AuthKeyUnregisteredError —
# если Telegram сразу отозвал ключ (юзер кикнул с телефона / антифрод сервера) — поймаем.
LIVE_CHECK_PINGS = 6
LIVE_CHECK_INTERVAL = 2  # секунд между пингами → суммарно ~12 сек наблюдения

SESSIONS_DIR = "sessions"
PROXIES_FILE = "GERNETh.txt"  # формат строк: login:pass@host:port (SOCKS5)

# ────────────────────────────────────────────────────────
#  Code API — catch-all почтовый сервер (mailserver/, veximail.space)
# ────────────────────────────────────────────────────────
# Если CODEAPI_TOKEN задан (env или константой ниже) — email-флоу полностью
# автоматический: адрес берётся через /address/new, код с почты вычитывается
# через /codes/latest?to=<addr>. Если токен пуст — фолбэк на ручной ввод
# (старое поведение). Токен лежит на сервере в /etc/codeapi/env.
CODEAPI_BASE = os.environ.get("CODEAPI_BASE", "https://mail.veximail.space:8443")
CODEAPI_TOKEN = os.environ.get("CODEAPI_TOKEN", "")
CODEAPI_POLL_INTERVAL = 3    # секунд между опросами /codes/latest
CODEAPI_POLL_TIMEOUT = 120   # сколько всего ждём письмо с кодом

DEVICES = [
    ("Samsung Galaxy S23", "Android 13"),
    ("Samsung Galaxy S22", "Android 12"),
    ("Samsung Galaxy A54", "Android 13"),
    ("Xiaomi 13 Pro", "Android 13"),
    ("Xiaomi Redmi Note 12", "Android 12"),
    ("Xiaomi Poco X5", "Android 12"),
    ("Huawei P50", "Android 11"),
    ("OnePlus 11", "Android 13"),
    ("Google Pixel 7", "Android 13"),
    ("Google Pixel 6a", "Android 12"),
    ("Realme GT 2", "Android 12"),
    ("Oppo Reno 8", "Android 12"),
]
APP_VERSIONS = ["10.14.5", "10.12.0", "10.9.3", "10.6.2", "10.3.2", "9.6.7"]

TELEGRAM_URLS = [
    "https://web.telegram.org",
    "https://oauth.telegram.org",
    "https://my.telegram.org",
    "https://telegram.org",
    "https://core.telegram.org",
]


# ────────────────────────────────────────────────────────
#  Прокси: загрузка из файла + рандомный выбор
# ────────────────────────────────────────────────────────

def load_proxies(filepath: str = PROXIES_FILE) -> list:
    """
    Читает файл с прокси формата `login:pass@host:port`.
    Возвращает список tuples для Telethon: (socks.SOCKS5, host, port, True, login, pass).
    """
    if not os.path.isabs(filepath):
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), filepath)
    if not os.path.exists(filepath):
        print(f"[proxy] файл {filepath} не найден — работаем без прокси")
        return []

    result = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if "@" in line:
                    creds, hostport = line.rsplit("@", 1)
                    username, password = creds.split(":", 1)
                    host, port = hostport.rsplit(":", 1)
                    result.append((socks.SOCKS5, host, int(port), True, username, password))
                else:
                    # без авторизации: host:port
                    host, port = line.rsplit(":", 1)
                    result.append((socks.SOCKS5, host, int(port)))
            except Exception:
                continue
    return result


def pick_random_proxy(proxies: list):
    """Рандомно дергаем одну прокси из списка."""
    if not proxies:
        return None
    return random.choice(proxies)


def _proxy_label(proxy) -> str:
    """Безопасная строка для логов (без пароля)."""
    if not proxy:
        return "DIRECT (без прокси)"
    return f"{proxy[1]}:{proxy[2]} (SOCKS5)"


# ────────────────────────────────────────────────────────
#  reCAPTCHA solver (NextCaptcha → 2captcha)
# ────────────────────────────────────────────────────────

async def _nextcaptcha_solve(api_key: str, site_key: str, action: str):
    """NextCaptcha mobile task — appPackageName = Telegram X."""
    url_create = "https://api.nextcaptcha.com/createTask"
    url_result = "https://api.nextcaptcha.com/getTaskResult"

    task = {
        "type": "RecaptchaMobileTaskProxyLess",
        "appPackageName": "org.thunderdog.challegram",
        "appKey": site_key,
        "appAction": action,
    }

    async with aiohttp.ClientSession() as session:
        print(f"[nextcaptcha] mobile task (action={action})")
        try:
            async with session.post(url_create, json={"clientKey": api_key, "task": task}) as resp:
                data = await resp.json(content_type=None)
        except Exception as e:
            print(f"[nextcaptcha] request error: {e}")
            return None

        if data.get("errorId", 0) != 0:
            print(f"[nextcaptcha] error: {data.get('errorCode')} — {data.get('errorDescription')}")
            return None

        task_id = data.get("taskId")
        if not task_id:
            print(f"[nextcaptcha] no taskId: {data}")
            return None

        print(f"[nextcaptcha] task: {task_id}")

        elapsed = 0
        while elapsed < CAPTCHA_POLL_TIMEOUT:
            await asyncio.sleep(CAPTCHA_POLL_INTERVAL)
            elapsed += CAPTCHA_POLL_INTERVAL

            try:
                async with session.post(url_result, json={"clientKey": api_key, "taskId": task_id}) as resp:
                    result = await resp.json(content_type=None)
            except Exception as e:
                print(f"[nextcaptcha] poll error: {e}")
                return None

            if result.get("errorId", 0) != 0:
                print(f"[nextcaptcha] error: {result.get('errorCode')}")
                return None

            if result.get("status") == "ready":
                token = result.get("solution", {}).get("gRecaptchaResponse")
                if token:
                    print(f"[nextcaptcha] solved in {elapsed}s")
                    return token
                return None

            if elapsed % 15 == 0:
                print(f"[nextcaptcha] solving... ({elapsed}s)")

        print(f"[nextcaptcha] timeout {CAPTCHA_POLL_TIMEOUT}s")
        return None


async def _twocaptcha_solve(api_key: str, site_key: str, action: str):
    """2captcha enterprise v2 — перебор Telegram URL'ов."""
    api_url = "https://api.2captcha.com"

    async with aiohttp.ClientSession() as session:
        for pageurl in TELEGRAM_URLS:
            task = {
                "type": "RecaptchaV2EnterpriseTaskProxyless",
                "websiteURL": pageurl,
                "websiteKey": site_key,
                "enterprisePayload": {"action": action},
            }
            print(f"[2captcha] trying: {pageurl}")

            try:
                async with session.post(f"{api_url}/createTask", json={"clientKey": api_key, "task": task}) as resp:
                    data = await resp.json(content_type=None)
            except Exception as e:
                print(f"[2captcha] error: {e}")
                continue

            if data.get("errorId", 0) != 0:
                print(f"[2captcha] {data.get('errorCode')}: {data.get('errorDescription')}")
                continue

            task_id = data.get("taskId")
            if not task_id:
                continue

            print(f"[2captcha] task: {task_id}")

            elapsed = 0
            while elapsed < CAPTCHA_POLL_TIMEOUT:
                await asyncio.sleep(CAPTCHA_POLL_INTERVAL)
                elapsed += CAPTCHA_POLL_INTERVAL

                try:
                    async with session.post(f"{api_url}/getTaskResult", json={"clientKey": api_key, "taskId": task_id}) as resp:
                        result = await resp.json(content_type=None)
                except Exception as e:
                    print(f"[2captcha] poll error: {e}")
                    break

                if result.get("errorId", 0) != 0:
                    print(f"[2captcha] {result.get('errorCode')}")
                    break

                if result.get("status") == "ready":
                    token = result.get("solution", {}).get("gRecaptchaResponse")
                    if token:
                        print(f"[2captcha] solved via {pageurl} in {elapsed}s")
                        return token
                    break

                if elapsed % 15 == 0:
                    print(f"[2captcha] solving... ({elapsed}s)")

            print(f"[2captcha] failed for {pageurl}, next URL...")

    print("[2captcha] all URLs exhausted")
    return None


async def solve_recaptcha(site_key: str, action: str):
    """Сначала NextCaptcha, если фейл — 2captcha."""
    print("\n[captcha] NextCaptcha…")
    token = await _nextcaptcha_solve(NEXTCAPTCHA_KEY, site_key, action)
    if token:
        return token

    print("[captcha] NextCaptcha failed → fallback 2captcha…")
    token = await _twocaptcha_solve(TWOCAPTCHA_KEY, site_key, action)
    return token


# ────────────────────────────────────────────────────────
#  Telethon helpers
# ────────────────────────────────────────────────────────

def _build_settings():
    return CodeSettings(
        allow_flashcall=False,
        current_number=False,
        allow_app_hash=False,
        allow_missed_call=False,
        allow_firebase=False,
        unknown_number=True,
    )


def _build_send_code(phone: str):
    return SendCodeRequest(
        phone_number=phone,
        api_id=API_ID,
        api_hash=API_HASH,
        settings=_build_settings(),
    )


def _parse_recaptcha_error(error_msg: str):
    """Из 'RECAPTCHA_CHECK_{action}__{sitekey}' вытаскиваем action и sitekey."""
    m = re.search(r"RECAPTCHA_CHECK_(\w+?)__(\S+)", str(error_msg))
    if m:
        return m.group(1), m.group(2)
    return None, None


def _is_sms(sent_code) -> bool:
    return "Sms" in type(sent_code.type).__name__


async def _wait_antiflood(sent_code) -> None:
    """
    Ждём перед ResendCodeRequest. Telegram блокирует Resend анти-флудом на
    `sent_code.timeout` секунд (обычно 60). Если дёрнуть Resend раньше — сервер
    вернёт фейковый SentCodeTypeSms, но реально SMS не отправит. Ждём
    min(timeout, RESEND_WAIT_MAX), чтобы получить настоящий SMS.
    """
    timeout = getattr(sent_code, "timeout", 0) or 60
    wait = min(timeout, RESEND_WAIT_MAX)
    print(f"[auth] timeout до Resend: {timeout}s (ждём {wait}s)")
    print(f"[auth] ждём {wait}s чтобы Telegram реально отправил SMS (анти-флуд)…")
    await asyncio.sleep(wait)


def _is_email_code(sent_code) -> bool:
    return "EmailCode" in type(sent_code.type).__name__


def _is_setup_email_required(sent_code) -> bool:
    """Telegram сам требует привязать login-email. ТОЛЬКО на этом типе валиден
    EmailVerifyPurposeLoginSetup. На App/Call он вернёт PhoneHashExpired."""
    return "SetUpEmailRequired" in type(sent_code.type).__name__


async def force_sms_via_resend(client, phone: str, phone_code_hash: str, sent_code):
    """
    Для App/Call ответа: ждём анти-флуд и форсим SMS через ResendCodeRequest.
    Email-привязку тут звать нельзя (тип ответа её не поддерживает). Возвращает
    phone_code_hash для последующего sign_in.
    """
    if _is_sms(sent_code):
        return phone_code_hash
    await _wait_antiflood(sent_code)
    print("[auth] форсим SMS через ResendCodeRequest…")
    resent = await client(ResendCodeRequest(
        phone_number=phone,
        phone_code_hash=phone_code_hash,
    ))
    print(f"[auth] resend ответ: {_describe(resent)}")
    if not _is_sms(resent):
        print(f"[auth] WARN: после resend всё ещё не SMS ({type(resent.type).__name__})")
    return resent.phone_code_hash


def _describe(sent_code) -> str:
    t = sent_code.type
    name = type(t).__name__
    length = getattr(t, "length", "?")
    return f"{name} ({length} digits)"


async def verify_session_live(client) -> bool:
    """
    Проверяет что auth_key реально работает на сервере Telegram.
    Шлёт LIVE_CHECK_PINGS запросов GetUsers(self) с интервалом LIVE_CHECK_INTERVAL.
    Ловит AuthKeyUnregisteredError — это значит ключ отозван (юзер кикнул / антифрод).
    Возвращает True если все пинги прошли, False если хоть один словил отзыв.
    """
    print(f"\n[live] проверяем живость сессии: {LIVE_CHECK_PINGS} пингов × {LIVE_CHECK_INTERVAL}s")
    for i in range(1, LIVE_CHECK_PINGS + 1):
        try:
            result = await client(GetUsersRequest(id=[InputUserSelf()]))
            if not result or not result[0]:
                print(f"[live] ping {i}/{LIVE_CHECK_PINGS}: пустой ответ")
                return False
            print(f"[live] ping {i}/{LIVE_CHECK_PINGS}: ok (id={result[0].id})")
        except errors.AuthKeyUnregisteredError:
            print(f"[live] ping {i}/{LIVE_CHECK_PINGS}: ✗ AUTH_KEY_UNREGISTERED — сессию отозвали")
            return False
        except errors.UserDeactivatedError:
            print(f"[live] ping {i}/{LIVE_CHECK_PINGS}: ✗ USER_DEACTIVATED — акк забанен")
            return False
        except errors.RPCError as e:
            print(f"[live] ping {i}/{LIVE_CHECK_PINGS}: RPC error {type(e).__name__}: {e}")
            return False

        if i < LIVE_CHECK_PINGS:
            await asyncio.sleep(LIVE_CHECK_INTERVAL)

    print(f"[live] ✓ сессия выдержала {LIVE_CHECK_PINGS * LIVE_CHECK_INTERVAL}s — живая")
    return True


async def _cleanup(client):
    """Дисконнект + удаление файлов сессии (для откатов при ошибке)."""
    if not client:
        return
    session_file = None
    try:
        session_file = client.session.filename
    except Exception:
        pass
    try:
        await client.disconnect()
    except Exception:
        pass
    if not session_file:
        return
    for ext in ("", "-journal", "-wal", "-shm"):
        path = session_file + ext
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass


# ────────────────────────────────────────────────────────
#  SendCode с авто-решением капчи
# ────────────────────────────────────────────────────────

async def send_code_with_captcha(client, phone: str):
    last_action = None
    last_site_key = None

    for attempt in range(1, CAPTCHA_MAX_RETRIES + 1):
        try:
            if last_action and last_site_key:
                print(f"\n[auth] RECAPTCHA (попытка {attempt}/{CAPTCHA_MAX_RETRIES})")
                print(f"[auth] action={last_action}, sitekey={last_site_key[:20]}...")

                token = await solve_recaptcha(last_site_key, last_action)
                if not token:
                    print("[auth] капча не решена, повторяем…")
                    continue

                print("[auth] капча решена, шлём запрос с токеном…")
                return await client(InvokeWithReCaptchaRequest(
                    token=token,
                    query=_build_send_code(phone),
                ))

            print("[auth] SendCodeRequest…")
            return await client(_build_send_code(phone))

        except errors.FloodWaitError as e:
            wait = min(e.seconds + 5, 300)
            print(f"[auth] FloodWait {e.seconds}s, ждём {wait}s…")
            await asyncio.sleep(wait)
            continue

        except errors.RPCError as e:
            action, site_key = _parse_recaptcha_error(str(e))
            if not action or not site_key:
                print(f"[auth] RPC error (не капча): {e}")
                return None
            last_action = action
            last_site_key = site_key

    print(f"[auth] провал после {CAPTCHA_MAX_RETRIES} попыток")
    return None


# ────────────────────────────────────────────────────────
#  Code API клиент (генерация адреса + чтение кода с почты)
# ────────────────────────────────────────────────────────

def _codeapi_enabled() -> bool:
    return bool(CODEAPI_TOKEN)


def _codeapi_headers() -> dict:
    return {"Authorization": f"Bearer {CODEAPI_TOKEN}"}


async def codeapi_new_address() -> str:
    """Запрашивает случайный адрес *@veximail.space через /address/new."""
    url = f"{CODEAPI_BASE}/address/new"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=_codeapi_headers()) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)
    return data["address"]


async def codeapi_wait_code(address: str) -> str:
    """
    Поллит /codes/latest?to=<address> пока не появится код или не истечёт
    CODEAPI_POLL_TIMEOUT. Адрес одноразовый и случайный, поэтому любой код
    для него — заведомо свежий (нет риска поймать старый код).
    """
    url = f"{CODEAPI_BASE}/codes/latest"
    params = {"to": address}
    elapsed = 0
    async with aiohttp.ClientSession() as session:
        while elapsed < CODEAPI_POLL_TIMEOUT:
            await asyncio.sleep(CODEAPI_POLL_INTERVAL)
            elapsed += CODEAPI_POLL_INTERVAL
            try:
                async with session.get(url, params=params, headers=_codeapi_headers()) as resp:
                    if resp.status == 404:
                        if elapsed % 15 == 0:
                            print(f"[codeapi] ждём код… ({elapsed}s)")
                        continue
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)
            except Exception as e:
                print(f"[codeapi] poll error: {e}")
                continue
            code = data.get("code")
            if code:
                print(f"[codeapi] код получен за {elapsed}s "
                      f"(service={data.get('service')}, from={data.get('from')})")
                return code
    print(f"[codeapi] таймаут {CODEAPI_POLL_TIMEOUT}s — код не пришёл")
    return ""


# ────────────────────────────────────────────────────────
#  Привязка email
# ────────────────────────────────────────────────────────

async def bind_email_and_force_sms(client, phone: str, phone_code_hash: str,
                                   preset_email: str = ""):
    """
    Привязка email + код с почты → верификация → форсим SMS.
    Если Code API сконфигурирован — адрес и код берутся автоматически,
    иначе используем заранее введённый preset_email (фолбэк на input()).
    Возвращает phone_code_hash после форса SMS.

    ВАЖНО: между SendCodeRequest и SendVerifyEmailCodeRequest НЕЛЬЗЯ блокировать
    event-loop ручным input() — phone_code_hash живёт недолго и блокирующий ввод
    замораживает соединение Telethon, из-за чего хэш протухает (PhoneHashExpired).
    Поэтому email должен быть готов ДО входа сюда (см. authorize()).
    """
    print("\n[auth] === ПРИВЯЗКА EMAIL ===")

    auto = _codeapi_enabled()
    if auto:
        try:
            email = await codeapi_new_address()
            print(f"[auth] адрес от Code API: {email}")
        except Exception as e:
            print(f"[auth] Code API недоступен ({e}) → ручной ввод")
            auto = False
            email = preset_email or input("Email: ").strip()
    else:
        email = preset_email or input("Email: ").strip()
    print(f"[auth] email для привязки: {email}")

    purpose = EmailVerifyPurposeLoginSetup(
        phone_number=phone,
        phone_code_hash=phone_code_hash,
    )

    print(f"[auth] отправляем код верификации на {email}…")
    sent_email = await client(SendVerifyEmailCodeRequest(
        purpose=purpose,
        email=email,
    ))
    print(f"[auth] код отправлен (длина {sent_email.length})")

    email_code = ""
    if auto:
        print(f"[auth] ждём код на {email} через Code API…")
        email_code = await codeapi_wait_code(email)
        if not email_code:
            print("[auth] Code API код не дал → ручной ввод")
    if not email_code:
        email_code = input("Код с почты: ").strip()

    print("[auth] верифицируем email…")
    result = await client(VerifyEmailRequest(
        purpose=purpose,
        verification=EmailVerificationCode(code=email_code),
    ))
    print(f"[auth] email подтверждён ({type(result).__name__})")

    if hasattr(result, "sent_code") and result.sent_code:
        new_hash = result.sent_code.phone_code_hash
        print(f"[auth] после email: {_describe(result.sent_code)}")

        if _is_sms(result.sent_code):
            print("[auth] SMS уже отправлена")
            return new_hash

        await _wait_antiflood(result.sent_code)
        print("[auth] не SMS — форсим ResendCodeRequest…")
        resent = await client(ResendCodeRequest(
            phone_number=phone,
            phone_code_hash=new_hash,
        ))
        print(f"[auth] resend: {_describe(resent)}")
        if not _is_sms(resent):
            print(f"[auth] WARN: после resend всё ещё не SMS ({type(resent.type).__name__})")
        return resent.phone_code_hash

    # В ответе нет sent_code — реквестим вручную
    print("[auth] нет sent_code в ответе, шлём SendCode заново…")
    sent_code2 = await client(_build_send_code(phone))
    new_hash = sent_code2.phone_code_hash
    print(f"[auth] ответ: {_describe(sent_code2)}")

    if not _is_sms(sent_code2):
        await _wait_antiflood(sent_code2)
        print("[auth] не SMS — форсим Resend…")
        resent = await client(ResendCodeRequest(
            phone_number=phone,
            phone_code_hash=new_hash,
        ))
        new_hash = resent.phone_code_hash
        print(f"[auth] resend: {_describe(resent)}")

    return new_hash


# ────────────────────────────────────────────────────────
#  Главный flow
# ────────────────────────────────────────────────────────

async def _run_attempt(phone: str, raw_phone: str, proxies: list,
                       preset_email: str = "") -> str:
    """
    Одна попытка авторизации с собственной прокси и fingerprint.
    Возвращает:
      "done"  — закончили (успех или терминальный стоп), ретраить НЕ надо
      "retry" — PhoneHashExpired (плохой IP) → имеет смысл новая прокси
    """
    model, sys_ver = random.choice(DEVICES)
    app_ver = random.choice(APP_VERSIONS)
    print(f"[auth] fingerprint: {model} / {sys_ver} / TG {app_ver}")

    proxy = pick_random_proxy(proxies)
    if proxies:
        print(f"[auth] прокси: {_proxy_label(proxy)} (из {len(proxies)} в пуле)")
    else:
        print(f"[auth] прокси: DIRECT — файл {PROXIES_FILE} пуст или отсутствует")

    os.makedirs(SESSIONS_DIR, exist_ok=True)
    session_path = os.path.join(SESSIONS_DIR, f"{raw_phone}_{int(time.time())}")

    client = TelegramClient(
        session_path,
        API_ID,
        API_HASH,
        device_model=model,
        system_version=sys_ver,
        app_version=app_ver,
        lang_code="uz",
        system_lang_code="uz",
        proxy=proxy,
    )

    try:
        await client.connect()

        if await client.is_user_authorized():
            me = await client.get_me()
            print(f"[auth] уже авторизован: {me.first_name} ({me.phone})")
            await client.disconnect()
            return "done"

        # 0. Прогрев соединения + диагностика: какую страну Telegram видит по нашему IP.
        # GetNearestDc — безобидный неавторизованный запрос, устанавливает связь до
        # чувствительного SendCode и возвращает country по IP. Если country != UZ —
        # это и есть "плохой IP", из-за которого email-привязка валит PhoneHashExpired.
        try:
            nd = await client(GetNearestDcRequest())
            flag = "✓" if nd.country.upper() == "UZ" else "✗ НЕ UZ — вероятная причина PhoneHashExpired"
            print(f"[auth] Telegram видит IP как: country={nd.country} "
                  f"(this_dc={nd.this_dc}, nearest_dc={nd.nearest_dc}) {flag}")
        except Exception as e:
            print(f"[auth] прогрев GetNearestDc не прошёл: {type(e).__name__}: {e}")

        # 1. SendCode (с капчей если нужно)
        sent_code = await send_code_with_captcha(client, phone)
        if not sent_code:
            print("[auth] SendCode провалился")
            await _cleanup(client)
            return "done"

        phone_code_hash = sent_code.phone_code_hash
        print(f"[auth] первый ответ: {_describe(sent_code)}")

        # 2. Классификация ответа
        if _is_email_code(sent_code):
            # Чужая почта реально привязана — туда у нас доступа нет, STOP
            email_pattern = getattr(sent_code.type, "email_pattern", "?")
            print(f"[auth] STOP — чужая почта привязана ({email_pattern})")
            await _cleanup(client)
            return "done"
        elif _is_sms(sent_code):
            print("[auth] SMS уже отправлена сразу, переходим к вводу кода")
        elif _is_setup_email_required(sent_code):
            # Telegram сам требует привязать login-email → email-флоу валиден.
            print("[auth] SetUpEmailRequired → email-флоу (привязка почты)")
            phone_code_hash = await bind_email_and_force_sms(
                client, phone, phone_code_hash, preset_email=preset_email)
        else:
            # App / Call / прочее: EmailVerifyPurposeLoginSetup НЕ поддерживается
            # этим типом (SendVerifyEmailCode вернёт PhoneHashExpired). Форсим SMS
            # через Resend — единственный рабочий путь для App-ответа.
            type_name = type(sent_code.type).__name__
            print(f"[auth] первый ответ '{type_name}' → форсим SMS через Resend")
            phone_code_hash = await force_sms_via_resend(
                client, phone, phone_code_hash, sent_code)

        # 3. Юзер вводит SMS-код, sign_in
        sms_code = input("SMS код: ").strip()

        try:
            await client.sign_in(
                phone=phone,
                code=sms_code,
                phone_code_hash=phone_code_hash,
            )
        except errors.SessionPasswordNeededError:
            print("[auth] STOP — на акке 2FA, обработка не реализована")
            await _cleanup(client)
            return "done"
        except errors.PhoneCodeInvalidError:
            print("[auth] неверный SMS код")
            await _cleanup(client)
            return "done"
        except errors.PhoneCodeExpiredError:
            print("[auth] SMS код протух")
            await _cleanup(client)
            return "done"

        me = await client.get_me()
        print(f"\n[auth] ✓ sign_in успешен: {me.first_name} (@{me.username or '-'}) | {me.phone}")

        # Проверяем что Telegram сервер реально принимает наш auth_key и не отозвал его
        alive = await verify_session_live(client)

        if alive:
            print(f"\n[auth] ✓✓ СЕССИЯ ВАЛИДНАЯ: {session_path}.session")
        else:
            print(f"\n[auth] ✗ СЕССИЯ МЁРТВАЯ — auth_key отозван (вероятно тапнули 'Завершить' в Telegram)")
            print(f"[auth] удаляю битый файл сессии…")
            await _cleanup(client)
            return "done"

        await client.disconnect()
        return "done"

    except errors.PhoneHashExpiredError as e:
        # Плохой IP/прокси: Telegram инвалидирует phone_code_hash почти сразу.
        # Сигналим наверх, чтобы попробовать заново с другой прокси.
        print(f"[auth] PhoneHashExpired на прокси {_proxy_label(proxy)}: {e}")
        await _cleanup(client)
        return "retry"
    except Exception as e:
        print(f"[auth] непредвиденная ошибка: {type(e).__name__}: {e}")
        await _cleanup(client)
        return "done"


async def authorize():
    raw_phone = input("Номер (с + или без): ").strip().lstrip("+")
    if not raw_phone or not raw_phone.isdigit():
        print("[auth] невалидный номер")
        return
    phone = f"+{raw_phone}"

    proxies = load_proxies()

    # Email собираем ЗАРАНЕЕ (до SendCodeRequest), чтобы внутри email-флоу не было
    # блокирующего input() между SendCode и SendVerifyEmailCode — иначе хэш протухает
    # (PhoneHashExpired). При включённом Code API адрес берётся автоматически.
    preset_email = ""
    if not _codeapi_enabled():
        preset_email = input("Email для привязки (Enter — спросить позже): ").strip()

    for attempt in range(1, AUTH_RETRY_MAX + 1):
        print(f"\n[auth] ═══ ПОПЫТКА {attempt}/{AUTH_RETRY_MAX} ═══")
        status = await _run_attempt(phone, raw_phone, proxies, preset_email)
        if status != "retry":
            return
        if attempt < AUTH_RETRY_MAX:
            print("[auth] PhoneHashExpired → берём новую прокси и пробуем заново…\n")

    print(f"\n[auth] ✗ исчерпаны {AUTH_RETRY_MAX} попытки — PhoneHashExpired на каждой.")
    print("[auth] вероятно прокси не подходят региону номера (поменяй пул в "
          f"{PROXIES_FILE} на прокси ближе к стране номера).")
    sys.exit(1)


if __name__ == "__main__":
    asyncio.run(authorize())
