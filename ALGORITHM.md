# Telegram MTProto авторизация — полный алгоритм

> Только процесс авторизации номера до готовой Telethon-сессии. Email вводится юзером вручную.

---

## Схема

```
Ввод номера → SendCodeRequest → [RECAPTCHA?] → solver → ответ Telegram
                                                              │
                    ┌─────────────────────────────────────────┤
                    │                                         │
             SetUpEmailRequired                    EmailCode / другое
             (email не привязан)                      → STOP
                    │
    Юзер вводит email + код ────► SendVerifyEmailCodeRequest
                                  VerifyEmailRequest
                                        │
                                  SMS на телефон
                                        │
                              Юзер вводит SMS-код
                                        │
                                  sign_in(code)
                                        │
                                 ┌──────┴──────┐
                                 │             │
                              SUCCESS    2FA / ошибка
                           (session ready)
```

---

## Этап 1 — Создание клиента

Telethon-клиент с рандомным fingerprint мобильного устройства.

```python
from telethon import TelegramClient

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

model, sys_ver = random.choice(DEVICES)
app_ver = random.choice(APP_VERSIONS)

client = TelegramClient(
    session_path,       # "sessions/{phone}_{timestamp}"
    api_id,
    api_hash,
    device_model=model,
    system_version=sys_ver,
    app_version=app_ver,
    lang_code="uz",
    system_lang_code="uz",
    proxy=proxy,        # SOCKS5 tuple или None
)
await client.connect()
```

**Что важно:**
- `lang_code` / `system_lang_code` = `"uz"` (узбекский)
- session path уникальный на каждую попытку (с timestamp), чтобы не конфликтовать со старыми
- proxy — tuple формата `(socks.SOCKS5, host, port, True, login, password)`

---

## Этап 2 — SendCodeRequest

Запрос на отправку кода авторизации.

```python
from telethon.tl.functions.auth import SendCodeRequest
from telethon.tl.types import CodeSettings

settings = CodeSettings(
    allow_flashcall=False,
    current_number=False,
    allow_app_hash=False,
    allow_missed_call=False,
    allow_firebase=False,
    unknown_number=True,   # обязательно True
)

request = SendCodeRequest(
    phone_number=f"+{phone}",
    api_id=api_id,
    api_hash=api_hash,
    settings=settings,
)

sent_code = await client(request)
```

### Три сценария ответа:

**A) Успех** — `sent_code` возвращён, переходим к этапу 3

**B) RECAPTCHA** — Telegram бросает RPCError вида:
```
RECAPTCHA_CHECK_{action}__{sitekey}
```
Парсим action и sitekey:
```python
import re

def parse_recaptcha_error(error_msg: str):
    match = re.search(r"RECAPTCHA_CHECK_(\w+?)__(\S+)", str(error_msg))
    if match:
        return match.group(1), match.group(2)
    return None, None
```
→ решаем капчу (этап 2.1), повторяем запрос с токеном

**C) FloodWait** — ждём `min(seconds + 5, 300)` и повторяем

---

## Этап 2.1 — Решение reCAPTCHA

Два солвера с приоритетом: NextCaptcha → 2captcha.

### NextCaptcha (primary) — mobile task

```python
# POST https://api.nextcaptcha.com/createTask
task = {
    "type": "RecaptchaMobileTaskProxyLess",
    "appPackageName": "org.thunderdog.challegram",  # Telegram X
    "appKey": site_key,     # из ошибки Telegram
    "appAction": action,    # из ошибки Telegram
}
payload = {"clientKey": nextcaptcha_api_key, "task": task}

# Поллинг POST https://api.nextcaptcha.com/getTaskResult
# каждые 5 сек, таймаут 180 сек
# Результат: result["solution"]["gRecaptchaResponse"]
```

### 2captcha (fallback) — URL перебор

Перебирает URL'ы Telegram (неизвестно к какому привязана капча):
```python
TELEGRAM_URLS = [
    "https://web.telegram.org",
    "https://oauth.telegram.org",
    "https://my.telegram.org",
    "https://telegram.org",
    "https://core.telegram.org",
]

# Для каждого URL:
# POST https://api.2captcha.com/createTask
task = {
    "type": "RecaptchaV2EnterpriseTaskProxyless",
    "websiteURL": pageurl,
    "websiteKey": site_key,
    "enterprisePayload": {"action": action},
}
payload = {"clientKey": twocaptcha_api_key, "task": task}

# Поллинг POST https://api.2captcha.com/getTaskResult
# каждые 5 сек, таймаут 180 сек
# Если URL не дал результат → следующий URL
```

### Отправка с токеном

После получения `gRecaptchaResponse` — повторяем SendCodeRequest через обёртку:

```python
from telethon.tl.functions import InvokeWithReCaptchaRequest

sent_code = await client(InvokeWithReCaptchaRequest(
    token=captcha_token,
    query=SendCodeRequest(
        phone_number=f"+{phone}",
        api_id=api_id,
        api_hash=api_hash,
        settings=settings,
    ),
))
```

Макс 3 попытки: solve → send → ошибка → solve → send → ...

---

## Этап 3 — Классификация ответа

Проверяем тип `sent_code`:

```python
def check_email_setup_required(sent_code) -> bool:
    return "SetUpEmailRequired" in type(sent_code.type).__name__

def check_email_code_sent(sent_code) -> bool:
    return "EmailCode" in type(sent_code.type).__name__

def is_sms_type(sent_code) -> bool:
    return "Sms" in type(sent_code.type).__name__
```

| Тип | Значение | Действие |
|-----|----------|----------|
| `SetUpEmailRequired` | Email не привязан к номеру | → Этап 4 (привязка email) |
| `EmailCode` | Привязан чужой email | **STOP** — нет доступа к почте |
| `SentCodeTypeSms` | SMS уже отправлена | → Сразу к этапу 5 |
| `SentCodeTypeApp` и др. | Email привязан, код в приложение | **STOP** или ResendCodeRequest для SMS |

**Работаем только с `SetUpEmailRequired`** — это номера без привязанного email.

---

## Этап 4 — Привязка email

Telegram требует привязать email прежде чем отправит SMS. Юзер вводит свой email и код с него.

```python
from telethon.tl.functions.account import (
    SendVerifyEmailCodeRequest,
    VerifyEmailRequest,
)
from telethon.tl.types import (
    EmailVerifyPurposeLoginSetup,
    EmailVerificationCode,
)

# 4.1 — Юзер вводит email
email = input("Email: ")

# 4.2 — Отправляем запрос на верификацию
purpose = EmailVerifyPurposeLoginSetup(
    phone_number=f"+{phone}",
    phone_code_hash=phone_code_hash,
)

sent_email = await client(SendVerifyEmailCodeRequest(
    purpose=purpose,
    email=email,
))
# sent_email.length — длина кода (6 цифр)
# Telegram отправляет 6-значный код на этот email

# 4.3 — Юзер вводит код с почты
email_code = input("Код с почты: ")

# 4.4 — Верифицируем
result = await client(VerifyEmailRequest(
    purpose=purpose,
    verification=EmailVerificationCode(code=email_code),
))
```

### После верификации

`result` может содержать `sent_code` — тип кода, который Telegram отправил:

```python
if hasattr(result, "sent_code") and result.sent_code:
    phone_code_hash = result.sent_code.phone_code_hash

    if is_sms_type(result.sent_code):
        # SMS уже отправлена → ждём от юзера
        pass
    else:
        # Код ушёл в приложение → форсируем SMS
        from telethon.tl.functions.auth import ResendCodeRequest

        resent = await client(ResendCodeRequest(
            phone_number=f"+{phone}",
            phone_code_hash=phone_code_hash,
        ))
        phone_code_hash = resent.phone_code_hash
        # Теперь SMS отправлена
else:
    # Нет sent_code в ответе — запрашиваем вручную
    sent_code2 = await client(SendCodeRequest(
        phone_number=f"+{phone}",
        api_id=api_id,
        api_hash=api_hash,
        settings=settings,
    ))
    phone_code_hash = sent_code2.phone_code_hash

    if not is_sms_type(sent_code2):
        resent = await client(ResendCodeRequest(f"+{phone}", phone_code_hash))
        phone_code_hash = resent.phone_code_hash
```

**Итог этапа:** email привязан, SMS-код отправлен на телефон, `phone_code_hash` обновлён.

---

## Этап 5 — sign_in

Юзер вводит SMS-код, завершаем авторизацию:

```python
from telethon import errors

sms_code = input("SMS код: ")

try:
    await client.sign_in(
        phone=f"+{phone}",
        code=sms_code,
        phone_code_hash=phone_code_hash,
    )
except errors.SessionPasswordNeededError:
    # 2FA включена — нужен пароль
    print("На аккаунте 2FA")
    raise
except errors.PhoneCodeInvalidError:
    print("Неверный код")
    raise
except errors.PhoneCodeExpiredError:
    print("Код протух")
    raise

me = await client.get_me()
print(f"Авторизован: {me.first_name} (@{me.username}) | +{me.phone}")
# Сессия сохранена в session_path (.session файл)
```

**Готово** — `client` авторизован, `.session` файл на диске = готовая Telethon-сессия.

---

## Очистка при ошибке

Если авторизация провалилась — удаляем файлы сессии:

```python
async def cleanup_client(client):
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
            os.remove(path)
```

---

## Весь flow одним куском (псевдокод)

```python
# 1. Создать клиент с fingerprint
client = TelegramClient(session, api_id, api_hash,
    device_model=rand_device, system_version=rand_os,
    app_version=rand_tg, lang_code="uz", system_lang_code="uz",
    proxy=proxy)
await client.connect()

# 2. SendCodeRequest (+ captcha если нужно)
sent_code = await send_code_with_captcha(client, phone, api_id, api_hash)
phone_code_hash = sent_code.phone_code_hash

# 3. Проверяем тип ответа
if "SetUpEmailRequired" in type(sent_code.type).__name__:
    # 4. Привязка email (юзер вводит email + код)
    email = input("Email: ")
    await client(SendVerifyEmailCodeRequest(purpose, email))
    email_code = input("Код с почты: ")
    result = await client(VerifyEmailRequest(purpose, EmailVerificationCode(email_code)))

    # обновляем hash, форсируем SMS если нужно
    phone_code_hash = result.sent_code.phone_code_hash
    if not is_sms_type(result.sent_code):
        resent = await client(ResendCodeRequest(phone, phone_code_hash))
        phone_code_hash = resent.phone_code_hash

    # 5. sign_in
    sms_code = input("SMS код: ")
    await client.sign_in(phone, code=sms_code, phone_code_hash=phone_code_hash)
    # ГОТОВО — сессия авторизована

elif "EmailCode" in type(sent_code.type).__name__:
    # чужой email привязан — не можем авторизоваться
    pass
else:
    # email уже привязан — другой сценарий
    pass
```
