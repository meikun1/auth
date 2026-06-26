# test/ — голый Telethon-авторизатор

## Что тут

Минимальный скрипт ручной авторизации Telegram-аккаунта через Telethon по алгоритму из `ALGORITHM.md`.

Используется как песочница / эталонная реализация без обвеса (без прокси, без temp-mail, без бота-приёмщика SMS).

## Flow

```
номер → SendCodeRequest → [reCAPTCHA solver если нужно]
                          │
                  SetUpEmailRequired (email не привязан)
                          │
   юзер вводит email → SendVerifyEmailCodeRequest
                          │
   юзер вводит код с почты → VerifyEmailRequest
                          │
              форс SMS (ResendCodeRequest если код пришёл не SMS)
                          │
   юзер вводит SMS-код → sign_in → готово
```

Если на акке 2FA → завершаем работу с ошибкой (без обработки пароля).

**Классификация ответа SendCodeRequest:**
- `SentCodeTypeEmailCode` (чужая почта привязана) → **STOP** — мы не имеем доступа
- `SentCodeTypeSms` (SMS уже отправлена) → сразу к вводу SMS-кода
- **ВСЁ остальное** (`SetUpEmailRequired` / `App` / `Call` / прочее) → **обязательный email-флоу**: юзер вводит email → `SendVerifyEmailCodeRequest` → юзер вводит код с почты → `VerifyEmailRequest` → автоматический SMS на телефон. Если после Verify код не SMS — `ResendCodeRequest`.

⚠️ **Без email-флоу настоящий SMS не приходит даже на App-номера.** Если делать `ResendCodeRequest` напрямую на App-hash, Telegram возвращает `SentCodeTypeSms`, но физически SMS не отправляется (анти-фрод). Email-привязка — единственный способ получить реальный SMS.

⚠️ Раньше при первом ответе App `SendVerifyEmailCodeRequest` валился с `PhoneHashExpiredError` — оказалось это из-за плохого IP (европейский VPS / узбекский номер). С SOCKS5 прокси проблема ушла.

После `sign_in` запускается `verify_session_live()` — 6 пингов `GetUsers(self)` × 2s. Если auth_key отзывают (юзер тапнул "Завершить" с телефона / антифрод) — поймает `AuthKeyUnregisteredError` и почистит файл сессии.

## Прокси

- Файл `GERNETh.txt` в той же папке — список SOCKS5 прокси формата `login:pass@host:port` (~1000 штук, proxyma.io).
- При каждом запуске `auth.py` берётся **рандомная** прокси через `random.choice(load_proxies())`.
- Передаётся в `TelegramClient(..., proxy=(socks.SOCKS5, host, port, True, login, pass))`.
- Если файл отсутствует / пустой — работаем DIRECT с предупреждением в логе.
- Зависимость: `pysocks>=1.7` (для константы `socks.SOCKS5`).

## Файлы

- `ALGORITHM.md` — копия алгоритма из корня воркспейса
- `CLAUDE.md` — этот файл, контекст задачи
- `auth.py` — голый скрипт авторизации
- `requirements.txt` — зависимости (`telethon`, `aiohttp`)

## Конфигурация (зашита в auth.py)

- **api_id / api_hash** — из `GEEKINTILLIDIE/config.json` → `auth_api`:
  - `api_id = 21724`
  - `api_hash = "3e0cb5efcd52300aec5994fdfc5bdc16"`
- **Капча**: NextCaptcha (primary) → 2captcha (fallback). Ключи зашиты из того же конфига.
- **Fingerprint**: рандомный девайс из списка Android-моделей + рандомная Telegram-версия (`10.x` / `9.x`) + `lang_code="uz"`. Идентично оригиналу GEEKINTILLIDIE.

## Что НЕ делает

- Не использует прокси (`proxy=None`)
- Не парсит код из temp-mail — юзер вводит вручную
- Не принимает SMS-код от бота — юзер вводит вручную
- Не обрабатывает 2FA-пароль — фейлит с сообщением
- Не делает retry / cleanup сессий между запусками — это однопроходник

## Запуск

```bash
cd /Users/bella/Desktop/WORKSPACE/test
pip install -r requirements.txt
python auth.py
```

Сессия сохраняется в `test/sessions/{phone}.session` после успешной авторизации.

## История изменений

- **2026-06-26** — первая версия. Извлечено из `GEEKINTILLIDIE/auth.py` + `captcha.py`, убраны temp-mail, бот, прокси, 2FA-flow.
