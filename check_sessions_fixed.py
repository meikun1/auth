#!/usr/bin/env python3
"""
Проверка Telegram-сессий (.session) из указанной папки.
Выводит таблицу: файл, статус, телефон/юзернейм, контакты, диалоги (чаты/группы/каналы).

Установка зависимостей:
    pip install telethon tabulate

Запуск:
    python3 check_sessions.py
"""

import os
import glob
from telethon.sync import TelegramClient
from telethon.errors import SessionPasswordNeededError
from tabulate import tabulate

# ==== Настройки ====
API_ID = 21724
API_HASH = "3e0cb5efcd52300aec5994fdfc5bdc16"
SESSION_DIR = "/root/tg_auth_test/sessions"
# ====================


def check_session(session_path: str) -> dict:
    row = {
        "Файл": os.path.basename(session_path),
        "Статус": "—",
        "Телефон": "—",
        "Username": "—",
        "Имя": "—",
        "Контакты": "—",
        "Личные чаты": "—",
        "Группы": "—",
        "Каналы": "—",
        "Всего диалогов": "—",
    }

    client = TelegramClient(session_path, API_ID, API_HASH)

    try:
        client.start()

        if not client.is_user_authorized():
            row["Статус"] = "❌ Не авторизован"
            return row

        me = client.get_me()
        row["Статус"] = "✅ Активна"
        row["Телефон"] = getattr(me, "phone", None) or "—"
        row["Username"] = f"@{me.username}" if getattr(me, "username", None) else "—"
        row["Имя"] = " ".join(filter(None, [me.first_name, me.last_name])) or "—"

        try:
            contacts = client.get_contacts()
            row["Контакты"] = len(contacts)
        except Exception as e:
            row["Контакты"] = f"ошибка: {e}"

        try:
            dialogs = client.get_dialogs()
            private_chats = sum(1 for d in dialogs if d.is_user)
            groups = sum(1 for d in dialogs if d.is_group)
            channels = sum(1 for d in dialogs if d.is_channel and not d.is_group)

            row["Личные чаты"] = private_chats
            row["Группы"] = groups
            row["Каналы"] = channels
            row["Всего диалогов"] = len(dialogs)
        except Exception as e:
            row["Всего диалогов"] = f"ошибка: {e}"

    except SessionPasswordNeededError:
        row["Статус"] = "⚠️ Нужен пароль 2FA"
    except Exception as e:
        row["Статус"] = f"⚠️ Ошибка: {e}"
    finally:
        try:
            client.disconnect()
        except Exception:
            pass

    return row


def main():
    session_files = sorted(glob.glob(os.path.join(SESSION_DIR, "*.session")))

    if not session_files:
        print(f"В папке {SESSION_DIR} не найдено .session файлов.")
        return

    print(f"Найдено {len(session_files)} session-файл(ов). Проверяю...\n")

    results = []
    for path in session_files:
        print(f"→ Проверяю {os.path.basename(path)}...")
        results.append(check_session(path))

    print("\n" + tabulate(results, headers="keys", tablefmt="grid"))


if __name__ == "__main__":
    main()
