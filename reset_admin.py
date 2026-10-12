"""Reset the password of an existing administrator in the app database.

Run this script in an environment connected to the SAME persistent database as
its deployed backend. This script does not expose an unauthenticated HTTP route.
"""
import getpass
import sqlite3

from main import initialize, db, password_hash


def main():
    initialize()
    nickname = input("Administrator login: ").strip().lower()
    if not nickname:
        raise SystemExit("Administrator loginini kiriting.")

    with db() as connection:
        row = connection.execute(
            "SELECT role FROM users WHERE nickname = ?", (nickname,)
        ).fetchone()
        if row is None or row[0] != "admin":
            raise SystemExit("Bunday administrator topilmadi.")

    new_password = getpass.getpass("Yangi parol (10-128 belgi): ")
    if not 10 <= len(new_password) <= 128:
        raise SystemExit("Parol 10–128 belgidan iborat bo‘lishi kerak.")
    confirmation = getpass.getpass("Yangi parolni takrorlang: ")
    if new_password != confirmation:
        raise SystemExit("Parollar mos kelmadi.")

    with db() as connection:
        cursor = connection.execute(
            "UPDATE users SET password = ? WHERE nickname = ? AND role = 'admin'",
            (password_hash(new_password), nickname),
        )
        if cursor.rowcount != 1:
            raise SystemExit("Administrator paroli yangilanmadi.")

    print("Administrator paroli muvaffaqiyatli yangilandi.")


if __name__ == "__main__":
    main()
