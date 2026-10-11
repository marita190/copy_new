import sqlite3
import os


DB = "lab_database.db"


def init_db():
    # удаляем старую БД 
    if os.path.exists(DB):
        os.remove(DB)

    # создание подключения к базе данных
    connection = sqlite3.connect(DB)
    cursor = connection.cursor()

    # создаем таблицу Users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # создаем таблицу секретов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Secrets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            secret_usser TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES Users(id)
        )
    ''')

    # заполняем таблицу Users
    cursor.executemany(
        "INSERT INTO Users (username, password) VALUES (?, ?)", [
            ("admin", "adminadminadminadmin"), 
            ("ann", "123456789"), 
            ("bob", "987654321"),
            ("tom", "qwertyuiop")
        ]
    )

    # заполняем таблицу секретов
    secrets = {
        "admin": "FLAG{4dm1n_0wn3d_y0ur_sqli}",
        "ann": "FLAG{1_f0g0t_t0_l0g0ut}",
        "bob": "FLAG{4nn_p4ss_1s_123456789}",
        "tom": "FLAG{t1m3_70_r3v34l_7h3_53cr37s}"
    }

    for username, flag in secrets.items():
        cursor.execute(
            """INSERT INTO Secrets (user_id, secret_usser) SELECT id, ?
            FROM Users WHERE username = ?""", 
                (flag, username),
        )

    connection.commit()
    connection.close()

if __name__ == "__main__":
    init_db()
