import sqlite3
import bcrypt
import os

# Путь к базе данных SQLite из переменной окружения или значение по умолчанию
DEFAULT_DATABASE_PATH = 'katarera.db'
DATABASE_PATH = os.environ.get('DATABASE_PATH', DEFAULT_DATABASE_PATH)

def create_database():
    """Создает базу данных и таблицы."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Создаем таблицу users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_admin INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0,
            name TEXT,
            bio TEXT,
            profile_picture TEXT,
            is_email_confirmed INTEGER DEFAULT 0,
            email_confirmation_token TEXT
        )
    """)

    # Создаем таблицу genres
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS genres (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    # Создаем таблицу tracks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tracks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            artist TEXT NOT NULL,
            file_path TEXT NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            release_date DATE,
            duration INTEGER,
            plays INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            genre_id INTEGER,
            artwork_path TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (genre_id) REFERENCES genres(id)
        )
    """)

    # Создаем таблицу reviews
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Создаем таблицу playlists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS playlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Создаем таблицу playlist_tracks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS playlist_tracks (
            playlist_id INTEGER NOT NULL,
            track_id INTEGER NOT NULL,
            added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (playlist_id, track_id),
            FOREIGN KEY (playlist_id) REFERENCES playlists(id),
            FOREIGN KEY (track_id) REFERENCES tracks(id)
        )
    """)

   # Создаем таблицу events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            date DATETIME NOT NULL,
            location TEXT,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Создаем таблицу user_follows
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_follows (
            follower_id INTEGER NOT NULL, -- ID того, кто подписывается
            followed_email TEXT NOT NULL, -- Email того, на кого подписываются
            follow_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (follower_id, followed_email),
            FOREIGN KEY (follower_id) REFERENCES users(id),
            FOREIGN KEY (followed_email) REFERENCES users(email) ON DELETE CASCADE ON UPDATE CASCADE
        )
    """)

    # Создаем таблицу homepage_media
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS homepage_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            media_type TEXT NOT NULL, -- 'image' or 'video'
            uploaded_by INTEGER NOT NULL, -- admin user_id
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

def create_admin():
    """Создает администратора."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE is_admin = 1")
    admin = cursor.fetchone()
    if admin is None:
        hashed_password = bcrypt.hashpw("adminpassword".encode('utf-8'), bcrypt.gensalt())
        # Устанавливаем is_email_confirmed в 1 для администратора
        cursor.execute("INSERT INTO users (email, password, is_admin, is_email_confirmed, name) VALUES (?, ?, ?, ?, ?)", ("admin@katarera.com", hashed_password, 1, 1, "Admin"))
        conn.commit()
        print("Администратор создан")
    else:
        print("Администратор уже существует")
    conn.close()

def add_default_genres():
    """Добавляет жанры в таблицу genres."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    default_genres = [
        "Поп",
        "Рок",
        "Хип-хоп",
        "Электроника",
        "Джаз",
        "Классика",
        "Кантри",
        "Блюз",
        "Метал",
        "Регги",
        "Фолк",
        "R&B",
        "Инди",
        "Альтернатива",
        "Панк"
    ]

    for genre_name in default_genres:
        try:
            cursor.execute("INSERT INTO genres (name) VALUES (?)", (genre_name,))
        except sqlite3.IntegrityError:
            print(f"Жанр '{genre_name}' уже существует")

    conn.commit()
    conn.close()
    print("Жанры добавлены")

# Вызываем функцию для создания базы данных
create_database()
# Вызываем функцию для создания администратора
create_admin()
# Вызываем функцию для добавления жанров
add_default_genres()