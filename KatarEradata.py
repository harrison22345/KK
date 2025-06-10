from flask import Flask, jsonify, request, abort, render_template, redirect, url_for, send_from_directory
import sqlite3
import bcrypt
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from mutagen import File as MutagenFile # Для определения длительности трека
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Используйте переменные окружения для конфигурации
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_fallback_secret_key_for_dev_only') # ОБЯЗАТЕЛЬНО установите SECRET_KEY в Render
    
# Конфигурация Flask-Mail (замените на свои данные)
app.config['MAIL_SERVER'] = 'katarexample@gmail.com' # Например, 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('KatarEra Admin', os.environ.get('MAIL_DEFAULT_SENDER_EMAIL', app.config['MAIL_USERNAME']))

# Путь для сохранения загруженных файлов
DEFAULT_UPLOAD_FOLDER = 'uploads'
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER_PATH', DEFAULT_UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Путь к базе данных SQLite
DEFAULT_DATABASE_PATH = 'katarera.db'
DATABASE_PATH = os.environ.get('DATABASE_PATH', DEFAULT_DATABASE_PATH)
    
# Функция для подключения к базе данных
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Ошибка подключения к базе данных: {e}")
        return None

# Декоратор для проверки прав администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id_from_header = request.headers.get('X-User-ID')
        if not user_id_from_header:
            abort(401, "Admin authentication required: User ID not provided.")
        try:
            user_id = int(user_id_from_header)
        except ValueError:
            abort(400, "Admin authentication required: Invalid User ID format.")

        conn = get_db_connection()
        if conn is None:
            abort(500, 'Database connection error')
        
        admin_user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()

        if not admin_user or not admin_user['is_admin']:
            abort(403, "Forbidden: Admin access required.")
        
        return f(*args, **kwargs)
    return decorated_function

# Функция для отправки email
def send_email(to, subject, template_body_html, template_body_text):
    try:
        msg = Message(subject, recipients=[to])
        msg.body = template_body_text
        msg.html = template_body_html
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Ошибка отправки email: {e}")
        app.logger.error(f"Ошибка отправки email: {e}") # Логирование ошибок
        return False

# Добавлен маршрут для обслуживания файлов из папки uploads
@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Маршрут для обслуживания статических файлов (CSS, JS, изображения)
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# Маршрут для главной страницы
@app.route('/')
def index():
    return render_template('KatarEra.html')

# Маршрут для страницы входа
@app.route('/login')
def login_page():
    return render_template('login.html')

# Маршрут для страницы регистрации
@app.route('/register')
def register_page():
    return render_template('register.html')

# Маршрут для личного кабинета
@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

# Маршрут для панели администратора
@app.route('/admin')
def admin_page():
    return render_template('admin.html')

# Маршрут для получения отзывов на главной странице
@app.route('/reviews')
def get_reviews_main():
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    # Join with users table to get user's name
    reviews = conn.execute('''
        SELECT r.id, r.text, r.date, r.user_id, u.name as user_name
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.date DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(review) for review in reviews])

# Маршрут для добавления отзыва
@app.route('/reviews/add', methods=['POST'])
def add_review():
    user_id_from_header = request.headers.get('X-User-ID')
    if not user_id_from_header:
        abort(401, "Authentication required: User ID not provided in headers.")

    try:
        user_id = int(user_id_from_header)
    except ValueError:
        abort(400, "Invalid User ID format in headers.")

    data = request.get_json()
    if not data:
        abort(400, 'Request body must be JSON.')
    text = data.get('text')
    # user_id теперь берется из заголовка

    if not text:
        abort(400, 'Review text is required')


    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')

    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user is None:
            conn.close()
            abort(400, 'User not found')

        conn.execute('INSERT INTO reviews (user_id, text) VALUES (?, ?)', (user_id, text))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Review added successfully'}), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        print(f"Ошибка при добавлении отзыва: {e}")
        abort(500, 'Error adding review')

# Маршрут для регистрации пользователя
@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    name = request.form.get('name')
    bio = request.form.get('bio')
    profile_picture = request.files.get('profile_picture')

    if not email or not password:
        abort(400, 'Email and password are required')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    token = s.dumps(email, salt='email-confirm-salt')

    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    try:
        profile_picture_path = None
        if profile_picture:
            filename = secure_filename(profile_picture.filename)
            profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(profile_picture_path)

        conn.execute(
            'INSERT INTO users (email, password, name, bio, profile_picture, email_confirmation_token, is_email_confirmed) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (email, hashed_password, name, bio, profile_picture_path, token, 0)
        )
        conn.commit()

        # Отправка письма для подтверждения
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html_body = f"<p>Добро пожаловать! Спасибо за регистрацию. Пожалуйста, подтвердите вашу почту, перейдя по ссылке: <a href='{confirm_url}'>{confirm_url}</a></p>"
        text_body = f"Добро пожаловать! Спасибо за регистрацию. Пожалуйста, подтвердите вашу почту, перейдя по ссылке: {confirm_url}"
        send_email(email, 'Подтвердите вашу почту на KatarEra', html_body, text_body)

    except sqlite3.IntegrityError as e:
        conn.close()
        abort(400, 'Email already exists')
    except sqlite3.Error as e:
        conn.close()
        print(f"Ошибка при регистрации: {e}")
        abort(500, 'Error adding user')
    finally:
        if conn:
            conn.close()
    return '', 200

# Маршрут для подтверждения email
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600) # Токен действителен 1 час
    except (SignatureExpired, BadTimeSignature):
        return 'Ссылка для подтверждения недействительна или срок ее действия истек.'
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_email_confirmed = 1, email_confirmation_token = NULL WHERE email = ?', (email,))
    conn.commit()
    conn.close()
    return 'Ваша почта успешно подтверждена! Теперь вы можете войти.'

# Маршрут для входа пользователя
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        abort(400, 'Email and password are required')

    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    try:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user is None:
            conn.close()
            abort(400, 'Invalid email or password')
        
        if not user['is_email_confirmed']:
            conn.close()
            abort(401, 'Пожалуйста, подтвердите вашу электронную почту перед входом.')

        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            conn.close()
            return jsonify({'is_admin': user['is_admin'], 'id': user['id']})
        else:
            conn.close()
            abort(400, 'Invalid email or password')
    except sqlite3.Error as e:
        conn.close()
        print(f"Ошибка при входе: {e}")
        abort(500, 'Error during login')
    finally:
        if conn:
            conn.close()

# Маршрут для получения данных пользователя
@app.route('/user')
def get_user_data():
    user_id_str = request.args.get('user_id')
    if user_id_str is None:
        abort(400, 'user_id is required')
    
    try:
        user_id = int(user_id_str)
    except ValueError:
        abort(400, 'Invalid user_id format. Must be an integer.')

    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user is None:
            abort(404, 'User not found') # Соединение закроется в блоке finally
        
        user_dict = dict(user)
        if user_dict.get('password'): 
            del user_dict['password']
        if user_dict.get('email_confirmation_token'): 
            del user_dict['email_confirmation_token']

        if user_dict.get('profile_picture') and isinstance(user_dict['profile_picture'], str):
            user_dict['profile_picture'] = '/uploads/' + os.path.basename(user_dict['profile_picture'])
        
        # Получение email текущего пользователя для подсчета подписчиков
        current_user_email_row = conn.execute('SELECT email FROM users WHERE id = ?', (user_id,)).fetchone()
        if not current_user_email_row:
            # Это не должно произойти, если user_id валиден
            abort(404, 'User email not found for follower count')
        current_user_email = current_user_email_row['email']

        followers_count = conn.execute('SELECT COUNT(*) FROM user_follows WHERE followed_email = ?', (current_user_email,)).fetchone()[0]
        following_count = conn.execute('SELECT COUNT(*) FROM user_follows WHERE follower_id = ?', (user_id,)).fetchone()[0]
        user_dict['followers_count'] = followers_count
        user_dict['following_count'] = following_count

        return jsonify(user_dict)
    finally:
        if conn:
            conn.close()

# Маршрут для повторной отправки письма с подтверждением
@app.route('/resend-confirmation', methods=['POST'])
def resend_confirmation():
    data = request.get_json()
    email = data.get('email')
    if not email:
        abort(400, 'Email is required')

    conn = get_db_connection()
    if conn is None: abort(500, 'Database connection error')

    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if not user:
        conn.close()
        abort(404, 'User not found')
    
    if user['is_email_confirmed']:
        conn.close()
        return jsonify({'message': 'Email already confirmed'}), 200

    token = s.dumps(email, salt='email-confirm-salt')
    conn.execute('UPDATE users SET email_confirmation_token = ? WHERE email = ?', (token, email))
    conn.commit()
    conn.close()

    confirm_url = url_for('confirm_email', token=token, _external=True)
    html_body = f"<p>Пожалуйста, подтвердите вашу почту, перейдя по ссылке: <a href='{confirm_url}'>{confirm_url}</a></p>"
    text_body = f"Пожалуйста, подтвердите вашу почту, перейдя по ссылке: {confirm_url}"
    if send_email(email, 'Подтвердите вашу почту на KatarEra', html_body, text_body):
        return jsonify({'message': 'Confirmation email resent'}), 200
    else:
        return jsonify({'message': 'Failed to resend confirmation email'}), 500


# Маршрут для получения треков пользователя
@app.route('/user/tracks')
def get_user_tracks():
    # ВАЖНО: Здесь user_id должен браться из сессии или токена аутентификации,
    # если это треки ТЕКУЩЕГО пользователя (для его личного кабинета).
    # Если это треки для публичного профиля, user_id может приходить из параметра.

    user_id_from_param = request.args.get('user_id') # Для просмотра профиля другого пользователя
    user_id_from_header = request.headers.get('X-User-ID') # Для треков текущего залогиненного пользователя

    user_id_to_fetch = None
    if user_id_from_param:
        user_id_to_fetch = user_id_from_param
    elif user_id_from_header: # Если не смотрим чужой профиль, а просто зашли в свой кабинет
        user_id_to_fetch = user_id_from_header

    if not user_id_to_fetch:
        abort(401, "User ID not provided for fetching tracks.")

    try:
        user_id = int(user_id_to_fetch)
    except ValueError:
        abort(400, "Invalid User ID format")

    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    tracks = conn.execute('SELECT * FROM tracks WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(track) for track in tracks])

# Маршрут для загрузки трека
@app.route('/user/tracks/upload', methods=['POST'])
def upload_track():
    # ВАЖНО: Аналогично get_user_tracks, user_id должен быть получен безопасным способом.
    user_id_from_client = request.headers.get('X-User-ID') # Пример
    if not user_id_from_client:
        abort(401, "User ID not provided or user not authenticated")
    try:
        user_id = int(user_id_from_client)
    except ValueError:
        abort(400, "Invalid User ID format")

    # Проверка, подтверждена ли почта пользователя перед загрузкой
    conn_check = get_db_connection()
    if conn_check is None: abort(500, 'Database connection error')
    user_email_status = conn_check.execute('SELECT is_email_confirmed FROM users WHERE id = ?', (user_id,)).fetchone()
    conn_check.close()

    if not user_email_status or not user_email_status['is_email_confirmed']:
        abort(403, 'Пожалуйста, подтвердите вашу электронную почту перед загрузкой треков.')


    if 'track-file' not in request.files:
        abort(400, 'No file part')
    track_file = request.files['track-file']
    if track_file.filename == '':
        abort(400, 'No selected file')
    if track_file:
        track_filename = secure_filename(f"user_{user_id}_track_{track_file.filename}")
        track_file_path = os.path.join(app.config['UPLOAD_FOLDER'], track_filename)
        track_file.save(track_file_path)

        title = request.form['track-name']
        artist = request.form['track-artist']
        genre_id = request.form['genre_id']
        track_artwork = request.files.get('track-artwork')
        artwork_path = None
        if track_artwork:
            artwork_filename = secure_filename(f"user_{user_id}_artwork_{track_artwork.filename}")
            artwork_path = os.path.join(app.config['UPLOAD_FOLDER'], artwork_filename)
            track_artwork.save(artwork_path)

        # Определение длительности трека
        duration_seconds = 0
        try:
            audio = MutagenFile(track_file_path)
            if audio and audio.info:
                duration_seconds = int(audio.info.length)
        except Exception as e:
            print(f"Не удалось определить длительность трека {track_filename}: {e}")
            # Можно оставить duration_seconds = 0 или вернуть ошибку, если длительность обязательна

        conn = get_db_connection()
        if conn is None:
            abort(500, 'Database connection error')
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO tracks (user_id, title, artist, file_path, genre_id, artwork_path, duration, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                         (user_id, title, artist, track_file_path, genre_id, artwork_path, duration_seconds, 'pending'))
            conn.commit()
            track_id = cursor.lastrowid # Получаем ID только что вставленного трека

            # Если трек сразу публикуется (или после одобрения), отправляем уведомления
            # Для примера, предположим, что 'pending' означает, что он еще не виден,
            # а 'approved' - что виден. Уведомления нужно слать при переходе в 'approved'.
            # Если у вас нет статуса 'approved' и треки видны сразу, этот код можно разместить здесь.
            # Мы рассмотрим отправку уведомлений при одобрении трека в функции approve_track.

        except sqlite3.Error as e:
            conn.rollback()
            print(f"Ошибка при загрузке трека: {e}")
            abort(500, "Error uploading track")
        finally:
            if conn:
                conn.close()
        return jsonify({'message': 'Track uploaded successfully and is pending review.', 'track_id': track_id}), 200

# Маршрут для получения списка пользователей
@app.route('/admin/users')
@admin_required
def get_users():
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    users = conn.execute('SELECT id, email, registration_date, is_admin, is_blocked, name, bio, profile_picture, is_email_confirmed FROM users').fetchall() # Убрали пароль и токен
    conn.close()
    user_list = []
    for user_row in users:
        user_dict = dict(user_row)
        if user_dict.get('profile_picture') is not None and isinstance(user_dict['profile_picture'], str):
            user_dict['profile_picture'] = '/uploads/' + os.path.basename(user_dict['profile_picture'])
        user_list.append(user_dict)
    return jsonify(user_list)

# Маршрут для получения списка треков
@app.route('/admin/tracks')
@admin_required
def get_tracks():
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    tracks = conn.execute('SELECT t.*, u.email as user_email FROM tracks t JOIN users u ON t.user_id = u.id').fetchall()
    conn.close()
    return jsonify([dict(track) for track in tracks])

# Маршрут для получения списка отзывов (для администратора)
@app.route('/admin/reviews')
@admin_required
def get_reviews_admin():
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    reviews = conn.execute('SELECT r.*, u.email as user_email FROM reviews r JOIN users u ON r.user_id = u.id').fetchall()
    conn.close()
    return jsonify([dict(review) for review in reviews])

# Маршрут для блокировки пользователя
@app.route('/admin/users/<int:user_id>/block', methods=['POST'])
@admin_required
def block_user(user_id):
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    conn.execute('UPDATE users SET is_blocked = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return '', 200

# Маршрут для одобрения трека
@app.route('/admin/tracks/<int:track_id>/approve', methods=['POST'])
@admin_required
def approve_track(track_id):
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    try:
        conn.execute('UPDATE tracks SET status = "approved" WHERE id = ?', (track_id,))
        conn.commit()
        
        # Отправка уведомления пользователю
        track_info = conn.execute('SELECT t.title, t.user_id, u.email, u.name as artist_name FROM tracks t JOIN users u ON t.user_id = u.id WHERE t.id = ?', (track_id,)).fetchone()
        if track_info:
            user_email = track_info['email']
            track_title = track_info['title']
            artist_user_id = track_info['user_id'] # ID пользователя-исполнителя
            artist_name_for_notification = track_info['artist_name'] if track_info['artist_name'] else "Исполнитель"

            # Получаем email исполнителя для поиска его подписчиков
            artist_email_row = conn.execute('SELECT email FROM users WHERE id = ?', (artist_user_id,)).fetchone()
            if not artist_email_row:
                print(f"Не удалось найти email для исполнителя с ID {artist_user_id} для отправки уведомлений подписчикам.")
                # Продолжаем без уведомления подписчиков, если email не найден
            else:
                artist_email_for_follow_check = artist_email_row['email']
                followers = conn.execute('SELECT u.email FROM user_follows uf JOIN users u ON uf.follower_id = u.id WHERE uf.followed_email = ? AND u.is_email_confirmed = 1', (artist_email_for_follow_check,)).fetchall()
                for follower in followers:
                    subject_follower = f"Новый трек от {artist_name_for_notification}: {track_title}"
                    html_body_follower = f"<p>Исполнитель {artist_name_for_notification}, на которого вы подписаны, выпустил новый трек: <strong>{track_title}</strong>.</p><p>Послушайте его на KatarEra!</p>"
                    text_body_follower = f"Исполнитель {artist_name_for_notification}, на которого вы подписаны, выпустил новый трек: {track_title}. Послушайте его на KatarEra!"
                    send_email(follower['email'], subject_follower, html_body_follower, text_body_follower)

            subject = f"Ваш трек '{track_title}' одобрен!"
            html_body = f"<p>Поздравляем! Ваш трек <strong>{track_title}</strong> был одобрен и теперь доступен на KatarEra.</p>"
            text_body = f"Поздравляем! Ваш трек {track_title} был одобрен и теперь доступен на KatarEra."
            send_email(user_email, subject, html_body, text_body)

    except sqlite3.Error as e:
        conn.rollback()
        print(f"Ошибка при одобрении трека: {e}")
        abort(500, "Error approving track")
    finally:
        if conn:
            conn.close()
    return '', 200

# Маршрут для отклонения трека
@app.route('/admin/tracks/<int:track_id>/reject', methods=['POST'])
@admin_required
def reject_track(track_id):
    # Можно добавить получение причины отклонения из request.form, если нужно
    reason = request.form.get('reason', 'Причина не указана.') 

    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    try:
        conn.execute('UPDATE tracks SET status = "rejected" WHERE id = ?', (track_id,))
        conn.commit()

        # Отправка уведомления пользователю
        track_info = conn.execute('SELECT t.title, u.email FROM tracks t JOIN users u ON t.user_id = u.id WHERE t.id = ?', (track_id,)).fetchone()
        if track_info:
            user_email = track_info['email']
            track_title = track_info['title']
            subject = f"Ваш трек '{track_title}' отклонен"
            html_body = f"<p>К сожалению, ваш трек <strong>{track_title}</strong> был отклонен. Причина: {reason}</p>"
            text_body = f"К сожалению, ваш трек {track_title} был отклонен. Причина: {reason}"
            send_email(user_email, subject, html_body, text_body)
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Ошибка при отклонении трека: {e}")
        abort(500, "Error rejecting track")
    finally:
        if conn:
            conn.close()
    return '', 200

# Маршрут для удаления трека
@app.route('/admin/tracks/<int:track_id>/delete', methods=['POST'])
@admin_required
def delete_track(track_id):
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    # TODO: Удалить также файлы с диска
    conn.execute('DELETE FROM tracks WHERE id = ?', (track_id,))
    conn.commit()
    conn.close()
    return '', 200

# Маршрут для удаления отзыва
@app.route('/admin/reviews/<int:review_id>/delete', methods=['POST'])
@admin_required
def delete_review(review_id):
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    conn.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
    conn.commit()
    conn.close()
    return '', 200

# Маршрут для получения списка жанров
@app.route('/genres')
def get_genres():
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    genres = conn.execute('SELECT * FROM genres').fetchall()
    conn.close()
    return jsonify([dict(genre) for genre in genres])

# Маршрут для получения списка исполнителей (например, всех пользователей, загрузивших хотя бы 1 трек)
@app.route('/artists')
def get_artists():
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    # Выбираем пользователей, у которых есть хотя бы один одобренный трек
    # и добавляем подсчет подписчиков
    artists_query = """
        SELECT DISTINCT u.id, u.name, u.profile_picture, u.bio, 
               (SELECT COUNT(*) FROM user_follows WHERE followed_email = u.email) as followers_count
        FROM users u 
        JOIN tracks t ON u.id = t.user_id 
        WHERE t.status = "approved" ORDER BY u.name
    """
    artists = conn.execute(artists_query).fetchall()
    conn.close()
    
    artist_list = []
    for artist_row in artists:
        artist_dict = dict(artist_row)
        if artist_dict.get('profile_picture') is not None and isinstance(artist_dict['profile_picture'], str):
            artist_dict['profile_picture'] = '/uploads/' + os.path.basename(artist_dict['profile_picture'])
        else:
            artist_dict['profile_picture'] = '/static/img/default_avatar.png' # Заглушка, если нет фото
        artist_list.append(artist_dict)
    return jsonify(artist_list)

# Маршрут для подписки на пользователя
@app.route('/user/<int:followed_id>/follow', methods=['POST']) # ID пользователя, на которого подписываются
def follow_user(followed_id):
    follower_id = request.headers.get('X-User-ID') # ID текущего залогиненного пользователя
    if not follower_id:
        abort(401, "Authentication required to follow.")
    try:
        follower_id = int(follower_id)
    except ValueError:
        abort(400, "Invalid follower User ID format.")

    if follower_id == followed_id:
        abort(400, "Cannot follow yourself.")

    conn = get_db_connection()
    if conn is None: abort(500, 'Database connection error')
    try:
        # Получаем email пользователя, на которого подписываемся
        followed_user_email_row = conn.execute('SELECT email FROM users WHERE id = ?', (followed_id,)).fetchone()
        if not followed_user_email_row:
            abort(404, "User to follow not found.")
        
        followed_email = followed_user_email_row['email']

        conn.execute('INSERT INTO user_follows (follower_id, followed_email) VALUES (?, ?)', (follower_id, followed_email))
        conn.commit()
    except sqlite3.IntegrityError: # Уже подписан или один из ID не существует
        # Проверяем, существует ли пользователь, на которого пытаются подписаться, чтобы дать более точную ошибку
        # (хотя это уже проверено выше)
        conn.rollback()
        # Можно проверить, существует ли followed_id, чтобы дать более точную ошибку
        return jsonify({'message': 'Already following or user does not exist.'}), 409 # Conflict
    except sqlite3.Error as e:
        conn.rollback()
        abort(500, f"Database error: {e}")
    finally:
        if conn: conn.close()
    return jsonify({'message': 'Successfully followed.'}), 200

# Маршрут для отписки от пользователя
@app.route('/user/<int:followed_id>/unfollow', methods=['POST'])
def unfollow_user(followed_user_id):
    follower_id = request.headers.get('X-User-ID')
    if not follower_id:
        abort(401, "Authentication required to unfollow.")
    try:
        follower_id = int(follower_id)
    except ValueError:
        abort(400, "Invalid follower User ID format.")

    conn = get_db_connection()
    if conn is None: abort(500, 'Database connection error')
    try:
        # Получаем email пользователя, от которого отписываемся
        followed_user_email_row = conn.execute('SELECT email FROM users WHERE id = ?', (followed_user_id,)).fetchone()
        if not followed_user_email_row:
            # Если пользователь не найден, то и подписки на него быть не может.
            # Можно вернуть успех, так как цель (отсутствие подписки) достигнута.
            return jsonify({'message': 'Successfully unfollowed (user not found).'}), 200
        
        followed_email = followed_user_email_row['email']

        conn.execute('DELETE FROM user_follows WHERE follower_id = ? AND followed_email = ?', (follower_id, followed_email))
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        abort(500, f"Database error: {e}")
    finally:
        if conn: conn.close()
    return jsonify({'message': 'Successfully unfollowed.'}), 200

# Маршрут для проверки, подписан ли текущий пользователь на другого
@app.route('/user/is_following/<int:followed_id>')
def is_following(followed_id): # Имя параметра изменено на followed_id
    follower_id = request.headers.get('X-User-ID') 
    if not follower_id: # Если не залогинен, считаем, что не подписан
        return jsonify({'is_following': False}), 200
    try:
        follower_id = int(follower_id)
    except ValueError:
         return jsonify({'is_following': False, 'reason': 'Invalid follower_id format'}), 200

    conn = get_db_connection()
    if conn is None: abort(500, 'Database connection error')
    # Используем followed_id для запроса к базе данных
    followed_user_email_row = conn.execute('SELECT email FROM users WHERE id = ?', (followed_id,)).fetchone()
    if not followed_user_email_row:
        conn.close() # Закрываем соединение перед выходом
        return jsonify({'is_following': False, 'reason': 'Followed user not found'}), 200
    followed_email = followed_user_email_row['email']
    result = conn.execute('SELECT 1 FROM user_follows WHERE follower_id = ? AND followed_email = ?', (follower_id, followed_email)).fetchone()
    conn.close() # Закрываем соединение
    return jsonify({'is_following': bool(result)})

# Маршрут для отображения страницы с пользователями, на которых подписан user_id
@app.route('/user/<int:user_id>/following_list')
def following_list_page(user_id):
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')

    # Проверяем, существует ли пользователь, для которого запрашивается список подписок
    user_exists = conn.execute('SELECT 1 FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user_exists:
        conn.close()
        abort(404, 'User not found')

    # Получаем список пользователей, на которых подписан user_id
    # Нам нужны id, name, profile_picture тех, на кого он подписан
    followed_users_data = conn.execute('''
        SELECT u.id, u.name, u.profile_picture
        FROM users u
        JOIN user_follows uf ON u.email = uf.followed_email
        WHERE uf.follower_id = ?
    ''', (user_id,)).fetchall()
    conn.close()

    followed_users_list = []
    for row in followed_users_data:
        user_dict = dict(row)
        user_dict['profile_picture_url'] = user_dict['profile_picture'] if user_dict['profile_picture'] else url_for('static', filename='img/default_avatar.png')
        if user_dict['profile_picture_url'] and not user_dict['profile_picture_url'].startswith('/static/'): # если это путь из uploads
            user_dict['profile_picture_url'] = url_for('serve_uploads', filename=os.path.basename(user_dict['profile_picture']))
        followed_users_list.append(user_dict)

    return render_template('following_list.html', followed_users=followed_users_list, viewing_user_id=user_id)

# Маршрут для отображения страницы с подписчиками пользователя user_id
@app.route('/user/<int:user_id>/followers_list')
def followers_list_page(user_id):
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')

    # Проверяем, существует ли пользователь, для которого запрашивается список подписчиков
    viewing_user = conn.execute('SELECT id, name, email FROM users WHERE id = ?', (user_id,)).fetchone()
    if not viewing_user:
        conn.close()
        abort(404, 'User not found')

    viewing_user_name = viewing_user['name'] if viewing_user['name'] else f"User ID {viewing_user['id']}"
    viewing_user_email = viewing_user['email']

    # Получаем список подписчиков пользователя user_id
    # Нам нужны id, name, profile_picture тех, кто на него подписан
    followers_data = conn.execute('''
        SELECT u.id, u.name, u.profile_picture
        FROM users u
        JOIN user_follows uf ON u.id = uf.follower_id
        WHERE uf.followed_email = ?
    ''', (viewing_user_email,)).fetchall()
    conn.close()

    followers_list = []
    for row in followers_data:
        user_dict = dict(row)
        user_dict['profile_picture_url'] = user_dict['profile_picture'] if user_dict['profile_picture'] else url_for('static', filename='img/default_avatar.png')
        if user_dict['profile_picture_url'] and not user_dict['profile_picture_url'].startswith(('/static/', '/uploads/')):
             # Если путь не начинается ни с /static/, ни с /uploads/, считаем, что это имя файла в uploads
            user_dict['profile_picture_url'] = url_for('serve_uploads', filename=os.path.basename(user_dict['profile_picture']))
        elif user_dict['profile_picture_url'] and user_dict['profile_picture_url'].startswith(app.config['UPLOAD_FOLDER']):
            user_dict['profile_picture_url'] = url_for('serve_uploads', filename=os.path.basename(user_dict['profile_picture']))
        followers_list.append(user_dict)

    return render_template('followers_list.html', followers=followers_list, viewing_user_id=user_id, viewing_user_name=viewing_user_name)

# Маршрут для получения медиа для главной страницы
@app.route('/homepage-media')
def get_homepage_media():
    conn = get_db_connection()
    if conn is None:
        abort(500, 'Database connection error')
    media_items = conn.execute('SELECT id, file_path, media_type FROM homepage_media ORDER BY upload_date DESC').fetchall()
    conn.close()
    return jsonify([dict(item) for item in media_items])

# Маршрут для загрузки медиа администратором
@app.route('/admin/homepage-media/upload', methods=['POST'])
@admin_required
def admin_upload_homepage_media():
    admin_user_id_from_header = request.headers.get('X-User-ID')
    # Декоратор @admin_required уже проверил, что это админ.
    # Теперь просто используем ID для записи в БД.
    try:
        admin_user_id = int(admin_user_id_from_header)
    except (ValueError, TypeError):
        abort(400, "Invalid Admin User ID format in header.")

    if 'media_file' not in request.files:
        abort(400, 'No file part')
    media_file = request.files['media_file']
    if media_file.filename == '':
        abort(400, 'No selected file')

    media_type = request.form.get('media_type') # 'image' or 'video'
    if media_type not in ['image', 'video']:
        abort(400, 'Invalid media type')

    if media_file:
        filename = secure_filename(f"homepage_{media_type}_{media_file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        media_file.save(file_path)

        conn = get_db_connection()
        if conn is None: abort(500, 'Database connection error')
        try:
            cursor = conn.cursor() # Используем курсор
            conn.execute('INSERT INTO homepage_media (file_path, media_type, uploaded_by) VALUES (?, ?, ?)',
                         (file_path, media_type, admin_user_id))
            conn.commit()
            last_id = cursor.lastrowid # Получаем ID до закрытия соединения
        except sqlite3.Error as e:
            conn.rollback()
            print(f"Ошибка при загрузке медиа для главной страницы: {e}")
            abort(500, "Error uploading homepage media")
        finally:
            if conn: conn.close()
        return jsonify({'message': 'Media uploaded successfully', 'file_path': '/uploads/' + filename, 'media_type': media_type, 'id': last_id}), 200
    return jsonify({'message': 'File could not be processed'}), 500

# Маршрут для удаления медиа администратором
@app.route('/admin/homepage-media/<int:media_id>/delete', methods=['POST'])
@admin_required
def admin_delete_homepage_media(media_id):
    # Декоратор @admin_required уже проверил, что это админ.
    # admin_user_id_from_header = request.headers.get('X-User-ID') # Можно использовать для логирования, кто удалил
    # if not admin_user_id_from_header:
    #     abort(401, "Admin User ID not found in header for logging deletion.")
    conn = get_db_connection()
    if conn is None: abort(500, 'Database connection error')
    
    media_item = conn.execute('SELECT file_path FROM homepage_media WHERE id = ?', (media_id,)).fetchone()
    if media_item:
        try:
            os.remove(media_item['file_path']) # Удаляем файл с диска
        except OSError as e:
            print(f"Ошибка удаления файла {media_item['file_path']}: {e}")
            # Не прерываем, если файл не найден, но логируем

    conn.execute('DELETE FROM homepage_media WHERE id = ?', (media_id,))
    conn.commit()
    conn.close()
    return '', 200

if __name__ == '__main__':
    # Важно: для URLSafeTimedSerializer нужен app.secret_key
    # В продакшене debug=False. Gunicorn будет запускать приложение, а не этот блок.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=False) # Для локального запуска можно временно поставить debug=True