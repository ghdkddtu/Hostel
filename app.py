from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import random, string
from datetime import datetime
import uuid
import sqlite3
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-12345'
DB_NAME = 'college.db'


def create_users_table():
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Пользователи (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL
    )
    ''')
    users = [
        ('admin@example.com', generate_password_hash('admin123'), 'Администратор', 'admin'),
        ('user1@example.com', generate_password_hash('user123'), 'Иван Иванов', 'user'),
        ('user2@example.com', generate_password_hash('user123'), 'Мария Петрова', 'user')
    ]
    cursor.executemany('INSERT OR IGNORE INTO Пользователи (username, password_hash, name, role) VALUES (?, ?, ?, ?)', users)
    connection.commit()
    connection.close()

def get_user_by_username(username):
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()
    cursor.execute('SELECT username, password_hash, name, role FROM Пользователи WHERE username = ?', (username,))
    user = cursor.fetchone()
    connection.close()
    if user:
        return {'username': user[0], 'password_hash': user[1], 'name': user[2], 'role': user[3]}
    return None

def register_new_user(username, password, name, role='user'):
    try:
        connection = sqlite3.connect(DB_NAME)
        cursor = connection.cursor()
        password_hash = generate_password_hash(password)
        cursor.execute('INSERT INTO Пользователи (username, password_hash, name, role) VALUES (?, ?, ?, ?)', (username, password_hash, name, role))
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        print(f"Ошибка регистрации: {e}")
        return False
    finally:
        connection.close()

create_users_table()

def generate_password(length):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password


@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    password = ""
    if request.method == 'POST':
        try:
            length = int(request.form.get('length', 12))
            if length <= 0:
                password = "Длина пароля должна быть больше 0"
            else:
                password = generate_password(length)
        except ValueError:
            password = "Ошибка: введите целое число"
    return render_template('index.html',
                           password=password,
                           user=session.get('user_info'),
                           login_time=session.get('login_time'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = 'remember' in request.form

        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            session['user_info'] = user
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session['session_id'] = str(uuid.uuid4())[:8]
            session.permanent = True if remember_me else False
            flash(f'Вы успешно вошли в систему, {user["name"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя (e-mail) или пароль', 'error')

    return render_template('login.html') 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('username', '').strip()
        user_name_input = request.form.get('user_name', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Пожалуйста, введите корректный e-mail.', 'error')
        elif not user_name_input:
            flash('Пожалуйста, введите имя пользователя.', 'error')
        elif password != confirm_password:
            flash('Пароли не совпадают.', 'error')
        elif len(password) < 6:
            flash('Пароль должен содержать минимум 6 символов.', 'error')
        else:
            if register_new_user(email, password, user_name_input, role='user'):
                flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Пользователь с таким e-mail уже существует.', 'error')
    return render_template('register.html', 
                           username=request.form.get('username', ''),
                           user_name=request.form.get('user_name', ''),
                           phone=request.form.get('phone', ''))

@app.route('/logout')
def logout():
    username = session.get('username', 'Гость')
    session.clear()
    flash(f'Вы вышли из системы. До свидания, {username}!', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
