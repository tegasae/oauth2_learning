from flask import Flask, request, redirect, url_for, session, render_template_string
import requests
import secrets
import hashlib
import base64
import time
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Конфигурация
AUTH_SERVER = "http://127.0.0.1:5000"
CLIENT_ID = "web_app"
REDIRECT_URI = "http://127.0.0.1:5003/callback"

# Временное хранилище PKCE данных
pkce_store = {}

# HTML шаблоны
SCOPE_SELECTION_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OAuth Client</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            max-width: 500px; 
            margin: 50px auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        h2 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .scope-item {
            margin: 15px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        label {
            display: flex;
            align-items: center;
            cursor: pointer;
        }
        input[type="checkbox"] {
            margin-right: 12px;
            transform: scale(1.2);
        }
        button { 
            background: #007bff; 
            color: white; 
            padding: 15px 30px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer;
            font-size: 16px;
            width: 100%;
            margin-top: 20px;
        }
        button:hover {
            background: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Выбор прав доступа</h2>

        <form method="post" action="/request_auth">
            <div class="scope-item">
                <label>
                    <input type="checkbox" name="scope" value="read_data" checked>
                    📖 Чтение данных
                </label>
            </div>

            <div class="scope-item">
                <label>
                    <input type="checkbox" name="scope" value="write_data">
                    ✏️ Запись данных
                </label>
            </div>

            <div class="scope-item">
                <label>
                    <input type="checkbox" name="scope" value="admin_panel">
                    ⚙️ Админ-панель
                </label>
            </div>

            <button type="submit">Войти →</button>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Профиль пользователя</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .user-card {
            border-left: 4px solid #28a745;
        }
        .scopes-card {
            border-left: 4px solid #007bff;
        }
        .scope-item {
            margin: 8px 0;
            padding: 10px;
            background: white;
            border-radius: 6px;
            border-left: 3px solid #6c757d;
        }
        .scope-active {
            border-left-color: #28a745;
            background: #f0fff4;
        }
        .scope-inactive {
            border-left-color: #dc3545;
            background: #fff5f5;
            opacity: 0.6;
        }
        button {
            background: #dc3545;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            margin-top: 20px;
        }
        button:hover {
            background: #c82333;
        }
        .badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            margin-left: 10px;
        }
        .badge-success {
            background: #28a745;
            color: white;
        }
        .badge-danger {
            background: #dc3545;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>👤 Профиль пользователя</h2>

        <div class="card user-card">
            <h3>Информация</h3>
            <p><strong>Пользователь:</strong> {{ user_id }}</p>
            <p><strong>Статус:</strong> 
                {% if 'admin_panel' in granted_scope %}
                <span class="badge badge-success">Администратор</span>
                {% else %}
                <span class="badge">Пользователь</span>
                {% endif %}
            </p>
        </div>

        <div class="card scopes-card">
            <h3>🔐 Права доступа</h3>

            <div class="scope-item {% if 'read_data' in granted_scope %}scope-active{% else %}scope-inactive{% endif %}">
                📖 Чтение данных
                {% if 'read_data' in granted_scope %}
                <span class="badge badge-success">Доступно</span>
                {% else %}
                <span class="badge badge-danger">Недоступно</span>
                {% endif %}
            </div>

            <div class="scope-item {% if 'write_data' in granted_scope %}scope-active{% else %}scope-inactive{% endif %}">
                ✏️ Запись данных
                {% if 'write_data' in granted_scope %}
                <span class="badge badge-success">Доступно</span>
                {% else %}
                <span class="badge badge-danger">Недоступно</span>
                {% endif %}
            </div>

            <div class="scope-item {% if 'admin_panel' in granted_scope %}scope-active{% else %}scope-inactive{% endif %}">
                ⚙️ Админ-панель
                {% if 'admin_panel' in granted_scope %}
                <span class="badge badge-success">Доступно</span>
                {% else %}
                <span class="badge badge-danger">Недоступно</span>
                {% endif %}
            </div>
        </div>

        <div class="card">
            <h3>ℹ️ Информация о сессии</h3>
            <p><strong>Токен:</strong> {{ access_token[:20] }}... (хранится в памяти)</p>
            <p><strong>Клиент:</strong> Public (без client_secret)</p>
            <p><strong>Защита:</strong> PKCE</p>
        </div>

        <form method="post" action="/logout">
            <button type="submit">🚪 Выйти</button>
        </form>
    </div>
</body>
</html>
"""


def generate_code_verifier():
    """Генерация code_verifier для PKCE"""
    return secrets.token_urlsafe(32)


def generate_code_challenge(verifier):
    """Генерация code_challenge для PKCE"""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().replace('=', '')


@app.route("/")
def home():
    """Главная страница"""
    session.clear()
    return render_template_string(SCOPE_SELECTION_TEMPLATE)


@app.route("/request_auth", methods=["POST"])
def request_auth():
    """Запрос авторизации с PKCE"""
    requested_scopes = request.form.getlist("scope")
    requested_scope = " ".join(requested_scopes) if requested_scopes else "read_data"

    # Генерируем PKCE
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    # Сохраняем данные
    session_id = secrets.token_urlsafe(16)
    pkce_store[session_id] = {
        "code_verifier": code_verifier,
        "requested_scope": requested_scope,
        "created_at": time.time()
    }

    session["pkce_session_id"] = session_id

    # URL авторизации
    auth_url = (
        f"{AUTH_SERVER}/authorize?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope={requested_scope}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )

    return redirect(auth_url)


@app.route("/callback")
def callback():
    """Обработка callback от сервера авторизации"""
    code = request.args.get("code")
    if not code:
        return "❌ Отсутствует код авторизации", 400

    # Получаем PKCE данные
    session_id = session.get("pkce_session_id")
    if not session_id or session_id not in pkce_store:
        return "❌ Сессия устарела", 400

    pkce_data = pkce_store[session_id]
    code_verifier = pkce_data["code_verifier"]

    # Удаляем использованные данные
    del pkce_store[session_id]
    session.pop("pkce_session_id", None)

    try:
        # Обмениваем код на токен
        token_response = requests.post(
            f"{AUTH_SERVER}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": code_verifier
            },
            timeout=10
        )

        if token_response.status_code != 200:
            return f"❌ Ошибка получения токена: {token_response.text}", 400

        token_data = token_response.json()

        # Получаем информацию о пользователе из токена
        (is_valid, token_info)=validate_token(token_data["access_token"])
        if not is_valid:
            return "❌ Ошибка проверки токена", 400


        # Сохраняем в сессии только необходимые данные
        session["access_token"] = token_data["access_token"]
        session["user_id"] = token_info.get("user_id", "unknown")
        session["granted_scope"] = token_info.get("scope", [])

        return redirect(url_for("dashboard"))

    except requests.exceptions.RequestException as e:
        return f"❌ Ошибка соединения: {e}", 500


def validate_token(token):
    """Проверяет токен через сервер авторизации"""
    try:
        response = requests.post(
            f"{AUTH_SERVER}/verify_token",
            data={"token": token},
            timeout=3
        )
        return response.status_code == 200, response.json() if response.status_code == 200 else None
    except:
        return False, None


@app.route("/dashboard")
def dashboard():
    if "access_token" not in session:
        return redirect(url_for("home"))

    # Проверяем токен
    is_valid, token_info = validate_token(session["access_token"])
    if not is_valid or not token_info.get("valid"):
        session.clear()
        return redirect(url_for("home"))

    return render_template_string(
        DASHBOARD_TEMPLATE,
        user_id=token_info.get("user_id", "unknown"),
        granted_scope=token_info.get("scope", []),
        access_token=session["access_token"]
    )


@app.route("/logout", methods=["POST"])
def logout():
    """Выход из системы"""
    session.clear()
    return redirect(url_for("home"))


@app.before_request
def cleanup_pkce_store():
    """Очистка устаревших PKCE данных"""
    current_time = time.time()
    for key in list(pkce_store.keys()):
        if current_time - pkce_store[key]["created_at"] > 300:  # 5 минут
            del pkce_store[key]


if __name__ == "__main__":
    app.run(port=5003, debug=True)