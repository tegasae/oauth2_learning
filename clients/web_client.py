import json

from flask import Flask, request, redirect, url_for, session, render_template_string
import requests
import secrets
import hashlib
import base64
import time
import jwt
import datetime
from typing import Dict, Optional, Tuple

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# =============================================================================
# КОНФИГУРАЦИЯ КЛИЕНТА
# =============================================================================

# OAuth 2.0 конфигурация
AUTH_SERVER = "http://127.0.0.1:5000"
CLIENT_ID = "web_app"
CLIENT_SECRET = "web_secret_123"
REDIRECT_URI = "http://127.0.0.1:5003/callback"

# JWT конфигурация
JWT_CONFIG = {
    "algorithm": "HS256",
    "issuer": "oauth2-auth-server",
    "audience": "resource-server"
}

# Временное хранилище PKCE данных
pkce_store = {}


# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

def generate_code_verifier() -> str:
    """Генерирует code_verifier для PKCE"""
    return secrets.token_urlsafe(32)


def generate_code_challenge(verifier: str) -> str:
    """Генерирует code_challenge из code_verifier"""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().replace('=', '')


def validate_jwt_token(token: str) -> Tuple[bool, Optional[dict]]:
    """Проверяет JWT токен локально"""
    try:
        # Декодируем JWT без проверки подписи для извлечения данных
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=[JWT_CONFIG["algorithm"]]
        )

        # Проверяем expiration
        if "exp" in payload and payload["exp"] < datetime.datetime.utcnow().timestamp():
            return False, {"error": "Token expired"}

        return True, payload

    except jwt.InvalidTokenError as e:
        return False, {"error": f"Invalid token: {str(e)}"}


def refresh_access_token() -> bool:
    """Обновляет access token с помощью refresh token"""
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        return False

    try:
        # Отправляем запрос на обновление токена
        token_response = requests.post(
            f"{AUTH_SERVER}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            },
            timeout=10
        )

        if token_response.status_code == 200:
            token_data = token_response.json()

            # Сохраняем новые токены
            session["access_token"] = token_data["access_token"]
            session["granted_scope"] = token_data.get("scope", "").split()

            # Обновляем refresh token если он был возвращен
            if "refresh_token" in token_data:
                session["refresh_token"] = token_data["refresh_token"]

            # Обновляем информацию из JWT
            is_valid, jwt_payload = validate_jwt_token(token_data["access_token"])
            if is_valid:
                session["user_id"] = jwt_payload.get("sub", "unknown")
                session["token_expiry"] = jwt_payload.get("exp", 0)

            return True
        else:
            return False

    except requests.exceptions.RequestException:
        return False


# =============================================================================
# HTML ШАБЛОНЫ
# =============================================================================

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
            max-width: 800px; 
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
        .token-card {
            border-left: 4px solid #6f42c1;
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
        .token-info {
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            background: #e9ecef;
            padding: 10px;
            border-radius: 4px;
            margin: 5px 0;
        }
        .btn {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            margin: 5px;
            text-decoration: none;
            display: inline-block;
        }
        .btn-danger {
            background: #dc3545;
        }
        .btn-success {
            background: #28a745;
        }
        .btn:hover {
            opacity: 0.9;
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
        .badge-warning {
            background: #ffc107;
            color: black;
        }
        .badge-danger {
            background: #dc3545;
            color: white;
        }
        .jwt-payload {
            background: #e9ecef;
            padding: 15px;
            border-radius: 6px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 12px;
            max-height: 200px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>👤 Профиль пользователя</h2>

        <div class="card user-card">
            <h3>📋 Информация о пользователе</h3>
            <p><strong>👤 Пользователь:</strong> {{ user_id }}</p>
            <p><strong>🏷️ Статус:</strong> 
                {% if 'admin_panel' in granted_scope %}
                <span class="badge badge-success">Администратор</span>
                {% else %}
                <span class="badge">Пользователь</span>
                {% endif %}
            </p>
            <p><strong>🔐 Тип аутентификации:</strong> 
                <span class="badge badge-success">JWT + Refresh Tokens</span>
            </p>
        </div>

        <div class="card scopes-card">
            <h3>🎯 Права доступа (Scopes)</h3>

            <div class="scope-item {% if 'read_data' in granted_scope %}scope-active{% else %}scope-inactive{% endif %}">
                📖 read_data
                {% if 'read_data' in granted_scope %}
                <span class="badge badge-success">Доступно</span>
                {% else %}
                <span class="badge badge-danger">Недоступно</span>
                {% endif %}
            </div>

            <div class="scope-item {% if 'write_data' in granted_scope %}scope-active{% else %}scope-inactive{% endif %}">
                ✏️ write_data
                {% if 'write_data' in granted_scope %}
                <span class="badge badge-success">Доступно</span>
                {% else %}
                <span class="badge badge-danger">Недоступно</span>
                {% endif %}
            </div>

            <div class="scope-item {% if 'admin_panel' in granted_scope %}scope-active{% else %}scope-inactive{% endif %}">
                ⚙️ admin_panel
                {% if 'admin_panel' in granted_scope %}
                <span class="badge badge-success">Доступно</span>
                {% else %}
                <span class="badge badge-danger">Недоступно</span>
                {% endif %}
            </div>
        </div>

        <div class="card token-card">
            <h3>🔑 JWT Access Token</h3>

            <div class="token-info">
                <strong>Полный токен:</strong><br>
                {{ access_token }}
            </div>

            <div class="token-info">
                <strong>Срок действия:</strong> 
                {% if token_expiry %}
                    {{ token_expiry }} минут
                {% else %}
                    Неизвестно
                {% endif %}
            </div>

            <h4>📊 JWT Payload:</h4>
            <div class="jwt-payload">
                {{ jwt_payload }}
            </div>
        </div>

        <div class="card token-card">
            <h3>🔄 Refresh Token</h3>

            <div class="token-info">
                <strong>Токен:</strong><br>
                {{ refresh_token }}
            </div>

            <div style="margin-top: 15px;">
                <a href="/refresh" class="btn btn-success">🔄 Обновить токен</a>
            </div>
        </div>

        <div class="card">
            <h3>⚙️ Управление сессией</h3>

            <form method="post" action="/logout">
                <button type="submit" class="btn btn-danger">🚪 Выйти (Отозвать токены)</button>
            </form>
        </div>
    </div>
</body>
</html>
"""


# =============================================================================
# ROUTES - ОСНОВНЫЕ ЭНДПОИНТЫ
# =============================================================================

@app.route("/")
def home():
    """Главная страница клиента"""
    session.clear()
    return render_template_string(SCOPE_SELECTION_TEMPLATE)


@app.route("/request_auth", methods=["POST"])
def request_auth():
    """Инициирует OAuth 2.0 Authorization Code flow с PKCE"""
    requested_scopes = request.form.getlist("scope")
    requested_scope = " ".join(requested_scopes) if requested_scopes else "read_data"

    # Генерируем PKCE пару
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    # Сохраняем данные для последующей проверки
    session_id = secrets.token_urlsafe(16)
    pkce_store[session_id] = {
        "code_verifier": code_verifier,
        "requested_scope": requested_scope,
        "created_at": time.time()
    }

    session["pkce_session_id"] = session_id

    # Формируем URL для авторизации
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
    """Callback endpoint - обменивает код на токены"""
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        return f"❌ Ошибка авторизации: {error}", 400

    if not code:
        return "❌ Отсутствует код авторизации", 400

    # Получаем сохраненные PKCE данные
    session_id = session.get("pkce_session_id")
    if not session_id or session_id not in pkce_store:
        return "❌ Сессия устарела", 400

    pkce_data = pkce_store[session_id]
    code_verifier = pkce_data["code_verifier"]

    # Удаляем использованные PKCE данные
    del pkce_store[session_id]
    session.pop("pkce_session_id", None)

    try:
        # Обмениваем код на токены
        token_response = requests.post(
            f"{AUTH_SERVER}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": code_verifier
            },
            timeout=10
        )

        if token_response.status_code != 200:
            return f"❌ Ошибка получения токенов: {token_response.text}", 400

        token_data = token_response.json()

        # Сохраняем токены в сессии
        session["access_token"] = token_data["access_token"]
        session["refresh_token"] = token_data.get("refresh_token", "")
        session["granted_scope"] = token_data.get("scope", "").split()

        # Декодируем JWT для получения информации
        is_valid, jwt_payload = validate_jwt_token(token_data["access_token"])
        if is_valid:
            session["user_id"] = jwt_payload.get("sub", "unknown")
            session["token_expiry"] = jwt_payload.get("exp", 0)
        else:
            session["user_id"] = "unknown"
            session["token_expiry"] = 0

        return redirect(url_for("dashboard"))

    except requests.exceptions.RequestException as e:
        return f"❌ Ошибка соединения: {e}", 500


@app.route("/dashboard")
def dashboard():
    """Дашборд пользователя с информацией о токенах"""
    # Проверяем наличие access token
    access_token = session.get("access_token")
    if not access_token:
        return redirect(url_for("home"))

    # Проверяем валидность токена
    is_valid, jwt_payload = validate_jwt_token(access_token)
    if not is_valid:
        # Пытаемся обновить токен
        if not refresh_access_token():
            session.clear()
            return redirect(url_for("home"))
        else:
            # Повторно получаем данные после обновления
            access_token = session["access_token"]
            is_valid, jwt_payload = validate_jwt_token(access_token)

    # Рассчитываем оставшееся время действия токена
    token_expiry = None
    if jwt_payload and "exp" in jwt_payload:
        expiry_time = datetime.datetime.fromtimestamp(jwt_payload["exp"])
        time_left = expiry_time - datetime.datetime.now()
        token_expiry = max(0, int(time_left.total_seconds() // 60))

    # Форматируем JWT payload для отображения
    formatted_jwt_payload = json.dumps(jwt_payload, indent=2, ensure_ascii=False) if jwt_payload else "{}"

    return render_template_string(
        DASHBOARD_TEMPLATE,
        user_id=session.get("user_id", "unknown"),
        granted_scope=session.get("granted_scope", []),
        access_token=session.get("access_token", ""),
        refresh_token=session.get("refresh_token", ""),
        token_expiry=token_expiry,
        jwt_payload=formatted_jwt_payload
    )


@app.route("/refresh")
def refresh_token_page():
    """Обновляет access token"""
    if refresh_access_token():
        return redirect(url_for("dashboard"))
    else:
        session.clear()
        return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
def logout():
    """Выход из системы с отзывом токенов"""
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")

    # Пытаемся отозвать токены на сервере
    if access_token:
        try:
            requests.post(
                f"{AUTH_SERVER}/revoke",
                data={
                    "token": access_token,
                    "token_type_hint": "access_token",
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET
                },
                timeout=5
            )
        except:
            pass

    if refresh_token:
        try:
            requests.post(
                f"{AUTH_SERVER}/revoke",
                data={
                    "token": refresh_token,
                    "token_type_hint": "refresh_token",
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET
                },
                timeout=5
            )
        except:
            pass

    # Очищаем сессию
    session.clear()
    return redirect(url_for("home"))


# =============================================================================
# УТИЛИТЫ И ОЧИСТКА
# =============================================================================

@app.before_request
def cleanup_pkce_store():
    """Очистка устаревших PKCE данных с TTL 5 минут"""
    current_time = time.time()

    # Создаем список ключей для удаления
    keys_to_delete = [k for k, v in pkce_store.items()
                      if current_time - v["created_at"] > 300]

    # Удаляем все устаревшие ключи
    for key in keys_to_delete:
        del pkce_store[key]


@app.before_request
def check_token_validity():
    """Проверяет валидность токена перед защищенными запросами"""
    protected_routes = ["/dashboard", "/refresh"]

    if request.path in protected_routes:
        access_token = session.get("access_token")
        if not access_token:
            return redirect(url_for("home"))

        # Проверяем токен
        is_valid, _ = validate_jwt_token(access_token)
        if not is_valid:
            # Пытаемся обновить
            if not refresh_access_token():
                session.clear()
                return redirect(url_for("home"))


# =============================================================================
# ЗАПУСК КЛИЕНТА
# =============================================================================

if __name__ == "__main__":
    print("🚀 Запуск OAuth 2.0 клиента с JWT поддержкой...")
    print("📍 Клиент доступен по: http://127.0.0.1:5003")
    print("🔐 Использует JWT + Refresh Tokens + PKCE")

    app.run(port=5003, debug=True)