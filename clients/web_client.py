#!/usr/bin/env python3
"""
OAuth 2.0 Web Client with JWT Support

Этот клиент демонстрирует полный OAuth 2.0 Authorization Code Flow с PKCE,
JWT токенами и защитой от CSRF с помощью state параметра.

Особенности:
- Authorization Code Flow с PKCE (RFC 7636)
- JWT access tokens и refresh tokens
- Защита от CSRF с помощью state параметра
- Автоматическое обновление токенов
- Валидация JWT на клиенте
- Полная документация и обработка ошибок

Endpoints:
- / - Выбор scope для авторизации
- /request_auth - Инициация OAuth flow
- /callback - Обработка callback от auth server
- /dashboard - Защищенный дашборд пользователя
- /refresh - Обновление access token
- /logout - Выход и отзыв токенов
"""

import json
from flask import Flask, request, redirect, url_for, session, render_template_string
import requests
import secrets
import hashlib
import base64
import time
import jwt
import datetime
from typing import Dict, List, Optional, Tuple, Any

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# =============================================================================
# КОНФИГУРАЦИЯ КЛИЕНТА
# =============================================================================

# OAuth 2.0 конфигурация
AUTH_SERVER = "http://127.0.0.1:5000"  # URL сервера авторизации
CLIENT_ID = "web_app"  # Идентификатор клиента
CLIENT_SECRET = "web_secret_123"  # Секрет клиента (для confidential client)
REDIRECT_URI = "http://127.0.0.1:5003/callback"  # URI для callback

# JWT конфигурация (должна совпадать с auth server)
JWT_CONFIG = {
    "algorithm": "HS256",  # Алгоритм подписи JWT
    "issuer": "oauth2-auth-server",  # Issuer claim
    "audience": "resource-server"  # Audience claim
}

# Временное хранилище для PKCE данных и state
# Формат: {session_id: {code_verifier, requested_scope, state, created_at}}
pkce_store: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

def generate_code_verifier() -> str:
    """
    Генерирует cryptographically random code_verifier для PKCE.

    Returns:
        str: Случайная URL-safe строка длиной 43 символа
    """
    return secrets.token_urlsafe(32)


def generate_code_challenge(verifier: str) -> str:
    """
    Генерирует code_challenge из code_verifier используя SHA-256.

    Args:
        verifier: Сгенерированный code_verifier

    Returns:
        str: Base64url-encoded SHA-256 хэш verifier
    """
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().replace('=', '')


def generate_state_parameter() -> str:
    """
    Генерирует cryptographically random state параметр для CSRF защиты.

    Returns:
        str: Случайная URL-safe строка длиной 16 символов
    """
    return secrets.token_urlsafe(16)


def validate_jwt_token(token: str) -> Tuple[bool, Optional[dict]]:
    """
    Проверяет JWT токен локально (без проверки подписи, только структура).

    Args:
        token: JWT токен для проверки

    Returns:
        Tuple[bool, Optional[dict]]:
            - True и payload если токен валиден
            - False и error message если токен невалиден
    """
    try:
        # Декодируем JWT без проверки подписи для извлечения данных
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=[JWT_CONFIG["algorithm"]]
        )

        # Проверяем expiration claim
        if "exp" in payload and payload["exp"] < datetime.datetime.utcnow().timestamp():
            return False, {"error": "Token expired"}

        return True, payload

    except jwt.InvalidTokenError as e:
        return False, {"error": f"Invalid token: {str(e)}"}


def refresh_access_token() -> bool:
    """
    Обновляет access token с помощью refresh token.

    Returns:
        bool: True если токен успешно обновлен, False в случае ошибки
    """
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

            # Сохраняем новые токены в сессии
            session["access_token"] = token_data["access_token"]
            session["granted_scope"] = token_data.get("scope", "").split()

            # Обновляем refresh token если он был возвращен
            if "refresh_token" in token_data:
                session["refresh_token"] = token_data["refresh_token"]

            # Обновляем информацию из JWT payload
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
    <title>OAuth Client - Выбор прав доступа</title>
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
        <p style="text-align: center; color: #666; margin-bottom: 30px;">
            Выберите права доступа для вашего приложения
        </p>

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
    <title>Профиль пользователя - OAuth Client</title>
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
    """
    Главная страница клиента.

    Показывает форму выбора scope для авторизации.
    Очищает сессию при каждом посещении.

    Returns:
        rendered template: HTML форму выбора scope
    """
    session.clear()
    return render_template_string(SCOPE_SELECTION_TEMPLATE)


@app.route("/request_auth", methods=["POST"])
def request_auth():
    """
    Инициирует OAuth 2.0 Authorization Code flow с PKCE и state.

    Генерирует PKCE пару (code_verifier + code_challenge) и state параметр,
    затем перенаправляет пользователя на сервер авторизации.

    Returns:
        redirect: Перенаправление на auth server с необходимыми параметрами
    """
    # Получаем выбранные пользователем scopes
    requested_scopes = request.form.getlist("scope")
    requested_scope = " ".join(requested_scopes) if requested_scopes else "read_data"

    # Генерируем PKCE пару (code_verifier + code_challenge)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    # Генерируем случайный state параметр для CSRF защиты
    state = generate_state_parameter()

    # Сохраняем данные для последующей проверки в callback
    session_id = secrets.token_urlsafe(16)
    pkce_store[session_id] = {
        "code_verifier": code_verifier,
        "requested_scope": requested_scope,
        "state": state,  # Сохраняем state для проверки в callback
        "created_at": time.time()
    }

    # Сохраняем ID сессии для последующего извлечения данных
    session["pkce_session_id"] = session_id

    # Формируем URL для авторизации со всеми необходимыми параметрами
    auth_url = (
        f"{AUTH_SERVER}/authorize?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope={requested_scope}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256&"
        f"state={state}"  # ✅ Добавляем state параметр для CSRF защиты
    )

    return redirect(auth_url)


@app.route("/callback")
def callback():
    """
    Callback endpoint - обрабатывает ответ от сервера авторизации.

    Проверяет state параметр (CSRF защита), обменивает authorization code
    на access token и refresh token, сохраняет токены в сессии.

    Returns:
        redirect: Перенаправление на dashboard или ошибку
    """
    # Получаем параметры из callback URL
    code = request.args.get("code")
    error = request.args.get("error")
    received_state = request.args.get("state")  # Получаем state из callback

    # Обработка ошибок авторизации
    if error:
        return f"❌ Ошибка авторизации: {error}", 400

    if not code:
        return "❌ Отсутствует код авторизации", 400

    # Получаем сохраненные PKCE данные из временного хранилища
    session_id = session.get("pkce_session_id")
    if not session_id or session_id not in pkce_store:
        return "❌ Сессия устарела или не найдена", 400

    pkce_data = pkce_store[session_id]
    code_verifier = pkce_data["code_verifier"]
    saved_state = pkce_data.get("state")  # Получаем сохраненный state

    # ✅ КРИТИЧЕСКАЯ ПРОВЕРКА: Сравниваем полученный state с сохраненным
    if received_state != saved_state:
        # Очищаем данные и возвращаем ошибку CSRF
        del pkce_store[session_id]
        session.pop("pkce_session_id", None)
        return "❌ Обнаружена CSRF атака: несовпадение state параметра", 400

    # Удаляем использованные PKCE данные (одноразовое использование)
    del pkce_store[session_id]
    session.pop("pkce_session_id", None)

    try:
        # Обмениваем authorization code на токены
        token_response = requests.post(
            f"{AUTH_SERVER}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": code_verifier  # PKCE verification
            },
            timeout=10
        )

        # Обработка ошибок от сервера токенов
        if token_response.status_code != 200:
            error_data = token_response.json()
            return f"❌ Ошибка получения токенов: {error_data.get('error', 'Unknown error')}", 400

        # Парсим успешный ответ с токенами
        token_data = token_response.json()

        # Сохраняем токены и метаданные в сессии
        session["access_token"] = token_data["access_token"]
        session["refresh_token"] = token_data.get("refresh_token", "")
        session["granted_scope"] = token_data.get("scope", "").split()

        # Декодируем JWT для получения дополнительной информации
        is_valid, jwt_payload = validate_jwt_token(token_data["access_token"])
        if is_valid:
            session["user_id"] = jwt_payload.get("sub", "unknown")
            session["token_expiry"] = jwt_payload.get("exp", 0)
        else:
            # Устанавливаем значения по умолчанию если JWT невалиден
            session["user_id"] = "unknown"
            session["token_expiry"] = 0

        # Перенаправляем пользователя на защищенный дашборд
        return redirect(url_for("dashboard"))

    except requests.exceptions.RequestException as e:
        # Обработка сетевых ошибок
        return f"❌ Ошибка соединения с сервером авторизации: {e}", 500
    except Exception as e:
        # Обработка непредвиденных ошибок
        return f"❌ Непредвиденная ошибка: {e}", 500


@app.route("/dashboard")
def dashboard():
    """
    Дашборд пользователя - токен уже проверен в before_request
    """
    from flask import g

    # Данные уже проверены, просто используем их
    jwt_payload = getattr(g, 'jwt_payload', {})
    access_token = getattr(g, 'access_token', '')

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
        access_token=access_token,
        refresh_token=session.get("refresh_token", ""),
        token_expiry=token_expiry,
        jwt_payload=formatted_jwt_payload
    )


@app.route("/refresh")
def refresh_token_page():
    """
    Endpoint для ручного обновления access token.

    Returns:
        redirect: Перенаправление на dashboard или home
    """
    if refresh_access_token():
        return redirect(url_for("dashboard"))
    else:
        session.clear()
        return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
def logout():
    """
    Выход из системы с отзывом токенов на сервере авторизации.

    Отзывает как access token, так и refresh token, затем очищает сессию.

    Returns:
        redirect: Перенаправление на главную страницу
    """
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")

    # Пытаемся отозвать access token на сервере авторизации
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
        except requests.exceptions.RequestException:
            # Игнорируем ошибки отзыва (лучше попытаться, чем не пытаться)
            pass

    # Пытаемся отозвать refresh token на сервере авторизации
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
        except requests.exceptions.RequestException:
            # Игнорируем ошибки отзыва
            pass

    # Полностью очищаем сессию клиента
    session.clear()
    return redirect(url_for("home"))


# =============================================================================
# УТИЛИТЫ И ОЧИСТКА
# =============================================================================

@app.before_request
def cleanup_pkce_store():
    """
    Очистка устаревших PKCE данных с TTL 5 минут.

    Выполняется перед каждым запросом для поддержания чистоты хранилища.
    """
    current_time = time.time()

    # Находим все ключи с истекшим временем жизни
    keys_to_delete = [k for k, v in pkce_store.items()
                      if current_time - v["created_at"] > 300]  # 5 минут

    # Удаляем устаревшие данные
    for key in keys_to_delete:
        del pkce_store[key]


@app.before_request
def check_token_validity():
    """
    Проверяет валидность токена перед защищенными запросами.
    """
    protected_routes = ["/dashboard", "/refresh"]

    if request.path in protected_routes:
        access_token = session.get("access_token")

        # Если нет токена - сразу на главную
        if not access_token:
            session.clear()
            return redirect(url_for("home"))

        # Проверяем валидность токена с помощью СУЩЕСТВУЮЩЕЙ функции
        is_valid, jwt_payload = validate_jwt_token(access_token)

        # Если токен невалиден, пытаемся обновить
        if not is_valid:
            if not refresh_access_token():
                session.clear()
                return redirect(url_for("home"))
            else:
                # После обновления получаем новый payload
                access_token = session["access_token"]
                is_valid, jwt_payload = validate_jwt_token(access_token)

        # Сохраняем данные токена для использования в route
        from flask import g
        g.jwt_payload = jwt_payload
        g.access_token = access_token


# =============================================================================
# ЗАПУСК КЛИЕНТА
# =============================================================================

if __name__ == "__main__":
    print("🚀 Запуск OAuth 2.0 Web Client с JWT поддержкой...")
    print("📍 Клиент доступен по: http://127.0.0.1:5003")
    print("🔐 Используемые технологии:")
    print("   - OAuth 2.0 Authorization Code Flow с PKCE")
    print("   - JWT Access Tokens + Refresh Tokens")
    print("   - State параметр для CSRF защиты")
    print("   - Автоматическое обновление токенов")
    print("")
    print("📋 Доступные endpoints:")
    print("   GET  /              - Выбор scope для авторизации")
    print("   POST /request_auth  - Инициация OAuth flow")
    print("   GET  /callback      - Callback от auth server")
    print("   GET  /dashboard     - Защищенный дашборд")
    print("   GET  /refresh       - Обновление токена")
    print("   POST /logout        - Выход и отзыв токенов")
    print("")
    print("⚡ Web Client готов к работе!")

    # Запуск Flask приложения
    app.run(port=5003, debug=True)