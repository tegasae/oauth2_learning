from flask import Flask, request, jsonify, redirect, render_template_string
import secrets
import time
import hashlib
import base64
import jwt
import datetime
from typing import Dict, List, Optional, Tuple

app = Flask(__name__)
app.secret_key = "super-secret-jwt-key-2024"  # Для JWT подписи

# =============================================================================
# КОНФИГУРАЦИЯ И НАСТРОЙКИ
# =============================================================================

# JWT конфигурация
JWT_CONFIG = {
    "algorithm": "HS256",
    "access_token_expiry": datetime.timedelta(minutes=15),  # 15 минут
    "refresh_token_expiry": datetime.timedelta(days=7),  # 7 дней
    "issuer": "oauth2-auth-server",
    "audience": "resource-server"
}

# Данные клиентов (OAuth 2.0 clients)
clients = {
    "web_app": {
        "secret": "web_secret_123",
        "scopes": ["read_data", "write_data", "admin_panel"],
        "name": "Веб-приложение",
        "type": "confidential",
        "redirect_uris": ["http://127.0.0.1:5003/callback"]
    },
    "mobile_app": {
        "secret": "mobile_secret_456",
        "scopes": ["read_data"],
        "name": "Мобильное приложение",
        "type": "public",
        "redirect_uris": ["http://127.0.0.1:5004/callback"]
    }
}

# Пользователи системы
users = {
    "alice": {
        "password": "password123",
        "scopes": ["read_data", "write_data", "admin_panel"],
        "name": "Алиса (Администратор)"
    },
    "bob": {
        "password": "password456",
        "scopes": ["read_data"],
        "name": "Боб (Пользователь)"
    }
}

# Хранилища данных
authorization_codes = {}  # Коды авторизации {code: data}
refresh_tokens = {}  # Refresh tokens {token: data}
revoked_tokens = set()  # Отозванные токены (blacklist)
auth_requests = {}  # Временные токены для авторизационных запросов {token: data}


# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

def generate_token() -> str:
    """Генерирует случайный токен для refresh tokens и authorization codes"""
    return secrets.token_urlsafe(32)


def validate_pkce(code_verifier: str, stored_challenge: str, challenge_method: str) -> bool:
    """
    Проверяет PKCE code_verifier против stored_challenge

    Args:
        code_verifier: Секретная строка от клиента
        stored_challenge: Challenge из authorization code
        challenge_method: Метод хеширования (S256 или plain)

    Returns:
        bool: True если верификация успешна
    """
    if not stored_challenge or not code_verifier:
        return False

    if challenge_method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        calculated_challenge = base64.urlsafe_b64encode(digest).decode().replace('=', '')
        return calculated_challenge == stored_challenge
    elif challenge_method == "plain":
        return code_verifier == stored_challenge
    else:
        return False


def create_access_token(user_id: str, client_id: str, scopes: List[str]) -> str:
    """
    Создает JWT access token

    Args:
        user_id: ID пользователя
        client_id: ID клиента
        scopes: Список прав доступа

    Returns:
        str: JWT токен
    """
    now = datetime.datetime.utcnow()

    payload = {
        "sub": user_id,  # Subject (пользователь)
        "client_id": client_id,  # Клиентское приложение
        "scopes": scopes,  # Права доступа
        "iat": now,  # Issued at
        "exp": now + JWT_CONFIG["access_token_expiry"],  # Expiration
        "iss": JWT_CONFIG["issuer"],  # Issuer
        "aud": JWT_CONFIG["audience"],  # Audience
        "jti": secrets.token_urlsafe(16),  # Unique token ID
        "type": "access"  # Token type
    }

    return jwt.encode(payload, app.secret_key, algorithm=JWT_CONFIG["algorithm"])


def create_refresh_token(user_id: str, client_id: str, scopes: List[str]) -> Tuple[str, dict]:
    """
    Создает refresh token (не-JWT, хранится в базе)

    Args:
        user_id: ID пользователя
        client_id: ID клиента
        scopes: Список прав доступа

    Returns:
        Tuple[str, dict]: (refresh_token, token_data)
    """
    token = generate_token()
    now = time.time()

    token_data = {
        "user_id": user_id,
        "client_id": client_id,
        "scopes": scopes,
        "created_at": now,
        "expires_at": now + JWT_CONFIG["refresh_token_expiry"].total_seconds(),
        "last_used": None
    }

    refresh_tokens[token] = token_data
    return token, token_data


def verify_jwt_token(token: str) -> Tuple[bool, Optional[dict]]:
    """
    Проверяет JWT access token

    Args:
        token: JWT токен для проверки

    Returns:
        Tuple[bool, Optional[dict]]: (is_valid, payload_or_error)
    """
    try:
        # Проверяем отозванные токены
        if token in revoked_tokens:
            return False, {"error": "Token revoked"}

        # Декодируем и проверяем JWT
        payload = jwt.decode(
            token,
            app.secret_key,
            algorithms=[JWT_CONFIG["algorithm"]],
            issuer=JWT_CONFIG["issuer"],
            audience=JWT_CONFIG["audience"]
        )

        # Дополнительная проверка типа токена
        if payload.get("type") != "access":
            return False, {"error": "Invalid token type"}

        return True, payload

    except jwt.ExpiredSignatureError:
        return False, {"error": "Token expired"}
    except jwt.InvalidTokenError as e:
        return False, {"error": f"Invalid token: {str(e)}"}


def verify_refresh_token(token: str) -> Tuple[bool, Optional[dict]]:
    """
    Проверяет refresh token

    Args:
        token: Refresh token для проверки

    Returns:
        Tuple[bool, Optional[dict]]: (is_valid, token_data_or_error)
    """
    if token not in refresh_tokens:
        return False, {"error": "Invalid refresh token"}

    token_data = refresh_tokens[token]

    # Проверяем срок действия
    if time.time() > token_data["expires_at"]:
        del refresh_tokens[token]
        return False, {"error": "Refresh token expired"}

    # Обновляем время последнего использования
    token_data["last_used"] = time.time()

    return True, token_data


# =============================================================================
# HTML ШАБЛОНЫ
# =============================================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Авторизация</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="password"] { 
            width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; 
        }
        button { 
            background: #007bff; color: white; padding: 10px 20px; 
            border: none; border-radius: 4px; cursor: pointer; 
        }
        .info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .error { 
            background: #ffe6e6; 
            color: #dc3545; 
            padding: 15px; 
            border-radius: 4px; 
            margin: 20px 0;
            border-left: 4px solid #dc3545;
        }
    </style>
</head>
<body>
    <h2>🔐 Авторизация</h2>

    {% if error_message %}
    <div class="error">
        <strong>❌ Ошибка:</strong> {{ error_message }}
    </div>
    {% endif %}

    <div class="info">
        <strong>Приложение:</strong> {{ client_name }}<br>
        <strong>Запрашиваемые права:</strong> {{ requested_scope }}
    </div>

    <form method="POST" action="/login_approve">
        <input type="hidden" name="auth_token" value="{{ auth_token }}">
        <input type="hidden" name="client_id" value="{{ client_id }}">
        <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
        <input type="hidden" name="requested_scope" value="{{ requested_scope_str }}">
        <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
        <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">
        {% if state %}
        <input type="hidden" name="state" value="{{ state }}">
        {% endif %}

        <div class="form-group">
            <label>Логин:</label>
            <input type="text" name="username" required>
        </div>

        <div class="form-group">
            <label>Пароль:</label>
            <input type="password" name="password" required>
        </div>

        <button type="submit">Войти</button>
    </form>

    <div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
        <strong>Тестовые пользователи:</strong><br>
        👩‍💼 <strong>alice</strong> / password123 (Админ: все права)<br>
        👨‍💼 <strong>bob</strong> / password456 (Пользователь: только чтение)
    </div>
</body>
</html>
"""


# =============================================================================
# OAUTH 2.0 ENDPOINTS
# =============================================================================

@app.route("/")
def home():
    """Главная страница сервера авторизации"""
    stats_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth2 Сервер авторизации</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; }}
            .card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <h1>🚀 OAuth2 Сервер авторизации (JWT)</h1>

        <div class="card">
            <h2>📊 Статистика системы</h2>
            <p>Зарегистрированных клиентов: <strong>{len(clients)}</strong></p>
            <p>Пользователей: <strong>{len(users)}</strong></p>
            <p>Активных кодов авторизации: <strong>{len(authorization_codes)}</strong></p>
            <p>Активных refresh токенов: <strong>{len(refresh_tokens)}</strong></p>
            <p>Отозванных токенов: <strong>{len(revoked_tokens)}</strong></p>
            <p>Активных auth запросов: <strong>{len(auth_requests)}</strong></p>
        </div>

        <div class="card">
            <h2>🔧 Доступные endpoints</h2>
            <ul>
                <li><code>GET /authorize</code> - Страница авторизации</li>
                <li><code>POST /token</code> - Получение токенов (JWT)</li>
                <li><code>POST /verify_token</code> - Проверка JWT токена</li>
                <li><code>POST /revoke</code> - Отзыв токена</li>
                <li><code>POST /refresh</code> - Обновление токенов</li>
            </ul>
        </div>

        <div class="card">
            <h2>👥 Тестовые пользователи</h2>
            <ul>
                <li><strong>alice</strong> / password123 (Админ - все права)</li>
                <li><strong>bob</strong> / password456 (Пользователь - только чтение)</li>
            </ul>
        </div>
    </body>
    </html>
    """
    return stats_html


@app.route("/authorize", methods=["GET"])
def authorize():
    """
    OAuth 2.0 Authorization Endpoint
    Возвращает HTML форму для аутентификации пользователя
    """
    # Извлекаем параметры из запроса
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    requested_scope = request.args.get("scope", "").split()
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method", "plain")
    state = request.args.get("state")

    # Валидация параметров
    if not client_id or not redirect_uri:
        return "❌ Неверные параметры: client_id и redirect_uri обязательны", 400

    if client_id not in clients:
        return "❌ Неизвестный client_id", 400

    client = clients[client_id]

    # Проверка PKCE для public clients
    if client["type"] == "public" and not code_challenge:
        return "❌ Публичные клиенты должны использовать PKCE", 400

    # Проверка разрешенных scopes
    invalid_scopes = [s for s in requested_scope if s not in client["scopes"]]
    if invalid_scopes:
        return f"❌ Неподдерживаемые scope: {', '.join(invalid_scopes)}", 400

    # Генерируем одноразовый токен для этого запроса авторизации
    auth_token = generate_token()

    # Сохраняем данные авторизации
    auth_requests[auth_token] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "requested_scope": requested_scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": state,
        "timestamp": time.time()
    }

    # Показываем форму авторизации
    return render_template_string(
        LOGIN_TEMPLATE,
        auth_token=auth_token,
        client_id=client_id,
        client_name=client["name"],
        redirect_uri=redirect_uri,
        requested_scope=requested_scope,
        requested_scope_str=" ".join(requested_scope),
        code_challenge=code_challenge or "",
        code_challenge_method=code_challenge_method,
        state=state or ""
    )


@app.route("/login_approve", methods=["POST"])
def login_approve():
    """
    Обработка формы авторизации
    Создает authorization code и перенаправляет на redirect_uri
    """
    try:
        # Получаем auth token из формы
        auth_token = request.form["auth_token"]

        # Проверяем существование и валидность auth token
        if auth_token not in auth_requests:
            return "❌ Недействительный запрос авторизации", 400

        auth_data = auth_requests[auth_token]

        # Проверяем время жизни запроса (5 минут)
        if time.time() - auth_data["timestamp"] > 300:
            del auth_requests[auth_token]
            return "❌ Запрос авторизации устарел", 400

        # Извлекаем данные
        client_id = auth_data["client_id"]
        redirect_uri = auth_data["redirect_uri"]
        requested_scope = auth_data["requested_scope"]
        code_challenge = auth_data["code_challenge"]
        code_challenge_method = auth_data["code_challenge_method"]
        state = auth_data["state"]

        # Получаем учетные данные из формы
        username = request.form["username"]
        password = request.form["password"]

        # Аутентификация пользователя
        if username not in users or users[username]["password"] != password:
            return render_template_string(
                LOGIN_TEMPLATE,
                auth_token=auth_token,
                client_id=client_id,
                client_name=clients[client_id]["name"],
                redirect_uri=redirect_uri,
                requested_scope=requested_scope,
                requested_scope_str=" ".join(requested_scope),
                code_challenge=code_challenge or "",
                code_challenge_method=code_challenge_method,
                state=state or "",
                error_message="Неверный логин или пароль"
            ), 401

        # Проверка прав доступа
        user_scopes = users[username]["scopes"]
        allowed_scope = [s for s in requested_scope if s in user_scopes]
        if not allowed_scope:
            return render_template_string(
                LOGIN_TEMPLATE,
                auth_token=auth_token,
                client_id=client_id,
                client_name=clients[client_id]["name"],
                redirect_uri=redirect_uri,
                requested_scope=requested_scope,
                requested_scope_str=" ".join(requested_scope),
                code_challenge=code_challenge or "",
                code_challenge_method=code_challenge_method,
                state=state or "",
                error_message="У пользователя нет запрашиваемых прав"
            ), 403

        # Создаем authorization code
        code = generate_token()
        authorization_codes[code] = {
            "client_id": client_id,
            "user_id": username,
            "scope": allowed_scope,
            "expires_at": time.time() + 300,  # 5 минут
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "redirect_uri": redirect_uri,
            "state": state
        }

        # Удаляем использованный auth token
        del auth_requests[auth_token]

        # Формируем URL для redirect
        redirect_url = f"{redirect_uri}?code={code}"
        if state:
            redirect_url += f"&state={state}"

        return redirect(redirect_url)

    except KeyError as e:
        return f"❌ Отсутствует обязательный параметр: {e}", 400
    except Exception as e:
        return f"❌ Ошибка сервера: {e}", 500


@app.route("/token", methods=["POST"])
def issue_token():
    """
    OAuth 2.0 Token Endpoint
    Выдает JWT access tokens и refresh tokens
    Поддерживает: authorization_code, password, refresh_token grants
    """
    data = request.form
    grant_type = data.get("grant_type")

    # Authorization Code Grant
    if grant_type == "authorization_code":
        return handle_authorization_code_grant(data)

    # Password Grant
    elif grant_type == "password":
        return handle_password_grant(data)

    # Refresh Token Grant
    elif grant_type == "refresh_token":
        return handle_refresh_token_grant(data)

    else:
        return jsonify({"error": "unsupported_grant_type"}), 400


def handle_authorization_code_grant(data: Dict) -> jsonify:
    """Обработка Authorization Code Grant flow"""
    code = data.get("code")
    client_id = data.get("client_id")
    redirect_uri = data.get("redirect_uri")
    code_verifier = data.get("code_verifier")
    client_secret = data.get("client_secret")

    # Валидация параметров
    if not code or not client_id or not redirect_uri:
        return jsonify({"error": "invalid_request", "error_description": "Missing parameters"}), 400

    if client_id not in clients:
        return jsonify({"error": "invalid_client"}), 401

    # Проверка authorization code
    if code not in authorization_codes:
        return jsonify({"error": "invalid_grant"}), 401

    code_data = authorization_codes[code]

    # Проверка срока действия
    if time.time() > code_data["expires_at"]:
        del authorization_codes[code]
        return jsonify({"error": "invalid_grant", "error_description": "Code expired"}), 401

    # Проверка клиента и redirect_uri
    if code_data["client_id"] != client_id or code_data["redirect_uri"] != redirect_uri:
        return jsonify({"error": "invalid_grant"}), 401

    # Проверка client_secret для confidential clients
    client = clients[client_id]
    if client["type"] == "confidential":
        if not client_secret or client_secret != client["secret"]:
            return jsonify({"error": "invalid_client"}), 401

    # Проверка PKCE
    if code_data.get("code_challenge"):
        if not code_verifier:
            return jsonify({"error": "invalid_grant", "error_description": "code_verifier required"}), 400
        if not validate_pkce(code_verifier, code_data["code_challenge"], code_data["code_challenge_method"]):
            return jsonify({"error": "invalid_grant", "error_description": "PKCE verification failed"}), 400

    # Удаляем использованный код
    del authorization_codes[code]

    # Создаем токены
    access_token = create_access_token(code_data["user_id"], client_id, code_data["scope"])
    refresh_token, refresh_data = create_refresh_token(code_data["user_id"], client_id, code_data["scope"])

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_CONFIG["access_token_expiry"].total_seconds()),
        "refresh_token": refresh_token,
        "scope": " ".join(code_data["scope"])
    })


def handle_password_grant(data: Dict) -> jsonify:
    """Обработка Resource Owner Password Credentials Grant flow"""
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    username = data.get("username")
    password = data.get("password")
    requested_scope = data.get("scope", "").split()

    # Валидация параметров
    if not client_id or not username or not password:
        return jsonify({"error": "invalid_request", "error_description": "Missing parameters"}), 400

    if client_id not in clients:
        return jsonify({"error": "invalid_client"}), 401

    # Проверка client_secret для confidential clients
    client = clients[client_id]
    if client["type"] == "confidential":
        if not client_secret or client_secret != client["secret"]:
            return jsonify({"error": "invalid_client"}), 401

    # Аутентификация пользователя
    if username not in users or users[username]["password"] != password:
        return jsonify({"error": "invalid_grant"}), 401

    # Проверка scopes
    user_scopes = users[username]["scopes"]
    allowed_scope = [s for s in requested_scope if s in user_scopes] if requested_scope else user_scopes

    # Создаем токены
    access_token = create_access_token(username, client_id, allowed_scope)
    refresh_token, refresh_data = create_refresh_token(username, client_id, allowed_scope)

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_CONFIG["access_token_expiry"].total_seconds()),
        "refresh_token": refresh_token,
        "scope": " ".join(allowed_scope)
    })


def handle_refresh_token_grant(data: Dict) -> jsonify:
    """Обработка Refresh Token Grant flow"""
    refresh_token = data.get("refresh_token")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    requested_scope = data.get("scope", "").split()

    if not refresh_token or not client_id:
        return jsonify({"error": "invalid_request", "error_description": "Missing parameters"}), 400

    if client_id not in clients:
        return jsonify({"error": "invalid_client"}), 401

    # Проверка client_secret для confidential clients
    client = clients[client_id]
    if client["type"] == "confidential":
        if not client_secret or client_secret != client["secret"]:
            return jsonify({"error": "invalid_client"}), 401

    # Проверка refresh token
    is_valid, token_data = verify_refresh_token(refresh_token)
    if not is_valid:
        return jsonify({"error": "invalid_grant"}), 401

    # Проверка клиента
    if token_data["client_id"] != client_id:
        return jsonify({"error": "invalid_grant"}), 401

    # Проверка scopes (если запрошены новые)
    if requested_scope:
        # Проверяем что запрошенные scope являются подмножеством оригинальных
        if not all(scope in token_data["scopes"] for scope in requested_scope):
            return jsonify({"error": "invalid_scope"}), 400
        final_scopes = requested_scope
    else:
        final_scopes = token_data["scopes"]

    # Создаем новые токены
    access_token = create_access_token(token_data["user_id"], client_id, final_scopes)

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_CONFIG["access_token_expiry"].total_seconds()),
        "scope": " ".join(final_scopes)
    })


@app.route("/verify_token", methods=["POST"])
def verify_token():
    """
    Проверяет валидность JWT access token
    Возвращает информацию о токене и пользователе
    """
    token = request.form.get("token")
    if not token:
        return jsonify({"valid": False, "error": "Token required"}), 400

    is_valid, result = verify_jwt_token(token)

    if is_valid:
        return jsonify({
            "valid": True,
            "client_id": result["client_id"],
            "user_id": result["sub"],
            "scope": result["scopes"],
            "expires_at": result["exp"]
        })
    else:
        return jsonify({"valid": False, "error": result["error"]}), 401


@app.route("/revoke", methods=["POST"])
def revoke_token():
    """
    Отзывает токен (добавляет в blacklist)
    Поддерживает отзыв как access, так и refresh токенов
    """
    token = request.form.get("token")
    token_type_hint = request.form.get("token_type_hint", "access_token")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    if not token or not client_id:
        return jsonify({"error": "invalid_request"}), 400

    if client_id not in clients:
        return jsonify({"error": "invalid_client"}), 401

    # Проверка client_secret для confidential clients
    client = clients[client_id]
    if client["type"] == "confidential":
        if not client_secret or client_secret != client["secret"]:
            return jsonify({"error": "invalid_client"}), 401

    # Отзыв токена
    if token_type_hint == "refresh_token" and token in refresh_tokens:
        # Проверяем принадлежность refresh token
        if refresh_tokens[token]["client_id"] == client_id:
            del refresh_tokens[token]
            revoked_tokens.add(token)  # Добавляем в blacklist
            return jsonify({"message": "Token revoked successfully"})

    # Для access tokens просто добавляем в blacklist
    revoked_tokens.add(token)

    # Также проверяем, не является ли это refresh token'ом
    if token in refresh_tokens and refresh_tokens[token]["client_id"] == client_id:
        del refresh_tokens[token]

    return jsonify({"message": "Token revoked successfully"})


@app.route("/refresh", methods=["POST"])
def refresh_token():
    """
    Альтернативный endpoint для обновления токенов
    (Дублирует функциональность grant_type=refresh_token в /token)
    """
    return handle_refresh_token_grant(request.form)


# =============================================================================
# УТИЛИТЫ И ОЧИСТКА
# =============================================================================

@app.route("/cleanup", methods=["POST"])
def cleanup():
    """
    Очистка устаревших данных
    Удаляет просроченные authorization codes, refresh tokens и auth requests
    """
    now = time.time()
    expired_codes = 0
    expired_refresh_tokens = 0
    expired_auth_requests = 0

    # Очистка authorization codes
    for code in list(authorization_codes.keys()):
        if authorization_codes[code]["expires_at"] < now:
            del authorization_codes[code]
            expired_codes += 1

    # Очистка refresh tokens
    for token in list(refresh_tokens.keys()):
        if refresh_tokens[token]["expires_at"] < now:
            del refresh_tokens[token]
            expired_refresh_tokens += 1

    # Очистка auth requests
    for token in list(auth_requests.keys()):
        if now - auth_requests[token]["timestamp"] > 300:  # 5 минут
            del auth_requests[token]
            expired_auth_requests += 1

    return jsonify({
        "message": "Cleanup completed",
        "expired_authorization_codes": expired_codes,
        "expired_refresh_tokens": expired_refresh_tokens,
        "expired_auth_requests": expired_auth_requests
    })


@app.before_request
def handle_options():
    """Обработка CORS preflight запросов"""
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        return response


@app.after_request
def after_request(response):
    """Добавляет CORS headers ко всем ответам"""
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    return response

# =============================================================================
# ЗАПУСК СЕРВЕРА
# =============================================================================

if __name__ == "__main__":
    print("🚀 Запуск OAuth 2.0 сервера с JWT поддержкой...")
    print("📍 Сервер авторизации: http://127.0.0.1:5000")
    print("🔐 Алгоритм JWT: HS256")
    print("⏰ Время жизни access token: 15 минут")
    print("🔄 Время жизни refresh token: 7 дней")
    print("🔑 Используется stateless подход без сессий")

    app.run(port=5000, debug=True)