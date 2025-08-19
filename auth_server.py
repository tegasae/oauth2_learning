from flask import Flask, request, jsonify, redirect, render_template_string
import secrets
import time
import hashlib
import base64

app = Flask(__name__)

# Данные клиентов
clients = {
    "web_app": {
        "secret": "web_secret_123",
        "scopes": ["read_data", "write_data", "admin_panel"],
        "name": "Веб-приложение",
        "type": "public"  # Может хранить секрет
    },
    "mobile_app": {
        "secret": "mobile_secret_456",
        "scopes": ["read_data"],
        "name": "Мобильное приложение",
        "type": "public"  # Не должен использовать секрет в запросах
    }
}

# Пользователи с разными правами
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

# Хранилища
tokens = {}
authorization_codes = {}
revoked_tokens = set()


def generate_token():
    return secrets.token_urlsafe(32)


def validate_pkce(code_verifier, stored_challenge, challenge_method):
    """Проверяет PKCE code_verifier против stored_challenge"""
    if not stored_challenge or not code_verifier:
        return False

    if challenge_method == "S256":
        # Вычисляем хеш от code_verifier
        digest = hashlib.sha256(code_verifier.encode()).digest()
        calculated_challenge = base64.urlsafe_b64encode(digest).decode().replace('=', '')
        return calculated_challenge == stored_challenge
    elif challenge_method == "plain":
        # Простое сравнение (менее безопасно)
        return code_verifier == stored_challenge
    else:
        return False


# HTML шаблоны (остаются без изменений)
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
    </style>
</head>
<body>
    <h2>🔐 Авторизация</h2>

    <div class="info">
        <strong>Приложение:</strong> {{ client_name }}<br>
        <strong>Запрашиваемые права:</strong> {{ requested_scope }}
    </div>

    <form method="POST" action="/login_approve">
        <input type="hidden" name="client_id" value="{{ client_id }}">
        <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
        <input type="hidden" name="requested_scope" value="{{ requested_scope_str }}">
        <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
        <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">

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

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Админ-панель</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h2>⚙️ Админ-панель управления токенами</h2>

    <div class="stats">
        <div class="stat-card">
            <h3>📊 Статистика</h3>
            <p>Активных токенов: <strong>{{ active_count }}</strong></p>
            <p>Отозванных токенов: <strong>{{ revoked_count }}</strong></p>
        </div>
    </div>

    <h3>🔑 Активные токены</h3>
    {% if tokens_list %}
    <table>
        <tr>
            <th>Токен (первые 10 символов)</th>
            <th>Пользователь</th>
            <th>Клиент</th>
            <th>Права</th>
            <th>Действия</th>
        </tr>
        {% for token, data in tokens_list %}
        <tr>
            <td><code>{{ token[:10] }}...</code></td>
            <td>{{ data.user_id }}</td>
            <td>{{ data.client_id }}</td>
            <td>{{ data.scope }}</td>
            <td>
                <form method="post" action="/admin/revoke" style="display: inline;">
                    <input type="hidden" name="token" value="{{ token }}">
                    <button type="submit" style="background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer;">
                        Отозвать
                    </button>
                </form>
            </td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p>Нет активных токенов</p>
    {% endif %}

    <h3>🚫 Отозванные токены</h3>
    <p>Всего отозвано: {{ revoked_count }}</p>

    <div style="margin-top: 30px;">
        <a href="/">← На главную</a>
    </div>
</body>
</html>
"""


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
        <h1>🚀 OAuth2 Сервер авторизации</h1>

        <div class="card">
            <h2>📊 Статистика системы</h2>
            <p>Зарегистрированных клиентов: <strong>{len(clients)}</strong></p>
            <p>Пользователей: <strong>{len(users)}</strong></p>
            <p>Активных токенов: <strong>{len(tokens)}</strong></p>
            <p>Отозванных токенов: <strong>{len(revoked_tokens)}</strong></p>
        </div>

        <div class="card">
            <h2>🔧 Доступные endpoints</h2>
            <ul>
                <li><code>GET /authorize</code> - Страница авторизации</li>
                <li><code>POST /token</code> - Получение токена</li>
                <li><code>POST /verify_token</code> - Проверка токена</li>
                <li><code>POST /revoke</code> - Отзыв токена</li>
                <li><code>GET /admin/tokens</code> - Админ-панель</li>
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
    """Страница авторизации OAuth2 с поддержкой PKCE"""
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    requested_scope = request.args.get("scope", "").split()
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method", "plain")

    if client_id not in clients:
        return "❌ Неверный client_id", 400

    if not redirect_uri:
        return "❌ Отсутствует redirect_uri", 400

    # Для публичных клиентов требовать PKCE
    if clients[client_id]["type"] == "public" and not code_challenge:
        return "❌ Публичные клиенты должны использовать PKCE (требуется code_challenge)", 400

    client_name = clients[client_id].get("name", client_id)

    return render_template_string(
        LOGIN_TEMPLATE,
        client_id=client_id,
        client_name=client_name,
        redirect_uri=redirect_uri,
        requested_scope=requested_scope,
        requested_scope_str=" ".join(requested_scope),
        code_challenge=code_challenge or "",
        code_challenge_method=code_challenge_method
    )


@app.route("/login_approve", methods=["POST"])
def login_approve():
    """Обработка формы авторизации с сохранением PKCE данных"""
    try:
        client_id = request.form["client_id"]
        username = request.form["username"]
        password = request.form["password"]
        redirect_uri = request.form["redirect_uri"]
        requested_scope = request.form.get("requested_scope", "").split()
        code_challenge = request.form.get("code_challenge")
        code_challenge_method = request.form.get("code_challenge_method", "plain")

        # Проверяем пользователя
        if username not in users or users[username]["password"] != password:
            return "❌ Неверный логин или пароль", 401

        # Проверяем scope
        user_scopes = users[username]["scopes"]
        allowed_scope = [s for s in requested_scope if s in user_scopes]

        if not allowed_scope:
            return "❌ У пользователя нет запрашиваемых прав", 403

        # Генерируем код авторизации
        code = secrets.token_urlsafe(16)
        authorization_codes[code] = {
            "client_id": client_id,
            "user_id": username,
            "scope": allowed_scope,
            "expires_at": time.time() + 300,  # 5 минут
            "code_challenge": code_challenge,  # Сохраняем PKCE challenge
            "code_challenge_method": code_challenge_method
        }

        return redirect(f"{redirect_uri}?code={code}")

    except Exception as e:
        return f"❌ Ошибка сервера: {e}", 500


@app.route("/token", methods=["POST"])
def issue_token():
    """Выдача токенов с поддержкой PKCE"""
    data = request.form
    grant_type = data.get("grant_type")

    # Password Grant (для мобильных приложений без браузера)
    if grant_type == "password":
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")
        username = data.get("username")
        password = data.get("password")
        requested_scope = data.get("scope", "").split()

        # Проверяем клиента
        if client_id not in clients:
            return jsonify({"error": "invalid_client"}), 401

        # Для confidential клиентов проверяем секрет
        if clients[client_id]["type"] == "confidential":
            if clients[client_id]["secret"] != client_secret:
                return jsonify({"error": "invalid_client"}), 401

        # Проверяем пользователя
        if username not in users or users[username]["password"] != password:
            return jsonify({"error": "invalid_grant"}), 401

        # Проверяем scope
        user_scopes = users[username]["scopes"]
        allowed_scope = [s for s in requested_scope if s in user_scopes]

        # Создаём токен
        token = generate_token()
        tokens[token] = {
            "client_id": client_id,
            "user_id": username,
            "scope": allowed_scope,
            "expires_at": time.time() + 3600  # 1 час
        }

        return jsonify({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": " ".join(allowed_scope)
        })

    # Authorization Code Grant с PKCE
    elif grant_type == "authorization_code":
        code = data.get("code")
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")  # Может быть None для public clients
        code_verifier = data.get("code_verifier")  # PKCE параметр

        # Проверяем клиента
        if client_id not in clients:
            return jsonify({"error": "invalid_client"}), 401

        client_type = clients[client_id]["type"]

        # 🔐 РАЗДЕЛЬНАЯ ПРОВЕРКА ДЛЯ РАЗНЫХ ТИПОВ КЛИЕНТОВ
        if client_type == "confidential":
            # Для confidential clients проверяем client_secret
            if not client_secret or clients[client_id]["secret"] != client_secret:
                return jsonify({"error": "invalid_client"}), 401
        elif client_type == "public":
            # Для public clients НЕ проверяем client_secret
            # Они не должны его отправлять, но если отправили - игнорируем
            pass
        else:
            return jsonify({"error": "invalid_client"}), 401

        # Проверяем код авторизации
        if code not in authorization_codes:
            return jsonify({"error": "invalid_grant"}), 401

        code_data = authorization_codes[code]

        # Проверяем срок действия кода
        if code_data["expires_at"] < time.time():
            del authorization_codes[code]
            return jsonify({"error": "invalid_grant"}), 401

        if code_data["client_id"] != client_id:
            return jsonify({"error": "invalid_grant"}), 401

        # 🔐 ОБЯЗАТЕЛЬНАЯ PKCE ПРОВЕРКА ДЛЯ ВСЕХ КЛИЕНТОВ
        if code_data.get("code_challenge"):
            if not code_verifier:
                return jsonify({
                    "error": "invalid_grant",
                    "error_description": "code_verifier required for PKCE"
                }), 400

            if not validate_pkce(code_verifier, code_data["code_challenge"], code_data["code_challenge_method"]):
                return jsonify({
                    "error": "invalid_grant",
                    "error_description": "PKCE verification failed"
                }), 400

        # Удаляем использованный код
        del authorization_codes[code]

        # Создаём токен
        token = generate_token()
        tokens[token] = {
            "client_id": client_id,
            "user_id": code_data["user_id"],
            "scope": code_data["scope"],
            "expires_at": time.time() + 3600
        }

        return jsonify({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": " ".join(code_data["scope"])
        })

    else:
        return jsonify({"error": "unsupported_grant_type"}), 400


# Остальные endpoints остаются без изменений
@app.route("/verify_token", methods=["POST"])
def verify_token():
    """Проверка валидности токена"""
    token = request.form.get("token")

    # Проверяем отозванные токены
    if token in revoked_tokens:
        return jsonify({"valid": False, "reason": "revoked"}), 401

    # Проверяем существование токена
    if token not in tokens:
        return jsonify({"valid": False, "reason": "not_found"}), 401

    token_data = tokens[token]

    # Проверяем срок действия
    if token_data["expires_at"] < time.time():
        revoked_tokens.add(token)  # Автоматически отзываем просроченные
        return jsonify({"valid": False, "reason": "expired"}), 401

    return jsonify({
        "valid": True,
        "client_id": token_data["client_id"],
        "user_id": token_data["user_id"],
        "scope": token_data["scope"]
    })


@app.route("/revoke", methods=["POST"])
def revoke_token():
    """Отзыв токена"""
    data = request.form
    token = data.get("token")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    # Проверяем клиента
    if client_id not in clients:
        return jsonify({"error": "invalid_client"}), 401

    # Для confidential клиентов проверяем секрет
    if clients[client_id]["type"] == "confidential":
        if clients[client_id]["secret"] != client_secret:
            return jsonify({"error": "invalid_client"}), 401
    # Для public клиентов НЕ проверяем секрет

    # Проверяем существование токена
    if token not in tokens:
        return jsonify({"error": "invalid_token"}), 400

    # Проверяем принадлежность токена
    if tokens[token]["client_id"] != client_id:
        return jsonify({"error": "token_belongs_to_another_client"}), 403

    # Отзываем токен
    revoked_tokens.add(token)

    return jsonify({
        "message": "Token revoked successfully",
        "token": token[:10] + "..."
    })


@app.route("/admin/tokens", methods=["GET"])
def admin_tokens():
    """Админ-панель управления токенами"""
    # Базовая проверка авторизации
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return "🔒 Требуется авторизация", 401

    token = auth_header.replace("Bearer ", "")

    # Проверяем токен и права
    if token not in tokens or "admin_panel" not in tokens[token]["scope"]:
        return "❌ Недостаточно прав для доступа к админ-панели", 403

    # Подготавливаем список токенов для отображения
    tokens_list = []
    for token_key, token_data in list(tokens.items())[:20]:  # Ограничиваем вывод
        tokens_list.append((token_key, token_data))

    return render_template_string(
        ADMIN_TEMPLATE,
        active_count=len(tokens),
        revoked_count=len(revoked_tokens),
        tokens_list=tokens_list
    )


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    """Отзыв токена из админ-панели"""
    token = request.form.get("token")

    if token and token in tokens:
        revoked_tokens.add(token)
        return redirect("/admin/tokens")

    return "❌ Токен не найден", 404


@app.route("/cleanup", methods=["POST"])
def cleanup():
    """Очистка просроченных токенов (для cron-задач)"""
    now = time.time()
    expired_count = 0

    for token, data in list(tokens.items()):
        if data["expires_at"] < now:
            revoked_tokens.add(token)
            del tokens[token]
            expired_count += 1

    # Очищаем просроченные коды авторизации
    for code, data in list(authorization_codes.items()):
        if data["expires_at"] < now:
            del authorization_codes[code]

    return jsonify({
        "message": "Cleanup completed",
        "expired_tokens_removed": expired_count
    })


if __name__ == "__main__":
    app.run(port=5000, debug=True)