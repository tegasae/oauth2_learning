from flask import Flask, request, redirect, url_for, session, render_template_string
import requests
import secrets
import base64
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Конфигурация для мобильного клиента
AUTH_SERVER = "http://127.0.0.1:5000"
RESOURCE_API = "http://127.0.0.1:5001"
CLIENT_ID = "mobile_app"
REDIRECT_URI = "http://127.0.0.1:5004/callback"

# HTML шаблоны для мобильного интерфейса
MOBILE_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Мобильное приложение - Вход</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 30px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            font-size: 28px;
            color: #333;
            margin-bottom: 10px;
        }
        .logo p {
            color: #666;
            font-size: 16px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 12px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:active {
            transform: scale(0.98);
        }
        .test-users {
            margin-top: 25px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
        }
        .test-users h3 {
            margin-bottom: 10px;
            color: #333;
        }
        .user-card {
            background: white;
            padding: 12px;
            margin: 8px 0;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>📱 Мобильное приложение</h1>
            <p>Войдите для продолжения</p>
        </div>

        <form method="POST" action="/mobile_login">
            <div class="form-group">
                <label>Логин:</label>
                <input type="text" name="username" placeholder="Введите ваш логин" required>
            </div>

            <div class="form-group">
                <label>Пароль:</label>
                <input type="password" name="password" placeholder="Введите ваш пароль" required>
            </div>

            <button type="submit" class="btn">Войти</button>
        </form>

        <div class="test-users">
            <h3>👥 Тестовые пользователи:</h3>
            <div class="user-card">
                <strong>alice</strong> / password123<br>
                <small>Администратор (все права)</small>
            </div>
            <div class="user-card">
                <strong>bob</strong> / password456<br>
                <small>Пользователь (только чтение)</small>
            </div>
        </div>
    </div>
</body>
</html>
"""

MOBILE_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Мобильное приложение</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px 20px;
            text-align: center;
        }
        .user-info {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 12px;
            margin: 15px 0;
            backdrop-filter: blur(10px);
        }
        .content {
            padding: 20px;
        }
        .card {
            background: white;
            border-radius: 16px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .api-buttons {
            display: grid;
            gap: 12px;
            margin: 20px 0;
        }
        .api-btn {
            padding: 16px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
        }
        .api-btn:active {
            transform: scale(0.98);
        }
        .api-btn.primary {
            background: #667eea;
            color: white;
        }
        .api-btn.success {
            background: #28a745;
            color: white;
        }
        .api-btn.warning {
            background: #ffc107;
            color: white;
        }
        .api-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .result {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 12px;
            margin: 15px 0;
            min-height: 50px;
            font-family: monospace;
            font-size: 14px;
            overflow-x: auto;
        }
        .logout-btn {
            background: #dc3545;
            color: white;
            padding: 15px;
            border: none;
            border-radius: 12px;
            width: 100%;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📱 Мобильное приложение</h1>
        <div class="user-info">
            <strong>👤 {{ user_id }}</strong>
            <br>
            <small>Права: {{ granted_scope | join(', ') }}</small>
        </div>
    </div>

    <div class="content">
        <div class="card">
            <h3>🚀 Доступные действия</h3>
            <div class="api-buttons">
                <button class="api-btn primary" onclick="testApi('/api/data')">
                    📖 Получить данные
                </button>
                <button class="api-btn success" onclick="testApi('/api/write')" 
                    {{ 'disabled' if 'write_data' not in granted_scope }}>
                    ✏️ Записать данные
                </button>
                <button class="api-btn warning" onclick="testApi('/api/admin')" 
                    {{ 'disabled' if 'admin_panel' not in granted_scope }}>
                    ⚙️ Админ-панель
                </button>
            </div>
        </div>

        <div class="card">
            <h3>📊 Результат</h3>
            <div id="result" class="result">Нажмите на кнопку для теста API</div>
        </div>

        <button class="logout-btn" onclick="location.href='/mobile_logout'">
            🚪 Выйти из приложения
        </button>
    </div>

    <script>
    async function testApi(endpoint) {
        const result = document.getElementById('result');
        result.innerHTML = '⏳ Загрузка...';

        try {
            const response = await fetch('http://127.0.0.1:5001' + endpoint, {
                headers: {
                    'Authorization': 'Bearer {{ access_token }}'
                }
            });

            if (response.ok) {
                const data = await response.json();
                result.innerHTML = '<div style="color: green;">✅ Успешно!</div>' + 
                    '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } else {
                const error = await response.text();
                result.innerHTML = '<div style="color: red;">❌ Ошибка ' + response.status + 
                    '</div><pre>' + error + '</pre>';
            }
        } catch (error) {
            result.innerHTML = '<div style="color: red;">❌ Ошибка сети: ' + error.message + '</div>';
        }
    }
    </script>
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
def mobile_home():
    """Главная страница мобильного приложения"""
    return MOBILE_LOGIN_TEMPLATE


@app.route("/mobile_login", methods=["POST"])
def mobile_login():
    """Обработка входа в мобильном приложении (Resource Owner Password Credentials)"""
    username = request.form.get("username")
    password = request.form.get("password")

    try:
        # Используем Resource Owner Password Credentials Flow
        token_response = requests.post(
            f"{AUTH_SERVER}/token",
            data={
                "grant_type": "password",
                "username": username,
                "password": password,
                "client_id": CLIENT_ID,
                "scope": "read_data write_data admin_panel"
            },
            timeout=10
        )

        if token_response.status_code == 200:
            token_data = token_response.json()
            session["access_token"] = token_data["access_token"]
            session["granted_scope"] = token_data.get("scope", "").split()
            return redirect(url_for("mobile_dashboard"))
        else:
            return f"❌ Ошибка входа: {token_response.text}", 401

    except requests.exceptions.RequestException as e:
        return f"❌ Ошибка соединения: {e}", 500


@app.route("/mobile_dashboard")
def mobile_dashboard():
    """Дашборд мобильного приложения"""
    if "access_token" not in session:
        return redirect(url_for("mobile_home"))

    # Получаем информацию о пользователе
    try:
        token_info = requests.post(
            f"{AUTH_SERVER}/verify_token",
            data={"token": session["access_token"]},
            timeout=5
        )

        if token_info.status_code == 200:
            user_data = token_info.json()
            user_id = user_data.get("user_id", "unknown")
        else:
            user_id = "unknown"
    except:
        user_id = "unknown"

    return render_template_string(
        MOBILE_DASHBOARD_TEMPLATE,
        access_token=session["access_token"],
        granted_scope=session.get("granted_scope", []),
        user_id=user_id
    )


@app.route("/mobile_logout")
def mobile_logout():
    """Выход из мобильного приложения"""
    # Для мобильного приложения обычно не отзываем токен сразу,
    # так как пользователь может захотеть вернуться
    session.clear()
    return redirect(url_for("mobile_home"))


@app.route("/mobile_auth_callback")
def mobile_auth_callback():
    """Callback для Authorization Code Flow с PKCE (альтернативный вариант)"""
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        return f"❌ Ошибка авторизации: {error}", 400

    if not code:
        return "❌ Отсутствует код авторизации", 400

    # Получаем сохраненные PKCE данные
    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return "❌ Сессия устарела", 400

    try:
        # Обмениваем код на токен с PKCE
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

        if token_response.status_code == 200:
            token_data = token_response.json()
            session["access_token"] = token_data["access_token"]
            session["granted_scope"] = token_data.get("scope", "").split()
            # Очищаем PKCE данные
            session.pop("code_verifier", None)
            return redirect(url_for("mobile_dashboard"))
        else:
            return f"❌ Ошибка получения токена: {token_response.text}", 400

    except requests.exceptions.RequestException as e:
        return f"❌ Ошибка соединения: {e}", 500


if __name__ == "__main__":
    app.run(port=5004, debug=True)