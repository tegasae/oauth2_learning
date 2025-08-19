from flask import Flask, request, redirect, url_for, session, render_template_string
import requests
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Конфигурация
AUTH_SERVER = "http://127.0.0.1:5000"
RESOURCE_API = "http://127.0.0.1:5001"
CLIENT_ID = "web_app"
CLIENT_SECRET = "web_secret_123"
REDIRECT_URI = "http://127.0.0.1:5003/callback"

# HTML шаблоны
SCOPE_SELECTION_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Выбор прав доступа</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
        }
        .form-group { 
            margin: 15px 0; 
        }
        label { 
            display: block; 
            margin-bottom: 5px; 
            font-weight: bold;
        }
        .checkbox-group {
            margin: 10px 0;
        }
        input[type="checkbox"] {
            margin-right: 10px;
        }
        button { 
            background: #007bff; 
            color: white; 
            padding: 12px 24px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background: #0056b3;
        }
        .info-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 4px solid #007bff;
        }
    </style>
</head>
<body>
    <h2>🔐 Выбор прав доступа</h2>

    <div class="info-box">
        <p>Выберите, какие права вы хотите предоставить приложению:</p>
    </div>

    <form method="post" action="/request_auth">
        <input type="hidden" name="required_scope" id="required_scope">

        <div class="checkbox-group">
            <label>
                <input type="checkbox" name="scope" value="read_data" checked>
                📖 Чтение данных (read_data)
            </label>
        </div>

        <div class="checkbox-group">
            <label>
                <input type="checkbox" name="scope" value="write_data">
                ✏️ Запись данных (write_data)
            </label>
        </div>

        <div class="checkbox-group">
            <label>
                <input type="checkbox" name="scope" value="admin_panel">
                ⚙️ Админ-панель (admin_panel)
            </label>
        </div>

        <div class="form-group">
            <button type="submit">Продолжить →</button>
        </div>
    </form>

    <script>
        document.querySelector('form').addEventListener('submit', function(e) {
            const scopes = Array.from(document.querySelectorAll('input[name="scope"]:checked'))
                .map(input => input.value)
                .join(' ');
            document.getElementById('required_scope').value = scopes;
        });
    </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Дашборд</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 800px; 
            margin: 50px auto; 
            padding: 20px;
        }
        .card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #28a745;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
        }
        button {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px;
        }
        button:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
        button:hover:not(:disabled) {
            background: #0056b3;
        }
        .danger {
            background: #dc3545;
        }
        .danger:hover {
            background: #c82333;
        }
        #result {
            margin-top: 20px;
            padding: 15px;
            background: #e9ecef;
            border-radius: 5px;
            min-height: 50px;
        }
    </style>
</head>
<body>
    <h2>📊 Дашборд</h2>

    <div class="card">
        <h3>👤 Информация о пользователе</h3>
        <p><strong>Пользователь:</strong> {{ user_id }}</p>
        <p><strong>Выданные права:</strong> {{ granted_scope | join(', ') }}</p>
    </div>

    <div class="card">
        <h3>🚀 Доступные API</h3>
        <ul>
            {% for api in available_apis %}
            <li>{{ api }}</li>
            {% endfor %}
        </ul>
    </div>

    <div class="card">
        <h3>🧪 Тестирование API</h3>
        <button onclick="testApi('/api/data')">Тест /api/data</button>
        <button onclick="testApi('/api/write')" {{ 'disabled' if 'write_data' not in granted_scope }}>Тест /api/write</button>
        <button onclick="testApi('/api/admin')" {{ 'disabled' if 'admin_panel' not in granted_scope }}>Тест /api/admin</button>

        <div id="result"></div>
    </div>

    <div class="card">
        <h3>⚙️ Управление</h3>
        <a href="/profile"><button>👤 Управление токенами</button></a>
        <a href="/logout"><button class="danger">🚪 Выйти</button></a>
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
                result.innerHTML = '<div style="color: green;">✅ Успешно!</div><pre>' + 
                    JSON.stringify(data, null, 2) + '</pre>';
            } else {
                const errorText = await response.text();
                result.innerHTML = '<div style="color: red;">❌ Ошибка ' + response.status + 
                    ': ' + errorText + '</div>';
            }
        } catch (error) {
            result.innerHTML = '<div style="color: red;">❌ Ошибка сети: ' + error.message + '</div>';
        }
    }
    </script>
</body>
</html>
"""

PROFILE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Управление токенами</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
        }
        .token-box {
            background: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-family: monospace;
            word-break: break-all;
        }
        .danger {
            background: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .danger:hover {
            background: #c82333;
        }
        .back-button {
            background: #6c757d;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 4px;
            display: inline-block;
        }
        .back-button:hover {
            background: #5a6268;
        }
    </style>
</head>
<body>
    <h2>🔑 Управление токенами</h2>

    <div>
        <h3>Текущий токен:</h3>
        <div class="token-box">
            {{ access_token }}
        </div>
    </div>

    <div style="margin: 20px 0;">
        <h3>⚠️ Опасные действия</h3>
        <form method="post" action="/revoke_my_token" onsubmit="return confirm('Вы уверены? Это немедленно завершит вашу сессию.');">
            <button type="submit" class="danger">🚫 Отозвать текущий токен</button>
        </form>
        <p style="color: #666; font-size: 14px; margin-top: 10px;">
            Отзыв токена немедленно завершит все ваши активные сессии.
        </p>
    </div>

    <div style="margin-top: 30px;">
        <a href="/dashboard" class="back-button">← Назад к дашборду</a>
    </div>
</body>
</html>
"""


@app.route("/")
def home():
    """Главная страница с выбором scope"""
    return SCOPE_SELECTION_TEMPLATE


@app.route("/request_auth", methods=["POST"])
def request_auth():
    """Обрабатываем выбранные scope и перенаправляем на авторизацию"""
    requested_scope = request.form.get("required_scope", "read_data")

    # Сохраняем запрошенные scope в сессии
    session["requested_scope"] = requested_scope

    # Формируем URL для авторизации с указанием scope
    auth_url = (
        f"{AUTH_SERVER}/authorize?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope={requested_scope}"
    )

    return redirect(auth_url)


@app.route("/callback")
def callback():
    """Обработка ответа от сервера авторизации"""
    code = request.args.get("code")
    if not code:
        return "❌ Ошибка авторизации: отсутствует код", 400

    # Обмениваем code на токен
    try:
        token_response = requests.post(
            f"{AUTH_SERVER}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI
            },
            timeout=10
        )

        if token_response.status_code != 200:
            return f"❌ Не удалось получить токен: {token_response.text}", 403

        # Сохраняем токен в сессии
        token_data = token_response.json()
        session["access_token"] = token_data["access_token"]
        session["granted_scope"] = token_data.get("scope", "").split()

        return redirect(url_for("dashboard"))

    except requests.exceptions.RequestException as e:
        return f"❌ Ошибка соединения с сервером авторизации: {e}", 500


@app.route("/dashboard")
def dashboard():
    """Дашборд с информацией о правах доступа"""
    if "access_token" not in session:
        return redirect(url_for("home"))

    # Определяем user_id из токена (запрашиваем у auth-сервера)
    try:
        token_info_response = requests.post(
            f"{AUTH_SERVER}/verify_token",
            data={"token": session["access_token"]},
            timeout=5
        )

        if token_info_response.status_code == 200:
            token_info = token_info_response.json()
            user_id = token_info.get("user_id", "unknown")
        else:
            user_id = "unknown"
    except:
        user_id = "unknown"

    # Проверяем, какие API доступны с текущими scope
    available_apis = []
    granted_scope = session.get("granted_scope", [])

    if "read_data" in granted_scope:
        available_apis.append("📖 Чтение данных (/api/data)")
    if "write_data" in granted_scope:
        available_apis.append("✏️ Запись данных (/api/write)")
    if "admin_panel" in granted_scope:
        available_apis.append("⚙️ Админ-панель (/api/admin)")

    return render_template_string(
        DASHBOARD_TEMPLATE,
        access_token=session["access_token"],
        granted_scope=granted_scope,
        available_apis=available_apis,
        user_id=user_id
    )


@app.route("/profile")
def profile():
    """Страница управления токенами"""
    if "access_token" not in session:
        return redirect(url_for("home"))

    return render_template_string(
        PROFILE_TEMPLATE,
        access_token=session["access_token"]
    )


@app.route("/revoke_my_token", methods=["POST"])
def revoke_my_token():
    """Отзыв текущего токена пользователя"""
    if "access_token" not in session:
        return redirect(url_for("home"))

    token = session["access_token"]

    try:
        # Отзываем токен
        response = requests.post(
            f"{AUTH_SERVER}/revoke",
            data={
                "token": token,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            },
            timeout=5
        )

        if response.status_code == 200:
            session.clear()
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Токен отозван</title>
                <meta charset="utf-8">
                <style>
                    body { font-family: Arial, sans-serif; max-width: 500px; margin: 100px auto; text-align: center; }
                    .success { color: #28a745; font-size: 24px; }
                </style>
            </head>
            <body>
                <div class="success">✅</div>
                <h2>Токен отозван</h2>
                <p>Ваш токен был успешно отозван. Все сессии завершены.</p>
                <p><a href="/">Вернуться на главную</a></p>
            </body>
            </html>
            """
        else:
            return f"❌ Ошибка отзыва токена: {response.text}", 500

    except requests.exceptions.RequestException as e:
        return f"❌ Ошибка соединения с сервером авторизации: {e}", 500


@app.route("/logout")
def logout():
    """Выход из системы (без отзыва токена)"""
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(port=5003, debug=True)