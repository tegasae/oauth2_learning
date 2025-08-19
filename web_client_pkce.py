from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify
import requests
import secrets
import hashlib
import base64
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Конфигурация
AUTH_SERVER = "http://127.0.0.1:5000"
RESOURCE_API = "http://127.0.0.1:5001"
CLIENT_ID = "web_app"
REDIRECT_URI = "http://127.0.0.1:5004/callback"

# HTML шаблоны для SPA с PKCE (используем raw string r""" """)
SPA_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>SPA с PKCE</title>
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
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .scope-selection {
            margin: 20px 0;
        }
        .scope-item {
            margin: 10px 0;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            margin: 10px 5px;
            transition: transform 0.2s;
        }
        .btn:active {
            transform: scale(0.98);
        }
        .btn-danger {
            background: #dc3545;
        }
        .status {
            margin: 20px 0;
            padding: 15px;
            border-radius: 8px;
            background: #e9ecef;
        }
        .token-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 12px;
        }
        .api-result {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            min-height: 100px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
        }
        .success { color: #28a745; }
        .error { color: #dc3545; }
        .warning { color: #ffc107; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 SPA с PKCE</h1>
            <p>Современное одностраничное приложение с защитой OAuth 2.0</p>
        </div>

        <div id="app">
            {% if not session.access_token %}
            <!-- Стартовая страница -->
            <div class="scope-selection">
                <h3>🔐 Выберите права доступа:</h3>
                <div class="scope-item">
                    <label>
                        <input type="checkbox" name="scope" value="read_data" checked>
                        📖 Чтение данных (read_data)
                    </label>
                </div>
                <div class="scope-item">
                    <label>
                        <input type="checkbox" name="scope" value="write_data">
                        ✏️ Запись данных (write_data)
                    </label>
                </div>
                <div class="scope-item">
                    <label>
                        <input type="checkbox" name="scope" value="admin_panel">
                        ⚙️ Админ-панель (admin_panel)
                    </label>
                </div>
            </div>

            <button class="btn" onclick="startAuth()">🔐 Начать авторизацию</button>

            {% else %}
            <!-- Дашборд после авторизации -->
            <div class="status">
                <h3>✅ Авторизован</h3>
                <p>Пользователь: <strong>{{ session.user_id or 'unknown' }}</strong></p>
                <p>Права: <strong>{{ session.granted_scope | join(', ') }}</strong></p>
            </div>

            <div class="token-info">
                <strong>Access Token:</strong><br>
                {{ session.access_token }}
            </div>

            <div>
                <h3>🧪 Тестирование API:</h3>
                <button class="btn" onclick="testApi('/api/data')">📖 /api/data</button>
                <button class="btn" onclick="testApi('/api/write')" 
                    {{ 'disabled' if 'write_data' not in session.granted_scope }}>
                    ✏️ /api/write
                </button>
                <button class="btn" onclick="testApi('/api/admin')" 
                    {{ 'disabled' if 'admin_panel' not in session.granted_scope }}>
                    ⚙️ /api/admin
                </button>
            </div>

            <div class="api-result" id="apiResult">
                Нажмите на кнопку для теста API
            </div>

            <button class="btn btn-danger" onclick="logout()">🚪 Выйти</button>

            {% endif %}
        </div>

        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
            <h4>🔍 Информация о PKCE:</h4>
            <p>Это SPA использует Authorization Code Flow с PKCE для безопасности</p>
            <p><strong>Client Type:</strong> Public (не использует client_secret)</p>
            <p><strong>Защита:</strong> PKCE (S256), HTTPS, короткоживущие токены</p>
        </div>
    </div>

    <script>
    function generateRandomString() {
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    async function generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const digest = await window.crypto.subtle.digest('SHA-256', data);

        return btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    async function startAuth() {
        try {
            // Получаем выбранные scope
            const scopes = Array.from(document.querySelectorAll('input[name="scope"]:checked'))
                .map(input => input.value)
                .join(' ');

            // Генерируем PKCE пару
            const codeVerifier = generateRandomString();
            const codeChallenge = await generateCodeChallenge(codeVerifier);
            const state = generateRandomString();

            // Сохраняем в sessionStorage (временное хранилище)
            sessionStorage.setItem('pkce_verifier', codeVerifier);
            sessionStorage.setItem('pkce_state', state);
            sessionStorage.setItem('requested_scope', scopes);

            // Формируем URL авторизации
            const authUrl = new URL('{{ AUTH_SERVER }}/authorize');
            authUrl.searchParams.append('response_type', 'code');
            authUrl.searchParams.append('client_id', '{{ CLIENT_ID }}');
            authUrl.searchParams.append('redirect_uri', '{{ REDIRECT_URI }}');
            authUrl.searchParams.append('scope', scopes);
            authUrl.searchParams.append('code_challenge', codeChallenge);
            authUrl.searchParams.append('code_challenge_method', 'S256');
            authUrl.searchParams.append('state', state);

            // Открываем popup для авторизации
            const popup = window.open(
                authUrl.toString(),
                'oauth_popup',
                'width=500,height=600,left=100,top=100'
            );

            // Слушаем сообщения от popup
            window.addEventListener('message', function(event) {
                if (event.origin !== window.location.origin) return;

                if (event.data.type === 'oauth_success') {
                    // Получаем данные из popup
                    const code = event.data.code;
                    const codeVerifier = sessionStorage.getItem('pkce_verifier');

                    // Обмениваем код на токен
                    fetch('/api/process_oauth', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            code: code,
                            code_verifier: codeVerifier
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            window.location.reload();
                        } else {
                            document.getElementById('apiResult').innerHTML = 
                                '<div class="error">❌ Ошибка: ' + data.error + '</div>';
                        }
                    })
                    .catch(error => {
                        document.getElementById('apiResult').innerHTML = 
                            '<div class="error">❌ Ошибка сети: ' + error.message + '</div>';
                    });

                } else if (event.data.type === 'oauth_error') {
                    document.getElementById('apiResult').innerHTML = 
                        '<div class="error">❌ Ошибка: ' + event.data.error + '</div>';
                }
            });

        } catch (error) {
            document.getElementById('apiResult').innerHTML = 
                '<div class="error">❌ Ошибка: ' + error.message + '</div>';
        }
    }

    async function testApi(endpoint) {
        const result = document.getElementById('apiResult');
        result.innerHTML = '⏳ Загрузка...';

        try {
            const response = await fetch('{{ RESOURCE_API }}' + endpoint, {
                headers: {
                    'Authorization': 'Bearer {{ session.access_token }}'
                }
            });

            if (response.ok) {
                const data = await response.json();
                result.innerHTML = '<div class="success">✅ Успешно!</div>' + 
                    '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } else {
                const error = await response.text();
                result.innerHTML = '<div class="error">❌ Ошибка ' + response.status + 
                    '</div><pre>' + error + '</pre>';
            }
        } catch (error) {
            result.innerHTML = '<div class="error">❌ Ошибка сети: ' + error.message + '</div>';
        }
    }

    function logout() {
        fetch('/logout', { method: 'POST' })
            .then(() => window.location.reload())
            .catch(error => {
                document.getElementById('apiResult').innerHTML = 
                    '<div class="error">❌ Ошибка выхода: ' + error.message + '</div>';
            });
    }
    </script>
</body>
</html>
"""


def generate_code_verifier():
    """Генерация code_verifier для PKCE"""
    return secrets.token_urlsafe(32)


def generate_code_challenge(verifier):
    """Генерация code_challenge для PKCE с S256"""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().replace('=', '')


@app.route("/")
def home():
    """Главная страница SPA"""
    return render_template_string(
        SPA_TEMPLATE,
        AUTH_SERVER=AUTH_SERVER,
        RESOURCE_API=RESOURCE_API,
        CLIENT_ID=CLIENT_ID,
        REDIRECT_URI=REDIRECT_URI
    )


@app.route("/callback")
def callback():
    """Callback endpoint - обрабатывает код от сервера авторизации"""
    code = request.args.get("code")
    error = request.args.get("error")
    state = request.args.get("state")

    if error:
        # Возвращаем ошибку в основное окно
        return f"""
        <html>
        <body>
            <script>
                window.opener.postMessage({{
                    type: 'oauth_error',
                    error: '{error}'
                }}, '{request.url_root}');
                window.close();
            </script>
        </body>
        </html>
        """

    if not code:
        return "❌ Отсутствует код авторизации", 400

    # Возвращаем код в основное окно
    return f"""
    <html>
    <body>
        <script>
            window.opener.postMessage({{
                type: 'oauth_success',
                code: '{code}',
                state: '{state}'
            }}, '{request.url_root}');
            window.close();
        </script>
    </body>
    </html>
    """


@app.route("/exchange_token", methods=["POST"])
def exchange_token():
    """Обмен кода на токен (выполняется на бэкенде для безопасности)"""
    data = request.json
    code = data.get("code")
    code_verifier = data.get("code_verifier")

    if not code or not code_verifier:
        return jsonify({"error": "Missing code or code_verifier"}), 400

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
                # НЕ отправляем client_secret - это public client!
            },
            timeout=10
        )

        if token_response.status_code == 200:
            token_data = token_response.json()

            # Сохраняем в сессии
            session["access_token"] = token_data["access_token"]
            session["granted_scope"] = token_data.get("scope", "").split()

            # Получаем информацию о пользователе
            user_info = get_user_info(token_data["access_token"])
            if user_info:
                session["user_id"] = user_info.get("user_id")

            return jsonify({"success": True, "token": token_data})
        else:
            return jsonify({
                "error": "Token exchange failed",
                "details": token_response.text
            }), 400

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error: {e}"}), 500


def get_user_info(access_token):
    """Получаем информацию о пользователе из токена"""
    try:
        response = requests.post(
            f"{AUTH_SERVER}/verify_token",
            data={"token": access_token},
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None


@app.route("/api/process_oauth", methods=["POST"])
def process_oauth():
    """API endpoint для обработки OAuth из frontend"""
    data = request.json
    code = data.get("code")
    code_verifier = data.get("code_verifier")

    if not code or not code_verifier:
        return jsonify({"error": "Missing parameters"}), 400

    # Используем внутренний метод обмена
    return exchange_token()


@app.route("/logout", methods=["POST"])
def logout():
    """Выход из системы"""
    session.clear()
    return jsonify({"success": True})


@app.route("/api/user_info")
def user_info():
    """Получение информации о текущем пользователе"""
    if "access_token" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_info = {
        "authenticated": True,
        "user_id": session.get("user_id", "unknown"),
        "scopes": session.get("granted_scope", []),
        "client_type": "public_spa"
    }

    return jsonify(user_info)


if __name__ == "__main__":
    app.run(port=5004, debug=True)