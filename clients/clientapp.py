from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Конфигурация
AUTH_SERVER_URL = "http://127.0.0.1:5000"
RESOURCE_API_URL = "http://127.0.0.1:5001"
CLIENT_ID = "client_app"
CLIENT_SECRET = "client_secret_123"

# Хранилище токенов (временное, в памяти)
user_tokens = {}


@app.route("/", methods=["GET"])
def home():
    """Главная страница. Проверяет авторизацию."""
    auth_header = request.headers.get("Authorization")

    # Если нет токена — 401
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Требуется авторизация"}), 401

    token = auth_header.split(" ")[1]

    # Проверяем токен через AuthServer
    token_check = requests.post(
        f"{AUTH_SERVER_URL}/verify_token",
        data={"token": token}
    )

    if token_check.status_code != 200 or not token_check.json().get("valid"):
        return jsonify({"error": "Неверный токен"}), 401

    # Получаем данные из API
    api_response = requests.get(
        f"{RESOURCE_API_URL}/api/data",
        headers={"Authorization": f"Bearer {token}"}
    )

    return jsonify({
        "message": "Добро пожаловать!",
        "api_data": api_response.json()
    })


@app.route("/login", methods=["POST"])
def login():
    """Эндпоинт для входа. Возвращает токен."""
    data = request.json

    # Запрашиваем токен у AuthServer
    token_response = requests.post(
        f"{AUTH_SERVER_URL}/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "username": data["username"],
            "password": data["password"],
            "grant_type": "password"
        }
    )

    if token_response.status_code != 200:
        return jsonify({"error": "Ошибка авторизации"}), 401

    access_token = token_response.json()["access_token"]
    user_tokens[access_token] = data["username"]  # Сохраняем токен

    return jsonify({
        "access_token": access_token,
        "message": "Используйте этот токен в заголовке Authorization: Bearer <токен>"
    })


if __name__ == "__main__":
    app.run(port=5002, debug=True)
