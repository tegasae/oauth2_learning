from flask import Flask, request, jsonify
from flask_cors import CORS  # ← Добавляем импорт
import requests

app = Flask(__name__)
CORS(app)  # ← Разрешаем все CORS запросы

AUTH_SERVER = "http://127.0.0.1:5000"
RESOURCE_API = "http://127.0.0.1:5001"


def validate_token(token):
    """Проверяет токен и возвращает данные включая scope"""
    resp = requests.post(
        f"{AUTH_SERVER}/verify_token",
        data={"token": token}
    )
    return resp.json() if resp.status_code == 200 else None


@app.route("/api/data", methods=["GET"])
def get_data():
    """Доступно всем с scope read_data"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Требуется авторизация"}), 401

    token = auth_header.split(" ")[1]
    token_data = validate_token(token)

    if not token_data or not token_data.get("valid"):
        return jsonify({"error": "Неверный токен"}), 401

    if "read_data" not in token_data["scope"]:
        return jsonify({"error": "Недостаточно прав. Нужен scope: read_data"}), 403

    return jsonify({
        "data": f"Данные для {token_data['user_id']}",
        "user": token_data["user_id"],
        "scope": token_data["scope"]
    })


@app.route("/api/admin", methods=["GET"])
def admin_panel():
    """Только для админов с scope admin_panel"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Требуется авторизация"}), 401

    token = auth_header.split(" ")[1]
    token_data = validate_token(token)

    if not token_data or not token_data.get("valid"):
        return jsonify({"error": "Неверный токен"}), 401

    if "admin_panel" not in token_data["scope"]:
        return jsonify({"error": "Недостаточно прав. Нужен scope: admin_panel"}), 403

    return jsonify({
        "data": "Секретные админские данные!",
        "user": token_data["user_id"],
        "scope": token_data["scope"]
    })


@app.route("/api/write", methods=["POST"])
def write_data():
    """Только для пользователей с scope write_data"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Требуется авторизация"}), 401

    token = auth_header.split(" ")[1]
    token_data = validate_token(token)

    if not token_data or not token_data.get("valid"):
        return jsonify({"error": "Неверный токен"}), 401

    if "write_data" not in token_data["scope"]:
        return jsonify({"error": "Недостаточно прав. Нужен scope: write_data"}), 403

    return jsonify({
        "data": "Данные успешно записаны!",
        "user": token_data["user_id"],
        "scope": token_data["scope"]
    })


if __name__ == "__main__":
    app.run(port=5001, debug=True)