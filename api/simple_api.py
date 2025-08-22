from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Конфигурация
AUTH_SERVER = "http://127.0.0.1:5000"  # Сервер авторизации


def validate_token(token):
    """Проверяет токен через сервер авторизации"""
    if not token:
        return False, None

    try:
        response = requests.post(
            f"{AUTH_SERVER}/verify_token",
            data={"token": token},
            timeout=3
        )

        if response.status_code == 200:
            token_info = response.json()
            return token_info.get("valid", False), token_info
        return False, None

    except requests.exceptions.RequestException:
        return False, None


@app.route('/all', methods=['GET'])
def get_all_data():
    """Доступно всем аутентифицированным пользователям"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header required"}), 401

    token = auth_header[7:]

    is_valid, token_info = validate_token(token)
    if not is_valid:
        return jsonify({"error": "Invalid token"}), 401

    return jsonify({
        "user": token_info.get("user_id", "unknown"),
        "scopes": token_info.get("scope", []),
        "message": "Access granted to all data",
        "items": [
            {"id": 1, "name": "Public item 1"},
            {"id": 2, "name": "Public item 2"},
            {"id": 3, "name": "Public item 3"}
        ]
    })


@app.route('/admin', methods=['GET'])
def get_admin_data():
    """Только для пользователей с scope admin_panel"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header required"}), 401

    token = auth_header[7:]

    is_valid, token_info = validate_token(token)
    if not is_valid:
        return jsonify({"error": "Invalid token"}), 401

    user_scopes = token_info.get("scope", [])
    if "admin_panel" not in user_scopes:
        return jsonify({
            "error": "Access denied",
            "required_scope": "admin_panel",
            "your_scopes": user_scopes
        }), 403

    return jsonify({
        "user": token_info.get("user_id", "unknown"),
        "scopes": user_scopes,
        "message": "Admin access granted",
        "admin_items": [
            {"id": 1, "name": "Server config", "sensitive": True},
            {"id": 2, "name": "User database", "sensitive": True},
            {"id": 3, "name": "System logs", "sensitive": True}
        ]
    })


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "ok", "service": "resource_server"})


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405


if __name__ == '__main__':
    app.run(port=5111, debug=True)
