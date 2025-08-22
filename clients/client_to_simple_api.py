import requests
import time


class AuthClient:
    def __init__(self, auth_server="http://127.0.0.1:5000", client_id="web_app"):
        self.auth_server = auth_server
        self.client_id = client_id
        self.token_cache = {}

    def get_token(self, username, password, scopes="read_data"):
        """Получение токена с кэшированием"""
        cache_key = f"{username}_{scopes}"

        # Проверяем кэш
        if cache_key in self.token_cache:
            token_data = self.token_cache[cache_key]
            if time.time() < token_data["expires_at"] - 60:  # Запас 60 секунд
                return token_data["access_token"]

        # Получаем новый токен
        try:
            response = requests.post(
                f"{self.auth_server}/token",
                data={
                    "grant_type": "password",
                    "client_id": self.client_id,
                    "username": username,
                    "password": password,
                    "scope": scopes
                },
                timeout=10
            )

            if response.status_code == 200:
                token_data = response.json()
                # Сохраняем в кэш с временем expiration
                token_data["expires_at"] = time.time() + token_data["expires_in"]
                self.token_cache[cache_key] = token_data

                return token_data["access_token"]
            else:
                print(f"Auth error: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"Connection error: {e}")
            return None

    def make_authenticated_request(self, url, username, password, scopes="read_data"):
        """Автоматически получает токен и делает запрос"""
        token = self.get_token(username, password, scopes)
        if not token:
            return None

        try:
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return None


# Использование
client = AuthClient()

# Просто получить токен
token = client.get_token("bob", "password456", "read_data")
print(f"Bob's token: {token}")

# Сделать автоматический запрос
response = client.make_authenticated_request(
    "http://127.0.0.1:5111/all",
    "alice",
    "password123",
    "read_data write_data admin_panel"
)

if response and response.status_code == 200:
    print("Data:", response.json())
