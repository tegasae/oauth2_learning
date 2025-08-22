import requests

# Данные из настроек клиента в GLPI
client_id = "0bb95d7585d1f45717735aa6d3662acf63ee3ba369be29c561524a97b359fa5c"
client_secret = "09c134e682765b1594eb29bc6191c0b3be3d365283f97ce056aa848bf9492008"

# Учетные данные пользователя GLPI (от чьего имени будет работать скрипт)
username = "tegaglpi"
password = "or!on!sC21"

# URL вашего сервера GLPI
glpi_url = "https://192.168.220.252/"

# 1. Запрос на получение токена
token_url = f"{glpi_url}/api.php/token"

auth_data = {
    "grant_type": "password",
    "client_id": client_id,
    "client_secret": client_secret,
    "username": username,
    "password": password,
    "scope": "api"  # Запрашиваемые области доступа
}

response = requests.post(token_url, data=auth_data,verify=False)

# Проверяем, что запрос успешен
if response.status_code == 200:
    token_info = response.json()
    access_token = token_info['access_token']
    print(f"Токен получен: {access_token}")
else:
    print(f"Ошибка аутентификации: {response.status_code}")
    print(response.text)
    exit()


api_headers = {
    "Authorization": f"Bearer {access_token}"
}

# Пример: получить список всех компьютеров (эндпоинт /Computer)
users_url = f"{glpi_url}/api.php/Administration/User"
api_response = requests.get(users_url, headers=api_headers,verify=False)

if api_response.status_code == 200:
    users = api_response.json()
    # Обрабатываем полученные данные...
    print(users)
else:
    print(f"Ошибка при запросе к API: {api_response.status_code}")
    print(api_response.text)
