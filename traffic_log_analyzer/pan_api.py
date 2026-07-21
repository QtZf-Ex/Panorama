# pan_api.py
import requests
import xml.etree.ElementTree as ET
import urllib3

urllib3.disable_warnings()
# Настройки API авторизации
import api_key  # должен содержать api_key.user и api_key.pass


def get_api_key():
    """
    Возвращает рабочий API ключ. Если ключ недействителен, генерирует новый.
    """
    # Попробуем использовать уже сохранённый ключ (если есть)
    try:
        current_key = api_key.api_key
        if validate_key(current_key):
            return current_key
    except AttributeError:
        pass  # ключа ещё нет

    # Генерируем новый ключ
    url = f"https://{api_key.api_ip}/api/?type=keygen&user={api_key.user}&password={api_key.passwd}"
    resp = requests.get(url, verify=False)
    resp.raise_for_status()

    root = ET.fromstring(resp.text)
    if root.attrib.get("status") != "success":
        raise Exception(f"Не удалось получить API ключ: {ET.tostring(root, encoding='unicode')}")

    new_key = root.find(".//key").text
    return new_key


def validate_key(key):
    """
    Проверяет, валиден ли API ключ, делая простой запрос к системе.
    """
    url = f"https://{api_key.api_ip}/api/?type=op&cmd=<show><system><info></info></system></show>&key={key}"
    resp = requests.get(url, verify=False)
    if resp.status_code != 200:
        return False
    root = ET.fromstring(resp.text)
    # Если статус success → ключ рабочий
    return root.attrib.get("status") == "success"

# -------------------------
# Пример использования:
# from pan_api import get_api_key
# key = get_api_key()
# print(key)
