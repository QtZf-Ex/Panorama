import csv
import sys
from xml.sax.saxutils import escape

import requests
import xml.etree.ElementTree as ET
import urllib3

import api_key
import pan_api

urllib3.disable_warnings()

PA_IP = api_key.api_ip
API_KEY = pan_api.get_api_key()

BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"

NO_PROFILE_LABEL = "(не задан)"


def api_get(params):
    url = f"https://{PA_IP}/api/"
    r = requests.get(url, params=params, verify=False, timeout=60)
    r.raise_for_status()
    return r.text


def response_ok(xml_text):
    return "<result>OK</result>" in xml_text or 'status="success"' in xml_text


def xpath_literal(value):
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    raise ValueError(f"Имя содержит и одинарные, и двойные кавычки: {value}")


def get_device_groups():
    xpath = f"{BASE_XPATH}/device-group"

    xml = api_get({
        "type": "config",
        "action": "get",
        "xpath": xpath,
        "key": API_KEY
    })

    root = ET.fromstring(xml)

    return sorted([
        entry.get("name")
        for entry in root.findall(".//device-group/entry")
        if entry.get("name")
    ])


def ask_device_groups(device_groups):
    if not device_groups:
        print("[!] Device-group не найдены")
        sys.exit(1)

    print("\nНайдены device-group / кластеры:")
    for i, dg in enumerate(device_groups, 1):
        print(f"{i} - {dg}")

    print("0 - все")

    choice = input("\nВыбери кластер или 0 для всех: ").strip()

    if choice == "0":
        return device_groups

    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Неверный выбор")
        sys.exit(1)

    if idx < 0 or idx >= len(device_groups):
        print("[!] Неверный номер device-group")
        sys.exit(1)

    return [device_groups[idx]]


def ask_rulebase_scope():
    print("\nГде искать правила?")
    print("1 - pre-rulebase  (созданные администраторами правила)")
    print("2 - post-rulebase (стандартные правила)")
    print("3 - оба варианта")

    choice = input("Выбор [1]: ").strip() or "1"

    if choice == "1":
        return ["pre-rulebase"]

    if choice == "2":
        return ["post-rulebase"]

    if choice == "3":
        return ["pre-rulebase", "post-rulebase"]

    print("[!] Неверный выбор")
    sys.exit(1)


def get_security_rules(device_group, rulebase):
    xpath = (
        f"{BASE_XPATH}"
        f"/device-group/entry[@name={xpath_literal(device_group)}]"
        f"/{rulebase}/security/rules"
    )

    xml = api_get({
        "type": "config",
        "action": "get",
        "xpath": xpath,
        "key": API_KEY
    })

    root = ET.fromstring(xml)
    return root.findall(".//rules/entry")


def normalize_log_forwarding(value):
    value = (value or "").strip()
    return value if value else NO_PROFILE_LABEL


def collect_rules(selected_device_groups, selected_rulebases):
    all_rules = []
    profiles = {}

    for device_group in selected_device_groups:
        for rulebase in selected_rulebases:
            rules = get_security_rules(device_group, rulebase)

            for rule in rules:
                log_forwarding = normalize_log_forwarding(rule.findtext("./log-setting"))

                item = {
                    "device_group": device_group,
                    "rulebase": rulebase,
                    "name": rule.get("name"),
                    "uuid": rule.get("uuid"),
                    "log_forwarding": log_forwarding
                }

                all_rules.append(item)
                profiles.setdefault(log_forwarding, []).append(item)

    return all_rules, profiles


def print_profiles_summary(profiles):
    print("\nНайденные варианты Log Forwarding:")

    ordered = sorted(profiles.items(), key=lambda kv: -len(kv[1]))

    for i, (profile, rules) in enumerate(ordered, 1):
        print(f"{i} - \"{profile}\" : используется в {len(rules)} правил(ах)")


def print_numbered_rules(rules):
    print("\nНайденные правила:\n")

    for idx, rule in enumerate(rules, 1):
        print(
            f"{idx:4} "
            f"[{rule['device_group']} / {rule['rulebase']}] "
            f"{rule['name']} | log-forwarding={rule['log_forwarding']}"
        )


def ask_mode():
    print("\nЧто нужно сделать с Log Forwarding?")
    print("1 - Заменить один профиль на другой (для всех правил, где он используется)")
    print("2 - Заменить профиль только для одного конкретного правила")
    print("3 - Заменить профили для набора правил из CSV-файла")

    choice = input("Выбор: ").strip()

    if choice in ("1", "2", "3"):
        return choice

    print("[!] Неверный выбор")
    sys.exit(1)


def ask_source_profile(profiles):
    ordered = sorted(profiles.items(), key=lambda kv: -len(kv[1]))
    profile_names = [name for name, _ in ordered]

    print_profiles_summary(profiles)
    choice = input("\nВыбери номер профиля-источника: ").strip()

    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Неверный ввод")
        sys.exit(1)

    if idx < 0 or idx >= len(profile_names):
        print("[!] Неверный номер профиля")
        sys.exit(1)

    return profile_names[idx]


def ask_target_profile():
    value = input("\nВведи имя нового профиля Log Forwarding: ").strip()

    if not value:
        print("[!] Имя профиля не может быть пустым")
        sys.exit(1)

    return value


def ask_rule_number(all_rules):
    choice = input("\nВыбери номер правила: ").strip()

    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Неверный ввод")
        sys.exit(1)

    if idx < 0 or idx >= len(all_rules):
        print("[!] Неверный номер правила")
        sys.exit(1)

    return all_rules[idx]


def set_log_forwarding(rule, value):
    xpath = (
        f"{BASE_XPATH}"
        f"/device-group/entry[@name={xpath_literal(rule['device_group'])}]"
        f"/{rule['rulebase']}/security/rules"
        f"/entry[@name={xpath_literal(rule['name'])}]"
    )

    element = f"<log-setting>{escape(value)}</log-setting>"

    xml = api_get({
        "type": "config",
        "action": "set",
        "xpath": xpath,
        "element": element,
        "key": API_KEY
    })

    return response_ok(xml), xml, xpath


def ask_confirmation(rules_to_change, target_of):
    if not rules_to_change:
        print("\n[=] Нет правил, требующих изменения")
        return False

    print(f"\nБудет изменено правил: {len(rules_to_change)}")

    print("\nПравила к изменению:")
    for rule in rules_to_change:
        print(
            f"  - [{rule['device_group']} / {rule['rulebase']}] "
            f"{rule['name']} | {rule['log_forwarding']} -> {target_of(rule)}"
        )

    answer = input("\nПодтвердить изменение? [y/N]: ").strip().lower()
    return answer == "y"


def apply_changes(rules_to_change, target_of):
    updated = []
    failed = []

    print("\n========== ОБНОВЛЕНИЕ ==========")

    for i, rule in enumerate(rules_to_change, 1):
        target_value = target_of(rule)

        print(
            f"[*] {i}/{len(rules_to_change)} "
            f"[{rule['device_group']} / {rule['rulebase']}] "
            f"{rule['name']} | log-forwarding={rule['log_forwarding']} -> {target_value}"
        )

        ok, xml, xpath = set_log_forwarding(rule, target_value)

        if ok:
            updated.append(rule)
            print(f"[+] OK: {rule['name']}")
        else:
            failed.append({"rule": rule, "xml": xml, "xpath": xpath})
            print(f"[!] ERROR: {rule['name']}")
            print(xml)

    return updated, failed


# ---- Режим 1: заменить один профиль на другой везде, где он встречается ----

def run_replace_profile(all_rules, profiles):
    source_profile = ask_source_profile(profiles)
    target_profile = ask_target_profile()

    if source_profile == target_profile:
        print("[!] Новый профиль совпадает со старым, изменения не требуются")
        return [], [], []

    candidates = [r for r in all_rules if r["log_forwarding"] == source_profile]
    target_of = lambda r: target_profile

    if not ask_confirmation(candidates, target_of):
        print("\n[=] Операция отменена пользователем")
        return [], [], candidates

    updated, failed = apply_changes(candidates, target_of)
    return updated, failed, candidates


# ---- Режим 2: заменить профиль только для одного правила ----

def run_replace_single_rule(all_rules):
    rule = ask_rule_number(all_rules)
    target_profile = ask_target_profile()

    if rule["log_forwarding"] == target_profile:
        print("[!] Новый профиль совпадает с текущим, изменения не требуются")
        return [], [], []

    selected = [rule]
    target_of = lambda r: target_profile

    if not ask_confirmation(selected, target_of):
        print("\n[=] Операция отменена пользователем")
        return [], [], selected

    updated, failed = apply_changes(selected, target_of)
    return updated, failed, selected


# ---- Режим 3: заменить профиль для набора правил, перечисленных в CSV ----
#
# CSV содержит один столбец - номера правил из нумерованного списка
# (тот же список и та же нумерация, что печатается перед выбором режима).
# Заголовок не обязателен: нечисловые строки просто пропускаются.

def read_csv_rule_numbers(path):
    for encoding in ("utf-8-sig", "cp1251"):
        try:
            with open(path, newline="", encoding=encoding) as f:
                rows = list(csv.reader(f))
            break
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            print(f"[!] Не удалось открыть CSV: {exc}")
            sys.exit(1)
    else:
        print("[!] Не удалось прочитать CSV ни в UTF-8, ни в cp1251")
        sys.exit(1)

    numbers = []
    skipped = []

    for row in rows:
        if not row:
            continue

        value = row[0].strip()

        if not value:
            continue

        try:
            numbers.append(int(value))
        except ValueError:
            skipped.append(value)

    if skipped:
        print(f"\n[!] Пропущены нечисловые строки CSV (например, заголовок): {skipped}")

    return numbers


def resolve_rules_by_number(numbers, all_rules):
    selected = []
    invalid = []
    seen = set()

    for number in numbers:
        idx = number - 1

        if idx < 0 or idx >= len(all_rules):
            invalid.append(number)
            continue

        if idx in seen:
            continue

        seen.add(idx)
        selected.append(all_rules[idx])

    if invalid:
        print(f"\n[!] Номера вне диапазона (пропущены): {invalid}")

    return selected


def run_replace_from_csv(all_rules):
    path = input("\nПуть к CSV-файлу (один столбец с номерами правил): ").strip().strip('"')
    numbers = read_csv_rule_numbers(path)

    if not numbers:
        print("[!] В CSV не найдено ни одного номера правила")
        sys.exit(1)

    selected = resolve_rules_by_number(numbers, all_rules)

    if not selected:
        print("[!] Ни один номер не соответствует найденным правилам")
        sys.exit(1)

    target_profile = ask_target_profile()
    target_of = lambda r: target_profile

    to_change = [r for r in selected if r["log_forwarding"] != target_profile]

    if not ask_confirmation(to_change, target_of):
        print("\n[=] Операция отменена пользователем")
        return [], [], to_change

    updated, failed = apply_changes(to_change, target_of)
    return updated, failed, to_change


def print_summary(all_rules, selected_rules, updated, failed):
    print("\n========== ИТОГ ==========")
    print(f"Всего найдено правил : {len(all_rules)}")
    print(f"Выбрано для проверки : {len(selected_rules)}")
    print(f"Обновлено правил     : {len(updated)}")
    print(f"Ошибок обновления    : {len(failed)}")

    if failed:
        print("\nОшибки:")
        for item in failed:
            rule = item["rule"]
            print(f"  - [{rule['device_group']} / {rule['rulebase']}] {rule['name']}")
            print(f"    XPath: {item['xpath']}")
            print(f"    XML: {item['xml']}")

    if updated:
        print("\nИзменения записаны в Candidate Configuration.")
        print("Commit НЕ выполнялся. Выполните Commit вручную при необходимости.")
    else:
        print("\nИзменения не вносились.")

    print("==========================\n")


def main():
    print("\n=== Palo Alto / Panorama Log Forwarding Manager ===\n")
    print("Commit: НЕ выполняется")
    print("Изменения будут записаны только в Candidate Configuration\n")

    device_groups = get_device_groups()
    selected_device_groups = ask_device_groups(device_groups)
    selected_rulebases = ask_rulebase_scope()

    print("\n--- Параметры запуска ---")
    print(f"Panorama: {PA_IP}")
    print(f"Device-group: {', '.join(selected_device_groups)}")
    print(f"Rulebase: {', '.join(selected_rulebases)}")
    print("Параметр: log-setting (Log Forwarding)")
    print("Commit: НЕ выполняется")
    print("-------------------------")

    all_rules, profiles = collect_rules(selected_device_groups, selected_rulebases)

    print("\n========== АНАЛИЗ ==========")
    print(f"Общее количество правил: {len(all_rules)}")
    print_profiles_summary(profiles)
    print_numbered_rules(all_rules)

    mode = ask_mode()

    if mode == "1":
        updated, failed, selected_rules = run_replace_profile(all_rules, profiles)
    elif mode == "2":
        updated, failed, selected_rules = run_replace_single_rule(all_rules)
    else:
        updated, failed, selected_rules = run_replace_from_csv(all_rules)

    print_summary(all_rules, selected_rules, updated, failed)


if __name__ == "__main__":
    main()
