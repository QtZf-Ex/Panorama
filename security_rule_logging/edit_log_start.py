import requests
import xml.etree.ElementTree as ET
import urllib3
import sys

import api_key
import pan_api

urllib3.disable_warnings()

PA_IP = api_key.api_ip
API_KEY = pan_api.get_api_key()

BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"


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


def ask_action():
    print("\nЧто сделать с параметром 'Log at Session Start'?")
    print("1 - Включить чекбокс")
    print("2 - Выключить чекбокс")

    choice = input("Выбор [1]: ").strip() or "1"

    if choice == "1":
        return "yes"

    if choice == "2":
        return "no"

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


def normalize_log_start(value):
    return value if value in ("yes", "no") else "no"


def collect_rules(selected_device_groups, selected_rulebases):
    all_rules = []
    rules_with_log_start = []
    rules_without_log_start = []

    for device_group in selected_device_groups:
        for rulebase in selected_rulebases:
            rules = get_security_rules(device_group, rulebase)

            for rule in rules:
                log_start = normalize_log_start(rule.findtext("./log-start"))

                item = {
                    "device_group": device_group,
                    "rulebase": rulebase,
                    "name": rule.get("name"),
                    "uuid": rule.get("uuid"),
                    "log_start": log_start
                }

                all_rules.append(item)

                if log_start == "yes":
                    rules_with_log_start.append(item)
                else:
                    rules_without_log_start.append(item)

    return all_rules, rules_with_log_start, rules_without_log_start


def print_rule_list(title, rules):
    print(f"\n{title}: {len(rules)}")

    for rule in rules:
        print(
            f"  - [{rule['device_group']} / {rule['rulebase']}] "
            f"{rule['name']} | log-start={rule['log_start']}"
        )


def print_numbered_rules(rules):
    print("\nНайденные правила:\n")

    for idx, rule in enumerate(rules, 1):
        print(
            f"{idx:4} "
            f"[{rule['device_group']} / {rule['rulebase']}] "
            f"{rule['name']} | log-start={rule['log_start']}"
        )


def ask_rules_to_edit(all_rules):
    if not all_rules:
        print("[!] Правила не найдены")
        sys.exit(1)

    print("\nЧто редактировать?")
    print("0 - все найденные правила")
    print(f"1..{len(all_rules)} - только одно правило по номеру")

    choice = input("Выбор: ").strip()

    if choice == "0":
        return all_rules

    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Неверный ввод")
        sys.exit(1)

    if idx < 0 or idx >= len(all_rules):
        print("[!] Неверный номер правила")
        sys.exit(1)

    return [all_rules[idx]]


def filter_rules_requiring_change(rules, target_value):
    return [
        rule for rule in rules
        if rule["log_start"] != target_value
    ]


def set_log_start(rule, value):
    xpath = (
        f"{BASE_XPATH}"
        f"/device-group/entry[@name={xpath_literal(rule['device_group'])}]"
        f"/{rule['rulebase']}/security/rules"
        f"/entry[@name={xpath_literal(rule['name'])}]"
    )

    element = f"<log-start>{value}</log-start>"

    xml = api_get({
        "type": "config",
        "action": "set",
        "xpath": xpath,
        "element": element,
        "key": API_KEY
    })

    return response_ok(xml), xml, xpath


def ask_confirmation(rules_to_change, target_value):
    if not rules_to_change:
        print("\n[=] Нет правил, требующих изменения")
        return False

    action_text = "добавить чекбокс" if target_value == "yes" else "удалить чекбокс"

    print(f"\nБудет изменено правил: {len(rules_to_change)}")
    print(f"Действие: {action_text} Log at Session Start")

    print("\nПравила к изменению:")
    for rule in rules_to_change:
        print(
            f"  - [{rule['device_group']} / {rule['rulebase']}] "
            f"{rule['name']} | {rule['log_start']} -> {target_value}"
        )

    answer = input("\nПодтвердить изменение? [y/N]: ").strip().lower()
    return answer == "y"


def main():
    print("\n=== Palo Alto / Panorama Log Session Start Manager ===\n")
    print("Commit: НЕ выполняется")
    print("Изменения будут записаны только в Candidate Configuration\n")

    device_groups = get_device_groups()
    selected_device_groups = ask_device_groups(device_groups)
    selected_rulebases = ask_rulebase_scope()

    print("\n--- Параметры запуска ---")
    print(f"Panorama: {PA_IP}")
    print(f"Device-group: {', '.join(selected_device_groups)}")
    print(f"Rulebase: {', '.join(selected_rulebases)}")
    print("Параметр: log-start")
    print("Commit: НЕ выполняется")
    print("-------------------------")

    all_rules, rules_with_log_start, rules_without_log_start = collect_rules(
        selected_device_groups,
        selected_rulebases
    )

    print("\n========== АНАЛИЗ ==========")
    print(f"Общее количество правил       : {len(all_rules)}")
    print(f"Правила с включенным чекбоксом: {len(rules_with_log_start)}")
    print(f"Правила без чекбокса          : {len(rules_without_log_start)}")

    print_rule_list("Правила с включенным Log at Session Start", rules_with_log_start)
    print_rule_list("Правила без Log at Session Start", rules_without_log_start)

    print_numbered_rules(all_rules)

    target_value = ask_action()
    selected_rules = ask_rules_to_edit(all_rules)
    rules_to_change = filter_rules_requiring_change(selected_rules, target_value)

    if not ask_confirmation(rules_to_change, target_value):
        print("\n[=] Операция отменена пользователем")
        return

    updated = []
    failed = []

    print("\n========== ОБНОВЛЕНИЕ ==========")

    for i, rule in enumerate(rules_to_change, 1):
        print(
            f"[*] {i}/{len(rules_to_change)} "
            f"[{rule['device_group']} / {rule['rulebase']}] "
            f"{rule['name']} | log-start={rule['log_start']} -> {target_value}"
        )

        ok, xml, xpath = set_log_start(rule, target_value)

        if ok:
            updated.append(rule)
            print(f"[+] OK: {rule['name']}")
        else:
            failed.append({
                "rule": rule,
                "xml": xml,
                "xpath": xpath
            })
            print(f"[!] ERROR: {rule['name']}")
            print(xml)

    print("\n========== ИТОГ ==========")
    print(f"Всего найдено правил          : {len(all_rules)}")
    print(f"Уже имели чекбокс             : {len(rules_with_log_start)}")
    print(f"Были без чекбокса             : {len(rules_without_log_start)}")
    print(f"Выбрано для проверки          : {len(selected_rules)}")
    print(f"Обновлено правил              : {len(updated)}")
    print(f"Ошибок обновления             : {len(failed)}")

    if failed:
        print("\nОшибки:")
        for item in failed:
            rule = item["rule"]
            print(
                f"  - [{rule['device_group']} / {rule['rulebase']}] "
                f"{rule['name']}"
            )
            print(f"    XPath: {item['xpath']}")
            print(f"    XML: {item['xml']}")

    if updated:
        print("\nИзменения записаны в Candidate Configuration.")
        print("Commit НЕ выполнялся. Выполните Commit вручную при необходимости.")
    else:
        print("\nИзменения не вносились.")

    print("==========================\n")


if __name__ == "__main__":
    main()