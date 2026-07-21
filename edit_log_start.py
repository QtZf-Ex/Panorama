import requests
import xml.etree.ElementTree as ET
import urllib3
import sys
import csv
import os
from datetime import datetime

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
    xml = api_get({"type": "config", "action": "get", "xpath": xpath, "key": API_KEY})
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
    print("1 - pre-rulebase")
    print("2 - post-rulebase")
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
    xml = api_get({"type": "config", "action": "get", "xpath": xpath, "key": API_KEY})
    root = ET.fromstring(xml)
    return root.findall(".//rules/entry")


def parse_profile_setting(rule):
    """
    Возвращает (profile_type, group_name, is_problem).

    Два проблемных случая (is_problem=True):
      1. "none"       — тег <profile-setting> отсутствует или пустой
                        (Profile Type = None в UI)
      2. "group_none" — Profile Type = Group, но Group Profile = None
                        (тег <member> отсутствует / пустой / буквально "None")

    Нормальные случаи (is_problem=False):
      3. "group"      — Profile Type = Group, Group Profile задан
      4. "profiles"   — Profile Type = Profiles (отдельные профили)
    """
    ps = rule.find("./profile-setting")

    # Случай 1: тег отсутствует или пустой
    if ps is None or len(ps) == 0:
        return "none", None, True

    # Случай 2 и 3: есть <group>
    if ps.find("group") is not None:
        member = ps.findtext("./group/member")
        if not member or member.strip().lower() == "none":
            return "group_none", None, True   # Group Profile = None
        return "group", member, False          # Group Profile задан

    # Случай 4: отдельные профили
    if ps.find("profiles") is not None:
        return "profiles", None, False

    # Неизвестная структура — считаем проблемой
    return "none", None, True


def format_profile(profile_type, group_name):
    if profile_type == "none":
        return "None"
    if profile_type == "group_none":
        return "Group(None)"
    if profile_type == "group":
        return f"Group({group_name})"
    return "Profiles(...)"


def collect_rules(selected_device_groups, selected_rulebases):
    all_rules = []
    counter = 0

    for device_group in selected_device_groups:
        for rulebase in selected_rulebases:
            rules = get_security_rules(device_group, rulebase)
            for rule in rules:
                counter += 1
                profile_type, group_name, is_problem = parse_profile_setting(rule)
                all_rules.append({
                    "num":            counter,
                    "device_group":   device_group,
                    "rulebase":       rulebase,
                    "name":           rule.get("name"),
                    "uuid":           rule.get("uuid", ""),
                    "profile_type":   profile_type,
                    "group_name":     group_name or "",
                    "is_problem":     is_problem,
                    "target_profile": "",   # заполняется вручную в CSV
                })

    return all_rules


# ─────────────────────────── РЕЖИМ 1: ПРОСМОТР ──────────────────────────────

def mode_view(all_rules):
    rules_none       = [r for r in all_rules if r["profile_type"] == "none"]
    rules_group_none = [r for r in all_rules if r["profile_type"] == "group_none"]
    problems         = [r for r in all_rules if r["is_problem"]]

    print("\n========== АНАЛИЗ ==========")
    print(f"Всего правил                       : {len(all_rules)}")
    print(f"Profile Type = None (не задан)     : {len(rules_none)}")
    print(f"Profile Type = Group(None)         : {len(rules_group_none)}")
    print(f"Итого проблемных                   : {len(problems)}")

    print("\n========== ВСЕ ПРАВИЛА ==========\n")
    for r in all_rules:
        marker = " <<<" if r["is_problem"] else ""
        print(
            f"{r['num']:5} [{r['device_group']} / {r['rulebase']}] "
            f"{r['name']} | Profile={format_profile(r['profile_type'], r['group_name'])}"
            f"{marker}"
        )

    print(f"\n========== ПРОБЛЕМНЫЕ ПРАВИЛА ({len(problems)} шт.) ==========\n")
    if not problems:
        print("  Проблемных правил не найдено.")
    else:
        print(f"  {'#':>5}  {'Device-group':<25} {'Rulebase':<15} {'Rule name':<45} Profile")
        print(f"  {'-'*5}  {'-'*25} {'-'*15} {'-'*45} {'-'*15}")
        for r in problems:
            print(
                f"  {r['num']:>5}  {r['device_group']:<25} {r['rulebase']:<15} "
                f"{r['name']:<45} {format_profile(r['profile_type'], r['group_name'])}"
            )

    return problems


def save_csv(all_rules):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"profile_report_{timestamp}.csv"

    with open(fname, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "num", "device_group", "rulebase", "name",
            "profile_type", "group_name", "target_profile", "uuid"
        ])
        writer.writeheader()
        for r in all_rules:
            writer.writerow({
                "num":            r["num"],
                "device_group":   r["device_group"],
                "rulebase":       r["rulebase"],
                "name":           r["name"],
                "profile_type":   r["profile_type"],
                "group_name":     r["group_name"],
                "target_profile": "",   # заполнить вручную для нужных правил
                "uuid":           r["uuid"],
            })

    print(f"\n[+] Отчёт сохранён: {fname}")
    print(f"    Заполни колонку 'target_profile' для нужных правил")
    print(f"    (например: servers, clients, GP, client_outside ...)")
    print(f"    Пустые строки при применении будут пропущены.")
    return fname


# ─────────────────────────── РЕЖИМ 2: ПРИМЕНЕНИЕ ────────────────────────────

def load_csv(fname):
    if not os.path.exists(fname):
        print(f"[!] Файл не найден: {fname}")
        sys.exit(1)

    rows = []
    with open(fname, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def set_group_profile(device_group, rulebase, rule_name, group_profile_name):
    xpath = (
        f"{BASE_XPATH}"
        f"/device-group/entry[@name={xpath_literal(device_group)}]"
        f"/{rulebase}/security/rules"
        f"/entry[@name={xpath_literal(rule_name)}]"
    )
    element = (
        "<profile-setting>"
        "<group>"
        f"<member>{group_profile_name}</member>"
        "</group>"
        "</profile-setting>"
    )
    xml = api_get({
        "type": "config",
        "action": "set",
        "xpath": xpath,
        "element": element,
        "key": API_KEY,
    })
    return response_ok(xml), xml, xpath


def mode_apply(fname):
    rows = load_csv(fname)
    to_apply = [r for r in rows if r.get("target_profile", "").strip()]

    if not to_apply:
        print("[!] В CSV нет ни одной строки с заполненным target_profile. Нечего применять.")
        sys.exit(0)

    print(f"\nБудет изменено правил: {len(to_apply)}\n")
    print(f"  {'#':>5}  {'Device-group':<25} {'Rulebase':<15} {'Rule name':<45} Действие")
    print(f"  {'-'*5}  {'-'*25} {'-'*15} {'-'*45} {'-'*20}")
    for r in to_apply:
        current = f"{r['profile_type']}({r['group_name']})" if r['group_name'] else r['profile_type']
        print(
            f"  {r['num']:>5}  {r['device_group']:<25} {r['rulebase']:<15} "
            f"{r['name']:<45} {current} -> Group({r['target_profile']})"
        )

    answer = input("\nПодтвердить изменение? [y/N]: ").strip().lower()
    if answer != "y":
        print("\n[=] Операция отменена")
        return

    updated, failed = [], []

    print("\n========== ПРИМЕНЕНИЕ ==========")
    for i, r in enumerate(to_apply, 1):
        target = r["target_profile"].strip()
        print(
            f"[*] {i}/{len(to_apply)} "
            f"[{r['device_group']} / {r['rulebase']}] "
            f"{r['name']} -> Group({target})"
        )
        ok, xml, xpath = set_group_profile(
            r["device_group"], r["rulebase"], r["name"], target
        )
        if ok:
            updated.append(r)
            print(f"[+] OK")
        else:
            failed.append({"row": r, "xml": xml, "xpath": xpath})
            print(f"[!] ERROR")
            print(xml)

    print("\n========== ИТОГ ==========")
    print(f"Обработано : {len(to_apply)}")
    print(f"Успешно    : {len(updated)}")
    print(f"Ошибок     : {len(failed)}")

    if failed:
        print("\nОшибки:")
        for item in failed:
            r = item["row"]
            print(f"  - [{r['device_group']} / {r['rulebase']}] {r['name']}")
            print(f"    XPath : {item['xpath']}")
            print(f"    XML   : {item['xml']}")

    if updated:
        print("\nИзменения записаны в Candidate Configuration.")
        print("Commit НЕ выполнялся. Выполните Commit вручную.")
    print("==========================\n")


# ────────────────────────────── MAIN ────────────────────────────────────────

def main():
    print("\n=== Palo Alto / Panorama — Profile Setting Manager ===\n")
    print("Commit: НЕ выполняется автоматически\n")

    print("Режим работы:")
    print("1 - Просмотр правил + сохранить CSV-отчёт")
    print("2 - Применить изменения из CSV")

    mode = input("Выбор [1]: ").strip() or "1"

    if mode == "2":
        fname = input("Путь к CSV-файлу: ").strip()
        mode_apply(fname)
        return

    if mode != "1":
        print("[!] Неверный выбор")
        sys.exit(1)

    # ── Режим 1: просмотр ──
    device_groups = get_device_groups()
    selected_device_groups = ask_device_groups(device_groups)
    selected_rulebases = ask_rulebase_scope()

    print("\n--- Параметры ---")
    print(f"Panorama    : {PA_IP}")
    print(f"Device-group: {', '.join(selected_device_groups)}")
    print(f"Rulebase    : {', '.join(selected_rulebases)}")
    print("-----------------")

    all_rules = collect_rules(selected_device_groups, selected_rulebases)
    mode_view(all_rules)

    save = input("\nСохранить CSV-отчёт? [Y/n]: ").strip().lower()
    if save != "n":
        save_csv(all_rules)


if __name__ == "__main__":
    main()