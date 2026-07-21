# Инструкция:
# 1 - Добавить/создать тег для объектов
# 2 - Массово переименовать address objects из CSV
# 3 - Нормализовать имена объектов, удалив постфикс, например .corp.local
#
# Поддерживаются address objects двух типов:
#   - IP / ip-netmask  -> <ip-netmask>10.0.0.1</ip-netmask>
#   - FQDN            -> <fqdn>example.com</fqdn>
#
# Плейсхолдеры в паттернах имени:
#   {IP}    - IP/ip-netmask с заменой "/" на "_"
#   {FQDN}  - FQDN с заменой недопустимых символов на "_"
#   {VALUE} - значение объекта: IP или FQDN
#   {N}     - порядковый номер цели из ввода/CSV, начиная с 1
#
# Пример для FQDN:
#   CSV:
#     cdn.sbis.ru
#     google.com
#
#   Паттерн:
#     SBIS-WEB_{N}
#
#   Будет создано:
#     SBIS-WEB_1 -> fqdn cdn.sbis.ru
#     SBIS-WEB_2 -> fqdn google.com

import requests
import xml.etree.ElementTree as ET
import urllib3
import csv
import sys
import ipaddress
import re
from xml.sax.saxutils import escape, quoteattr

import api_key
import pan_api

urllib3.disable_warnings()

PA_IP = api_key.api_ip
API_KEY = pan_api.get_api_key()


TAG_COLORS = {
    "color1": "красный",
    "color2": "зелёный",
    "color3": "синий",
    "color4": "жёлтый",
    "color5": "медный",
    "color6": "оранжевый",
    "color7": "фиолетовый",
    "color8": "серый",
    "color9": "светло-зелёный",
    "color10": "голубой",
    "color11": "лавандовый",
    "color12": "красно-оранжевый",
    "color13": "оливковый",
    "color14": "светло-серый",
    "color15": "тёмно-красный",
    "color16": "зелёный",
    "color17": "средний синий",
    "color18": "синий",
    "color19": "фиолетовый",
    "color20": "средний серый",
    "color21": "светло-зелёный",
    "color22": "голубой",
    "color23": "синий",
    "color24": "фиолетовый",
    "color25": "коричневый",
}


def color_to_text(color_code):
    if not color_code:
        return "цвет не задан"

    color_name = TAG_COLORS.get(color_code, "неизвестный цвет")
    return f"{color_code} ({color_name})"


def api_get(params):
    url = f"https://{PA_IP}/api/"
    r = requests.get(url, params=params, verify=False, timeout=30)
    r.raise_for_status()
    return r.text


def response_ok(xml_text):
    return "<result>OK</result>" in xml_text or 'status="success"' in xml_text


def xml_text(value):
    return escape(str(value), {"'": "&apos;", '"': "&quot;"})


def xml_attr(value):
    return quoteattr(str(value))


def get_tag(tag_name):
    xpath = f"/config/shared/tag/entry[@name={xml_attr(tag_name)}]"

    xml = api_get({
        "type": "config",
        "action": "get",
        "xpath": xpath,
        "key": API_KEY
    })

    root = ET.fromstring(xml)
    entry = root.find(".//entry")

    if entry is None:
        return None

    return {
        "name": entry.get("name"),
        "color": entry.findtext("./color")
    }


def ensure_tag(tag_name, tag_color):
    tag = get_tag(tag_name)

    if tag:
        print(f"[=] Тег '{tag_name}' уже создан")
        print(f"[=] Цвет существующего тега: {color_to_text(tag['color'])}")
        print("[=] Будет использоваться существующий тег")
        return tag

    print(f"[*] Тег '{tag_name}' не найден")
    print(f"[*] Создаю тег с цветом: {color_to_text(tag_color)}")

    element = (
        f"<entry name={xml_attr(tag_name)}>"
        f"<color>{xml_text(tag_color)}</color>"
        f"</entry>"
    )

    xml = api_get({
        "type": "config",
        "action": "set",
        "xpath": "/config/shared/tag",
        "element": element,
        "key": API_KEY
    })

    if response_ok(xml):
        print(f"[+] Тег '{tag_name}' создан")
        print(f"[+] Использованный цвет: {color_to_text(tag_color)}")
        return {"name": tag_name, "color": tag_color}

    raise RuntimeError(f"Ошибка создания тега: {xml}")


def get_address_objects():
    xml = api_get({
        "type": "config",
        "action": "get",
        "xpath": "/config/shared/address",
        "key": API_KEY
    })

    root = ET.fromstring(xml)
    return root.findall(".//entry")


def get_object_tags(entry):
    return {
        member.text
        for member in entry.findall("./tag/member")
        if member.text
    }


def get_object_value(entry):
    """Возвращает значение address object: сначала ip-netmask, затем fqdn."""
    return entry.findtext("./ip-netmask") or entry.findtext("./fqdn")


def get_object_type(entry):
    if entry.findtext("./ip-netmask"):
        return "ip-netmask"
    if entry.findtext("./fqdn"):
        return "fqdn"
    return None


def is_ip_or_netmask(value):
    """True для IPv4/IPv6 адреса или сети, например 10.0.0.1, 10.0.0.0/24, 2001:db8::1."""
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_fqdn(value):
    """Простая проверка FQDN. Wildcard вида *.example.com тоже разрешён."""
    value = value.strip().rstrip(".")
    if not value:
        return False

    if value.startswith("*."):
        value = value[2:]

    if len(value) > 253 or "." not in value:
        return False

    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return all(label_re.match(label) for label in value.split("."))


def detect_address_type(value):
    if is_ip_or_netmask(value):
        return "ip-netmask"

    if is_fqdn(value):
        return "fqdn"

    return None


def sanitize_for_name(value):
    """PAN-OS object name безопаснее делать без /, пробелов и спецсимволов."""
    value = str(value).strip()
    value = value.replace("/", "_")
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_")


def make_name_by_pattern(pattern, value, n=None):
    """
    Поддерживает {IP}, {FQDN}, {VALUE}, {N}.
    Для FQDN лучше использовать {N}, чтобы имя не содержало полный домен.
    """
    clean_value = sanitize_for_name(value)
    clean_ip = sanitize_for_name(value) if is_ip_or_netmask(value) else ""
    clean_fqdn = sanitize_for_name(value) if is_fqdn(value) else ""

    result = pattern
    result = result.replace("{IP}", clean_ip or clean_value)
    result = result.replace("{FQDN}", clean_fqdn or clean_value)
    result = result.replace("{VALUE}", clean_value)

    if "{N}" in result:
        if n is None:
            raise ValueError("В паттерне есть {N}, но порядковый номер не передан")
        result = result.replace("{N}", str(n))

    return result


def pattern_has_supported_placeholder(pattern):
    return any(ph in pattern for ph in ("{IP}", "{FQDN}", "{VALUE}", "{N}"))


def add_tag_to_object(object_name, tag_name):
    xpath = f"/config/shared/address/entry[@name={xml_attr(object_name)}]/tag"
    element = f"<member>{xml_text(tag_name)}</member>"

    xml = api_get({
        "type": "config",
        "action": "set",
        "xpath": xpath,
        "element": element,
        "key": API_KEY
    })

    return response_ok(xml), xml


def create_address_object(object_name, value, tag_name=None):
    address_type = detect_address_type(value)

    if address_type is None:
        return False, f"'{value}' не является IP/ip-netmask или FQDN"

    xpath = "/config/shared/address"

    tag_xml = ""
    if tag_name:
        tag_xml = f"<tag><member>{xml_text(tag_name)}</member></tag>"

    value_xml = f"<{address_type}>{xml_text(value)}</{address_type}>"

    element = (
        f"<entry name={xml_attr(object_name)}>"
        f"{value_xml}"
        f"{tag_xml}"
        f"</entry>"
    )

    xml = api_get({
        "type": "config",
        "action": "set",
        "xpath": xpath,
        "element": element,
        "key": API_KEY
    })

    return response_ok(xml), xml


def rename_address_object(old_name, new_name):
    xpath = f"/config/shared/address/entry[@name={xml_attr(old_name)}]"

    xml = api_get({
        "type": "config",
        "action": "rename",
        "xpath": xpath,
        "newname": new_name,
        "key": API_KEY
    })

    return response_ok(xml), xml



def strip_name_suffix(object_name, suffix):
    """Удаляет заданный постфикс из имени объекта без учёта регистра."""
    if not object_name:
        return object_name

    if not suffix:
        return object_name

    name = object_name.strip()
    suffix = suffix.strip()

    if name.lower().endswith(suffix.lower()):
        return name[:-len(suffix)]

    return name


def ask_object_name_targets():
    print("\nКак передать список имён объектов?")
    print("1 - Одно имя объекта")
    print("2 - CSV файл со списком имён объектов")

    choice = input("Выбор: ").strip()

    if choice == "1":
        name = input("Введите имя объекта: ").strip()
        return unique_keep_order([name])

    if choice == "2":
        csv_file = input("Введите имя CSV файла: ").strip()
        return load_targets_from_csv(csv_file)

    print("[!] Неверный выбор")
    sys.exit(1)


def find_objects_by_name(objects, object_names):
    targets_set = set(object_names)
    matched = []
    found = set()

    for entry in objects:
        name = entry.get("name")

        if name in targets_set:
            matched.append(entry)
            found.add(name)

    not_found = [name for name in object_names if name not in found]
    return matched, not_found


def unique_keep_order(items):
    result = []
    seen = set()

    for item in items:
        item = item.strip()
        if not item or item in seen:
            continue

        result.append(item)
        seen.add(item)

    return result


def load_targets_from_csv(csv_file):
    targets = []

    with open(csv_file, newline="", encoding="utf-8-sig") as f:
        for row in csv.reader(f):
            if row and row[0].strip():
                targets.append(row[0].strip())

    return unique_keep_order(targets)


def ask_targets():
    print("\nЧто будем искать?")
    print("1 - IP адрес / ip-netmask / FQDN")
    print("2 - Имя объекта")
    print("3 - CSV файл")

    choice = input("Выбор: ").strip()

    if choice == "1":
        value = input("Введите IP, ip-netmask или FQDN: ").strip()
        return unique_keep_order([value])

    if choice == "2":
        name = input("Введите имя объекта: ").strip()
        return unique_keep_order([name])

    if choice == "3":
        csv_file = input("Введите имя CSV файла: ").strip()
        return load_targets_from_csv(csv_file)

    print("[!] Неверный выбор")
    sys.exit(1)


def object_matches(entry, targets_set):
    name = entry.get("name")
    value = get_object_value(entry)

    return name in targets_set or value in targets_set


def find_matching_objects(objects, targets):
    matched = []
    found_targets = set()
    target_numbers = {target: index for index, target in enumerate(targets, start=1)}
    targets_set = set(targets)

    for entry in objects:
        name = entry.get("name")
        value = get_object_value(entry)

        matched_target = None

        if name in targets_set:
            matched_target = name
        elif value in targets_set:
            matched_target = value

        if matched_target:
            matched.append({
                "entry": entry,
                "target": matched_target,
                "n": target_numbers[matched_target],
            })
            found_targets.add(matched_target)

    not_found = [target for target in targets if target not in found_targets]
    return matched, not_found


def bulk_rename_objects_from_csv():
    print("\n=== Массовое переименование address objects ===\n")

    csv_file = input("Введите имя CSV файла: ").strip()
    pattern = input("Введите паттерн нового имени объекта [DC_{N}]: ").strip() or "DC_{N}"

    if not pattern_has_supported_placeholder(pattern):
        print("[!] В паттерне должен быть хотя бы один плейсхолдер: {IP}, {FQDN}, {VALUE} или {N}")
        return

    targets = load_targets_from_csv(csv_file)
    objects = get_address_objects()

    matched_objects, not_found = find_matching_objects(objects, targets)

    if not matched_objects:
        print("[!] Объекты из CSV не найдены")

        if not_found:
            print("\nНе найдено:")
            for item in not_found:
                print(f"  - {item}")

        return

    existing_names = {entry.get("name") for entry in objects}
    planned_new_names = set()
    rename_plan = []
    already_ok = []
    conflicts = []
    skipped_no_value = []

    print("\nПлан переименования:")

    for item in matched_objects:
        entry = item["entry"]
        n = item["n"]

        old_name = entry.get("name")
        value = get_object_value(entry)

        if not value:
            skipped_no_value.append(old_name)
            print(f"[!] Пропуск '{old_name}': нет ip-netmask/fqdn")
            continue

        new_name = make_name_by_pattern(pattern, value, n=n)

        if old_name == new_name:
            already_ok.append(old_name)
            print(f"[=] Уже в нужном формате: {old_name}")
            continue

        if new_name in existing_names or new_name in planned_new_names:
            conflicts.append((old_name, new_name))
            print(f"[!] Конфликт: '{old_name}' нельзя переименовать в '{new_name}', имя уже существует или уже запланировано")
            continue

        rename_plan.append((old_name, new_name, value))
        planned_new_names.add(new_name)
        print(f"  - {old_name}  ->  {new_name} ({get_object_type(entry)}: {value})")

    if not rename_plan:
        print("\n[=] Нет объектов для переименования")
        print("\n========== ИТОГ ==========")
        print(f"Уже были в нужном формате    : {len(already_ok)}")
        print(f"Конфликтов имён              : {len(conflicts)}")
        print(f"Пропущено без ip-netmask/fqdn: {len(skipped_no_value)}")
        print(f"Не найдено целей             : {len(not_found)}")
        print("Изменения не вносились.")
        print("==========================\n")
        return

    answer = input(f"\nПереименовать объектов: {len(rename_plan)}? [y/N]: ").strip().lower()

    if answer != "y":
        print("[=] Операция отменена")
        return

    renamed = []

    for old_name, new_name, value in rename_plan:
        ok, xml = rename_address_object(old_name, new_name)

        if ok:
            renamed.append(new_name)
            print(f"[+] Переименован: {old_name} -> {new_name}")
        else:
            print(f"[!] Ошибка переименования '{old_name}': {xml}")

    print("\n========== ИТОГ ==========")
    print(f"Переименовано объектов       : {len(renamed)}")
    print(f"Уже были в нужном формате    : {len(already_ok)}")
    print(f"Конфликтов имён              : {len(conflicts)}")
    print(f"Пропущено без ip-netmask/fqdn: {len(skipped_no_value)}")
    print(f"Не найдено целей             : {len(not_found)}")

    if not_found:
        print("\nНе найдено:")
        for item in not_found:
            print(f"  - {item}")

    if renamed:
        print("\nИзменения записаны в Candidate Configuration.")
        print("Commit НЕ выполнялся. Выполните Commit вручную при необходимости.")
    else:
        print("\nИзменения не вносились.")

    print("==========================\n")


def tag_manager_mode():
    tag_name = input("Имя тега [Ansible]: ").strip() or "Ansible"
    tag_color = input("Цвет тега, если нужно создать [color6]: ").strip() or "color6"

    targets = ask_targets()

    if not targets:
        print("[!] Нет целей для обработки")
        return

    print("\n--- Параметры запуска ---")
    print(f"Тег: {tag_name}")
    print(f"Цвет при создании: {color_to_text(tag_color)}")
    print(f"Целей: {len(targets)}")
    print("Commit: НЕ выполняется")
    print("-------------------------\n")

    ensure_tag(tag_name, tag_color)

    objects = get_address_objects()
    matched_objects, not_found = find_matching_objects(objects, targets)

    created = []

    if not_found:
        creatable = []
        not_creatable = []

        for item in not_found:
            address_type = detect_address_type(item)
            if address_type:
                creatable.append((item, address_type))
            else:
                not_creatable.append(item)

        if creatable:
            print("\nНе найденные IP/FQDN объекты можно создать:")
            for item, address_type in creatable:
                print(f"  - {item} ({address_type})")

            if not_creatable:
                print("\nНельзя автоматически создать, потому что это не IP/ip-netmask и не FQDN:")
                for item in not_creatable:
                    print(f"  - {item}")

            answer = input(
                f"\nСоздать address object для не найденных IP/FQDN целей ({len(creatable)}) "
                f"и сразу добавить тег '{tag_name}'? [y/N]: "
            ).strip().lower()

            if answer == "y":
                object_pattern = input(
                    "Паттерн имени создаваемых объектов [ADDR_{N}]: "
                ).strip() or "ADDR_{N}"

                if not pattern_has_supported_placeholder(object_pattern):
                    print("[!] В паттерне должен быть хотя бы один плейсхолдер: {IP}, {FQDN}, {VALUE} или {N}")
                    return

                existing_names = {entry.get("name") for entry in objects}
                planned_names = set()
                target_numbers = {target: index for index, target in enumerate(targets, start=1)}

                for item, address_type in creatable:
                    n = target_numbers[item]
                    object_name = make_name_by_pattern(object_pattern, item, n=n)

                    if object_name in existing_names or object_name in planned_names:
                        print(f"[!] Объект '{object_name}' уже существует или уже запланирован, пропуск")
                        continue

                    ok, xml = create_address_object(
                        object_name=object_name,
                        value=item,
                        tag_name=tag_name
                    )

                    if ok:
                        print(f"[+] Создан объект '{object_name}' / {address_type}: {item} с тегом '{tag_name}'")
                        created.append(object_name)
                        existing_names.add(object_name)
                        planned_names.add(object_name)
                    else:
                        print(f"[!] Ошибка создания объекта для '{item}': {xml}")

                objects = get_address_objects()
                matched_objects, not_found = find_matching_objects(objects, targets)
        else:
            print("\nНе найденные цели нельзя автоматически создать как address object:")
            for item in not_found:
                print(f"  - {item}")

    if not matched_objects:
        print("[!] Объекты не найдены")

        if not_found:
            print("\nНе найдено:")
            for item in not_found:
                print(f"  - {item}")

        return

    objects_with_tag = []
    objects_without_tag = []

    for item in matched_objects:
        entry = item["entry"]
        tags = get_object_tags(entry)

        if tag_name in tags:
            objects_with_tag.append(entry)
        else:
            objects_without_tag.append(entry)

    print("\nНайденные объекты:")

    if objects_with_tag:
        print(f"\nУже имеют тег '{tag_name}':")
        for entry in objects_with_tag:
            print(f"  - {entry.get('name')} / {get_object_type(entry)}: {get_object_value(entry)}")

    if objects_without_tag:
        print(f"\nТребуют добавления тега '{tag_name}':")
        for entry in objects_without_tag:
            print(f"  - {entry.get('name')} / {get_object_type(entry)}: {get_object_value(entry)}")

    updated = []
    skipped = [entry.get("name") for entry in objects_with_tag]

    if not objects_without_tag:
        print(f"\n[=] Все найденные объекты уже имеют тег '{tag_name}'")
    else:
        answer = input(
            f"\nДобавить тег '{tag_name}' только объектам без тега "
            f"({len(objects_without_tag)})? [Y/n]: "
        ).strip().lower()

        if answer == "n":
            print("[=] Операция отменена пользователем")
            skipped.extend(entry.get("name") for entry in objects_without_tag)
        else:
            for entry in objects_without_tag:
                name = entry.get("name")
                value = get_object_value(entry)

                ok, xml = add_tag_to_object(name, tag_name)

                if ok:
                    updated.append(name)
                    print(f"[+] Тег '{tag_name}' добавлен к '{name}' ({get_object_type(entry)}: {value})")
                else:
                    print(f"[!] Ошибка обновления '{name}': {xml}")

    print("\n========== ИТОГ ==========")
    print(f"Создано объектов             : {len(created)}")
    print(f"Обновлено объектов           : {len(updated)}")
    print(f"Уже имели тег                : {len(objects_with_tag)}")
    print(f"Пропущено пользователем      : {len(skipped) - len(objects_with_tag)}")
    print(f"Не найдено целей             : {len(not_found)}")

    if not_found:
        print("\nНе найдено:")
        for item in not_found:
            print(f"  - {item}")

    if updated or created:
        print("\nИзменения записаны в Candidate Configuration.")
        print("Commit НЕ выполнялся. Выполните Commit вручную при необходимости.")
    else:
        print("\nИзменения не вносились.")

    print("==========================\n")




def normalize_object_names_mode():
    print("\n=== Нормализация имён address objects ===\n")

    suffix = input("Постфикс для удаления [.corp.local]: ").strip() or ".corp.local"
    targets = ask_object_name_targets()

    if not targets:
        print("[!] Нет целей для обработки")
        return

    objects = get_address_objects()
    matched_objects, not_found = find_objects_by_name(objects, targets)

    if not matched_objects:
        print("[!] Объекты по указанным именам не найдены")

        if not_found:
            print("\nНе найдено:")
            for item in not_found:
                print(f"  - {item}")

        return

    existing_names = {entry.get("name") for entry in objects}
    planned_new_names = set()
    rename_plan = []
    already_ok = []
    conflicts = []

    print("\nПлан нормализации имён:")

    for entry in matched_objects:
        old_name = entry.get("name")
        new_name = strip_name_suffix(old_name, suffix)

        if old_name == new_name:
            already_ok.append(old_name)
            print(f"[=] Без изменений: {old_name}")
            continue

        if not new_name:
            conflicts.append((old_name, new_name))
            print(f"[!] Конфликт: '{old_name}' нельзя переименовать в пустое имя")
            continue

        if new_name in existing_names or new_name in planned_new_names:
            conflicts.append((old_name, new_name))
            print(f"[!] Конфликт: '{old_name}' нельзя переименовать в '{new_name}', имя уже существует или уже запланировано")
            continue

        rename_plan.append((old_name, new_name))
        planned_new_names.add(new_name)
        print(f"  - {old_name}  ->  {new_name}")

    if not rename_plan:
        print("\n[=] Нет объектов для переименования")
        print("\n========== ИТОГ ==========")
        print(f"Уже были в нужном формате: {len(already_ok)}")
        print(f"Конфликтов имён          : {len(conflicts)}")
        print(f"Не найдено целей         : {len(not_found)}")
        print("Изменения не вносились.")
        print("==========================\n")
        return

    answer = input(f"\nПереименовать объектов: {len(rename_plan)}? [y/N]: ").strip().lower()

    if answer != "y":
        print("[=] Операция отменена")
        return

    renamed = []

    for old_name, new_name in rename_plan:
        ok, xml = rename_address_object(old_name, new_name)

        if ok:
            renamed.append(new_name)
            print(f"[+] Переименован: {old_name} -> {new_name}")
        else:
            print(f"[!] Ошибка переименования '{old_name}': {xml}")

    print("\n========== ИТОГ ==========")
    print(f"Переименовано объектов   : {len(renamed)}")
    print(f"Уже были в нужном формате: {len(already_ok)}")
    print(f"Конфликтов имён          : {len(conflicts)}")
    print(f"Не найдено целей         : {len(not_found)}")

    if not_found:
        print("\nНе найдено:")
        for item in not_found:
            print(f"  - {item}")

    if renamed:
        print("\nИзменения записаны в Candidate Configuration.")
        print("Commit НЕ выполнялся. Выполните Commit вручную при необходимости.")
    else:
        print("\nИзменения не вносились.")

    print("==========================\n")


def main():
    print("\n=== Palo Alto Tag Manager ===\n")

    print("Режим работы:")
    print("1 - Добавить/создать тег для объектов")
    print("2 - Массово переименовать address objects из CSV")
    print("3 - Нормализовать имена объектов, удалив постфикс")

    mode = input("Выбор: ").strip()

    if mode == "1":
        tag_manager_mode()
        return

    if mode == "2":
        bulk_rename_objects_from_csv()
        return

    if mode == "3":
        normalize_object_names_mode()
        return

    print("[!] Неверный выбор")


if __name__ == "__main__":
    main()
