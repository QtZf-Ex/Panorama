# Можно допилить. Когда ищу обращения от устройства, показывает всегда src. То есть его самого Получается ip 1500 | object. Бесполезная инфа. Пока что можно юзать только поиск "кто обращался к серверу"

import requests
import xml.etree.ElementTree as ET
import urllib3
import csv
import sys
import time
import ipaddress
from collections import Counter, defaultdict

import api_key
import pan_api

urllib3.disable_warnings()

PA_IP = api_key.api_ip
API_KEY = pan_api.get_api_key()

DEFAULT_MAIL_IP = "192.0.2.25"
DEFAULT_MAIL_PORT = "587"
DEFAULT_THRESHOLD = 30
DEFAULT_PAGE_SIZE = 1500
DEFAULT_MAX_TOTAL_LOGS = 10000
DEFAULT_OUTPUT_CSV = "potential_mail_bruteforce.csv"


def api_get(params):
    url = f"https://{PA_IP}/api/"
    r = requests.get(url, params=params, verify=False, timeout=90)
    r.raise_for_status()
    return r.text


def get_text(entry, field):
    value = entry.findtext(f"./{field}")
    return value.strip() if value else ""


def get_members(entry, path):
    return [
        member.text.strip()
        for member in entry.findall(path)
        if member.text and member.text.strip()
    ]


def ask_int(prompt, default):
    value = input(f"{prompt} [{default}]: ").strip()

    if not value:
        return default

    try:
        return int(value)
    except ValueError:
        print("[!] Нужно ввести число")
        sys.exit(1)


def build_query(filters):
    parts = []

    if filters.get("src_ip"):
        parts.append(f"(addr.src eq {filters['src_ip']})")

    if filters.get("src_port"):
        parts.append(f"(port.src eq {filters['src_port']})")

    if filters.get("dst_ip"):
        parts.append(f"(addr.dst eq {filters['dst_ip']})")

    if filters.get("dst_port"):
        parts.append(f"(port.dst eq {filters['dst_port']})")

    return " and ".join(parts)


def create_log_job(query, nlogs, skip=0):
    params = {
        "type": "log",
        "log-type": "traffic",
        "nlogs": str(nlogs),
        "skip": str(skip),
        "key": API_KEY
    }

    if query:
        params["query"] = query

    xml = api_get(params)
    root = ET.fromstring(xml)
    job_id = root.findtext(".//job")

    if not job_id:
        raise RuntimeError(f"Не удалось получить job-id:\n{xml}")

    return job_id


def get_log_job_result(job_id):
    return api_get({
        "type": "log",
        "action": "get",
        "job-id": job_id,
        "key": API_KEY
    })


def wait_for_job(job_id, attempts=20, delay=3):
    for attempt in range(1, attempts + 1):
        xml = get_log_job_result(job_id)
        root = ET.fromstring(xml)

        status = root.findtext(".//job/status")

        if status == "FIN":
            return xml

        print(f"[*] Job {job_id}: статус {status or 'UNKNOWN'}, попытка {attempt}/{attempts}")
        time.sleep(delay)

    raise TimeoutError(f"Job {job_id} не завершился за отведенное время")


def parse_logs(xml):
    root = ET.fromstring(xml)
    entries = root.findall(".//log/logs/entry")

    logs = []

    for entry in entries:
        logs.append({
            "receive_time": get_text(entry, "receive_time"),
            "src": get_text(entry, "src"),
            "dst": get_text(entry, "dst"),
            "sport": get_text(entry, "sport"),
            "dport": get_text(entry, "dport"),
            "app": get_text(entry, "app"),
            "action": get_text(entry, "action"),
            "rule": get_text(entry, "rule"),
            "srcloc": get_text(entry, "srcloc"),
            "device_name": get_text(entry, "device_name"),
            "session_end_reason": get_text(entry, "session_end_reason"),
        })

    cached_logs = int(root.findtext(".//cached-logs") or 0)
    logs_node = root.find(".//log/logs")
    returned_count = int(logs_node.get("count")) if logs_node is not None else 0

    return logs, cached_logs, returned_count


def load_logs_paged(query, page_size, max_total_logs):
    all_logs = []
    skip = 0
    cached_total = 0

    while len(all_logs) < max_total_logs:
        print(f"\n[*] Создаю log job: skip={skip}, nlogs={page_size}")
        job_id = create_log_job(query, page_size, skip=skip)
        print(f"[+] Job создан: {job_id}")

        result_xml = wait_for_job(job_id)
        logs, cached_logs, returned_count = parse_logs(result_xml)

        cached_total = max(cached_total, cached_logs)
        all_logs.extend(logs)

        print(f"[+] Получено: {returned_count}, всего загружено: {len(all_logs)}, cached: {cached_logs}")

        if returned_count == 0:
            break

        if len(all_logs) >= cached_logs:
            break

        if len(all_logs) >= max_total_logs:
            break

        skip += returned_count

    return all_logs, cached_total, len(all_logs)


def get_shared_address_objects():
    xml = api_get({
        "type": "config",
        "action": "get",
        "xpath": "/config/shared/address",
        "key": API_KEY
    })

    root = ET.fromstring(xml)
    objects = []

    for entry in root.findall(".//address/entry"):
        objects.append({
            "name": entry.get("name", ""),
            "ip_netmask": get_text(entry, "ip-netmask"),
            "fqdn": get_text(entry, "fqdn"),
            "description": get_text(entry, "description"),
            "tags": get_members(entry, "./tag/member")
        })

    return objects


def build_ip_object_index(objects):
    exact_ip_index = {}
    network_index = []

    for obj in objects:
        ip_netmask = obj["ip_netmask"]

        if not ip_netmask:
            continue

        try:
            if "/" in ip_netmask:
                network = ipaddress.ip_network(ip_netmask, strict=False)
                network_index.append((network, obj))
            else:
                ip = ipaddress.ip_address(ip_netmask)
                exact_ip_index[str(ip)] = obj
        except ValueError:
            continue

    network_index.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return exact_ip_index, network_index


def find_object_by_ip(ip, exact_ip_index, network_index):
    if not ip:
        return None

    if ip in exact_ip_index:
        return exact_ip_index[ip]

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for network, obj in network_index:
        if ip_obj in network:
            return obj

    return None


def choose_analysis_field(filters):
    """
    Выбирает, какое поле считать объектом анализа.

    Сценарии:
    - задан dst и не задан src: ищем, кто обращался к серверу -> группируем по src;
    - задан src и не задан dst: ищем, куда обращалось устройство -> группируем по dst;
    - задан dst port без src/dst IP, как в mail bruteforce, -> группируем по src;
    - если заданы обе стороны или ничего не задано, по умолчанию группируем по src.
    """
    has_src_filter = bool(filters.get("src_ip") or filters.get("src_port"))
    has_dst_filter = bool(filters.get("dst_ip") or filters.get("dst_port"))

    if has_src_filter and not has_dst_filter:
        return "dst"

    return "src"


def get_analysis_title(analysis_field):
    if analysis_field == "dst":
        return "dst IP"

    return "src IP"


def analyze_by_field(logs, threshold, exact_ip_index, network_index, analysis_field):
    counter = Counter()
    details = defaultdict(list)

    for log in logs:
        ip = log.get(analysis_field, "")

        if not ip:
            continue

        counter[ip] += 1
        details[ip].append(log)

    suspicious = {
        ip: count
        for ip, count in counter.items()
        if count >= threshold
    }

    normal = {
        ip: count
        for ip, count in counter.items()
        if count < threshold
    }

    objects_by_ip = {
        ip: find_object_by_ip(ip, exact_ip_index, network_index)
        for ip in counter
    }

    suspicious_known = {
        ip: count
        for ip, count in suspicious.items()
        if objects_by_ip.get(ip)
    }

    suspicious_unknown = {
        ip: count
        for ip, count in suspicious.items()
        if not objects_by_ip.get(ip)
    }

    return counter, suspicious, normal, suspicious_known, suspicious_unknown, details, objects_by_ip


def format_object(obj):
    if not obj:
        return "object не найден"

    tags = ", ".join(obj["tags"]) if obj["tags"] else "tags нет"
    return f"{obj['name']} | tags: {tags}"


def get_last_log_line(logs):
    if not logs:
        return None

    return logs[-1]


def save_suspicious_to_csv(suspicious, details, objects_by_ip, output_file, analysis_field):
    with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        writer.writerow([
            analysis_field,
            "known_status",
            "object_name",
            "object_tags",
            "count",
            "first_seen",
            "last_seen",
            "sample_src",
            "sample_sport",
            "sample_dst",
            "sample_dport",
            "app",
            "action",
            "rule",
            "srcloc",
            "device_name"
        ])

        for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
            ip_logs = details[ip]
            sample = ip_logs[0] if ip_logs else {}
            obj = objects_by_ip.get(ip)

            writer.writerow([
                ip,
                "known" if obj else "unknown",
                obj["name"] if obj else "",
                ", ".join(obj["tags"]) if obj else "",
                count,
                ip_logs[-1]["receive_time"] if ip_logs else "",
                ip_logs[0]["receive_time"] if ip_logs else "",
                sample.get("src", ""),
                sample.get("sport", ""),
                sample.get("dst", ""),
                sample.get("dport", ""),
                sample.get("app", ""),
                sample.get("action", ""),
                sample.get("rule", ""),
                sample.get("srcloc", ""),
                sample.get("device_name", "")
            ])


def ask_mail_search():
    print("\n=== Поиск mail bruteforce ===")
    print(f"dst IP по умолчанию: {DEFAULT_MAIL_IP}")
    print(f"dst port по умолчанию: {DEFAULT_MAIL_PORT}")

    dst_ip = input(f"Mail server dst IP [{DEFAULT_MAIL_IP}]: ").strip() or DEFAULT_MAIL_IP
    dst_port = input(f"Mail dst port [{DEFAULT_MAIL_PORT}]: ").strip() or DEFAULT_MAIL_PORT

    return {
        "src_ip": "",
        "src_port": "",
        "dst_ip": dst_ip,
        "dst_port": dst_port
    }


def ask_custom_search():
    print("\n=== Произвольный поиск traffic logs ===")
    print("Пустые поля не будут добавлены в query")

    return {
        "src_ip": input("src IP: ").strip(),
        "src_port": input("src port: ").strip(),
        "dst_ip": input("dst IP: ").strip(),
        "dst_port": input("dst port: ").strip()
    }


def ask_search_mode():
    print("\nЧто ищем?")
    print(f"1 - Mail bruteforce: dst IP {DEFAULT_MAIL_IP} + dst port {DEFAULT_MAIL_PORT}")
    print("2 - Произвольный поиск: src IP/port + dst IP/port")

    choice = input("Выбор [1]: ").strip() or "1"

    if choice == "1":
        return ask_mail_search()

    if choice == "2":
        return ask_custom_search()

    print("[!] Неверный выбор")
    sys.exit(1)


def print_summary(
    logs,
    cached_logs,
    returned_count,
    counter,
    suspicious,
    normal,
    suspicious_known,
    suspicious_unknown,
    threshold,
    objects_by_ip,
    analysis_field
):
    last_log = get_last_log_line(logs)

    print("\n========== РЕЗУЛЬТАТ ==========")
    print(f"Cached logs в Panorama       : {cached_logs}")
    print(f"Загружено logs               : {returned_count}")
    print(f"Распарсено logs              : {len(logs)}")
    analysis_title = get_analysis_title(analysis_field)

    print(f"Поле анализа                 : {analysis_title}")
    print(f"Уникальных {analysis_title:<15}: {len(counter)}")
    print(f"Порог подозрительности       : {threshold}")
    print(f"Подозрительных {analysis_title:<15}: {len(suspicious)}")
    print(f"  - знакомых IP              : {len(suspicious_known)}")
    print(f"  - незнакомых IP            : {len(suspicious_unknown)}")
    print(f"Нормальных {analysis_title:<15}: {len(normal)}")

    if last_log:
        print("\nПоследняя полученная строка лога:")
        print(f"  receive_time        : {last_log['receive_time']}")
        print(f"  src                 : {last_log['src']}")
        print(f"  dst                 : {last_log['dst']}")
        print(f"  dport               : {last_log['dport']}")
        print(f"  app                 : {last_log['app']}")
        print(f"  action              : {last_log['action']}")
        print(f"  rule                : {last_log['rule']}")
        print(f"  device_name         : {last_log['device_name']}")
        print(f"  session_end_reason  : {last_log['session_end_reason']}")

    if suspicious_known:
        print(f"\nПодозрительные знакомые {analysis_title}:")
        for ip, count in sorted(suspicious_known.items(), key=lambda x: x[1], reverse=True):
            obj = objects_by_ip.get(ip)
            print(f"  - {ip}: {count} | {format_object(obj)}")

    if suspicious_unknown:
        print(f"\nПодозрительные незнакомые {analysis_title}:")
        for ip, count in sorted(suspicious_unknown.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {ip}: {count} | object не найден")

    print("===============================")


def main():
    print("\n=== Panorama Traffic Log Analyzer ===")
    print("Назначение: поиск потенциального mail bruteforce по количеству обращений")
    print("Commit: НЕ выполняется")
    print("Запись в Panorama: НЕ выполняется\n")

    filters = ask_search_mode()
    threshold = ask_int("Порог обращений от одного IP", DEFAULT_THRESHOLD)
    page_size = ask_int("Размер одной страницы логов", DEFAULT_PAGE_SIZE)
    max_total_logs = ask_int("Максимум логов загрузить за запуск", DEFAULT_MAX_TOTAL_LOGS)

    query = build_query(filters)
    analysis_field = choose_analysis_field(filters)
    analysis_title = get_analysis_title(analysis_field)

    print("\n--- Параметры запуска ---")
    print(f"Panorama: {PA_IP}")
    print(f"Query: {query or 'без query, будут запрошены последние traffic logs'}")
    print("Глубина поиска: не ограничена по времени")
    print(f"Размер страницы: {page_size}")
    print(f"Максимум логов: {max_total_logs}")
    print(f"Поле анализа: {analysis_title}")
    print(f"threshold: {threshold}")
    print("-------------------------")

    confirm = input("\nЗапустить поиск? [y/N]: ").strip().lower()

    if confirm != "y":
        print("[=] Операция отменена")
        return

    print("\n[*] Загружаю shared address objects...")
    objects = get_shared_address_objects()
    exact_ip_index, network_index = build_ip_object_index(objects)
    print(f"[+] Загружено address objects: {len(objects)}")

    logs, cached_logs, returned_count = load_logs_paged(
        query=query,
        page_size=page_size,
        max_total_logs=max_total_logs
    )

    counter, suspicious, normal, suspicious_known, suspicious_unknown, details, objects_by_ip = analyze_by_field(
        logs,
        threshold,
        exact_ip_index,
        network_index,
        analysis_field
    )

    print_summary(
        logs=logs,
        cached_logs=cached_logs,
        returned_count=returned_count,
        counter=counter,
        suspicious=suspicious,
        normal=normal,
        suspicious_known=suspicious_known,
        suspicious_unknown=suspicious_unknown,
        threshold=threshold,
        objects_by_ip=objects_by_ip,
        analysis_field=analysis_field
    )

    if suspicious:
        save_suspicious_to_csv(
            suspicious=suspicious,
            details=details,
            objects_by_ip=objects_by_ip,
            output_file=DEFAULT_OUTPUT_CSV,
            analysis_field=analysis_field
        )
        print(f"\n[+] Подозрительные IP записаны в CSV: {DEFAULT_OUTPUT_CSV}")
    else:
        print("\n[=] Подозрительных IP нет. CSV не создан.")


if __name__ == "__main__":
    main()