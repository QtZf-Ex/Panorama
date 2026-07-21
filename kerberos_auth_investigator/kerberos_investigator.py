import requests
import xml.etree.ElementTree as ET
import urllib3
import csv
import sys
import time
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import api_key
import pan_api

urllib3.disable_warnings()

PA_IP = api_key.api_ip
API_KEY = pan_api.get_api_key()

DEFAULT_PAM_IPS = [
    "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14",
    "192.0.2.15", "192.0.2.16", "192.0.2.17", "192.0.2.18",
    "192.0.2.19", "192.0.2.20",
]

DEFAULT_SUSPECT_IP = "192.0.2.20"
DEFAULT_ACCOUNT = "SRV-EXAMPLE-ACCOUNT$"
DEFAULT_AUTH_PORTS = ["88"]
DEFAULT_AUTH_APPS = ["kerberos"]
DEFAULT_CONTEXT_PORTS = ["88", "389", "445", "135", "139", "464", "636", "3268", "3269", "3389", "5985", "5986", "443", "80"]
DEFAULT_CONTEXT_APPS = ["kerberos", "ldap", "ms-ds-smb", "ms-rdp", "winrm", "ssl", "web-browsing"]
DEFAULT_PAGE_SIZE = 1500
DEFAULT_MAX_TOTAL_LOGS = 30000
DEFAULT_TOP = 50
DEFAULT_BUCKET_SECONDS = 60
DEFAULT_CONTEXT_BEFORE_SECONDS = 30
DEFAULT_OUTPUT_PREFIX = "panorama_4771_v2"

# Panorama API traffic-log time format is normally YYYY/MM/DD HH:MM:SS
TIME_FORMATS = [
    "%d.%m.%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
]


def api_get(params):
    url = f"https://{PA_IP}/api/"
    r = requests.get(url, params=params, verify=False, timeout=90)
    r.raise_for_status()
    return r.text


def get_text(entry, field):
    value = entry.findtext(f"./{field}")
    return value.strip() if value else ""


def get_members(entry, path):
    return [m.text.strip() for m in entry.findall(path) if m.text and m.text.strip()]


def ask(prompt, default=""):
    suffix = f" [{default}]" if default != "" else ""
    return input(f"{prompt}{suffix}: ").strip() or default


def ask_int(prompt, default):
    value = input(f"{prompt} [{default}]: ").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        print("[!] Нужно ввести число")
        sys.exit(1)


def parse_csv_list(value):
    return [x.strip() for x in value.split(",") if x.strip()]


def or_eq(field, values):
    values = [v for v in values if v]
    if not values:
        return ""
    return "(" + " or ".join(f"({field} eq {v})" for v in values) + ")"


def or_app(values):
    values = [v for v in values if v]
    if not values:
        return ""
    return "(" + " or ".join(f"(app eq '{v}')" for v in values) + ")"


def and_parts(parts):
    parts = [p for p in parts if p]
    return " and ".join(parts)


def or_parts(parts):
    parts = [p for p in parts if p]
    if not parts:
        return ""
    return "(" + " or ".join(parts) + ")"


def parse_time(value):
    value = value.strip()
    if not value:
        return None
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    print(f"[!] Не понял формат времени: {value}")
    print("    Поддерживается: 22.06.2026 11:39:33 или 2026/06/22 11:39:33")
    sys.exit(1)


def fmt_pan_time(dt):
    return dt.strftime("%Y/%m/%d %H:%M:%S")


def build_time_query(start_dt, end_dt):
    if not start_dt or not end_dt:
        return ""
    return f"(receive_time geq '{fmt_pan_time(start_dt)}') and (receive_time leq '{fmt_pan_time(end_dt)}')"


def create_log_job(query, nlogs, skip=0):
    params = {
        "type": "log",
        "log-type": "traffic",
        "nlogs": str(nlogs),
        "skip": str(skip),
        "key": API_KEY,
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
    return api_get({"type": "log", "action": "get", "job-id": job_id, "key": API_KEY})


def wait_for_job(job_id, attempts=20, delay=3):
    for attempt in range(1, attempts + 1):
        xml = get_log_job_result(job_id)
        root = ET.fromstring(xml)
        status = root.findtext(".//job/status")
        if status == "FIN":
            return xml
        print(f"[*] Job {job_id}: статус {status or 'UNKNOWN'}, попытка {attempt}/{attempts}")
        time.sleep(delay)
    raise TimeoutError(f"Job {job_id} не завершился")


def parse_receive_time(value):
    return parse_time(value) if value else None


def parse_logs(xml):
    root = ET.fromstring(xml)
    entries = root.findall(".//log/logs/entry")
    logs = []
    for entry in entries:
        rt = get_text(entry, "receive_time")
        logs.append({
            "receive_time": rt,
            "dt": parse_receive_time(rt),
            "src": get_text(entry, "src"),
            "dst": get_text(entry, "dst"),
            "sport": get_text(entry, "sport"),
            "dport": get_text(entry, "dport"),
            "app": get_text(entry, "app"),
            "action": get_text(entry, "action"),
            "rule": get_text(entry, "rule"),
            "srcuser": get_text(entry, "srcuser"),
            "dstuser": get_text(entry, "dstuser"),
            "device_name": get_text(entry, "device_name"),
            "sessionid": get_text(entry, "sessionid"),
            "session_end_reason": get_text(entry, "session_end_reason"),
        })
    cached_logs = int(root.findtext(".//cached-logs") or 0)
    logs_node = root.find(".//log/logs")
    returned_count = int(logs_node.get("count")) if logs_node is not None and logs_node.get("count") else len(logs)
    return logs, cached_logs, returned_count


def load_logs_paged(query, page_size, max_total_logs):
    all_logs = []
    skip = 0
    cached_total = 0
    seen_page_guard = 0
    while len(all_logs) < max_total_logs:
        print(f"\n[*] Создаю log job: skip={skip}, nlogs={page_size}")
        job_id = create_log_job(query, page_size, skip=skip)
        print(f"[+] Job создан: {job_id}")
        result_xml = wait_for_job(job_id)
        logs, cached_logs, returned_count = parse_logs(result_xml)
        cached_total = max(cached_total, cached_logs)
        if not logs or returned_count == 0:
            break
        all_logs.extend(logs)
        print(f"[+] Получено: {returned_count}, всего загружено: {len(all_logs)}, cached: {cached_logs}")
        if returned_count < page_size:
            break
        if cached_logs and skip + returned_count >= cached_logs:
            break
        skip += returned_count
        seen_page_guard += 1
        if seen_page_guard > 100:
            break
    return all_logs[:max_total_logs], cached_total, min(len(all_logs), max_total_logs)


def get_shared_address_objects():
    xml = api_get({"type": "config", "action": "get", "xpath": "/config/shared/address", "key": API_KEY})
    root = ET.fromstring(xml)
    objects = []
    for entry in root.findall(".//address/entry"):
        objects.append({
            "name": entry.get("name", ""),
            "ip_netmask": get_text(entry, "ip-netmask"),
            "fqdn": get_text(entry, "fqdn"),
            "description": get_text(entry, "description"),
            "tags": get_members(entry, "./tag/member"),
        })
    return objects


def build_ip_object_index(objects):
    exact = {}
    networks = []
    for obj in objects:
        val = obj["ip_netmask"]
        if not val:
            continue
        try:
            if "/" in val:
                networks.append((ipaddress.ip_network(val, strict=False), obj))
            else:
                exact[str(ipaddress.ip_address(val))] = obj
        except ValueError:
            continue
    networks.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return exact, networks


def find_object_by_ip(ip, exact, networks):
    if ip in exact:
        return exact[ip]
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, obj in networks:
        if ip_obj in net:
            return obj
    return None


def obj_name(ip, exact, networks):
    obj = find_object_by_ip(ip, exact, networks)
    return obj["name"] if obj else ""


def top(counter, n=3):
    return ", ".join(f"{k}({v})" for k, v in counter.most_common(n))


def bucket_time(dt, seconds):
    if not dt:
        return ""
    epoch = int(dt.timestamp())
    b = epoch - (epoch % seconds)
    return datetime.fromtimestamp(b).strftime("%Y/%m/%d %H:%M:%S")


def print_table(title, headers, rows, limit=50, widths=None):
    print(f"\n========== {title} ==========")
    if not rows:
        print("[=] Нет данных")
        return
    rows = rows[:limit]
    if widths is None:
        widths = [min(max(len(str(h)), *(len(str(r[i])) for r in rows)), 32) for i, h in enumerate(headers)]
    def cut(s, w):
        s = str(s)
        return s if len(s) <= w else s[:w-3] + "..."
    print(" | ".join(cut(h, widths[i]).ljust(widths[i]) for i, h in enumerate(headers)))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(" | ".join(cut(r[i], widths[i]).ljust(widths[i]) for i in range(len(headers))))


def save_csv(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def analyze(logs, suspect_ips, exact, networks, bucket_seconds, context_before_seconds):
    kerberos = [l for l in logs if l["app"] == "kerberos" or l["dport"] == "88"]
    context = [l for l in logs if l not in kerberos]

    node_counter = Counter(l["src"] for l in kerberos)
    node_rows = []
    for src, count in node_counter.most_common():
        src_logs = [l for l in kerberos if l["src"] == src]
        node_rows.append([
            src,
            obj_name(src, exact, networks),
            count,
            len(set(l["sport"] for l in src_logs if l["sport"])),
            top(Counter(l["dst"] for l in src_logs), 5),
            top(Counter(l["rule"] for l in src_logs), 3),
            min(l["receive_time"] for l in src_logs),
            max(l["receive_time"] for l in src_logs),
        ])

    pair_counter = Counter((l["src"], l["dst"]) for l in kerberos)
    pair_rows = []
    for (src, dst), count in pair_counter.most_common():
        pair_logs = [l for l in kerberos if l["src"] == src and l["dst"] == dst]
        pair_rows.append([
            src,
            obj_name(src, exact, networks),
            dst,
            obj_name(dst, exact, networks),
            count,
            len(set(l["sport"] for l in pair_logs if l["sport"])),
            top(Counter(l["sport"] for l in pair_logs), 5),
            top(Counter(l["action"] for l in pair_logs), 3),
            top(Counter(l["rule"] for l in pair_logs), 3),
            min(l["receive_time"] for l in pair_logs),
            max(l["receive_time"] for l in pair_logs),
        ])

    time_counter = Counter(bucket_time(l["dt"], bucket_seconds) for l in kerberos if l["dt"])
    time_rows = [[t, c] for t, c in time_counter.most_common()]

    time_pair_counter = Counter((bucket_time(l["dt"], bucket_seconds), l["src"], l["dst"]) for l in kerberos if l["dt"])
    time_pair_rows = []
    for (bt, src, dst), count in time_pair_counter.most_common():
        time_pair_rows.append([bt, src, obj_name(src, exact, networks), dst, obj_name(dst, exact, networks), count])

    # Context immediately before Kerberos from same node. This is the only useful Panorama-side hint for "what triggered it".
    context_hits = []
    context_sorted = sorted([l for l in context if l["dt"]], key=lambda x: x["dt"])
    for k in kerberos:
        if not k["dt"]:
            continue
        start = k["dt"] - timedelta(seconds=context_before_seconds)
        for c in context_sorted:
            if c["src"] != k["src"]:
                continue
            if start <= c["dt"] <= k["dt"]:
                context_hits.append((c, k))
    ctx_counter = Counter((c["src"], c["dst"], c["dport"], c["app"], c["rule"]) for c, k in context_hits)
    ctx_rows = []
    for (src, dst, dport, app, rule), count in ctx_counter.most_common():
        ctx_rows.append([
            src, obj_name(src, exact, networks), dst, obj_name(dst, exact, networks), dport, app, rule, count
        ])

    # Source port pattern. If many unique sports and each repeats once, it is retry loop/new Kerberos attempts.
    sport_rows = []
    for src in suspect_ips:
        src_k = [l for l in kerberos if l["src"] == src]
        if not src_k:
            continue
        c = Counter(l["sport"] for l in src_k if l["sport"])
        ones = sum(1 for _, v in c.items() if v == 1)
        sport_rows.append([
            src,
            obj_name(src, exact, networks),
            len(src_k),
            len(c),
            ones,
            round((len(c) / len(src_k)) if src_k else 0, 3),
            top(c, 10),
        ])

    return {
        "kerberos": kerberos,
        "node_rows": node_rows,
        "pair_rows": pair_rows,
        "time_rows": time_rows,
        "time_pair_rows": time_pair_rows,
        "ctx_rows": ctx_rows,
        "sport_rows": sport_rows,
    }


def main():
    print("\n=== Panorama 4771 Investigator v2 ===")
    print("Назначение: по traffic logs найти сетевой профиль PAM-node, который генерирует Kerberos 4771")
    print("Важно: Panorama не видит Windows Event Status=24 и процесс. Она помогает доказать источник, ритм, DC и сетевой триггер рядом.\n")

    pam_ips = parse_csv_list(ask("PAM IP по умолчанию", ",".join(DEFAULT_PAM_IPS)))
    suspect_ips = parse_csv_list(ask("Проблемные PAM node/IP из DCAP", DEFAULT_SUSPECT_IP))
    dcap_times_raw = ask("Время DCAP 4771 через запятую, например 22.06.2026 11:39:33 [пусто = без time-window]", "")
    dcap_ports = parse_csv_list(ask("IpPort из DCAP через запятую [пусто = не фильтровать sport]", ""))
    dc_ips = parse_csv_list(ask("DC IP через запятую [пусто = любые dst]", ""))
    auth_ports = parse_csv_list(ask("Kerberos dst ports", ",".join(DEFAULT_AUTH_PORTS)))
    context_ports = parse_csv_list(ask("Контекстные dst ports", ",".join(DEFAULT_CONTEXT_PORTS)))
    context_apps = parse_csv_list(ask("Контекстные apps", ",".join(DEFAULT_CONTEXT_APPS)))
    window_minutes = ask_int("Окно вокруг DCAP времени, минут", 15)
    bucket_seconds = ask_int("Размер временного бакета, секунд", DEFAULT_BUCKET_SECONDS)
    context_before_seconds = ask_int("Искать контекст перед Kerberos, секунд", DEFAULT_CONTEXT_BEFORE_SECONDS)
    page_size = ask_int("Размер одной страницы логов", DEFAULT_PAGE_SIZE)
    max_logs = ask_int("Максимум логов загрузить за запуск", DEFAULT_MAX_TOTAL_LOGS)
    top_n = ask_int("Сколько строк показать", DEFAULT_TOP)
    output_prefix = ask("Префикс CSV файлов", DEFAULT_OUTPUT_PREFIX)
    raw_query = ask("Raw Panorama query дополнительно [пусто = нет]", "")

    dcap_times = [parse_time(x.strip()) for x in dcap_times_raw.split(",") if x.strip()]

    # Build a useful query. If DCAP time exists, do NOT search latest random cached logs; force time bounds.
    ip_scope = sorted(set(pam_ips + suspect_ips))
    src_part = or_eq("addr.src", ip_scope)
    dst_part = or_eq("addr.dst", dc_ips) if dc_ips else ""
    port_part = or_eq("port.dst", sorted(set(context_ports + auth_ports)))
    app_part = or_app(context_apps)

    base_query = and_parts([src_part, dst_part, port_part, app_part])

    if dcap_ports:
        # Keep the wide query, but add exact sport branch so exact match is not lost.
        exact_sport = and_parts([or_eq("addr.src", suspect_ips), or_eq("port.src", dcap_ports), or_eq("port.dst", auth_ports)])
        base_query = or_parts([f"({base_query})", f"({exact_sport})"])

    time_query = ""
    if dcap_times:
        start = min(dcap_times) - timedelta(minutes=window_minutes)
        end = max(dcap_times) + timedelta(minutes=window_minutes)
        time_query = build_time_query(start, end)

    query = and_parts([base_query, time_query, raw_query])

    print("\n--- Параметры запуска ---")
    print(f"Panorama       : {PA_IP}")
    print(f"PAM scope      : {', '.join(ip_scope)}")
    print(f"Suspect IP     : {', '.join(suspect_ips)}")
    print(f"DCAP time      : {dcap_times_raw or 'не задано'}")
    print(f"DCAP IpPort    : {', '.join(dcap_ports) or 'не задан'}")
    print(f"Query          : {query}")
    print("-------------------------")

    if input("\nЗапустить поиск? [y/N]: ").strip().lower() != "y":
        print("[=] Операция отменена")
        return

    print("\n[*] Загружаю shared address objects...")
    objects = get_shared_address_objects()
    exact, networks = build_ip_object_index(objects)
    print(f"[+] Загружено address objects: {len(objects)}")

    logs, cached, returned = load_logs_paged(query, page_size, max_logs)
    result = analyze(logs, suspect_ips, exact, networks, bucket_seconds, context_before_seconds)

    kerberos = result["kerberos"]
    exact_matches = [l for l in kerberos if (not dcap_ports or l["sport"] in dcap_ports) and l["src"] in suspect_ips]

    print("\n========== СВОДКА ==========")
    print(f"Cached logs в Panorama        : {cached}")
    print(f"Загружено logs                : {returned}")
    print(f"Распарсено logs               : {len(logs)}")
    print(f"Kerberos logs                 : {len(kerberos)}")
    print(f"Kerberos от suspect IP        : {sum(1 for l in kerberos if l['src'] in suspect_ips)}")
    print(f"Exact по DCAP IpPort          : {len(exact_matches)}")
    print("===========================")

    print_table("Топ PAM-node по Kerberos", ["PAM", "Object", "Count", "Уник src ports", "Top DC", "Rules", "First", "Last"], result["node_rows"], top_n)
    print_table("PAM -> DC Kerberos", ["PAM", "Object PAM", "DC", "Object DC", "Count", "Уник sport", "Top sport", "Action", "Rules", "First", "Last"], result["pair_rows"], top_n)
    print_table("Пики Kerberos по времени", ["Time bucket", "Count"], result["time_rows"], top_n)
    print_table("Пики Kerberos по времени и DC", ["Time bucket", "PAM", "Object PAM", "DC", "Object DC", "Count"], result["time_pair_rows"], top_n)
    print_table("Паттерн source ports suspect IP", ["PAM", "Object", "Kerberos", "Уник sport", "sport=1 раз", "uniq/total", "Top sport"], result["sport_rows"], top_n)
    print_table("Контекст перед Kerberos с того же PAM", ["PAM", "Object PAM", "Dst", "Object dst", "Dport", "App", "Rule", "Hits before Kerberos"], result["ctx_rows"], top_n)

    save_csv(f"{output_prefix}_all_logs.csv", list(logs[0].keys()) if logs else ["empty"], [[l.get(k, "") for k in logs[0].keys()] for l in logs] if logs else [])
    save_csv(f"{output_prefix}_pam_nodes.csv", ["pam", "object", "count", "unique_src_ports", "top_dc", "rules", "first", "last"], result["node_rows"])
    save_csv(f"{output_prefix}_pam_to_dc.csv", ["pam", "object_pam", "dc", "object_dc", "count", "unique_sport", "top_sport", "action", "rules", "first", "last"], result["pair_rows"])
    save_csv(f"{output_prefix}_time_spikes.csv", ["time_bucket", "count"], result["time_rows"])
    save_csv(f"{output_prefix}_time_dc_spikes.csv", ["time_bucket", "pam", "object_pam", "dc", "object_dc", "count"], result["time_pair_rows"])
    save_csv(f"{output_prefix}_source_ports.csv", ["pam", "object", "kerberos", "unique_sport", "sport_seen_once", "uniq_total_ratio", "top_sport"], result["sport_rows"])
    save_csv(f"{output_prefix}_pre_kerberos_context.csv", ["pam", "object_pam", "dst", "object_dst", "dport", "app", "rule", "hits_before_kerberos"], result["ctx_rows"])

    print("\n[+] CSV файлы созданы с префиксом:", output_prefix)
    print("\nКак читать результат:")
    print("- Если Kerberos есть только от одного PAM-node и source ports почти всегда новые — это локальный retry-loop/сломанный machine account на узле.")
    print("- Если перед Kerberos стабильно есть один и тот же dst/app/rule — это сетевой кандидат, который триггерит Kerberos.")
    print("- Если exact IpPort не найден, обязательно задавай время DCAP и IpPort. Без времени Panorama отдаёт просто последние cached logs, что часто бесполезно.")


if __name__ == "__main__":
    main()
