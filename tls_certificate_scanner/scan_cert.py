#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interactive certificate scanner for Windows/Linux.

Modes:
  1) Поиск  - сначала ищет открытые TCP-порты, потом проверяет TLS-сертификаты на найденных портах.
  2) Аудит  - проверяет только известные TLS-порты.

Input:
  - один IP/FQDN
  - CSV файл, первая колонка = IP/FQDN
  - Palo Alto tag, если рядом есть api_key.py и pan_api.py

Output:
  reports/cert_full_YYYYmmdd_HHMMSS.csv          - все сертификаты, включая цепочки
  reports/cert_leaf_YYYYmmdd_HHMMSS.csv          - только leaf-сертификаты
  reports/open_target_ports_YYYYmmdd_HHMMSS.csv  - найденные открытые комбинации target;port
  reports/tcp_scan_full_YYYYmmdd_HHMMSS.csv      - полный TCP-лог режима "Поиск"

Requires:
  - Python 3.8+
  - OpenSSL в PATH.
    Если OpenSSL не найден, скрипт предложит установку через winget на Windows.

Important:
  - Скрипт НЕ использует OpenSSL "-verify 0", потому что в некоторых сборках это ломает s_client:
    "Non-positive number 0 for option -verify".
"""

import csv
import datetime as dt
import hashlib
import ipaddress
import os
import platform
import queue
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except Exception:
    requests = None


# Известные TLS/SSL порты для режима АУДИТ.
# Список специально расширен под инфраструктурные сервисы:
# ksc, mpvm, dlp, dcap, pam, ngfw, nac, unifi + типовые web/TLS-сервисы.
KNOWN_TLS_PORTS = sorted(set([
    # Standard HTTPS / alternative HTTPS
    443, 444, 4443, 4444, 5443, 6443, 7443, 7444, 8443, 8444, 9443, 9444, 10443,
    11443, 12443, 18443, 20443, 21443, 30443, 50000, 50001,

    # Web admin / appliances / Java apps
    8081, 8082, 8083, 8088, 8089, 8090, 8091, 8092, 8181, 8243, 8280, 8281, 8383,
    8883, 8888, 9001, 9002, 9091, 9092, 9445, 9447, 9999, 10000,

    # LDAP/LDAPS, mail TLS
    636, 465, 993, 995, 990,

    # Windows / management
    3389, 5986, 8531, 9389,

    # Kaspersky Security Center / KSC typical admin/web ports
    13000, 13291, 13292, 13299, 14000, 17000,

    # Elasticsearch/Kibana/Logstash and similar stacks
    5044, 5601, 9200, 9243, 9300,

    # Kubernetes / containers / Docker
    2376, 6443, 8443, 10250, 10257, 10259,

    # Message brokers / MQTT / RabbitMQ
    5671, 5672, 8883, 15671,

    # UniFi / controllers / captive portal / device mgmt
    6789, 8080, 8443, 8843, 8880,

    # NAC / NGFW / PAM / DLP / DCAP appliances often expose HTTPS here
    9443, 10443, 12443, 8443, 443,
]))

# Частый список для режима ПОИСК, чтобы не гонять 1-65535 каждый раз.
# Полный поиск всё равно доступен отдельным пунктом.
COMMON_SEARCH_PORTS = sorted(set(KNOWN_TLS_PORTS + [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 445, 593,
    587, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 7001, 7002,
    8000, 8008, 8080, 8088, 8180, 8880, 9000, 9090, 10050, 10051, 27017,
]))

SCRIPT_DIR = Path(__file__).resolve().parent
REPORT_DIR = SCRIPT_DIR / "reports"
ASSETS_FILE = SCRIPT_DIR / "assets_ip_port.csv"


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def prompt(text: str, default: Optional[str] = None) -> str:
    if default is None:
        return input(f"{text}: ").strip()
    value = input(f"{text} [{default}]: ").strip()
    return value if value else default


def yes_no(text: str, default_yes: bool = True) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    value = input(f"{text} {suffix}: ").strip().lower()
    if not value:
        return default_yes
    return value in ("y", "yes", "д", "да")


def unique_keep_order(items: Iterable[str]) -> List[str]:
    result = []
    seen = set()
    for item in items:
        item = str(item).strip()
        if not item or item in seen:
            continue
        result.append(item)
        seen.add(item)
    return result


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def expand_ip_or_network(value: str) -> List[str]:
    value = value.strip()
    if "/" not in value:
        return [value]
    try:
        net = ipaddress.ip_network(value, strict=False)
        # Для очень больших сетей лучше не взрывать всё случайно.
        if net.num_addresses > 4096:
            print(f"[!] Сеть {value} содержит {net.num_addresses} адресов. Пропуск, максимум 4096.")
            return []
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [value]


def detect_csv_delimiter(sample: str) -> Optional[str]:
    sample = sample.strip("\ufeff\r\n ")
    if not sample:
        return None
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        return dialect.delimiter
    except csv.Error:
        first_line = sample.splitlines()[0] if sample.splitlines() else sample
        candidates = [";", ",", "\t", "|"]
        counts = {d: first_line.count(d) for d in candidates}
        best = max(counts, key=counts.get)
        return best if counts[best] > 0 else None


def read_csv_loose(path: str) -> List[List[str]]:
    p = Path(path.strip().strip('"'))
    if not p.exists():
        raise FileNotFoundError(f"CSV не найден: {p}")

    text = p.read_text(encoding="utf-8-sig", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []

    delimiter = detect_csv_delimiter("\n".join(lines[:20]))
    rows: List[List[str]] = []

    if delimiter is None:
        # CSV может быть просто списком IP по одному в строке.
        for line in lines:
            rows.append([line.strip().strip('"')])
        return rows

    reader = csv.reader(lines, delimiter=delimiter)
    for row in reader:
        cleaned = [c.strip().strip('"') for c in row]
        if any(cleaned):
            rows.append(cleaned)
    return rows


def header_index(header: List[str], names: set) -> Optional[int]:
    normalized = [h.strip().lower().replace(" ", "_") for h in header]
    for i, h in enumerate(normalized):
        if h in names:
            return i
    return None


def split_host_port(value: str) -> Optional[Tuple[str, int]]:
    value = value.strip()
    # IPv6 без скобок специально не режем по ':'. Для IPv4/FQDN:port подходит.
    if value.count(":") == 1:
        host, port_raw = value.rsplit(":", 1)
        if port_raw.isdigit():
            port = int(port_raw)
            if 1 <= port <= 65535:
                return host.strip(), port
    return None


def read_targets_from_csv(path: str) -> List[str]:
    rows = read_csv_loose(path)
    if not rows:
        return []

    header = rows[0]
    target_names = {"target", "ip", "fqdn", "host", "hostname", "object", "name", "address", "server"}
    target_col = header_index(header, target_names)
    start_idx = 1 if target_col is not None else 0
    if target_col is None:
        target_col = 0

    targets = []
    for row in rows[start_idx:]:
        if len(row) <= target_col:
            continue
        value = row[target_col].strip()
        if not value:
            continue
        if value.lower() in target_names:
            continue
        hp = split_host_port(value)
        if hp:
            value = hp[0]
        targets.extend(expand_ip_or_network(value))

    return unique_keep_order(targets)


def read_target_ports_from_csv(path: str) -> List[Tuple[str, int]]:
    rows = read_csv_loose(path)
    if not rows:
        return []

    target_names = {"target", "ip", "fqdn", "host", "hostname", "address", "server", "connect_host"}
    port_names = {"port", "tcp_port", "dst_port", "destination_port"}

    header = rows[0]
    target_col = header_index(header, target_names)
    port_col = header_index(header, port_names)
    start_idx = 1 if target_col is not None or port_col is not None else 0

    pairs: List[Tuple[str, int]] = []
    for row in rows[start_idx:]:
        if not row:
            continue

        host = ""
        port: Optional[int] = None

        if target_col is not None and len(row) > target_col:
            host = row[target_col].strip()
        else:
            host = row[0].strip()

        if port_col is not None and len(row) > port_col and row[port_col].strip().isdigit():
            port = int(row[port_col].strip())
        elif len(row) >= 2 and row[1].strip().isdigit():
            port = int(row[1].strip())
        else:
            hp = split_host_port(host)
            if hp:
                host, port = hp

        if host and port and 1 <= port <= 65535:
            pairs.append((host, port))

    seen = set()
    result = []
    for host, port in pairs:
        key = (host, port)
        if key in seen:
            continue
        result.append(key)
        seen.add(key)
    return result


def xml_attr(value: str) -> str:
    from xml.sax.saxutils import quoteattr
    return quoteattr(str(value))


def get_palo_alto_targets_by_tag(tag_name: str) -> List[str]:
    if requests is None:
        raise RuntimeError("Для Palo Alto режима нужен модуль requests: pip install requests")

    try:
        import api_key
        import pan_api
    except Exception as e:
        raise RuntimeError(
            "Для режима Palo Alto tag рядом должны лежать api_key.py и pan_api.py "
            "или добавь их в PYTHONPATH."
        ) from e

    pa_ip = api_key.api_ip
    api_key_value = pan_api.get_api_key()

    url = f"https://{pa_ip}/api/"
    xpath = "/config/shared/address"

    r = requests.get(
        url,
        params={"type": "config", "action": "get", "xpath": xpath, "key": api_key_value},
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    root = ET.fromstring(r.text)

    targets = []
    for entry in root.findall(".//entry"):
        tags = {m.text for m in entry.findall("./tag/member") if m.text}
        if tag_name not in tags:
            continue

        value = entry.findtext("./ip-netmask") or entry.findtext("./fqdn")
        if not value:
            continue

        if "/" in value:
            targets.extend(expand_ip_or_network(value))
        else:
            targets.append(value.strip())

    return unique_keep_order(targets)


def ask_targets() -> Tuple[str, List[str]]:
    print()
    print("Источник целей:")
    print("1 - Один IP/FQDN")
    print("2 - CSV файл")
    print("3 - Тег Palo Alto")
    choice = prompt("Выбор")

    if choice == "1":
        target = prompt("Введите IP/FQDN или сеть CIDR")
        return f"target:{target}", unique_keep_order(expand_ip_or_network(target))

    if choice == "2":
        path = prompt("Введите путь к CSV")
        return f"csv:{path}", read_targets_from_csv(path)

    if choice == "3":
        tag = prompt("Введите тег Palo Alto")
        return f"pa_tag:{tag}", get_palo_alto_targets_by_tag(tag)

    raise RuntimeError("Неверный источник целей")


def find_openssl() -> Optional[str]:
    exe = shutil.which("openssl")
    if exe:
        return exe

    candidates = [
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
        r"C:\msys64\ucrt64\bin\openssl.exe",
        r"C:\msys64\mingw64\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
    ]
    for path in candidates:
        if Path(path).exists():
            return path

    return None


def try_install_openssl_windows() -> Optional[str]:
    if platform.system().lower() != "windows":
        return None
    if not shutil.which("winget"):
        return None

    print("[*] OpenSSL не найден.")
    if not yes_no("Установить OpenSSL через winget", True):
        return None

    packages = [
        ["winget", "install", "--id", "ShiningLight.OpenSSL.Light", "-e", "--accept-package-agreements", "--accept-source-agreements"],
        ["winget", "install", "--id", "FireDaemon.OpenSSL", "-e", "--accept-package-agreements", "--accept-source-agreements"],
    ]

    for cmd in packages:
        try:
            subprocess.run(cmd, check=False)
            exe = find_openssl()
            if exe:
                return exe
        except Exception:
            pass

    return find_openssl()


def tcp_connect_open(host: str, port: int, timeout: float) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "open"
    except socket.timeout:
        return False, "timeout"
    except ConnectionRefusedError as e:
        return False, "closed"
    except OSError as e:
        msg = str(e)
        if "10061" in msg:
            return False, "closed"
        if "timed out" in msg.lower():
            return False, "timeout"
        return False, msg


def scan_open_ports_for_target(
    target: str,
    ports: List[int],
    timeout: float,
    workers: int,
) -> List[Dict[str, str]]:
    results = []

    def check(port: int):
        ok, status = tcp_connect_open(target, port, timeout)
        return {"target": target, "port": port, "is_open": ok, "tcp_status": status}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(check, p) for p in ports]
        for fut in as_completed(futs):
            results.append(fut.result())

    results.sort(key=lambda x: int(x["port"]))
    return results


def build_search_ports() -> List[int]:
    print()
    print("Диапазон портов для режима ПОИСК:")
    print("1 - Все TCP-порты 1-65535")
    print("2 - Частый расширенный список")
    print("3 - Свой диапазон")
    choice = prompt("Выбор", "1")

    if choice == "1":
        return list(range(1, 65536))

    if choice == "2":
        return COMMON_SEARCH_PORTS

    if choice == "3":
        raw = prompt("Введите диапазон, например 1-10000 или 443,8443,9000-9100")
        return parse_ports(raw)

    return list(range(1, 65536))


def parse_ports(raw: str) -> List[int]:
    ports = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a.strip())
            end = int(b.strip())
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def ask_mode_and_ports() -> Tuple[str, List[int], bool]:
    print()
    print("Режим:")
    print("1 - Поиск: пройти по портам, найти открытые, затем проверить сертификаты")
    print("2 - Аудит: проверить только известные TLS-порты")
    mode_choice = prompt("Выбор", "2")

    if mode_choice == "1":
        ports = build_search_ports()
        return "search", ports, True

    print()
    print("Порты аудита:")
    print(f"1 - Известные TLS-порты: {','.join(map(str, KNOWN_TLS_PORTS))}")
    print("2 - Свой список")
    choice = prompt("Выбор", "1")
    if choice == "2":
        ports = parse_ports(prompt("Введите порты через запятую"))
    else:
        ports = KNOWN_TLS_PORTS
    return "audit", ports, False


def extract_pem_blocks(text: str) -> List[str]:
    pattern = r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    return re.findall(pattern, text, flags=re.S)


def run_openssl_s_client(
    openssl: str,
    target: str,
    port: int,
    timeout_sec: int,
) -> Tuple[str, str, int]:
    connect = f"{target}:{port}"

    cmd = [
        openssl, "s_client",
        "-connect", connect,
        "-showcerts",
        "-ign_eof",
    ]

    # SNI добавляем только для DNS-имён. Для IP часто лучше без SNI.
    if not is_ip(target):
        cmd.extend(["-servername", target])

    # ВАЖНО: не добавляем "-verify 0". В некоторых OpenSSL это ломается.
    # Также не используем -brief, потому что в старых сборках может отличаться вывод.

    try:
        p = subprocess.run(
            cmd,
            input=b"Q\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
        )
        out = p.stdout.decode("utf-8", errors="replace")
        err = p.stderr.decode("utf-8", errors="replace")
        return out, err, p.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", errors="replace")
        err = (e.stderr or b"").decode("utf-8", errors="replace")
        return out, err + "\nopenssl timeout", 124


def parse_cert_pem(pem: str) -> Dict[str, str]:
    der = ssl.PEM_cert_to_DER_cert(pem)
    sha1 = hashlib.sha1(der).hexdigest().upper()
    sha256 = hashlib.sha256(der).hexdigest().upper()

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem", encoding="ascii") as f:
        f.write(pem)
        temp_path = f.name

    try:
        info = ssl._ssl._test_decode_cert(temp_path)
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    subject = flatten_x509_name(info.get("subject", ()))
    issuer = flatten_x509_name(info.get("issuer", ()))
    cn = get_name_attr(info.get("subject", ()), "commonName")
    issuer_cn = get_name_attr(info.get("issuer", ()), "commonName")

    not_before_raw = info.get("notBefore", "")
    not_after_raw = info.get("notAfter", "")
    not_before = parse_cert_time(not_before_raw)
    not_after = parse_cert_time(not_after_raw)

    days_left = ""
    expired = ""
    if not_after:
        delta = not_after - dt.datetime.now(dt.timezone.utc)
        days_left = str(delta.days)
        expired = str(delta.total_seconds() < 0).lower()

    san_items = []
    for san_type, san_value in info.get("subjectAltName", ()):
        san_items.append(f"{san_type}:{san_value}")

    return {
        "subject": subject,
        "cn": cn,
        "issuer": issuer,
        "issuer_cn": issuer_cn,
        "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S %z") if not_before else "",
        "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S %z") if not_after else "",
        "days_left": days_left,
        "expired": expired,
        "san": "; ".join(san_items),
        "serial_number": info.get("serialNumber", ""),
        "sha1": sha1,
        "sha256": sha256,
        "certificate_pem": pem.replace("\r\n", "\n"),
    }


def parse_cert_time(value: str) -> Optional[dt.datetime]:
    if not value:
        return None
    # Пример: 'Oct  9 18:14:17 2027 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            parsed = dt.datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            pass
    return None


def flatten_x509_name(name) -> str:
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def get_name_attr(name, attr: str) -> str:
    for rdn in name:
        for key, value in rdn:
            if key == attr:
                return value
    return ""


def certificate_rows_for_endpoint(
    openssl: str,
    target: str,
    port: int,
    timeout_sec: int,
    source: str,
) -> List[Dict[str, str]]:
    out, err, rc = run_openssl_s_client(openssl, target, port, timeout_sec)
    pem_blocks = extract_pem_blocks(out + "\n" + err)

    if not pem_blocks:
        return [{
            "scan_time": dt.datetime.now().isoformat(timespec="seconds"),
            "source": source,
            "target": target,
            "port": port,
            "status": "no_certificate",
            "error": " ".join((err or out).split())[:500],
            "chain_index": -1,
            "is_leaf": "",
            "subject": "",
            "cn": "",
            "issuer": "",
            "issuer_cn": "",
            "not_before": "",
            "not_after": "",
            "days_left": "",
            "expired": "",
            "san": "",
            "serial_number": "",
            "sha1": "",
            "sha256": "",
            "certificate_pem": "",
        }]

    rows = []
    for idx, pem in enumerate(pem_blocks):
        try:
            parsed = parse_cert_pem(pem)
            status = "ok"
            error = ""
        except Exception as e:
            parsed = {
                "subject": "", "cn": "", "issuer": "", "issuer_cn": "",
                "not_before": "", "not_after": "", "days_left": "", "expired": "",
                "san": "", "serial_number": "", "sha1": "", "sha256": "",
                "certificate_pem": pem,
            }
            status = "parse_error"
            error = str(e)

        row = {
            "scan_time": dt.datetime.now().isoformat(timespec="seconds"),
            "source": source,
            "target": target,
            "port": port,
            "status": status,
            "error": error,
            "chain_index": idx,
            "is_leaf": str(idx == 0).lower(),
        }
        row.update(parsed)
        rows.append(row)

    return rows


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "scan_time", "source", "target", "port", "status", "error",
        "chain_index", "is_leaf",
        "subject", "cn", "issuer", "issuer_cn",
        "not_before", "not_after", "days_left", "expired",
        "san", "serial_number", "sha1", "sha256", "certificate_pem",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore", delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def write_tcp_scan_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["target", "port", "is_open", "tcp_status"], delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def service_hint_by_port(port: int) -> str:
    hints = {
        443: "https", 4443: "alt_https", 5443: "alt_https", 6443: "k8s_api_or_alt_https",
        7443: "unifi_or_alt_https", 8443: "unifi_ngfw_pam_nac_or_alt_https",
        9443: "ngfw_pam_nac_dlp_or_alt_https", 10443: "ngfw_pam_or_alt_https",
        636: "ldaps", 465: "smtps", 993: "imaps", 995: "pop3s", 990: "ftps",
        3389: "rdp_tls", 5986: "winrm_https", 8531: "wsus_https",
        13000: "ksc", 13291: "ksc_web", 13292: "ksc", 13299: "ksc",
        14000: "ksc", 17000: "ksc",
        5601: "kibana", 9200: "elasticsearch", 9243: "elasticsearch_https", 9300: "elasticsearch_transport",
        2376: "docker_tls", 10250: "kubelet_https", 10257: "kube_controller", 10259: "kube_scheduler",
        5671: "amqps", 8883: "mqtts", 15671: "rabbitmq_https",
        6789: "unifi", 8080: "http_or_unifi", 8843: "unifi_guest_https", 8880: "unifi_guest_http",
    }
    return hints.get(int(port), "")


def write_target_ports_csv(path: Path, pairs: List[Tuple[str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        fieldnames = ["resource", "target", "port", "service_hint", "last_seen"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        for target, port in pairs:
            writer.writerow({
                "resource": f"{target}:{port}",
                "target": target,
                "port": port,
                "service_hint": service_hint_by_port(int(port)),
                "last_seen": stamp,
            })


def print_expiry_summary(rows: List[Dict[str, str]], limit: int) -> None:
    leafs = []
    for r in rows:
        if r.get("status") != "ok" or r.get("is_leaf") != "true":
            continue
        try:
            days = int(r.get("days_left") or "999999")
        except ValueError:
            days = 999999
        leafs.append((days, r))

    leafs.sort(key=lambda x: x[0])

    print()
    print("========== БЛИЖАЙШИЕ СРОКИ ИСТЕЧЕНИЯ ==========")
    if not leafs:
        print("Сертификаты не найдены.")
        return

    print(f"{'target':<20} {'port':<6} {'days':<7} {'not_after':<26} {'CN':<35} issuer")
    print("-" * 125)
    for days, r in leafs[:limit]:
        print(
            f"{r.get('target',''):<20} "
            f"{str(r.get('port','')):<6} "
            f"{str(days):<7} "
            f"{r.get('not_after',''):<26} "
            f"{r.get('cn','')[:35]:<35} "
            f"{r.get('issuer_cn','')[:40]}"
        )


def main() -> int:
    print()
    print("=== Certificate Scanner v3 ===")
    print("Движок: TCP scan + OpenSSL s_client -showcerts")
    print()

    openssl = find_openssl()
    if not openssl:
        openssl = try_install_openssl_windows()

    if not openssl:
        print("[!] OpenSSL не найден. Установи OpenSSL или добавь openssl.exe в PATH.")
        return 1

    print(f"[+] OpenSSL найден: {openssl}")

    try:
        mode, selected_ports, does_discovery = ask_mode_and_ports()

        saved_target_ports: List[Tuple[str, int]] = []
        if mode == "audit":
            # В режиме аудита пользователь не выбирает файл вручную.
            # Если рядом со скриптом есть assets_ip_port.csv, берём известные ip:port оттуда.
            if ASSETS_FILE.exists():
                saved_target_ports = read_target_ports_from_csv(str(ASSETS_FILE))
                source = f"assets:{ASSETS_FILE.name}"
                targets = unique_keep_order([t for t, _ in saved_target_ports])
                print()
                print(f"[+] Найден файл активов: {ASSETS_FILE}")
                print(f"[+] Известных ip:port для аудита: {len(saved_target_ports)}")
            else:
                print()
                print(f"[!] Файл активов не найден: {ASSETS_FILE.name}")
                print("[=] Аудит будет выполнен по выбранным целям и известным TLS-портам.")
                source, targets = ask_targets()
        else:
            source, targets = ask_targets()
    except Exception as e:
        print(f"[!] Ошибка ввода: {e}")
        return 1

    if mode == "audit" and 'saved_target_ports' in locals() and saved_target_ports:
        pass
    elif not targets:
        print("[!] Нет целей для сканирования")
        return 1

    tcp_timeout = float(prompt("TCP timeout в секундах", "1.5"))
    tls_timeout = int(prompt("OpenSSL timeout в секундах", "6"))
    workers = int(prompt("Параллельных TCP-проверок", "200" if mode == "search" else "50"))
    summary_limit = int(prompt("Сколько ближайших сертификатов показать", "30"))

    print()
    print("--- Параметры ---")
    print(f"Режим: {mode}")
    print(f"Источник: {source}")
    print(f"Целей: {len(targets)}")
    if mode == "audit" and 'saved_target_ports' in locals() and saved_target_ports:
        print(f"Известных target:port: {len(saved_target_ports)}")
    else:
        print(f"Портов для TCP-поиска/аудита: {len(selected_ports)}")
    print(f"OpenSSL: {openssl}")
    print("-----------------")

    if not yes_no("Начать", True):
        print("[=] Отменено")
        return 0

    stamp = now_stamp()
    full_report = REPORT_DIR / f"cert_full_{stamp}.csv"
    leaf_report = REPORT_DIR / f"cert_leaf_{stamp}.csv"
    open_ports_report = REPORT_DIR / f"open_target_ports_{stamp}.csv"
    tcp_scan_report = REPORT_DIR / f"tcp_scan_full_{stamp}.csv"

    all_cert_rows: List[Dict[str, str]] = []
    open_port_rows: List[Dict[str, str]] = []
    target_ports_to_tls: List[Tuple[str, int]] = []

    try:
        if mode == "search":
            print()
            print("[*] Режим ПОИСК: сначала ищу открытые порты.")
            for idx, target in enumerate(targets, start=1):
                print(f"[*] TCP scan {idx}/{len(targets)}: {target}")
                rows = scan_open_ports_for_target(target, selected_ports, tcp_timeout, workers)
                open_port_rows.extend(rows)
                open_ports = [r["port"] for r in rows if r["is_open"]]
                if open_ports:
                    print(f"    [+] Открыто: {','.join(map(str, open_ports[:50]))}" + (" ..." if len(open_ports) > 50 else ""))
                else:
                    print("    [-] Открытых портов не найдено")
                for port in open_ports:
                    target_ports_to_tls.append((target, int(port)))

            write_tcp_scan_csv(tcp_scan_report, open_port_rows)
            write_target_ports_csv(open_ports_report, target_ports_to_tls)
            write_target_ports_csv(ASSETS_FILE, target_ports_to_tls)
        else:
            if 'saved_target_ports' in locals() and saved_target_ports:
                target_ports_to_tls = list(saved_target_ports)
            else:
                for target in targets:
                    for port in selected_ports:
                        target_ports_to_tls.append((target, int(port)))

        print()
        print(f"[*] TLS-проверок: {len(target_ports_to_tls)}")
        for idx, (target, port) in enumerate(target_ports_to_tls, start=1):
            rows = certificate_rows_for_endpoint(openssl, target, port, tls_timeout, source)
            all_cert_rows.extend(rows)

            leaf = next((r for r in rows if r.get("status") == "ok" and r.get("is_leaf") == "true"), None)
            if leaf:
                print(f"[+] {idx}/{len(target_ports_to_tls)} {target}:{port} CN={leaf.get('cn')} expires={leaf.get('not_after')} days={leaf.get('days_left')}")
            else:
                first = rows[0] if rows else {}
                print(f"[-] {idx}/{len(target_ports_to_tls)} {target}:{port} {first.get('status')} {first.get('error','')[:120]}")

    except KeyboardInterrupt:
        print()
        print("[=] Остановлено пользователем. Сохраняю то, что уже собрано.")

    leaf_rows = [r for r in all_cert_rows if r.get("status") == "ok" and r.get("is_leaf") == "true"]

    write_csv(full_report, all_cert_rows)
    write_csv(leaf_report, leaf_rows)

    print_expiry_summary(all_cert_rows, summary_limit)

    expired = [r for r in leaf_rows if r.get("expired") == "true"]
    soon = []
    for r in leaf_rows:
        try:
            days = int(r.get("days_left") or "999999")
            if 0 <= days <= 30:
                soon.append(r)
        except ValueError:
            pass

    print()
    print("========== ИТОГ ==========")
    print(f"Режим                  : {mode}")
    print(f"Целей                  : {len(targets)}")
    if mode == "search":
        print(f"Открытых target:port   : {len(target_ports_to_tls)}")
        print(f"Сохранённые target:port : {open_ports_report}")
        print(f"Файл активов ip:port   : {ASSETS_FILE}")
        print(f"Полный TCP-лог          : {tcp_scan_report}")
    else:
        print(f"Проверок target:port   : {len(target_ports_to_tls)}")
    print(f"Найдено leaf-сертов    : {len(leaf_rows)}")
    print(f"Всего строк cert report: {len(all_cert_rows)}")
    print(f"Просрочено             : {len(expired)}")
    print(f"Истекает <= 30 дней    : {len(soon)}")
    print(f"Полный отчёт           : {full_report}")
    print(f"Leaf отчёт             : {leaf_report}")
    print("==========================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
