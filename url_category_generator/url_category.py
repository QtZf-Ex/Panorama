from urllib.parse import urlparse


def normalize_domain(url: str) -> str:
    """
    Из URL или доменного имени получает чистое доменное имя.
    """
    url = url.strip()

    if not url:
        return None

    # Если схемы нет, временно добавляем https://
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # Убираем порт
    if ":" in domain:
        domain = domain.split(":")[0]

    # Убираем www., чтобы потом добавить его самостоятельно
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def generate_patterns(domain: str):
    return [
        f"{domain}/*",
        f"{domain}/",
        f"www.{domain}",
        f"www.{domain}/*",
    ]


def convert_file(input_file: str, output_file: str):
    result = []

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            domain = normalize_domain(line)

            if domain:
                result.extend(generate_patterns(domain))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(result))

    print(f"Готово. Записано {len(result)} строк в {output_file}")


if __name__ == "__main__":
    convert_file("input.txt", "output.txt")
