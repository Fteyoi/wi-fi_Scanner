from datetime import datetime
from typing import Optional, Tuple, Dict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl, socket, hashlib, json, urllib.request, subprocess, urllib.error, time

def get_ssl_cert_improved(hostname: str, port: int = 443, timeout: float = 5, validate: bool = True):
    """Возвращает (cert_dict, expires_datetime, issuer_dict, error_msg)"""
    try:
        ctx = ssl.create_default_context()
        if not validate:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                expires = datetime.strptime(cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z')
                cert = x509.load_der_x509_certificate(der, default_backend())
                issuer = cert.issuer
                issuer_dict = {}
                for attr in issuer:
                    oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                    issuer_dict[oid_name] = attr.value
                if not issuer_dict:
                    issuer_dict = {'raw': str(issuer)}
                return cert_dict, expires, issuer_dict, None
    except Exception as e:
        return None, None, None, f"Ошибка: {type(e).__name__}: {e}"

def check_mitm_via_ct_improved(
    hostname: str,
    port: int = 443,
    timeout: float = 5,
    verify_ssl: bool = True
) -> Tuple[Optional[str], Optional[bool], str, Optional[Dict[str, str]], Optional[bool]]:
    fingerprint = None
    issuer_dict = None
    serial_number = None
    try:
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                fingerprint = hashlib.sha256(der).hexdigest()
                cert = x509.load_der_x509_certificate(der, default_backend())
                serial_number = hex(cert.serial_number)[2:].upper()
                issuer = cert.issuer
                issuer_dict = {}
                for attr in issuer:
                    oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                    issuer_dict[oid_name] = attr.value
                if not issuer_dict:
                    issuer_dict = {'raw': str(issuer)}
    except Exception as e:
        return None, None, f"Не удалось получить сертификат: {type(e).__name__}: {e}", None, True

    ssl_context = ssl.create_default_context()
    max_retries = 3
    last_error = None
    for attempt in range(max_retries):
        try:
            url = f"https://crt.sh/?q=sha256:{fingerprint}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))
            with opener.open(req, timeout=10) as resp:
                if resp.getcode() != 200:
                    return fingerprint, None, f"crt.sh вернул статус {resp.getcode()}", issuer_dict, False
                data = resp.read().decode('utf-8').strip()
                if not data:
                    return fingerprint, False, "crt.sh вернул пустой ответ", issuer_dict, True
                entries = json.loads(data)
                if isinstance(entries, dict) and 'data' in entries:
                    entries = entries['data']
                found = False
                if entries:
                    for entry in entries:
                        ct_serial = entry.get('serial_number', '').upper()
                        ct_serial_normalized = ct_serial.lstrip('0')
                        if ct_serial_normalized == serial_number:
                            found = True
                            break
                    if found:
                        return fingerprint, True, "Сертификат найден в CT-логах (crt.sh) с совпадением серийного номера.", issuer_dict, False
                    else:
                        return fingerprint, False, "Найден сертификат с таким же SHA256, но другим серийным номером (возможна коллизия или подмена).", issuer_dict, True
                else:
                    return fingerprint, False, "Сертификат НЕ НАЙДЕН в CT-логах (crt.sh).", issuer_dict, True
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return fingerprint, None, f"Ошибка HTTP {e.code}: {e.reason}", issuer_dict, False
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return fingerprint, None, f"Ошибка при запросе: {type(e).__name__}: {e}", issuer_dict, False
    return fingerprint, None, f"Не удалось получить ответ после {max_retries} попыток. Последняя ошибка: {last_error}", issuer_dict, False

def check_dns_security():
    result = {'servers': [], 'is_safe': True, 'warnings': []}
    try:
        output = subprocess.check_output(['ipconfig', '/all'], encoding='cp866', errors='ignore')
        lines = output.splitlines()
        dns_list = []
        collecting = False
        for line in lines:
            if 'DNS Servers' in line or 'DNS-серверы' in line:
                collecting = True
                if ':' in line:
                    addr = line.split(':', 1)[1].strip()
                    if addr and addr[0].isdigit():
                        dns_list.append(addr)
                continue
            if collecting:
                stripped = line.strip()
                if not stripped or 'NetBIOS' in stripped or 'Default Gateway' in stripped:
                    collecting = False
                elif stripped and stripped[0].isdigit():
                    dns_list.append(stripped)
        result['servers'] = list(dict.fromkeys(dns_list))
    except Exception:
        result['servers'] = []
        result['warnings'].append("Не удалось определить DNS-серверы")
        result['is_safe'] = False
        return result

    safe_dns = {
        '8.8.8.8': 'Google Public DNS', '8.8.4.4': 'Google Public DNS',
        '1.1.1.1': 'Cloudflare DNS', '1.0.0.1': 'Cloudflare DNS',
        '9.9.9.9': 'Quad9 DNS', '149.112.112.112': 'Quad9 DNS',
        '208.67.222.222': 'OpenDNS', '208.67.220.220': 'OpenDNS',
        '77.88.8.8': 'Yandex DNS', '77.88.8.1': 'Yandex DNS'
    }
    for dns in result['servers']:
        if dns in safe_dns:
            result['warnings'].append(f"DNS {dns} является публичным ({safe_dns[dns]}) — это нормально, но может быть небезопасно в корпоративной сети.")
        elif dns.startswith(('192.168.', '10.', '172.')):
            result['warnings'].append(f"DNS {dns} является локальным — обычно безопасно, если вы доверяете сети.")
        else:
            result['warnings'].append(f"DNS {dns} не входит в список известных безопасных DNS. Возможно, он подконтролен злоумышленникам.")
            result['is_safe'] = False
    return result

# Демонстрация (только новые функции)
print("Начинаем проверку безопасности Wi-Fi сети")
print("==========================================")

dns_security = check_dns_security()
print("\n--- Проверка DNS ---")
print(f"DNS-серверы: {', '.join(dns_security['servers']) if dns_security['servers'] else 'не определены'}")
print(f"Безопасность DNS: {'ВНИМАНИЕ: есть риски' if not dns_security['is_safe'] else 'OK (предупреждения см. ниже)'}")
if dns_security['warnings']:
    print("Предупреждения:")
    for w in dns_security['warnings']:
        print(f"  - {w}")

print("\n--- Проверка SSL-сертификата ---")
cert_imp, expires_imp, issuer_imp, err_imp = get_ssl_cert_improved('example.com')
if err_imp:
    print(f"Ошибка: {err_imp}")
else:
    print(f"Истекает: {expires_imp}")
    print(f"Issuer: {issuer_imp}")

print("\n--- Проверка MITM через CT-логи ---")
fp_imp, safe_imp, msg_imp, issuer_dict_imp, net_err_imp = check_mitm_via_ct_improved('google.com')
print(f"Отпечаток: {fp_imp}")
print(f"Безопасность: {safe_imp}")
print(f"Сообщение: {msg_imp}")
print(f"Issuer: {issuer_dict_imp}")
if net_err_imp:
    print("Вероятно, используется firewall, антивирус или VPN, иначе MITM атака")

print("\n==========================================")
print("Проверка завершена.")
time.sleep(15)
print("==========================================")
