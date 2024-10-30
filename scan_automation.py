import nmap
import json
import os
import asyncio
import ipaddress
import schedule
import time
from datetime import datetime
from quart import Quart, request, jsonify
from cryptography.fernet import Fernet
import logging
from telegram import Bot

# Конфиденциальные данные загружаются из переменных среды
TELEGRAM_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
bot = Bot(token=TELEGRAM_TOKEN)

# Настройка логирования
logging.basicConfig(filename='scan_log.txt', level=logging.INFO, format='[%(asctime)s] %(message)s')

# Генерация ключа для шифрования
def generate_key():
    return Fernet.generate_key()

# Инициализация шифрования
key = generate_key()
cipher = Fernet(key)

app = Quart(__name__)

# Логирование событий
def log_event(event):
    logging.info(event)
    print(event)

# Уведомление в Telegram
def send_telegram_message(message):
    try:
        bot.send_message(chat_id=CHAT_ID, text=message)
    except Exception as e:
        log_event(f"Ошибка отправки сообщения в Telegram: {e}")

# Валидация IP-адреса
def validate_ip(ip):
    try:
        ipaddress.ip_network(ip)
        return True
    except ValueError:
        log_event(f"Неверный IP адрес: {ip}")
        return False

# Выбор аргументов для nmap
def get_scan_args(scan_type):
    scan_options = {
        "SYN": "-sS",
        "TCP": "-sT",
        "UDP": "-sU",
        "Aggressive": "-A",
        "OS": "-O",
        "Ping": "-sn"
    }
    return scan_options.get(scan_type, "-sS")

# Основное сканирование
def scan_network(target, scan_type):
    scanner = nmap.PortScanner()
    scan_args = get_scan_args(scan_type)

    log_event(f"Запуск сканирования {target} с типом {scan_type}")
    try:
        scanner.scan(target, arguments=scan_args)
    except Exception as e:
        log_event(f"Ошибка при сканировании {target}: {e}")
        return None

    results = process_scan_results(scanner)
    save_scan_results(results, target, scan_type)
    send_telegram_message(f"Сканирование {target} завершено.")
    return results

# Обработка результатов сканирования
def process_scan_results(scanner):
    results = []
    for host in scanner.all_hosts():
        host_data = {
            "host": host,
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "ports": []
        }
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                port_data = {
                    "port": port,
                    "state": scanner[host][proto][port]["state"],
                    "name": scanner[host][proto][port]["name"]
                }
                host_data["ports"].append(port_data)
        results.append(host_data)
    return results

# Шифрование и сохранение результатов
def save_scan_results(results, target, scan_type):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target.replace('/', '_')}_{scan_type}_{timestamp}.json"
    os.makedirs("encrypted_results", exist_ok=True)
    path = os.path.join("encrypted_results", filename)

    encrypted_data = cipher.encrypt(json.dumps(results).encode())
    with open(path, "wb") as enc_file:
        enc_file.write(encrypted_data)
    
    log_event(f"Результаты сохранены в зашифрованный файл {path}")

# Асинхронное сканирование
async def async_scan(targets, scan_type):
    tasks = [asyncio.to_thread(scan_network, target, scan_type) for target in targets]
    await asyncio.gather(*tasks)

# Планировщик асинхронного сканирования
def schedule_scan(target, scan_type, interval):
    schedule.every(interval).minutes.do(lambda: asyncio.run(async_scan([target], scan_type)))
    log_event(f"Запланировано сканирование {target} каждые {interval} минут.")

# API для запуска сканирования через POST-запрос
@app.route('/scan', methods=['POST'])
async def start_scan():
    data = await request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'SYN')

    if not validate_ip(target):
        return jsonify({"error": "Неверный IP адрес"}), 400

    results = scan_network(target, scan_type)
    return jsonify(results), 200

# Декодирование и расшифровка результатов
def decrypt_results(file_path):
    with open(file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    return json.loads(decrypted_data)

# Главная функция
async def main():
    # Инициализация
    log_event("Скрипт запущен как служба.")
    targets = ["192.168.1.1", "192.168.1.2"]
    scan_type = "TCP"

    # Асинхронный запуск
    await async_scan(targets, scan_type)

    # Запуск планировщика в фоновом режиме
    interval = 30  # интервал в минутах
    for target in targets:
        schedule_scan(target, scan_type, interval)

    # Запуск API-сервера
    await app.run_task(port=5000)

if __name__ == "__main__":
    asyncio.run(main())


if __name__ == "__main__":
    main()
