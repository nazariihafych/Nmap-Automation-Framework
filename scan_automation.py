import nmap
import json
import csv
import os
import asyncio
import ipaddress
import schedule
import time
from datetime import datetime
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from telegram import Bot
from telegram.ext import Updater

# Конфигурация для Telegram уведомлений
TELEGRAM_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
CHAT_ID = 'YOUR_TELEGRAM_CHAT_ID'
bot = Bot(token=TELEGRAM_TOKEN)

# Генерация ключа для шифрования
def generate_key():
    return Fernet.generate_key()

# Инициализация шифрования
key = generate_key()
cipher = Fernet(key)

app = Flask(__name__)

# Логирование и обработка событий
def log_event(event):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("scan_log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] {event}\n")
    print(f"[{timestamp}] {event}")

# Уведомление в Telegram
def send_telegram_message(message):
    bot.send_message(chat_id=CHAT_ID, text=message)

# Валидация IP
def validate_ip(ip):
    try:
        ipaddress.ip_network(ip)
        return True
    except ValueError:
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

# Обработка результатов
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

    # Шифрование данных
    encrypted_data = cipher.encrypt(json.dumps(results).encode())
    with open(path, "wb") as enc_file:
        enc_file.write(encrypted_data)
    
    log_event(f"Результаты сохранены в зашифрованный файл {path}")

# Асинхронное сканирование
async def async_scan(targets, scan_type):
    tasks = [asyncio.to_thread(scan_network, target, scan_type) for target in targets]
    await asyncio.gather(*tasks)

# Планировщик
def schedule_scan(target, scan_type, interval):
    schedule.every(interval).minutes.do(scan_network, target=target, scan_type=scan_type)
    log_event(f"Запланировано сканирование {target} каждые {interval} минут.")
    while True:
        schedule.run_pending()
        time.sleep(1)

# API для удаленного запуска сканирования
@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
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
def main():
    # Настройки инициализации
    log_event("Скрипт запущен как служба.")
    targets = ["192.168.1.1", "192.168.1.2"]
    scan_type = "TCP"

    # Асинхронный запуск
    asyncio.run(async_scan(targets, scan_type))

    # Запуск API-сервера
    app.run(port=5000)

if __name__ == "__main__":
    main()
