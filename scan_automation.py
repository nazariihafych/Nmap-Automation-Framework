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

# Конфиденциальные данные из переменных среды
TELEGRAM_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
bot = Bot(token=TELEGRAM_TOKEN)

# Настройка логирования
logging.basicConfig(filename='scan_log.txt', level=logging.INFO, format='[%(asctime)s] %(message)s')

# Генерация ключа для шифрования
key = Fernet.generate_key()  # Новый ключ при каждом запуске
cipher = Fernet(key)

app = Quart(__name__)

def log_event(event):
    logging.info(event)
    print(event)

def send_telegram_message(message):
    try:
        bot.send_message(chat_id=CHAT_ID, text=message)
    except Exception as e:
        log_event(f"Ошибка отправки сообщения в Telegram: {e}")

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)  # Только одиночные IP
        return True
    except ValueError:
        log_event(f"Неверный IP адрес: {ip}")
        return False

def get_scan_args(scan_type):
    scan_options = {
        "SYN": "-sS", "TCP": "-sT", "UDP": "-sU",
        "Aggressive": "-A", "OS": "-O", "Ping": "-sn"
    }
    return scan_options.get(scan_type, "-sS")

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
    send_telegram_message(f"Сканирование {target} ({scan_type}) завершено.")
    return results

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

def save_scan_results(results, target, scan_type):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target.replace('/', '_')}_{scan_type}_{timestamp}.json"
    os.makedirs("encrypted_results", exist_ok=True)
    path = os.path.join("encrypted_results", filename)
    encrypted_data = cipher.encrypt(json.dumps(results).encode())
    with open(path, "wb") as enc_file:
        enc_file.write(encrypted_data)
    log_event(f"Результаты сохранены в зашифрованный файл {path}")

async def async_scan(targets, scan_type):
    tasks = [asyncio.to_thread(scan_network, target, scan_type) for target in targets]
    await asyncio.gather(*tasks)

def schedule_scan(target, scan_type, interval):
    async def run_scan():
        await async_scan([target], scan_type)
    schedule.every(interval).minutes.do(lambda: asyncio.create_task(run_scan()))
    log_event(f"Запланировано сканирование {target} каждые {interval} минут.")

@app.route('/scan', methods=['POST'])
async def start_scan():
    data = await request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'SYN')
    if not validate_ip(target):
        return jsonify({"error": "Неверный IP адрес"}), 400
    results = scan_network(target, scan_type)
    if results is None:
        return jsonify({"error": "Ошибка при сканировании"}), 500
    return jsonify(results), 200

def decrypt_results(file_path):
    with open(file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    return json.loads(decrypted_data)

async def run_scheduler():
    while True:
        schedule.run_pending()
        await asyncio.sleep(1)

async def main():
    log_event("Скрипт запущен как служба.")
    targets = ["192.168.1.1", "192.168.1.2"]
    scan_type = "TCP"
    await async_scan(targets, scan_type)
    interval = 30
    for target in targets:
        schedule_scan(target, scan_type, interval)
    await asyncio.gather(
        run_scheduler(),
        app.run_task(port=5000)
    )

if __name__ == "__main__":
    asyncio.run(main())