import nmap
import json
import os
import asyncio
import ipaddress
import signal
from datetime import datetime
from quart import Quart, request, jsonify
from cryptography.fernet import Fernet
import logging
from telegram import Bot

# Конфиденциальные данные из переменных среды
TELEGRAM_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
bot = Bot(token=TELEGRAM_TOKEN) if TELEGRAM_TOKEN and CHAT_ID else None

# Настройка логирования
logging.basicConfig(
    filename='scan_log.txt', 
    level=logging.INFO, 
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Генерация ключа для шифрования
key = Fernet.generate_key()
cipher = Fernet(key)

app = Quart(__name__)
scan_tasks = {}  # Для хранения активных задач

def log_event(event):
    logging.info(event)
    print(event)

def send_telegram_message(message):
    if not bot:
        log_event("Telegram не настроен. Сообщение не отправлено.")
        return
        
    try:
        bot.send_message(chat_id=CHAT_ID, text=message)
    except Exception as e:
        log_event(f"Ошибка отправки сообщения в Telegram: {e}")

def validate_ip(ip):
    try:
        ipaddress.ip_network(ip, strict=False)  # Поддержка подсетей
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
    except nmap.PortScannerError as e:
        log_event(f"Ошибка nmap: {e}")
        return None
    except Exception as e:
        log_event(f"Критическая ошибка при сканировании {target}: {e}")
        return None
        
    return process_scan_results(scanner)

def process_scan_results(scanner):
    results = []
    for host in scanner.all_hosts():
        host_data = {
            "host": host,
            "hostname": scanner[host].hostname() or "N/A",
            "state": scanner[host].state(),
            "ports": []
        }
        for proto in scanner[host].all_protocols():
            for port, port_info in scanner[host][proto].items():
                host_data["ports"].append({
                    "port": port,
                    "state": port_info["state"],
                    "name": port_info["name"]
                })
        results.append(host_data)
    return results

def save_scan_results(results, target, scan_type):
    if not results:
        return
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target.replace('/', '_')}_{scan_type}_{timestamp}.json"
    os.makedirs("encrypted_results", exist_ok=True)
    path = os.path.join("encrypted_results", filename)
    
    try:
        encrypted_data = cipher.encrypt(json.dumps(results).encode())
        with open(path, "wb") as enc_file:
            enc_file.write(encrypted_data)
        log_event(f"Результаты сохранены в {path}")
        send_telegram_message(f"Сканирование {target} завершено. Результаты: {filename}")
    except Exception as e:
        log_event(f"Ошибка сохранения результатов: {e}")

async def async_scan(target, scan_type):
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(None, scan_network, target, scan_type)
    if results:
        save_scan_results(results, target, scan_type)
    return results

@app.route('/scan', methods=['POST'])
async def start_scan():
    data = await request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'SYN')
    
    if not validate_ip(target):
        return jsonify({"error": "Неверный IP адрес"}), 400
        
    try:
        results = await async_scan(target, scan_type)
        return jsonify(results or {"message": "Сканирование завершено без результатов"}), 200
    except Exception as e:
        log_event(f"API ошибка: {e}")
        return jsonify({"error": str(e)}), 500

async def periodic_scan(target, scan_type, interval_minutes):
    """Асинхронное периодическое сканирование"""
    while True:
        try:
            await async_scan(target, scan_type)
        except Exception as e:
            log_event(f"Ошибка периодического сканирования: {e}")
        
        await asyncio.sleep(interval_minutes * 60)

@app.route('/schedule', methods=['POST'])
async def add_scheduled_scan():
    data = await request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'SYN')
    interval = data.get('interval', 30)
    
    if not validate_ip(target):
        return jsonify({"error": "Неверный IP адрес"}), 400
        
    task_id = f"{target}-{scan_type}"
    if task_id in scan_tasks:
        return jsonify({"error": "Сканирование уже запланировано"}), 400
        
    task = asyncio.create_task(periodic_scan(target, scan_type, interval))
    scan_tasks[task_id] = task
    return jsonify({"message": f"Сканирование {target} запланировано каждые {interval} минут"}), 200

async def main():
    log_event("Сервис запущен")
    
    # Пример начальных задач
    initial_tasks = [
        ("192.168.1.1", "TCP", 30),
        ("192.168.1.2", "SYN", 45)
    ]
    
    for target, scan_type, interval in initial_tasks:
        task_id = f"{target}-{scan_type}"
        task = asyncio.create_task(periodic_scan(target, scan_type, interval))
        scan_tasks[task_id] = task

    # Запуск сервера с обработкой сигналов
    server_task = asyncio.create_task(app.run_task(host='0.0.0.0', port=5000))
    
    # Обработка остановки
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    for signame in {'SIGINT', 'SIGTERM'}:
        loop.add_signal_handler(
            getattr(signal, signame),
            stop_event.set)
    
    await stop_event.wait()
    log_event("Получен сигнал остановки")
    
    # Отмена всех задач
    for task in scan_tasks.values():
        task.cancel()
    server_task.cancel()
    
    await asyncio.gather(*scan_tasks.values(), server_task, return_exceptions=True)
    log_event("Сервис остановлен")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass