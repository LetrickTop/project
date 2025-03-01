from flask import Flask, render_template, request, jsonify
import threading
import sqlite3
from traffic_sniffer import TrafficSniffer
from database import init_db

app = Flask(__name__)
sudo psudo python3 app.py212969
# Инициализация базы данных
init_db()

# Создание объекта сниффера
sniffer = TrafficSniffer(interface="en0")  # в "en0" можно выбрать свой интерфейс
sniffing_thread = None

@app.route('/')
def index():
    """Главная страница"""
    return render_template("home.html")

@app.route('/sniffing')
def sniffing_page():
    """Страница управления сниффингом"""
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic ORDER BY id DESC LIMIT 10")
    packets = cursor.fetchall()
    conn.close()

    return render_template("index.html", packets=packets)

@app.route('/cyberattack')
def cyberattack_page():
    """Страница для определения кибератаки"""
    return render_template("cyberattack.html")

@app.route('/data')
def get_data():
    """Возвращает последние 10 пакетов в JSON"""
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic ORDER BY id DESC LIMIT 10")
    packets = cursor.fetchall()
    conn.close()

    packets_list = [
        {"timestamp": p[1], "src_ip": p[2], "dst_ip": p[3], "protocol": p[4], "src_bytes": p[5],
         "dst_bytes": p[6], "service": p[7], "flag": p[8], "count": p[9], "srv_count": p[10],
         "dst_host_count": p[11], "dst_host_srv_count": p[12]}
        for p in packets
    ]
    return jsonify(packets_list)

@app.route('/start', methods=['POST'])
def start_sniffing():
    """Запуск сниффинга"""
    global sniffing_thread
    if not sniffer.sniffing:
        sniffing_thread = threading.Thread(target=sniffer.start_sniffing)
        sniffing_thread.start()
    return '', 204

@app.route('/stop', methods=['POST'])
def stop_sniffing():
    """Остановка сниффинга"""
    sniffer.stop_sniffing()
    return '', 204

@app.route('/analytics')
def analytics_page():
    """Страница аналитики трафика"""
    return render_template("analytics.html")

@app.route('/traffic/analytics')
def traffic_analytics():
    """Возвращает данные для аналитики трафика в формате JSON"""
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()

    # Считываем количество пакетов по протоколам
    cursor.execute("""
        SELECT protocol, COUNT(*) FROM traffic
        GROUP BY protocol
    """)
    protocol_data = cursor.fetchall()

    # Считываем количество пакетов по сервисам
    cursor.execute("""
        SELECT service, COUNT(*) FROM traffic
        GROUP BY service
    """)
    service_data = cursor.fetchall()

    conn.close()

    # Подготовка данных для графиков
    protocols = [{"protocol": row[0], "count": row[1]} for row in protocol_data]
    services = [{"service": row[0], "count": row[1]} for row in service_data]

    return jsonify({"protocols": protocols, "services": services})

if __name__ == '__main__':
    app.run(debug=True)