import scapy.all as scapy
import threading
import sqlite3
import time
from collections import defaultdict

class TrafficSniffer:
    def __init__(self, interface="eth0", db_path="traffic.db"):
        self.interface = interface
        self.db_path = db_path
        self.sniffing = False
        self.thread = None
        self.ip_counts = defaultdict(int)
        self.service_counts = defaultdict(int)

    def packet_handler(self, packet):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol_num = packet[scapy.IP].proto
            protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol_num, "OTHER")

            src_bytes = len(packet) if packet.haslayer(scapy.Raw) else 0
            dst_bytes = src_bytes

            service = "Unknown"
            if packet.haslayer(scapy.TCP):
                dport = packet[scapy.TCP].dport
                sport = packet[scapy.TCP].sport
                service = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 53: "DNS"}.get(dport, "Other")

                flag = str(packet[scapy.TCP].flags)
            else:
                flag = "None"

            self.ip_counts[src_ip] += 1
            self.service_counts[(dst_ip, service)] += 1

            count = self.ip_counts[src_ip]  # Количество пакетов от источника
            srv_count = self.service_counts[(dst_ip, service)]  # Пакеты к сервису
            dst_host_count = len(set(self.ip_counts.keys()))  # Уникальные IP
            dst_host_srv_count = len(set(self.service_counts.keys()))  # Уникальные сервисы

            self.save_to_db(timestamp, src_ip, dst_ip, protocol, src_bytes, dst_bytes, service, flag, count, srv_count, dst_host_count, dst_host_srv_count)

    def save_to_db(self, timestamp, src_ip, dst_ip, protocol, src_bytes, dst_bytes, service, flag, count, srv_count, dst_host_count, dst_host_srv_count):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO traffic (timestamp, src_ip, dst_ip, protocol, src_bytes, dst_bytes, service, flag, count, srv_count, dst_host_count, dst_host_srv_count) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, src_ip, dst_ip, protocol, src_bytes, dst_bytes, service, flag, count, srv_count, dst_host_count, dst_host_srv_count))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Ошибка при записи в БД: {e}")

    def sniff(self):
        try:
            scapy.sniff(iface=self.interface, prn=self.packet_handler, store=False, promisc=True, stop_filter=lambda p: not self.sniffing)
        except Exception as e:
            print(f"Ошибка сниффинга: {e}")

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.thread = threading.Thread(target=self.sniff, daemon=True)
            self.thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        print("Остановка сниффера...")
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)