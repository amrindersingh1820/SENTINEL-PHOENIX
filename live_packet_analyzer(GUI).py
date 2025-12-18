import sys
import threading
import datetime
import psutil
import socket
import concurrent.futures
from scapy.all import sniff, IP, TCP, ARP, Ether, srp, ICMP, sr1, conf, Raw
from scapy.layers.tls.all import TLS, TLSClientHello
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel, QHeaderView,
    QStackedWidget, QFrame, QLineEdit, QProgressBar, QTextEdit, QSplitter,
    QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import pyqtSignal, QObject, Qt, QTimer, QThread

# --- UI THEME: Cyberpunk Glass / Phoenix Edition ---
PHOENIX_STYLE = """
    QMainWindow { background-color: #0d1117; }
    QWidget { color: #c9d1d9; font-family: 'Segoe UI', 'SF Pro Display', sans-serif; }

    QFrame#sidebar { 
        background-color: #161b22; 
        border-right: 2px solid #30363d; 
        min-width: 280px;
    }

    QPushButton.nav-btn {
        background-color: transparent; border: none; border-radius: 12px;
        padding: 18px; text-align: left; font-size: 15px; color: #8b949e; margin: 6px 15px;
    }
    QPushButton.nav-btn:hover { background-color: #21262d; color: #58a6ff; }
    QPushButton.nav-btn:checked { 
        background-color: #1f6feb; color: #ffffff; font-weight: 700; 
        border-left: 6px solid #58a6ff;
    }

    QTableWidget { 
        background-color: #0d1117; border: none; gridline-color: #30363d; 
        border-radius: 12px; selection-background-color: #1f6feb;
    }
    QHeaderView::section {
        background-color: #161b22; color: #8b949e; padding: 12px; border: none; font-weight: bold;
    }

    QLineEdit { 
        background-color: #0d1117; border: 1px solid #3fb950; 
        border-radius: 8px; padding: 12px; color: #3fb950; font-family: 'Consolas';
    }

    QPushButton#actionBtn { 
        background-color: #238636; border-radius: 8px; padding: 12px 25px; 
        font-weight: bold; color: white; border: 1px solid #2ea043;
    }
    QPushButton#actionBtn:hover { background-color: #2ea043; box-shadow: 0 0 15px #2ea043; }

    QTreeWidget, QTextEdit { 
        background-color: #161b22; border: 1px solid #30363d; border-radius: 10px; 
        font-family: 'Consolas', monospace; padding: 10px; font-size: 13px;
    }

    QProgressBar { border: 1px solid #30363d; border-radius: 5px; text-align: center; height: 10px; background: #0d1117; }
    QProgressBar::chunk { background-color: #3fb950; border-radius: 5px; }
"""


class WorkerSignals(QObject):
    packet_received = pyqtSignal(list, object)
    scan_result = pyqtSignal(list)
    scan_finished = pyqtSignal()


# --- HYBRID SCANNER ENGINE (Fixes the "Not Working" Issue) ---
class PhoenixScanner(QThread):
    def __init__(self, target, signals):
        super().__init__()
        self.target = target
        self.signals = signals

    def run(self):
        # Top 20 common ports for speed and reliability
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8000, 8080, 8443, 9000, 27017]
        for port in ports:
            try:
                # Standard Connect Scan (Works on localhost and through firewalls)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    service = "Unknown"
                    try:
                        service = socket.getservbyport(port).upper()
                    except:
                        pass

                    # Banner Grabbing
                    banner = "No banner"
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(512).decode().split('\r\n')[0][:30]
                    except:
                        pass

                    self.signals.scan_result.emit([str(port), service, "OPEN ✅", banner])
                sock.close()
            except:
                pass
        self.signals.scan_finished.emit()


class SentinelProPhoenix(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel Pro: Phoenix Edition")
        self.resize(1600, 950)
        self.setStyleSheet(PHOENIX_STYLE)

        self.signals = WorkerSignals()
        self.is_sniffing = False
        self.packet_list = []
        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 1. NAVIGATION SIDEBAR
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        side_layout = QVBoxLayout(self.sidebar)

        logo = QLabel("🛡️ SENTINEL PHOENIX")
        logo.setStyleSheet("font-size: 24px; font-weight: 900; padding: 35px; color: #58a6ff;")
        side_layout.addWidget(logo)

        self.btn_sniffer = self.create_nav_btn("🔍 Packet Inspector", True)
        self.btn_mapper = self.create_nav_btn("🌐 Network Mapper")
        self.btn_audit = self.create_nav_btn("⚖️ Security Audit")

        side_layout.addWidget(self.btn_sniffer)
        side_layout.addWidget(self.btn_mapper)
        side_layout.addWidget(self.btn_audit)
        side_layout.addStretch()

        layout.addWidget(self.sidebar)

        # 2. WORKSPACE
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        self.init_sniffer_tab()
        self.init_mapper_tab()

    def create_nav_btn(self, text, checked=False):
        btn = QPushButton(text)
        btn.setCheckable(True)
        btn.setChecked(checked)
        btn.setAutoExclusive(True)
        btn.setProperty("class", "nav-btn")
        btn.clicked.connect(self.switch_tab)
        return btn

    def switch_tab(self):
        idx = [self.btn_sniffer, self.btn_mapper, self.btn_audit].index(self.sender())
        self.stack.setCurrentIndex(idx)

    # --- TAB 1: ADVANCED PACKET INSPECTOR ---
    def init_sniffer_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)

        ctrl = QHBoxLayout()
        self.sniff_btn = QPushButton("Start Live Capture")
        self.sniff_btn.setObjectName("actionBtn")
        self.sniff_btn.clicked.connect(self.toggle_sniff)
        ctrl.addWidget(self.sniff_btn)
        ctrl.addStretch()
        layout.addLayout(ctrl)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.packet_table = QTableWidget(0, 6)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.packet_table.itemClicked.connect(self.inspect_packet)

        h_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.packet_tree = QTreeWidget()
        self.packet_tree.setHeaderLabel("Protocol Layers")

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setPlaceholderText("Select a packet for hex data...")

        h_splitter.addWidget(self.packet_tree)
        h_splitter.addWidget(self.hex_view)

        splitter.addWidget(self.packet_table)
        splitter.addWidget(h_splitter)
        layout.addWidget(splitter)

        self.signals.packet_received.connect(self.add_packet_to_ui)
        self.stack.addWidget(page)

    # --- TAB 2: NETWORK MAPPER ---
    def init_mapper_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)

        header = QLabel("Network Asset Intelligence")
        header.setStyleSheet("font-size: 28px; font-weight: 800; color: #ffffff;")
        layout.addWidget(header)

        form = QHBoxLayout()
        self.target_input = QLineEdit("127.0.0.1")
        form.addWidget(QLabel("Target IP:"))
        form.addWidget(self.target_input)

        self.scan_btn = QPushButton("Run Deep Intelligence Scan")
        self.scan_btn.setObjectName("actionBtn")
        self.scan_btn.clicked.connect(self.start_mapping)
        form.addWidget(self.scan_btn)
        layout.addLayout(form)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        self.mapper_table = QTableWidget(0, 4)
        self.mapper_table.setHorizontalHeaderLabels(["Port", "Service", "Status", "Banner / Info"])
        self.mapper_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.mapper_table)

        self.signals.scan_result.connect(self.add_map_row)
        self.signals.scan_finished.connect(lambda: self.scan_btn.setEnabled(True))
        self.stack.addWidget(page)

    # --- CORE LOGIC: SNIFFER ---
    def toggle_sniff(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.sniff_btn.setText("Stop Capture")
            self.sniff_btn.setStyleSheet("background-color: #da3633;")
            threading.Thread(target=self.sniff_loop, daemon=True).start()
        else:
            self.is_sniffing = False
            self.sniff_btn.setText("Start Live Capture")
            self.sniff_btn.setStyleSheet("")

    def sniff_loop(self):
        # Identify active interface
        sniff(prn=self.handle_packet, stop_filter=lambda x: not self.is_sniffing, store=0)

    def handle_packet(self, pkt):
        if IP in pkt:
            time = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            num = self.packet_table.rowCount() + 1
            data = [str(num), time, pkt[IP].src, pkt[IP].dst, pkt.sprintf("%IP.proto%"), str(len(pkt))]
            self.signals.packet_received.emit(data, pkt)

    def add_packet_to_ui(self, data, pkt):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        for i, val in enumerate(data): self.packet_table.setItem(row, i, QTableWidgetItem(val))
        self.packet_list.append(pkt)
        if row > 25: self.packet_table.scrollToBottom()

    def inspect_packet(self, item):
        pkt = self.packet_list[item.row()]
        self.packet_tree.clear()

        # Build protocol layer tree
        temp_pkt = pkt
        while temp_pkt:
            layer = QTreeWidgetItem([temp_pkt.name])
            for name, val in temp_pkt.fields.items():
                layer.addChild(QTreeWidgetItem([f"{name}: {val}"]))
            self.packet_tree.addTopLevelItem(layer)
            temp_pkt = temp_pkt.payload
        self.packet_tree.expandAll()

        # Hex Dump view
        from scapy.utils import hexdump
        self.hex_view.setText(hexdump(pkt, dump=True))

    # --- CORE LOGIC: MAPPER ---
    def start_mapping(self):
        target = self.target_input.text()
        self.scan_btn.setEnabled(False)
        self.mapper_table.setRowCount(0)
        self.progress_bar.setRange(0, 0)  # Infinite pulse
        self.scan_worker = PhoenixScanner(target, self.signals)
        self.scan_worker.start()
        self.signals.scan_finished.connect(lambda: self.progress_bar.setRange(0, 100))
        self.signals.scan_finished.connect(lambda: self.progress_bar.setValue(100))

    def add_map_row(self, res):
        row = self.mapper_table.rowCount()
        self.mapper_table.insertRow(row)
        for i, val in enumerate(res): self.mapper_table.setItem(row, i, QTableWidgetItem(val))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SentinelProPhoenix()
    window.show()
    sys.exit(app.exec())
