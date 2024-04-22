from scapy.all import *
from scapy.layers.inet import *
from scapy.layers import http
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QTreeWidgetItem
from PyQt5.QtGui import QColor, QBrush, QPalette

from app.ui.Ui_main_window import Ui_MainWindow
from app.capture.sniffer import Sniffer
from app.capture.filter_checker import Filter_Checker

import app.utils.bytes2str as b2s


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.sniffer = Sniffer()
        self.sniffer.sig.connect(self.on_packet_recived)
        self.filter = ""
        self.filter_color = {"": "FFFFFF"}
        self.filter_checkers = []
        self.iface = ""
        self.packets = []
        self.selected_row = -1
        self.protocol_color = {
            "IP": "#fff3d6",
            "TCP": "#e7e6ff",
            "ARP": "#faf0d7",
            "UDP": "#daeeff",
            "DNS": "#daeeff",
            "DHCP": "#daeeff",
            "LLMNRQuery": "#daeeff",
            "HTTP": "#e4ffc7",
            "HTTPRequest": "#e4ffc7",
            "HTTPResponse": "#e4ffc7",
            "ICMP": "#fce0ff",
            "ICMPv6MLReport2": "#fce0ff",
        }

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.ActionBtn.clicked.connect(self.do_sniff)
        self.ui.ClearBtn.clicked.connect(self.do_clear)
        self.ui.FilterBtn.clicked.connect(self.do_filter)
        self.ui.FilterInput.textChanged.connect(self.do_check_filter)
        self.ui.FilterInput.returnPressed.connect(self.ui.FilterBtn.click)
        self.ui.IfaceInput.addItems([iface.name for iface in get_working_ifaces()])
        self.ui.IfaceInput.currentTextChanged.connect(self.do_select_iface)
        self.ui.PacketTable.itemClicked.connect(self.do_packet_clicked)

        for i, w in enumerate([50, 90, 150, 150, 100, 75, 800]):
            self.ui.PacketTable.setColumnWidth(i, w)

    def on_packet_recived(self, packet):
        row = self.ui.PacketTable.rowCount()

        self.packets.append(packet)
        self.ui.PacketTable.setRowCount(row + 1)
        self.ui.PacketTable.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.ui.PacketTable.setItem(row, 1, QTableWidgetItem(f"{packet.time-self.sniffer.start_time:.6f}"))
        src = packet[IP].src if IP in packet else packet.src
        dst = packet[IP].dst if IP in packet else packet.dst
        self.ui.PacketTable.setItem(row, 2, QTableWidgetItem(src))
        self.ui.PacketTable.setItem(row, 3, QTableWidgetItem(dst))
        protocol = None
        for layer in packet.layers():
            if layer.__name__ not in ["Padding", "Raw"]:
                protocol = layer.__name__
        if protocol[:3] == "DNS":
            protocol = "DNS"
        self.ui.PacketTable.setItem(row, 4, QTableWidgetItem(protocol))
        self.ui.PacketTable.setItem(row, 5, QTableWidgetItem(str(len(packet))))
        info = ""
        try:
            info = packet.summary()
        except:
            info = "Error"
        self.ui.PacketTable.setItem(row, 6, QTableWidgetItem(info))

        bg_color = self.protocol_color.get(protocol, "#ffffff")
        for col in range(7):
            self.ui.PacketTable.item(row, col).setBackground(QColor(bg_color))

    def do_sniff(self):
        if self.sniffer.sniffer is None:
            self.ui.IfaceInput.setDisabled(True)
            self.ui.FilterBtn.setDisabled(True)
            self.setWindowTitle(f"网络捕获{''if self.filter=='' else ' - 过滤器: '+self.filter} - 正在捕获: {self.iface}")
            self.ui.ActionBtn.setText("停止捕获")
            self.sniffer.start(self.filter, self.iface)
        else:
            self.ui.IfaceInput.setDisabled(False)
            self.ui.FilterBtn.setDisabled(False)
            self.setWindowTitle(f"网络捕获{''if self.filter=='' else ' - 过滤器: '+self.filter}")
            self.ui.ActionBtn.setText("开始捕获")
            self.sniffer.stop()

    def do_clear(self):
        self.packets = []
        self.ui.PacketTable.clearContents()
        self.ui.PacketTable.setRowCount(0)
        self.ui.PacketTree.clear()
        self.ui.PacketHex.setPlainText("")
        self.selected_row = -1

    def do_filter(self):
        if self.ui.FilterInput.text() == "" or self.filter_color[self.ui.FilterInput.text()] == "DDFFDD":
            self.filter = self.ui.FilterInput.text()
            self.setWindowTitle(f"网络捕获{''if self.filter=='' else ' - 过滤器: '+self.filter}")

    def on_filter_checked(self, filter, is_ok):
        self.filter_color[filter] = "DDFFDD" if is_ok else "FFDDDD"
        filter = self.ui.FilterInput.text()
        if filter in self.filter_color:
            self.ui.FilterInput.setStyleSheet(f"QLineEdit {{ background-color: #{self.filter_color[filter]}; }}")

    def do_check_filter(self):
        filter = self.ui.FilterInput.text()
        if filter in self.filter_color:
            self.ui.FilterInput.setStyleSheet(f"QLineEdit {{ background-color: #{self.filter_color[filter]}; }}")
            return
        del_filter_checkers = []
        for fc in self.filter_checkers:
            if fc.isFinished():
                del_filter_checkers.append(fc)
        for fc in del_filter_checkers:
            self.filter_checkers.remove(fc)
        filter_checker = Filter_Checker(filter)
        self.filter_checkers.append(filter_checker)
        filter_checker.result.connect(self.on_filter_checked)
        filter_checker.start()

    def do_select_iface(self):
        iface = self.ui.IfaceInput.currentText()
        if iface == "未选择":
            iface = ""
        self.iface = iface

    def do_packet_clicked(self, clicked):
        row = clicked.row()
        if row == self.selected_row:
            return
        self.selected_row = row
        packet = self.packets[row]
        self.ui.PacketHex.setPlainText(b2s.conv(bytes(packet)))
        self.ui.PacketTree.clear()
        while True:
            node = QTreeWidgetItem(self.ui.PacketTree)
            node.setText(0, packet.name)
            for f in packet.fields_desc:
                fvalue = packet.getfieldval(f.name)
                child = QTreeWidgetItem(node)
                if isinstance(fvalue, list):
                    if len(fvalue) == 0:
                        child.setText(0, f.name + ": []")
                        continue
                    child.setText(0, f.name + ":")
                    for pair in fvalue:
                        pchild = QTreeWidgetItem(child)
                        if isinstance(pair, tuple):
                            if len(pair) == 2:
                                pchild.setText(0, str(pair[0]) + ": " + str(pair[1]))
                            else:
                                pchild.setText(0, str(pair[0]) + ": " + str(pair[1:]))
                        else:
                            pchild.setText(0, str(pair))
                else:
                    child.setText(0, f.name + ": " + str(fvalue))
            if packet.payload:
                packet = packet.payload
            else:
                break
