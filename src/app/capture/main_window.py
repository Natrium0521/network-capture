from scapy.all import *
from PyQt5.QtWidgets import QMainWindow

from app.ui.Ui_test import Ui_MainWindow
from app.capture.sniffer import Sniffer
import app.utils.bytes2str as b2s


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.sniffer = Sniffer()
        self.sniffer.sig.connect(self.sniffer_update_gui)

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.Start.clicked.connect(self.start_sniff)
        self.ui.Stop.clicked.connect(self.sniffer.stop)

        print([iface.name for iface in get_working_ifaces()])

    def sniffer_update_gui(self, packet):
        self.ui.ShowBox.setText(b2s.conv(bytes(packet)))

    def start_sniff(self):
        self.sniffer.start("", "以太网")
