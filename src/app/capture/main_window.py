from scapy.all import *
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWidgets import QMainWindow

from app.ui.Ui_test import Ui_MainWindow
from ..utils import bytes2str


class Sniffer(QObject):
    sig = pyqtSignal(bytes)
    sniffer = None

    def start(self, filter, iface):
        if self.sniffer is None:
            self.sniffer = AsyncSniffer(filter=filter, prn=lambda data: self.sig.emit(bytes(data)), iface=iface)
            self.sniffer.start()

    def stop(self):
        if not self.sniffer is None:
            self.sniffer.stop()
            self.sniffer = None


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.sniffer = Sniffer()
        self.sniffer.sig.connect(self.sniffer_update_gui)

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.Start.clicked.connect(self.start_sniff)
        self.ui.Stop.clicked.connect(self.sniffer.stop)

    def sniffer_update_gui(self, data):
        self.ui.ShowBox.setText(bytes2str.conv(data))

    def start_sniff(self):
        self.sniffer.start("", "以太网")
