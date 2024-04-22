from scapy.all import *
import time

from PyQt5.QtCore import pyqtSignal, QObject


class Sniffer(QObject):
    sig = pyqtSignal(Packet)
    sniffer = None
    start_time = 0

    def start(self, filter, iface):
        if self.sniffer is None:
            self.sniffer = AsyncSniffer(filter=filter, prn=lambda packet: self.sig.emit(packet), iface=iface)
            self.start_time = time.time()
            self.sniffer.start()

    def stop(self):
        if not self.sniffer is None:
            self.sniffer.stop()
            self.start_time = 0
            self.sniffer = None
