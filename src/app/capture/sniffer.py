from scapy.all import *

from PyQt5.QtCore import pyqtSignal, QObject


class Sniffer(QObject):
    sig = pyqtSignal(Packet)
    sniffer = None

    def start(self, filter, iface):
        if self.sniffer is None:
            self.sniffer = AsyncSniffer(filter=filter, prn=lambda packet: self.sig.emit(packet), iface=iface)
            self.sniffer.start()

    def stop(self):
        if not self.sniffer is None:
            self.sniffer.stop()
            self.sniffer = None
