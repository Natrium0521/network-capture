from scapy.all import *
from scapy.arch.libpcap import _PcapWrapper_libpcap
from scapy.libs.winpcapy import pcap_compile
from PyQt5.QtCore import QObject, QThread, pyqtSignal


class Filter_Checker(QThread):
    result = pyqtSignal(str, bool)

    def __init__(self, filter):
        super().__init__()
        self.filter = filter

    def run(self) -> None:
        tmp = _PcapWrapper_libpcap(conf.iface, MTU, conf.sniff_promisc, 0)
        if pcap_compile(tmp.pcap, tmp.bpf_program, self.filter.encode("utf-8"), 1, -1) == 0:
            self.result.emit(self.filter, True)
        else:
            self.result.emit(self.filter, False)
