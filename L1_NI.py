from scapy.sendrecv import sendp

from Dictionary import *
import struct
import pcap
import threading


class L1_NI:
    def __init__(self, name):  # Initialization
        self.name = name
        self.underLayer = None
        self.upperLayer = None
        self.device = None
        self.ifnum = -1

    def connectLayers(self, underLayer, upperLayer):   # 레이어 연결을 위해 사용, 해당 레이어의 상위/하위 레이어 정보를 설정 (main에서 수행)
        self.underLayer = underLayer
        self.upperLayer = upperLayer

    def getAdapterList(self):
        print('[Layer ' + self.name + '] Called setAdapter()')
        print('TODO: Sniffer를 이용한 네트워크 어뎁터 설정')

        # network adapter list 불러오기
        self.devices = pcap.findalldevs()
        i=0
        # adapter 록 하나씩 불러와서 print 하기
        buf = ''
        for dev in self.devices:
            buf = buf + (str(i) + ') ' + dev + ', ')
            i = i+1
        print(buf)

    def setAdapter(self,ifnum):
        self.ifnum = ifnum
        print("Selected "+ifnum+"th device: " + self.devices[int(self.ifnum)])

    def execute(self):
        print(threading.currentThread().getName(), self.name)
        packets = pcap.pcap(name=self.devices[int(self.ifnum)], promisc=True, immediate=True, timeout_ms=50)

        for ts, ppayload in packets:
            self.receive(ppayload)

    def startAdapter(self):
        my_thread = threading.Thread(target=self.execute, args=())
        my_thread.start()

    def receive(self, ppayload):
        self.upperLayer.receive(ppayload)

    def send(self, data):  # IP나 ARP로부터 받은 패킷을 Ethernet Frame을 씌워서 NI 전달
        sendp(data, iface = self.devices[int(self.ifnum)])
        pass
