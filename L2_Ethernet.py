from Dictionary import *
import struct


class L2_Ethernet:
    def __init__(self, name, src):  # Initialization
        self.name = name
        self.underLayer = None
        self.upperLayer = None

        self._dst = None  # Ethernet Destination Address
        self._src = src  # Ethernet Source Address
        self._type = None  # Ethernet Frame Type
        self._data = None  # Etherent Data13

    def connectLayers(self, underLayer, upperLayers):                           # 레이어 연결을 위해 사용, 해당 레이어의 상위/하위 레이어 정보를 설정 (main에서 수행)
        # Ethernet의 경우 상위 레이어가 IP와 ARP이므로 배열형태로 전달 받음 (main에서 수행)
        self.underLayer = underLayer
        self.upperLayers = upperLayers

    def set_dst(self, ARP_MAC_address):  # Ethernet Destination Address 설정
        self._dst = ARP_MAC_address  # ARP로부터 전달받은 Ethernet 주소
        # debug
        # print(self._dst)

    def receive(self, ppayload):
        #print('[Layer ' + self.name + '] Called receive()')

        # Ethernet header 분석
        self.extractHeader(ppayload)
        print("받은 패킷:", ppayload)
        # Ethernet header's destination이 자기 자신의 MAC이면 Frametype 비교
        if self._pdst == ETH_ADDR_BROADCAST or self._src == self._pdst:
            #패킷이 자기자신인 경우 패킷을 분석하지 않는다.
            if self._src == self._psrc:
                return
            # Frametype 0x0800이면 IP로 전달
            if self._ptype == ETHERNET_TYPE_IP:
                self.upperLayers[0].receive(self._pdata)

            # Frametype 0x0806이면 ARP로 전달
            if self._ptype == ETHERNET_TYPE_ARP:
                self.upperLayers[1].receive(self._pdata)

    def send(self, data, type, opt=None):  # IP나 ARP로부터 받은 패킷을 Ethernet Frame을 씌워서 NI 전달.

        #print('[Layer ' + self.name + '] Called send()')

        if type == ETHERNET_TYPE_IP:  # 상위 계층으로부터 받은 Frame type이 IP일 경우
            self._type = ETHERNET_TYPE_IP
        if type == ETHERNET_TYPE_ARP:  # 상위 계층으로부터 받은 Frame type이 ARP일 경우
            self._type = ETHERNET_TYPE_ARP
            #self._dst = opt

        # NILayer의 Send함수 호출 후 생성한 ethernet frame 전달
        self.underLayer.send(self.generatePayload(data))

    def extractHeader(self, raw):  # NI로부터 받은 패킷 Ethernet Frame에 맞춰 분석
        self._pdst = raw[:6]
        self._psrc = raw[6:12]
        self._ptype = raw[12:14]
        self._pdata = raw[14:]
        self._pheader = raw[:14]

    def generatePayload(self, data):  # Etherent Frame 생성
        # todo 테스트를 위해 임시적으로 설정한 것 (향후 수정해야 함)
        # print(self._dst)
        self._data = data
        return self._dst + self._src + self._type + self._data