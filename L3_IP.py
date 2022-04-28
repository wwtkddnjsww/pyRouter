from Dictionary import *
import struct
from ForwardingTable import *

class L3_IP:
    def __init__(self, name):  # Initialization
        self.name = name
        self.underLayers = None
        self.upperLayer = None
        self.arpLayers = None

        self._verlen = None
        self._service = None
        self._total = None  # IP header + data 길이
        self._id = None
        self._flag_and_offset = None
        self._ttl = None
        self._type = None
        self._check_sum = None
        self._src = None
        self._dst = None

        self.fowardingtable = None

    def connectLayers(self, underLayers, upperLayer, arpLayers):                                            # 레이어 연결을 위해 사용, 해당 레이어의 상위/하위 레이어 정보를 설정 (main에서 수행)
        # IP의 경우 하위 레이어 및 arp 레이어는 인터페이스 개수 만큼 갖고 있어야하기 때문에 배열형태로 전달 받음 (main에서 수행)
        self.underLayers = underLayers
        self.upperLayer = upperLayer
        self.arpLayers = arpLayers

    def connectTable(self, fowardingtable):
        self.fowardingtable = fowardingtable

    def receive(self, ppayload):
        #print('[Layer ' + self.name + '] Called receive()')

        # IP header 분석
        self.extractHeader(ppayload)

        index = self.fowardingtable.search(self._pdst)
        #index를 찾았을 경우
        if index != None:
            self.send(index)

    def send(self,index):  # 라우팅 과정 수행과 수행 결과에 따른 IP 패킷 생성 후, Ethernet layer로 전달
        #print('[Layer ' + self.name + '] Called send()')
        print('튜플: ',self.fowardingtable.get_tuple(index))

        # 라우팅 테이블 탐색
        # destination, Netmask, Gateway, Flag, Interface, Metric 순으로 들어감.
        address,netmask,gateway,flag,ifnum,metric = self.fowardingtable.get_tuple(index)
        if flag == FLAG_UH:
            # ARP의 cache table을 확인하기 위해서 추출된 주소를 ARP에 전달
            result = self.arpLayers[ifnum].checkARPCacheTable(self._pdst)
        elif flag == FLAG_UG:
            result = self.arpLayers[ifnum].checkARPCacheTable(gateway)
        if result == True:
            # Ethernet layer로 생성된 IP 패킷 전달
            self.underLayers[ifnum].send(self.generatePayload(), ETHERNET_TYPE_IP)


    # IP Test header: b'\x45\x00\x00\x14\x00\x00\x00\x00\xff\x00\x00\x00\xcd\x00\x00\x00\x10\x00\x00\x00'
    def extractHeader(self, raw):  # 수신된 패킷에 IP 헤더 구조를 디멀티플렉싱
        self._pverlen = raw[:1]
        self._pservice = raw[1:2]
        self._ptotal = raw[2:4]  # IP header + data 길이
        self._pid = raw[4:6]
        self._pflag_and_offset = raw[6:8]
        self._pttl = raw[8:9]
        self._ptype = raw[9:10]
        self._pcheck_sum = raw[10:12]
        self._psrc = raw[12:16]
        self._pdst = raw[16:20]
        self._data = raw[20:]
        self._pheader = raw[:20]


    def generatePayload(self):
        return self._pverlen + self._pservice + self._ptotal + self._pid + self._pflag_and_offset + self._pttl + self._ptype + self._pcheck_sum + self._psrc + self._pdst + self._data
