from Dictionary import *
import struct
from ARPCacheTable import *

class L3_ARP:
    def __init__(self, name, my_mac, my_ip):  # Initialization
        self.name = name
        self.underLayer = None
        self.upperLayer = None

        self._hard_type = b'\x00\x01'
        self._proto_type = b'\x08\x00'
        self._hard_len = b'\x06'
        self._proto_len = b'\x04'
        self._opcode = None
        self._sender_mac = my_mac
        self._sender_ip = my_ip
        self._target_mac = None
        self._target_ip = None

        self.arptable = None

    def connectTable(self, arptable):
        self.arptable = arptable

    def connectLayers(self, underLayer, upperLayer):
        self.underLayer = underLayer
        self.upperLayer = upperLayer

    def receive(self, ppayload):  # Ethernet으로 패킷 수신
        print('[Layer ' + self.name + '] Called receive()')

        # ARP 헤더 분석
        self.extractHeader(ppayload)

        proxy_i = self.arptable.proxysearch(self._ptarget_ip)
        if proxy_i != None:
            self.sendPARPReply(self.arptable.proxy_get_ip(proxy_i))


        # 수신된 packet target_ip가 sender가 아니면 무시
        if self._ptarget_ip != self._sender_ip:
            return
        # 수신된 패킷의 sender_ip가 자기자신이면 무시
        if self._psender_ip == self._sender_ip:
            return
        # 수신된 ARP message의 op code 확인
        # opcode가 1이면 ARP request
        if self._popcode == ARP_OPCODE_REQUEST:
            # ARP cache table에 sender에 대한 정보 등록
            index = self.arptable.search(self._psender_ip)
            if index == None:
                self.arptable.insert(self._psender_ip, self._psender_mac)
            else:
                self.arptable.update(index, self._psender_mac)

            # Gratuitous ARP가 아닌 경우
            if self._psender_ip != self._ptarget_ip:
                self.sendARPReply()

        # opcode가 2이면 ARP reply
        if self._popcode == ARP_OPCODE_REPLY:
            # ARP 메시지의 sender ip address와 sender mac address를 이용해서 ARP cache table에 등록
            index = self.arptable.search(self._psender_ip)
            if index == None:
                self.arptable.insert(self._psender_ip, self._psender_mac)
            else:
                self.arptable.update(index, self._psender_mac)

            #print('TODO: ARP 메시지의 Sender 정보를 ARP cache table에 등록') << end

    def send(self, data):  # Ethernet으로 패킷 전달
        print('[Layer ' + self.name + '] Called send()')
        self.underLayer.send(data, ETHERNET_TYPE_ARP)

    # ARP Test header: b'\x00\x01\x08\x00\x06\x04\x00\x02\xef\x00\x00\x00\x00\xfe\x10\x00\x00\x02\xab\x00\x00\x00\x00\xcd\x10\x00\x00\x01'
    def extractHeader(self, raw):
        self._phard_type = raw[:2]
        self._pproto_type = raw[2:4]
        self._phard_len = raw[4:5]
        self._pproto_len = raw[5:6]
        self._popcode = raw[6:8]
        self._psender_mac = raw[8:14]
        self._psender_ip = raw[14:18]
        self._ptarget_mac = raw[18:24]
        self._ptarget_ip = raw[24:28]
        self._pheader = raw[:28]

    # # todo ARP cache table에서 정보 찾기 << end
    # def searchARPCacheTable(self, ipdst):
    #     print('TODO: ARP cache table 탐색')
    #     index = self.arptable.search(ipdst)
    #     if index != None:
    #         return self.arptable.get_ip(index)  # 찾은 경우 address를 반환
    #     else:
    #         return None
    #     # return None #못 찾은 경우 None을 반환

    def checkARPCacheTable(self, ipdst):
        # debug
        #print('[Layer ' + self.name + '] Called checkARPCacheTable(): ARP cache entry 찾기 시작')
        print('TODO: ARP cache table 확인', ipdst)
        # ARP 캐쉬 테이블 탐색하여 ipdst에 매핑되는 ethernet 주소 찾기
        # ethernet 주소를 찾으면, Ethernet layer의 dst 주소로 설정
        index = self.arptable.search(ipdst)
        if index != None:
            # underlayer의 dst를 ipdst에 해당하는 mac주소로 설정
            print('[Layer ' + self.name + '] ARP cache entry 찾기 성공')
            eth_dst = self.arptable.get_mac(index)
            self.underLayer.set_dst(eth_dst)
            return True
        else:
            #if ipdst != IP: #일단 자기자신으로 GARP 못보내게 막기
            print('[Layer ' + self.name +'] ARP cache entry 찾기 실패')
            self.sendARPRequest(ipdst)
            return False
        # result = self.searchARPCacheTable(ipdst)
        # if result == ipdst:
        #
        #
        #     self.underLayer.set_dst() #b'\x00\x00\x00\x00\x00\x03'
        #     return True

        # elif result == None:
        #     # ethernet 주소가 없으면, ARP request/reply 과정 수행 후 알아오기
        #     print('[Layer ' + self.name + '] ARP cache entry 찾기 실패')
        #     self.sendARPRequest(ipdst)
        #     return False

    def sendARPRequest(self, ipdst):
        print('[Layer ' + self.name + '] Called sendARPRequest()')
        # ARP request 메시지 생성
        self._hard_type = b'\x00\x01'
        self._proto_type = b'\x08\x00'
        self._hard_len = b'\x06'
        self._proto_len = b'\x04'
        self._opcode = ARP_OPCODE_REQUEST
        self._target_mac = b'\x00\x00\x00\x00\x00\x00'
        self._target_ip = ipdst

        self.underLayer.set_dst(b'\xff\xff\xff\xff\xff\xff')
        print(self.generatePayload())  # 생성된 ARP 요청 메시지 확인

        # send 함수 호출 후 생성된 메시지 전달
        self.send(self.generatePayload())

    def sendARPReply(self):
        print('[Layer ' + self.name + '] Called sendARPReply()')
        # ARP reply 메시지 생성
        self._hard_type = self._phard_type
        self._proto_type = self._pproto_type
        self._hard_len = self._phard_len
        self._proto_len = self._pproto_len
        self._opcode = ARP_OPCODE_REPLY
        self._target_mac = self._psender_mac
        self._target_ip = self._psender_ip

        # print(self._pheader) #수신된 ARP 요청 메시지 확인
        # print(self.generatePayload()) #생성된 ARP 응답 메시지 확인

        self.underLayer.set_dst(self._psender_mac)
        # send 함수 호출 후 생성된 메시지 전달
        self.send(self.generatePayload())

    def sendPARPReply(self,ip):
        print('[Layer ' + self.name + '] Called sendARPReply()')
        # ARP reply 메시지 생성
        self._hard_type = self._phard_type
        self._proto_type = self._pproto_type
        self._hard_len = self._phard_len
        self._proto_len = self._pproto_len
        self._opcode = ARP_OPCODE_REPLY
        self._sender_ip = ip
        self._target_mac = self._psender_mac
        self._target_ip = self._psender_ip

        # print(self._pheader) #수신된 ARP 요청 메시지 확인
        # print(self.generatePayload()) #생성된 ARP 응답 메시지 확인

        self.underLayer.set_dst(self._psender_mac)
        # send 함수 호출 후 생성된 메시지 전달
        self.send(self.generatePayload())

    def generatePayload(self):  # ARP message 생성
        return self._hard_type + self._proto_type + self._hard_len + self._proto_len + self._opcode + self._sender_mac + self._sender_ip + self._target_mac + self._target_ip
