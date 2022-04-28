import struct

class ForwardingTable:
    def __init__(self, name):
        self.name = name
        self.fowardingtable = [] #destination, Netmask, Gateway, Flag, Interface, Metric 순으로 들어감.

    def getTable(self):
        return self.fowardingtable

    #포워딩 테이블 검색
    def search(self, dst_ip):
        print('탐색 시작: ', dst_ip)
        for i in range(len(self.fowardingtable)):
            address = self.fowardingtable[i][0]
            netmask = self.fowardingtable[i][1]

            print('어드레스 :',address,'넷마스크 :',netmask)
            #수신된 패킷의 목적지에 맞는 네트워크 탐색
            if self.byte_and_operator(dst_ip, netmask) == address:
                print('일치하는 튜플 : ', i)
                return i

        #포워딩테이블에서 주소 검색하는 반복문이 다 끝난 이후에도 주소를 찾을 수 없으면 None 리턴
        print('탐색실패')
        return None

    def byte_and_operator(self,address, netmask):
        (addr0,addr1,addr2,addr3) = struct.unpack('!4B',address)
        (net0,net1,net2,net3) = struct.unpack('!4B', netmask)

        ret_val = struct.pack('!4B',addr0 & net0, addr1 & net1, addr2 & net2, addr3 & net3)
        print ('리턴밸류 :', ret_val)
        return ret_val


    #Routing Table 새로운 원소 입력
    def insert(self,dst_ip,netmask, gateway_ip, flag, interface, metric):
        print('ROUTING TABLE_INSERT')
        self.fowardingtable.append([dst_ip, netmask, gateway_ip, flag, interface, metric])
        print(self.fowardingtable)

    #index를 입력받아 i번째 항목 수정
    def update(self,i, netmask, gateway_ip, flag, interface, metric):
        print('ROUTING TABLE_UPDATE')
        self.fowardingtable[i][1] = netmask
        self.fowardingtable[i][2] = gateway_ip
        self.fowardingtable[i][3] = flag
        self.fowardingtable[i][4] = interface
        self.fowardingtable[i][5] = metric

    def delete(self):
        pass

    # def header(self, packet): # Dynamic Routing 구현시 아직 몇바이트인지 몰라서 추후 수정 해야함 todo list 1
    #     self._pdst_ip = packet[:4]
    #     self._pnetmask = packet[4:8]
    #     self._pgateway_ip = packet[8:12]
    #     self._pflag = packet[12:15]

    def get_tuple(self,i):
        if i == None:
            return None
        return self.fowardingtable[i][0],self.fowardingtable[i][1],self.fowardingtable[i][2],self.fowardingtable[i][3],self.fowardingtable[i][4],self.fowardingtable[i][5]
