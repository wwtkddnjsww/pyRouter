class ARPCacheTable:
    def __init__(self, name):
        self.name = name
        self.arpcachetable = [] #arp_ip, arp_eth순으로 들어감

    def getTable(self):
        return self.arpcachetable

    #ARP Cache Table에서
    def insert(self,arp_ip,arp_eth):
        print('ARP_INSERT')
        self.arpcachetable.append([arp_ip,arp_eth])

    #index를 입력받아 i번째 MAC주소 수정
    def update(self,i, arp_eth):
        print('ARP_UPDATE')
        self.arpcachetable[i][1] = arp_eth

    def delete(self):
        pass

    #ARP cache table에서 찾는 ip가 있으면 ip주소를 리턴
    def search(self,arp_ip):
        for i in range(len(self.arpcachetable)):
            if self.arpcachetable[i][0] == arp_ip:
                return i
        return None

    def get_ip(self, i):
        return self.arpcachetable[i][0]

    def get_mac(self, i):
        return self.arpcachetable[i][1]

