from L1_NI import *
from L2_Ethernet import *
from L3_ARP import *
from L3_IP import *
from PyRouterUI import *

def main():
    print('==계층 생성=============================')
    # 계층들을 생성한다.
    ni0 = L1_NI('ni0')
    ni1 = L1_NI('ni1')
    eth0 = L2_Ethernet('eth0', MAC) # 뒷부분 변수로 빼기
    eth1 = L2_Ethernet('eth1', MAC2)
    ip = L3_IP('ip')
    arp0 = L3_ARP('arp0',MAC,IP)
    arp1 = L3_ARP('arp1',MAC2,IP2)
    arpcache0 = ARPCacheTable('arpcache1')
    arpcache1 = ARPCacheTable('arpcache2')
    forwarding = ForwardingTable('fowarding')

    forwarding.insert(b'\xa9\xfe\x63\x00', b'\xff\xff\xff\x00', b'\xa9\xfe\x63\xa1', b'\x01\x01\x00', 0, 1)
    forwarding.insert(b'\xa9\xfe\x1e\x00', b'\xff\xff\xff\x00', b'\xa9\xfe\x1e\xde', b'\x01\x01\x00', 1, 1)
    forwarding.insert(b'\xaa\xbb\xcc\x00', b'\xff\xff\xff\x00', b'\x21\x22\x23\x26', b'\x01\x01\x00', 1, 1)
    forwarding.insert(b'\x00\x11\x22\x00', b'\xff\xff\xff\x00', b'\x31\x32\x33\x36', b'\x01\x01\x00', 1, 1)


    arpcache0.insert(b'\xa9\xfe\x63\xa1', b'\x00\xe0\x4c\x68\xce\x40')
    arpcache0.insert(b'\x11\x12\x13\x16', b'\x11\x10\x10\x10\x10\x12')
    arpcache0.insert(b'\x21\x22\x23\x26', b'\x21\x20\x20\x20\x20\x22')
    arpcache0.insert(b'\x31\x32\x33\x36', b'\x31\x30\x30\x30\x30\x32')

    arpcache1.insert(b'\xa9\xfe\x1e\xde', b'\xb8\x27\xeb\x11\x55\x01')
    arpcache1.insert(b'\x11\x12\x13\x16', b'\x11\x10\x10\x10\x10\x12')
    arpcache1.insert(b'\x21\x22\x23\x26', b'\x21\x20\x20\x20\x20\x22')
    arpcache1.insert(b'\x31\x32\x33\x36', b'\x31\x30\x30\x30\x30\x32')

    # 계층들을 연결한다.
    print('\n==계층 연결=============================')
    ni0.connectLayers(None, eth0)
    ni1.connectLayers(None, eth1)

    eth0ULayers = [ip, arp0]
    eth0.connectLayers(ni0, eth0ULayers)

    eth1ULayers = [ip, arp1]
    eth1.connectLayers(ni1, eth1ULayers)

    arp0.connectLayers(eth0, None)
    arp0.connectTable(arpcache0)
    arp1.connectLayers(eth1, None)
    arp1.connectTable(arpcache1)

    ethLayers = [eth0, eth1]
    arpLayers = [arp0, arp1]
    ip.connectLayers(ethLayers, None, arpLayers)
    ip.connectTable(forwarding)

    # 프로그램을 실행시킨다.
    ni0.getAdapterList()
    input0 = input("[NI0] 입력하세요")
    ni0.setAdapter(input0)

    ni1.getAdapterList()
    input1 = input("[NI1] 입력하세요")
    ni1.setAdapter(input1)

    ni0.startAdapter()
    ni1.startAdapter()


    app = QApplication(sys.argv)
    myWindow = MyWindow(arpcache0,arpcache1,ni0,ni1, forwarding)
    myWindow.show()
    app.exec_()

if __name__ == '__main__':
    main()
