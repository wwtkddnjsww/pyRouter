#Ethernet header
ETHERNET_TYPE_IP = b'\x08\x00'
ETHERNET_TYPE_ARP = b'\x08\x06'

#ARP header
ARP_OPCODE_REQUEST = b'\x00\x01'
ARP_OPCODE_REPLY = b'\x00\x02'

#IP address
IP_ADDR_BROADCAST = b'\xff\xff\xff\xff'

#Ethernet address
ETH_ADDR_BROADCAST = b'\xff\xff\xff\xff\xff\xff'

FLAG_UG = b'\x01\x01\x00' # todo 향후 flag 수정
FLAG_UH = b'\x01\x00\x01' # todo 향후 flag 수정

IP = b'\xa9\xfe\x63\x0a'
MAC = b'\x00\xe0\x4c\x59\x9e\x36'

IP2 = b'\xa9\xfe\x1e\x0a'
MAC2 = b'\x00\xe0\x4c\x68\xaf\x95'