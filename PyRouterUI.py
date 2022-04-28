import sys
from PyQt5.QtWidgets import *
from PyQt5 import uic
from ForwardingTable import *
from ARPCacheTable import *
from L1_NI import *
from L2_Ethernet import *
from L3_ARP import *
from L3_IP import *
import struct

#### Start ####

form_class = uic.loadUiType("PyRouterUI.ui")[0]


#### From this, to Development the UI ####


class MyWindow(QMainWindow, form_class):
    def __init__(self,arpcache0, arpcache1, ni0, ni1, forwarding):
        super().__init__()
        self.setupUi(self)
        self.ForwardingViewButton.clicked.connect(self.btn_ForwardingViewButtonClicked)
        self.ForwardingInsertButton.clicked.connect(self.btn_ForwardingInsertButtonClicked)
        self.ARPViewButton.clicked.connect(self.btn_ARPViewButtonClicked)
        self.ARPInsertButton.clicked.connect(self.btn_ARPInsertButtonClicked)
        self.StartButton.clicked.connect(self.btn_StartButtonClicked)
        self.arpcache0 = arpcache0
        self.arpcache1 = arpcache1
        self.ni0 = ni0
        self.ni1 = ni1
        self.forwarding = forwarding

    def btn_ForwardingViewButtonClicked(self):
        self.RefreshForwardingTable()
        QMessageBox.about(self, "Forwarding Table 조회", "View Forwarding Table")

    def btn_ForwardingInsertButtonClicked(self):
        Flag = self.FlagCheckBoxToBytes()
        self.InsertForwardingTable(self.ForwardingDestinationEdit.text(),self.ForwardingNetmaskEdit.text(),
                                   self.ForwardingGatewayEdit.text(),Flag,self.ForwardingInterfaceEdit.text(),
                                   self.ForwardingMetricEdit.text())
        self.ForwardingDestinationEdit.clear()
        self.ForwardingNetmaskEdit.clear()
        self.ForwardingGatewayEdit.clear()
        self.UpCheckBox.setChecked(False)
        self.GatewayCheckBox.setChecked(False)
        self.HostCheckBox.setChecked(False)
        self.ForwardingInterfaceEdit.clear()
        self.ForwardingMetricEdit.clear()
        QMessageBox.about(self, "Forwarding Table 추가", "Add Forwarding")

    def btn_ARPViewButtonClicked(self):
        self.RefreshARPTable()
        QMessageBox.about(self, "ARP Table 조회", "View ARP Table")

    def btn_ARPInsertButtonClicked(self):
        self.InsertARPTable(self.ARPTableNumberEdit.text(),self.IPDestinationEdit.text(),self.MACDestinationEdit.text())
        self.ARPTableNumberEdit.clear()
        self.IPDestinationEdit.clear()
        self.MACDestinationEdit.clear()
        QMessageBox.about(self, "ARP Table 추가", "Add ARP Table")

    def btn_StartButtonClicked(self):
        self.ni0.startAdapter()
        self.ni1.startAdapter()
        QMessageBox.about(self, "Routing Start", "Start Routing")

    def InsertForwardingTable(self,IP,Netmask,Gateway,Flag,Interface,Metric):
        IP = self.IPStrToBytes(IP)
        Netmask = self.IPStrToBytes(Netmask)
        Gateway = self.IPStrToBytes(Gateway)
        Interface = int(Interface)
        Metric = int(Metric)
        self.forwarding.insert(IP,Netmask,Gateway,Flag,Interface,Metric)

    def InsertARPTable(self,tableNumber, IP, MAC):
        IP = self.IPStrToBytes(IP)
        MAC = self.MACStrToBytes(MAC)

        if tableNumber == '0':
            self.arpcache0.insert(IP,MAC)

        elif tableNumber == '1':
            self.arpcache1.insert(IP,MAC)


    #View Forwarding Table
    def RefreshForwardingTable(self):
        Table = self.forwarding.getTable()
        self.ForwardingTableWidget.setRowCount(len(Table))
        count = 0

        for TableData in Table:
            IP = self.IPBytesToStr(TableData[0])
            Netmask = self.IPBytesToStr(TableData[1])
            Gateway = self.IPBytesToStr(TableData[2])
            Flag = self.FlagBytesToStr(TableData[3])
            Interface = str(TableData[4])
            Metric = str(TableData[5])

            self.ForwardingTableWidget.setItem(count, 0, QTableWidgetItem(IP))
            self.ForwardingTableWidget.setItem(count, 1, QTableWidgetItem(Netmask))
            self.ForwardingTableWidget.setItem(count, 2, QTableWidgetItem(Gateway))
            self.ForwardingTableWidget.setItem(count, 3, QTableWidgetItem(Flag))
            self.ForwardingTableWidget.setItem(count, 4, QTableWidgetItem(Interface))
            self.ForwardingTableWidget.setItem(count, 5, QTableWidgetItem(Metric))
            count = count + 1

    #View ARP Cache Table
    def RefreshARPTable(self):
        ARPTable0 = self.arpcache0.getTable()
        ARPTable1 = self.arpcache1.getTable()
        self.ARPCacheTableWidget.setRowCount(len(ARPTable0)+len(ARPTable1))
        count = 0

        for ARPData in ARPTable0:
            IP = self.IPBytesToStr(ARPData[0])
            MAC = self.MACBytesToStr(ARPData[1])
            self.ARPCacheTableWidget.setItem(count, 0, QTableWidgetItem(IP))
            self.ARPCacheTableWidget.setItem(count, 1, QTableWidgetItem(MAC))
            self.ARPCacheTableWidget.setItem(count, 2, QTableWidgetItem('0'))
            count = count + 1

        for ARPData in ARPTable1:
            IP = self.IPBytesToStr(ARPData[0])
            MAC = self.MACBytesToStr(ARPData[1])
            self.ARPCacheTableWidget.setItem(count, 0, QTableWidgetItem(IP))
            self.ARPCacheTableWidget.setItem(count, 1, QTableWidgetItem(MAC))
            self.ARPCacheTableWidget.setItem(count, 2, QTableWidgetItem('1'))
            count = count + 1

    def FlagCheckBoxToBytes(self):
        U = self.UpCheckBox
        G = self.GatewayCheckBox
        H = self.HostCheckBox

        if U.isChecked() == True:
            if G.isChecked() == True:
                return FLAG_UG
            elif H.isChecked() == True:
                return FLAG_UH

        else:
            return b'\x00\x00\x00'
    #Change Data Type
    def FlagBytesToStr(self,FlagData):
        if FlagData == FLAG_UG:
            return 'UG'
        if FlagData == FLAG_UH:
            return 'UH'
        else:
            return 'WrongData'

    def IPBytesToStr(self, IPData):
        IP = struct.unpack('!4B', IPData)
        IP = '%d.%d.%d.%d'%IP
        return IP

    def IPStrToBytes(self, IPData):
        IP = bytes(map(int, IPData.split('.')))
        return IP

    def MACStrToBytes(self, MACData):
        MAC = MACData.split(':')
        MAC = MAC[0] + MAC[1] + MAC[2] + MAC[3] + MAC[4] + MAC[5]
        MAC = bytes.fromhex(MAC)
        return MAC

    def MACBytesToStr(self, MACData):
        Eth = struct.unpack('!6B',MACData)
        Eth = '%02x:%02x:%02x:%02x:%02x:%02x'%Eth
        return Eth

