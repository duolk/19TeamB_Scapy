# -*-coding:utf-8-*-
import scapy.all as scapy

s = scapy.rdpcap('invalid.pcap')
s.show()