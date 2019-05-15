# -*-coding:utf-8-*-
import scapy.all as scapy


class Disney(scapy.Packet):
    name = "DisneyPacket "
    fields_desc=[ scapy.ShortField("mickey",5),
                 scapy.XByteField("minnie",3) ,
                 scapy.IntEnumField("donald" , 1 ,
                      { 1: "happy", 2: "cool" , 3: "angry" } ) ]


if __name__=="__main__":
    scapy.bind_layers(scapy.TCP, Disney, sport=59000)
    scapy.bind_layers(scapy.TCP, Disney, dport=59000)

    p = scapy.IP(dst="192.144.133.122") / scapy.TCP(sport=59000, dport=59000) / Disney()
    scapy.wrpcap('./test.pcap', p)

    s = scapy.rdpcap('./test.pcap')
    print("构造的报文：")
    print('——' * 20)
    scapy.ls(p)

    print("读入的报文：")
    print('——' * 20)
    scapy.ls(s[0])