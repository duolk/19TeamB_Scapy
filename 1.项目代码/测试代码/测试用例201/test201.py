# -*-coding:utf-8-*-
import scapy.all as scapy
packets = scapy.PacketList()

def sniff():
    ps = scapy.sniff(count=10)
    print("从网卡捕获了10条报文：")
    print("——" * 20)
    ps.show()
    print("——" * 20)


def create():
    print("构造了2条报文：")
    a = scapy.Ether()/scapy.IP(dst="www.slashdot.org")/scapy.TCP()/"GET /index.html HTTP/1.0 \n\n"
    b = scapy.IP(ttl=10, dst="www.buaa.edu.cn")
    packets.append(a)
    packets.append(b)

    packets.show()


def export():
    print("导出了2条报文：./export.pcap")
    scapy.wrpcap('./export.pcap', packets)


def parse():
    global packets
    print("导入并解析了2条报文：./export.pcap")
    packets = scapy.rdpcap('./export.pcap')


def display():
    print("可视化一条报文：")
    scapy.hexdump(packets[0])
    scapy.ls(packets[0])


def send():
    scapy.send(scapy.IP(dst="1.2.3.4") / scapy.ICMP())
    scapy.sendp(scapy.Ether() / scapy.IP(dst="1.2.3.4", ttl=(1, 4)))


if __name__=="__main__":

    print("=" * 20, "《端口监听功能》", "=" * 20)
    sniff()

    print("=" * 20, "《数据构造功能》", "=" * 20)
    create()

    print("=" * 20, "《数据导出功能》", "=" * 20)
    export()

    print("=" * 20, "《数据导入解析》", "=" * 20)
    parse()

    print("=" * 20, "《数据展示功能》", "=" * 20)
    display()

    print("=" * 20, "《数据发送功能》", "=" * 20)
    send()
