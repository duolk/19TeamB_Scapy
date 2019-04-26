# -*-coding:utf-8-*-
import scapy.all as scapy
import os
import copy
import operator


def log(level, message, verbose):
    """打印运行时需要输出到控制台的信息

    接受信息的类型、内容和系统的信息显示级别，打印格式化的信息

    Args:
        level: 0代表error，1代表info
        message: 信息正文
        verbose: 信息显示级别，0为不显示，1为只显示error，2为全显示

    """
    if verbose == 0:
        return
    elif verbose == 1:
        if level == 0:
            print("[ERROR] " + message)
    else:
        print("[INFO] " + message)


class PacketSession:
    """报文会话类

    由四元组（源ip，目的ip，源port，目的port）划分的会话类，
    包含会话报文数据、时间信息、存储信息

    Attributes:
        session_count: 会话个数计数器
        start_time: 会话创建时间
        last_time: 会话最后活动时间
        time_window: 会话切分时间阈值
        data: 会话报文数据
        append: 会话追加存储标志
        _filename: 存储路径格式化字符串
    """

    session_count = 0

    def __init__(self, start_time, packet, time_window, dst_dir, prefix, key):
        self.start_time = start_time
        self.last_time = start_time
        self.time_window = time_window
        self.data = scapy.PacketList()
        self.data.append(packet)
        self.append = False

        _f = key + "_{stime}.pcap" \
            if prefix is None else prefix + "_{stime}.pcap"
        self._filename = os.path.join(dst_dir, _f)

    def update(self, time, packet, mode):
        """使用符合该会话四元组的一条报文更新该会话

        该报文若在此会话中，更新会话信息，否则存储旧会话，并以此创建新会话

        Attributes:
            time: 该条报文的时间
            packet: 该条报文数据对象
            mode: 会话切分模式，True表示固定时间窗，False表示最大时间间隔切分
        """
        if mode is True:  # Fixed time window
            base_time = self.start_time
        else:
            base_time = self.last_time

        if time - base_time < self.time_window:
            self.data.append(packet)
            self.last_time = time
        else:
            self.save()
            self.start_time = time
            self.last_time = time
            self.data.append(packet)

    def scan(self, time, mode):
        """使用一条时间信息更新该会话

        若该时间信息可截断会话，存储旧会话

        Attributes:
            time: 某条报文时间
            mode: 会话切分模式，True表示固定时间窗，False表示最大时间间隔切分

        Returns:
            若截断了会话，返回True，其他返回False
        """
        if mode is True:  # Fixed time window
            base_time = self.start_time
        else:
            base_time = self.last_time

        if time - base_time >= self.time_window:
            self.save()
            return True
        elif len(self.data) > 5000:
            self.save(plus=False)
        return False

    def save(self, plus=True):
        """存储该会话

        Attributes:
            plus: 若为True，则会话存储为追加模式
        """
        scapy.wrpcap(self._filename.format(stime=str(self.start_time)), self.data, append=self.append)
        self.data.clear()
        if(plus):
            PacketSession.session_count += 1
            self.append = False
        else:
            self.append = True


class SessionExtractor:
    """会话提取类

    从指定文件中提取由四元组（源ip，目的ip，源port，目的port）划分的会话类，
    并分别存储至指定文件夹

    Attributes:
        session_dict: 会话字典 <会话ID, PacketSession>
        packets: 单批次报文数据
    """
    def __init__(self):
        self.session_dict = {}
        self.packets = None

    @staticmethod
    def get_key(ipsrc, ipdst, portsrc, portdst):
        str1 = ipsrc + "_" + portsrc
        str2 = ipdst + "_" + portdst
        if (operator.lt(str1, str2) == True):
            return str1 + "_" + str2
        else:
            return str2 + "_" + str1

    def run(self, src_path, dst_dir, batch_size=1000, prefix=None, tetrad=None, time_window=300, mode=True, verbose=1):
        """从源文件进行会话提取

        分批读取报文数据，提取会话，并进行存储

        Attributes:
            src_path: 源文件路径
            dst_dir: 存储文件目录
            batch_size: 分批读入报文个数，缺省1000
            prefix: 存储文件前缀，缺省为None
            tetrad: 四元组过滤器，缺省为None，格式为（源ip，目的ip，源port，目的port）
            time_window: 会话切分时间阈值，缺省为300, 单位为秒
            mode: 会话切分模式，True表示固定时间窗，False表示最大时间间隔切分，缺省为True
            verbose: 信息显示级别，缺省为1

        Returns:
            成功提取并存储的会话个数
        """
        if not os.path.isdir(dst_dir):
            log(0, "destination directory not exists!", verbose)
            return -1

        self.session_dict = {}
        self.packets = None
        PacketSession.session_count = 0

        pr = scapy.PcapReader(src_path)
        i = 0
        while True:
            i += 1
            self.packets = pr.read_all(batch_size)
            count = len(self.packets)
            if count == 0:
                break
            self.session_extract(dst_dir, prefix, tetrad, time_window, mode, verbose)
            log(1, "batch "+str(i)+" finished!", 2)

        for (key, value) in self.session_dict.items():
            value.save()

        return PacketSession.session_count

    def session_extract(self, dstdir, prefix, tetrad, timewindow, mode, verbose):
        """由单批次报文构造会话字典

        Attributes:
            dstdir: 存储文件目录
            prefix: 存储文件前缀
            tetrad: 四元组过滤器，格式为（源ip，目的ip，源port，目的port）
            time_window: 会话切分时间阈值 单位为秒
            mode: 会话切分模式，True表示固定时间窗，False表示最大时间间隔切分
            verbose: 信息显示级别
        """
        last_time = 0
        for packet in self.packets:
            if (packet.name != "Ethernet"):
                log(1, "Not ethernet packet!", verbose)
                continue

            layer2_packet = packet.payload
            if (layer2_packet.name != "IP"):
                log(1, "Not IP packet!", verbose)
                continue

            stime = packet.time
            last_time = stime
            ipsrc = layer2_packet.src
            ipdst = layer2_packet.dst

            if (tetrad != None and
                    TetradJudge.judge_ip_tetrad((ipsrc, ipdst), tetrad[0:2])):
                log(1, "Not the specific tetrad!", verbose)
                continue

            layer3_packet = layer2_packet.payload
            if not (hasattr(layer3_packet, "sport") and hasattr(layer3_packet, "dport")):
                log(1, "packet contains no port message!", verbose)
                continue

            portsrc = str(layer3_packet.sport)
            portdst = str(layer2_packet.dport)

            if (tetrad != None and
                    TetradJudge.judge_tetrad((ipsrc, ipdst, portsrc, portdst), tetrad)):
                log(1, "Not the specific tetrad!", verbose)
                continue


            key = SessionExtractor.get_key(ipsrc, ipdst, portsrc, portdst)

            if key not in self.session_dict:
                self.session_dict[key] = PacketSession(stime, packet, timewindow, dstdir, prefix, key)
            else:
                self.session_dict[key].update(stime, packet, mode)

        del_key_list = []
        for (key, value) in self.session_dict.items():
            if value.scan(last_time, mode) is True:
                del_key_list.append(key)

        for key in del_key_list:
            del self.session_dict[key]


class TetradJudge:

    @staticmethod
    def judge_ip_tetrad(packet_tetrad, tetrad):
        """判断ip对是否符合指定四元组过滤器

        Attributes:
            packet_tetrad: 元组，ip对 (ipsrc, ipdst)
            tetrad: 元组，四元组过滤器中的ip对 (ipsrc, ipdst)

        Returns:
            符合返回True，否则返回False
        """
        s = tetrad.count(None)
        if(s == 0):
            return TetradJudge._judge_ip_tetrad(packet_tetrad, tetrad)
        elif(s == 1):
            return (TetradJudge._judge_ip_tetrad((packet_tetrad[0], None), tetrad)
                    and TetradJudge._judge_ip_tetrad((packet_tetrad[1], None), tetrad))
        else:
            return False

    @staticmethod
    def _judge_ip_tetrad(packet_tetrad, tetrad):

        if(packet_tetrad[0] not in tetrad):
            return True
        if(packet_tetrad[1] not in tetrad):
            return True
        return False

    @staticmethod
    def judge_tetrad(packet_tetrad, tetrad):
        """判断四元组是否符合指定四元组过滤器

        Attributes:
            packet_tetrad: 元组，报文四元组 (ipsrc, ipdst, portsrc, portdst)
            tetrad: 元组，四元组过滤器 (ipsrc, ipdst, portsrc, portdst)

        Returns:
            符合返回True，否则返回False
        """
        s = tetrad.count(None)
        if (s == 0):
            return TetradJudge._judge_tetrad(packet_tetrad, tetrad)

        (replaced1, replaced2) = TetradJudge.replace_tetrad(packet_tetrad, tetrad)
        return TetradJudge._judge_tetrad(packet_tetrad, replaced1) and TetradJudge._judge_tetrad(packet_tetrad, replaced2)

    @staticmethod
    def replace_tetrad(packet_tetrad, tetrad):
        list1 = list(tetrad)
        list2 = copy.deepcopy(list1)
        if(tetrad[0] is None):
            list1[0] = packet_tetrad[0]
            list2[0] = packet_tetrad[1]
        if (tetrad[1] is None):
            list1[1] = packet_tetrad[1]
            list2[1] = packet_tetrad[0]
        if (tetrad[2] is None):
            list1[2] = packet_tetrad[2]
            list2[2] = packet_tetrad[3]
        if (tetrad[3] is None):
            list1[3] = packet_tetrad[3]
            list2[3] = packet_tetrad[2]

        return (tuple(list1), tuple(list2))

    @staticmethod
    def _judge_tetrad(packet_tetrad, tetrad):
        if(operator.eq(packet_tetrad, tetrad) == True):
            return False

        recombine_tetrad = (tetrad[1],tetrad[0],tetrad[3],tetrad[2])
        if (operator.eq(packet_tetrad, recombine_tetrad) == True):
            return False
        return True


if __name__ == "__main__":
    # # , tetrad = ("10.2.2.83", "47.95.42.129", "2563", "443")

    se = SessionExtractor()
    session_num = se.run("E:/5.pcap", "E:/session_extract/",
                         tetrad=(None,None,None,"443"), batch_size=2000, mode=False, verbose=1)

    if(session_num > 0):
        print("[INFO] " + str(session_num), "sessions detected and successfully saved!")
    elif(session_num == 0):
        print("[INFO] no session detected.")

