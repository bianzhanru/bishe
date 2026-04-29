import hashlib
from scapy.all import rdpcap, TCP, UDP, Raw

class TrafficPreprocessor:
    """负责将抓包文件清洗并转换为大模型易读的格式"""
    def __init__(self, pcap_path: str, target_port: int = 1883):
        self.pcap_path = pcap_path
        self.target_port = target_port # 目标设备的端口，Mosquitto默认是1883
        self.seen_payloads = set()     # 用于记录数据包的指纹，避免处理重复数据

    def process(self):
        """执行清洗并返回结构化数据列表"""
        packets = rdpcap(self.pcap_path)
        result = []

        for idx, pkt in enumerate(packets):
            # 只处理包含实际传输层的包
            if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                continue
            
            # 提取最核心的应用层真实数据
            if not pkt.haslayer(Raw):
                continue
            payload = pkt[Raw].load

            # 生成数据包的“指纹”进行去重
            payload_hash = hashlib.md5(payload).hexdigest()
            if payload_hash in self.seen_payloads:
                continue
            self.seen_payloads.add(payload_hash)

            # 将二进制数据转换为十六进制和文本，这是为了大模型能看懂
            hex_data = payload.hex()
            try:
                # 尝试将数据解码为普通文字，无法显示的字符替换为点
                text_data = payload.decode('utf-8', errors='ignore').replace('\x00', '.')
            except:
                text_data = "无法解码"

            # 整理成字典格式存入列表
            result.append({
                "packet_id": idx,
                "payload_length": len(payload),
                "hex_content": hex_data,
                "text_content": text_data
            })

        return result
