import os
from scapy.all import sniff, wrpcap

class TrafficSniffer:
    """自动化流量嗅探器：负责静默抓取靶场交互流量并落盘"""
    
    def __init__(self, interface="lo", port=1883, save_path="../workspace/pcaps/auto_capture.pcap"):
        self.interface = interface  # 监听的网卡，本地靶场通常是 'lo' (loopback)
        self.port = port            # 监听的端口，MQTT默认1883
        self.save_path = save_path  # 抓包后的保存路径

    def capture_traffic(self, packet_count=20, timeout=30) -> str:
        """
        执行抓包任务。
        packet_count: 抓满多少个包就停止
        timeout: 最多监听多少秒（防止死等）
        """
        print(f"[*] 雷达开启：正在网卡 {self.interface} 监听端口 {self.port} 的数据流...")
        
        # BPF 过滤规则：只抓 TCP 协议且端口对应的包
        bpf_filter = f"tcp port {self.port}"
        
        # 核心抓包动作
        packets = sniff(iface=self.interface, filter=bpf_filter, count=packet_count, timeout=timeout)
        
        if len(packets) == 0:
            raise Exception(f"监听 {timeout} 秒后未捕获到任何数据，请确认目标设备正在通信。")
            
        print(f"[+] 捕获完成！共抓取 {len(packets)} 个交互包。")
        
        # 确保存放抓包文件的文件夹存在
        os.makedirs(os.path.dirname(self.save_path), exist_ok=True)
        # 将内存中的包物理写入 pcap 文件
        wrpcap(self.save_path, packets)
        print(f"[+] 文件已保存至：{self.save_path}")
        
        return self.save_path
