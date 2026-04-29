# backend/app/core/seed_generator.py
import os
import httpx  # FastAPI 推荐用异步 httpx 代替 requests
from scapy.all import raw, Ether, IP, TCP, wrpcap

class AISeedService:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.api_url = "https://api.deepseek.com/v1/chat/completions"

    async def generate_poison_pcap(self, save_path: str):
        prompt = """
        你是一个网络安全专家。请生成一段恶意的 MQTT 字节流（十六进制）。
        要求：不发送 CONNECT 直接发送 QoS 2 的 PUBLISH，且包含非法的 PUBREL。
        只需输出纯十六进制字符串，不要任何解释。
        """
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.api_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": "deepseek-chat",
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=60.0
            )
            result = response.json()
            hex_stream = result['choices'][0]['message']['content'].strip()
            # 简单清洗 Hex
            hex_stream = ''.join(c for c in hex_stream if c in '0123456789abcdefABCDEF')
            
            # 使用 Scapy 封装
            raw_bytes = bytes.fromhex(hex_stream)
            packet = Ether()/IP(dst="127.0.0.1")/TCP(dport=1883)/raw(raw_bytes)
            wrpcap(save_path, packet)
            return save_path
