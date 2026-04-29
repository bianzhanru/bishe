import socket
import time
import random

class StatefulFuzzer:
    """核心模糊测试引擎：负责按照状态机与靶场交互，并发送变异数据"""

    def __init__(self, target_ip="127.0.0.1", target_port=1883):
        self.target_ip = target_ip
        self.target_port = target_port 
        
        # [新增核心功能]：危险载荷字典 (Bad Strings & Boundary Values)
        # 这些正是你在中期检查表中承诺要引入的“多维度安全测试算子”
        self.mutation_dict = [
            b"%s%p%x%n",                 # 危险格式化字符串注入 (泄露内存/崩溃)
            b"A" * 1024,                 # 缓冲区溢出 (超长边界值)
            b"\x00",                     # 空字符截断 (逻辑绕过)
            b"\xff\xff\xff\xff",         # 整数溢出边界极限值
            b"admin' OR 1=1--",          # 经典的 SQL/逻辑 注入变形
            b"../../../../etc/passwd",   # 路径穿越测试
            b'{"cmd": "rm -rf /"}'       # 简单的命令注入探测
        ]

    def _mutate_data(self, hex_data: str) -> bytes:
        """多维数据变异器：引入了边界值注入、危险字典和随机翻转的混合策略"""
        try:
            # 去除可能混入的空格或非十六进制字符
            clean_hex = ''.join(c for c in hex_data if c in '0123456789abcdefABCDEF')
            if not clean_hex or len(clean_hex) % 2 != 0:
                return b"FALLBACK_DATA" 
                
            original_bytes = bytearray.fromhex(clean_hex)
            if not original_bytes:
                return b"FALLBACK_DATA"
            
            # [核心升级]：基于概率分布的深度变异路由
            mutation_choice = random.random()
            
            if mutation_choice < 0.3:
                # 30% 概率：危险格式化字符串与字典注入 (Bad Strings)
                bad_payload = random.choice(self.mutation_dict)
                # 随机决定是“替换载荷后半段”还是“直接追加在末尾”
                if random.random() < 0.5:
                    return bytes(original_bytes) + bad_payload
                else:
                    half_len = len(original_bytes) // 2
                    return bytes(original_bytes[:half_len]) + bad_payload
                    
            elif mutation_choice < 0.5:
                # 20% 概率：边界值注入 (Boundary Values)
                mutate_idx = random.randint(0, len(original_bytes) - 1)
                # 将随机位置的字节替换为极端的边界值
                original_bytes[mutate_idx] = random.choice([0x00, 0x7F, 0x80, 0xFF])
                return bytes(original_bytes)
                
            elif mutation_choice < 0.7:
                # 20% 概率：传统的单字节随机翻转 (Bit/Byte Flip)
                mutate_idx = random.randint(0, len(original_bytes) - 1)
                original_bytes[mutate_idx] = random.randint(0, 255)
                return bytes(original_bytes)
                
            else:
                # 30% 概率：保持原样 (为了确保前面的状态能正常跃迁，不被过早破坏)
                return bytes(original_bytes)
                
        except Exception:
            return b"ERROR_PAYLOAD" 

    def run_fuzzing(self, transitions: list):
        """执行状态制导的模糊测试流程"""
        print(f"[*] 开始向目标 {self.target_ip}:{self.target_port} 发起状态机交互...")
        
        # [新增] 建立一个空列表，用来记录给前端的“真实战报”
        fuzz_log = [] 

        try:
            # 建立与靶场的底层 TCP 连接
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((self.target_ip, self.target_port))

            # 严格按照大模型推断出的状态顺序发送数据
            for step in transitions:
                print(f"  -> 状态跃迁: {step['source_state']} => {step['target_state']}")

                raw_hex = step['trigger_message']
                mutated_payload = self._mutate_data(raw_hex)

                s.send(mutated_payload)
                print(f"     [发送成功] 载荷: {mutated_payload.hex()}")

                is_crash = False # 默认没有崩溃
                
                # 接收靶场响应，监控是否异常
                try:
                    resp = s.recv(1024)
                    if not resp:
                        is_crash = True # 真的崩溃了！
                except socket.timeout:
                    pass # 超时无响应属于正常情况，继续下一个状态
                
                # [新增] 把真实的变异载荷和崩溃结果写进日志
                fuzz_log.append({
                    "hex": mutated_payload.hex(),
                    "is_crash": is_crash,
                    "target_state": step['target_state']
                })

                if is_crash:
                    print("     [!] 警告: 靶场意外断开连接！可能触发了崩溃！")
                    break # 既然靶场崩了，就没法往下发包了，直接退出循环

                time.sleep(0.1) # 稍微停顿，控制发包频率

            s.close()
            print("[+] 本轮交互结束，靶场依然存活。")
            
            return fuzz_log # [新增] 把战报返回给 API
            
        except ConnectionRefusedError:
            print("[-] 连接失败！请检查你的仿真环境（如 Mosquitto）是否正在运行。")
            # 如果连不上，也包装成战报返回给前端
            return [{"hex": "CONNECTION_REFUSED", "is_crash": True, "target_state": "连接失败"}]
        except Exception as e:
            print(f"[!] 捕获到异常: {e}")
            # [优化] 如果之前已经发过包了，把崩溃记录追加到日志末尾，这样前端能回放整个过程
            fuzz_log.append({
                "hex": "TARGET_CRASH_OR_RESET", 
                "is_crash": True, 
                "target_state": "通信中断"
            })
            return fuzz_log
