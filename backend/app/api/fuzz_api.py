from fastapi import APIRouter
from pydantic import BaseModel
from openai import OpenAI
from app.core.pcap_parser import TrafficPreprocessor
from app.core.llm_agent import DeepSeekAgent
from app.core.state_engine import StatefulFuzzer
import os
import requests
from scapy.all import raw, Ether, IP, TCP, wrpcap
import glob

router = APIRouter()

API_KEY = "sk-397acb295df543b9a67ea0d42956233f"

# ==========================================
# Step 0: 你的特色功能 (保留不动)
# ==========================================
class ParseRequest(BaseModel):
    pcap_file: str
    
@router.post("/step0_generate_ai_seed")
async def generate_ai_seed():
    print("正在向 DeepSeek 索要恶意 MQTT 报文...")
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {API_KEY}", 
        "Content-Type": "application/json"
    }
    
    prompt = """
    你是一个网络安全专家与模糊测试工程师。
    请生成一段恶意的 MQTT 客户端字节流。要求包含以下逻辑错误：
    1. 不发送 CONNECT 报文，直接发送一个要求 QoS 2 的 PUBLISH 报文。
    2. 紧接着发送一个非法的 PUBREL 报文。
    请不要解释，不要提供代码，只输出纯十六进制字符串（Hex Stream），不要带空格和换行。
    """
    
    try:
        response_data = requests.post(url, headers=headers, json={
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7
        }).json()
        
        if 'choices' not in response_data:
            print(f"DeepSeek API 返回异常: {response_data}")
            return {"status": "error", "message": f"API调用失败，请查看后端终端日志"}
            
        hex_data = response_data['choices'][0]['message']['content'].strip()
        hex_data = ''.join(c for c in hex_data if c in '0123456789abcdefABCDEF')
        
        save_path = "ai_poisoned_logic.pcap"
        raw_bytes = bytes.fromhex(hex_data)
        packet = Ether()/IP(dst="127.0.0.1")/TCP(dport=1883, sport=54321)/raw(raw_bytes)
        wrpcap(save_path, packet)
        
        return {"status": "success", "message": "AI毒药包生成成功", "pcap_path": save_path}
    except Exception as e:
        return {"status": "error", "message": f"生成失败: {str(e)}"}

# ==========================================
# Step 1: 解析 PCAP (新增了前端字段对齐映射)
# ==========================================
class ParseBatchRequest(BaseModel):
    pcap_file: str = None 
    pcap_dir: str = "data/pcaps" 

@router.post("/step1_parse")
async def step1_parse_batch_traffic(req: ParseBatchRequest):
    try:
        all_parsed_data = []
        search_pattern = os.path.join(req.pcap_dir, "**/*.pcap")
        pcap_files = glob.glob(search_pattern, recursive=True)
        
        if not pcap_files:
            return {"status": "error", "message": f"在 {req.pcap_dir} 目录下没有找到任何 pcap 文件！"}
            
        print(f"准备清洗弹药库，共发现 {len(pcap_files)} 个数据包...")
        
        global_packet_id = 1 # 为前端界面生成全局连续的报文 ID
        
        for pcap_file in pcap_files:
            print(f" -> 正在清洗: {pcap_file}")
            try:
                parser = TrafficPreprocessor(pcap_path=pcap_file)
                file_data = parser.process() 
                
                # 【修改点】确保输出的数据能点亮前端的流水线动画
                for item in file_data:
                    # 动态适配：如果你的解析器输出没这三个字段，这里会自动兼容补齐
                    frontend_item = {
                        "packet_id": item.get("packet_id", global_packet_id),
                        "payload_length": item.get("payload_length", len(str(item.get("payload", "")))),
                        "hex_content": item.get("hex_content", str(item.get("payload", "00"))),
                        "source_pcap": os.path.basename(pcap_file)
                    }
                    frontend_item.update(item) # 保留你原本的其他字段
                    all_parsed_data.append(frontend_item)
                    global_packet_id += 1
                    
            except Exception as inner_e:
                print(f" -> 文件 {pcap_file} 解析出错，跳过: {str(inner_e)}")
                continue 
                
        print(f"所有弹药清洗完毕！共提取出 {len(all_parsed_data)} 个交互动作。")
        return {"status": "success", "data": all_parsed_data, "file_count": len(pcap_files)}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ==========================================
# Step 2: AI 推断状态机
# ==========================================
class AnalyzeRequest(BaseModel):
    traffic_data: list

@router.post("/step2_analyze")
async def step2_analyze_traffic(req: AnalyzeRequest):
    try:
        agent = DeepSeekAgent(api_key=API_KEY)
        # 前提条件：确保 ai_result.model_dump() 输出的结果里有一个 "transitions" 的列表
        ai_result = agent.analyze_traffic(req.traffic_data)
        return {"status": "success", "data": ai_result.model_dump()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ==========================================
# Step 3: 启动真实变异打靶
# ==========================================
class FuzzRequest(BaseModel):
    transitions: list
    target_ip: str = "127.0.0.1"
    target_port: int = 1883

@router.post("/step3_fuzz")
async def step3_start_fuzzing(req: FuzzRequest):
    try:
        print(f"⚡ 开始对目标 {req.target_ip}:{req.target_port} 执行打靶...")
        fuzzer = StatefulFuzzer(target_ip=req.target_ip, target_port=req.target_port)
        
        # [核心修复] 获取真实的打靶日志
        real_fuzz_log = fuzzer.run_fuzzing(req.transitions)
        
        return {
            "status": "success", 
            "message": "变异测试执行完毕",
            "fuzz_log": real_fuzz_log  # <--- 就是漏了这一行！把真实战报传给前端！
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ==========================================
# Step 4: AI 生成最终评估报告
# ==========================================
class ReportRequest(BaseModel):
    transitions: list
    fuzz_result: str

@router.post("/step4_report")
async def step4_generate_report(req: ReportRequest):
    try:
        print("正在调用大模型生成渗透测试报告，请稍候...")
        client = OpenAI(api_key=API_KEY, base_url="https://api.deepseek.com")
        
        # 提取异常状态节点，提供给大模型参考
        error_nodes = []
        for t in req.transitions:
            if any(bad_word in t['target_state'] for bad_word in ['异常', '死锁', '畸形', '攻击', '恶意', '无效', '短包', '未知', '错误', '截断', '零长度', '失败', '无状态']):
                error_nodes.append(t['target_state'])
        
        # 去重
        error_nodes = list(set(error_nodes))
        error_nodes_str = ", ".join(error_nodes) if error_nodes else "未发现明显异常状态"

        prompt = f"""
        你是一名资深的物联网(IoT)安全专家与渗透测试工程师。
        请根据以下模糊测试(Fuzzing)的数据，自动生成一份极具专业性和学术价值的《物联网 MQTT 协议安全审计报告》。
        
        【系统输入数据】
        1. AI 推断出的目标设备状态机异常节点：[{error_nodes_str}]
        2. 测试引擎执行战报：{req.fuzz_result}
        3. 状态转移数据参考：{req.transitions}
        
        【报告结构要求】
        请使用 Markdown 格式输出，内容必须包含以下 5 个核心部分：
        
        # 物联网状态敏感模糊测试评估报告
        
        ## 1. 审计概况
        (基于输入数据简述测试的目标、协议类型以及最终的存活状态或崩溃情况)
        
        ## 2. 状态机逆向与漏洞发现
        (分析系统发现的异常状态节点，例如：为什么“截断的CONNECT”或“畸形长度”等会导致状态异常。结合物联网安全背景进行技术分析)
        
        ## 3. 风险评估与 CVSS 预估
        (根据发现的异常节点，假设其被黑客利用，给出预估的 CVSS v3.1 评分，例如网络级拒绝服务攻击可评 7.5 分，并说明理由)
        
        ## 4. 攻击复现路径推演
        (基于输入的状态转移数据，推演出一条可能导致崩溃的恶意交互序列，比如从'未连接'如何一步步走到'异常状态')
        
        ## 5. 修复与防御建议
        (给出针对底层 C/C++ MQTT 解析器的修复建议，比如加强边界检查、引入状态超时机制等)
        
        【格式限制】
        必须直接输出报告正文，不要输出任何前言、后记、或者“好的，我已经生成”之类的废话。用词必须高度专业、严谨。
        """
        
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7 # 适当增加一点创造性，让报告看起来更真实
        )
        
        report_content = response.choices[0].message.content
        print("报告生成完毕！")
        return {"status": "success", "report": report_content}
        
    except Exception as e:
        print(f"报告生成失败: {str(e)}")
        return {"status": "error", "message": str(e)}
