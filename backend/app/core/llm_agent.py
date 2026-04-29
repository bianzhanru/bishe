
import json

from openai import OpenAI

from app.schemas.llm_schema import LLMOutputTemplate



class DeepSeekAgent:

    """负责与 DeepSeek 大模型进行对话，并强制其输出标准化数据"""

    

    def __init__(self, api_key: str):

        # 初始化与 DeepSeek 的网络连接，使用的是兼容的 OpenAI 工具包

        self.client = OpenAI(

            api_key="sk-397acb295df543b9a67ea0d42956233f",

            base_url="https://api.deepseek.com" # DeepSeek 的官方接口地址

        )



    def analyze_traffic(self, traffic_data: list) -> LLMOutputTemplate:

        """将流量发给大模型分析，并校验返回的格式"""

        

        # 1. 给大模型下达的死命令（系统提示词），附带了我们上一步做的 JSON 模板要求

        system_prompt = (
   	 "你是一名顶尖的物联网安全专家与协议逆向工程师。\n"
   	 "请根据提供的海量混合流量，构建一张专业、清晰、语义化的【全局网状协议安全拓扑图】。\n"
   	"【最高优先级指令】：\n"
    	"1. 独立异常：必须为所有畸变、非法、死锁流量创建独立的【异常】节点，并将其作为分支锚定在对应的合法状态上。\n"
   	 "2. 语义化连线：严禁在 `trigger_message` 中直接输出原始的 Hex 数据！你必须将其‘翻译’为人类可读的协议动作（例如：'正常 CONNECT', '异常-截断的 PUBLISH', '恶意 HACK 协议标识'）。\n"
    	"3. 拓扑优化：以‘已连接’为中心辐射源，清晰展现功能模块分支（鉴权链、消息链、异常控制链），确保主干挺拔，分支繁茂。\n"
    	"4.请深度挖掘 已连接 之后的所有交互。如果在订阅（SUBSCRIBE）或发布（PUBLISH）动作后出现了非预期的报文回复或 TCP 行为，严禁直接连接到‘断开’，必须根据报文特征建立如‘异常-订阅越权’、‘异常-载荷解析崩溃’等深层节点。\n"
   	 "严格按照 JSON 格式返回结果。"
    	f"\n格式要求:\n{LLMOutputTemplate.model_json_schema()}"
	)            

        # 2. 把清洗好的流量数据转成文字（这里做了截断，防止数据太大撑爆大模型）

        traffic_text = json.dumps(traffic_data, ensure_ascii=False)[:3000]

        user_prompt = f"以下是清洗后的设备流量数据：\n{traffic_text}"



        # 3. 正式向 DeepSeek 发起请求

        response = self.client.chat.completions.create(

            model="deepseek-chat",

            messages=[

                {"role": "system", "content": system_prompt},

                {"role": "user", "content": user_prompt}

            ],

            response_format={"type": "json_object"} # 强制要求模型只返回 JSON 格式

        )

        

        # 4. 拿到答卷，并用我们的模板 Pydantic 进行最后质检

        raw_json_str = response.choices[0].message.content

        

        # 如果大模型填写的格式完全正确，这里会成功转换；如果有错，会自动报错拦截

        validated_result = LLMOutputTemplate.model_validate_json(raw_json_str)

        return validated_result



