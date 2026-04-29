from pydantic import BaseModel, Field
from typing import List

class StateTransition(BaseModel):
    """定义状态机流转的格式"""
    source_state: str = Field(description="当前的设备状态，例如 '未连接'")
    target_state: str = Field(description="触发后的状态，例如 '已连接'")
    trigger_message: str = Field(description="触发这个状态变化需要发送什么数据包")

class ProtocolField(BaseModel):
    """定义协议字段规则的格式"""
    field_name: str = Field(description="字段名称，例如 '消息类型(Message Type)'")
    is_required: bool = Field(description="这个字段是不是每次发送都必须要有")
    format_rule: str = Field(description="字段的格式要求，例如 '必须是1个字节的整数'")

class LLMOutputTemplate(BaseModel):
    """DeepSeek 最终必须交出的总答卷格式"""
    transitions: List[StateTransition] = Field(description="推断出的设备状态机图谱")
    protocol_fields: List[ProtocolField] = Field(description="提取出的关键协议字段规则")
