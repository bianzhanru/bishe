# IoT LLM Fuzzer

**基于大语言模型的物联网状态敏感模糊测试系统设计与实现** (Design and Implementation of an IoT State-Sensitive Fuzzing System Based on Large Language Models)

## 📌 项目简介

本项目为北京邮电大学网络空间安全专业的毕业设计项目。
系统旨在利用大语言模型（LLM，如 DeepSeek）的上下文推理能力，针对物联网（IoT）设备协议（例如 MQTT）进行状态敏感的模糊测试（Fuzzing）。通过动态推断设备通信状态、自动生成高覆盖率的测试种子（Seed Generation），以及深度解析协议交互流量（Auto Sniffer），实现对复杂物联网设备的深度漏洞自动化挖掘。

**开发者**: 卞展汝

## 🏗️ 系统架构

本项目采用前后端分离的架构：

- **`backend/`**: 基于 FastAPI 构建的核心模糊测试引擎。
  - `llm_agent.py`: 负责与大语言模型接口进行交互，利用 Prompt 工程引导 LLM 进行状态推理与测试用例变异。
  - `state_engine.py`: 状态机引擎，用于维护和推断 IoT 设备的当前协议交互状态。
  - `seed_generator.py`: 测试种子生成器，结合大模型输出生成具有针对性的畸形数据包。
  - `auto_sniffer.py` & `pcap_parser.py`: 流量捕获与 PCAP 解析模块，用于分析目标设备反馈，指导后续 Fuzzing 策略。
  - `fuzz_api.py`: 提供控制测试流程的 RESTful API。
  
- **`frontend/`**: 采用 Vue 3 + Vite 构建的前端可视化控制台，用于实时展示 Fuzzing 进度、状态转移图以及发现的崩溃日志。

## 🚀 环境配置与运行

### 后端 (Backend)
建议使用 Python 3.8+ 并配置虚拟环境：

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows 下使用 .venv\Scripts\activate
pip install -r requirements.txt
