# IoT LLM Fuzzer

**基于大语言模型的物联网状态敏感模糊测试系统设计与实现** *(Design and Implementation of an IoT State-Sensitive Fuzzing System Based on Large Language Models)*

## 📌 项目简介

本项目为网络空间安全专业的毕业设计项目。

系统旨在利用大语言模型（LLM，如 DeepSeek）的上下文推理与代码理解能力，针对物联网（IoT）设备协议（如 MQTT 等）进行状态敏感的自动化模糊测试（Fuzzing）。通过动态推断设备通信状态、自动生成高覆盖率的测试种子（Seed Generation），以及深度解析协议交互流量（Auto Sniffer），实现对复杂物联网设备的深度漏洞自动化挖掘。

**开发者**: 卞展如

---

## 🏗️ 系统架构

本项目采用前后端分离的架构设计，核心组件如下：

### 1. 核心后端 (`backend/`)
基于 **FastAPI** 构建的 Fuzzing 核心控制引擎与调度中心。
- **`llm_agent.py`**: 负责与大语言模型（DeepSeek）接口进行交互，利用 Prompt 工程引导 LLM 进行状态推理与测试用例变异。
- **`state_engine.py`**: 状态机引擎，用于维护和推断目标 IoT 设备的当前协议交互状态及状态转移逻辑。
- **`seed_generator.py`**: 测试种子生成器，结合大模型输出的策略，生成具有针对性的畸形数据包。
- **`auto_sniffer.py` & `pcap_parser.py`**: 流量自动化捕获与 PCAP 包解析模块，用于分析目标设备的响应反馈，指导后续 Fuzzing 策略。
- **`fuzz_api.py`**: 对外暴露的 RESTful API 接口，用于控制和下发测试任务。

### 2. 可视化前端 (`frontend/`)
采用 **Vue 3 + Vite** 构建的前端可视化控制台。
- 实时展示 Fuzzing 进度与发包速率。
- 动态绘制 IoT 设备的状态转移图。
- 汇总并高亮显示发现的潜在漏洞与崩溃日志（Crash Logs）。

---

## 🚀 环境配置与运行指南

### 预备环境
- **Python**: 3.8 或更高版本
- **Node.js**: 16.x 或更高版本 (用于前端)
- **Git**: 版本控制

### 🛠️ 后端配置 (Backend)

1. **进入后端目录并创建虚拟环境**:
   ```bash
   cd backend
   python -m venv .venv
   ```

2. **激活虚拟环境**:
   - Windows: `.venv\Scripts\activate`
   - Linux/macOS: `source .venv/bin/activate`

3. **安装项目依赖**:
   ```bash
   pip install -r requirements.txt
   ```

4. **配置环境变量**:
   在 `backend` 目录下创建一个名为 `.env` 的文件，填入你的 LLM API 密钥（系统将自动安全读取，避免硬编码）：
   ```ini
   DEEPSEEK_API_KEY=your_api_key_here
   ```

5. **启动后端服务**:
   ```bash
   uvicorn app.main:app --reload
   ```
   *服务默认运行在 `http://127.0.0.1:8000`*

### 🎨 前端配置 (Frontend)

1. **进入前端目录并安装依赖**:
   ```bash
   cd frontend
   npm install
   ```

2. **启动前端开发服务器**:
   ```bash
   npm run dev
   ```
   *启动后，可在浏览器中访问控制台面板（通常为 `http://localhost:5173`）*

---

## ⚠️ 安全与免责声明 (Disclaimer)

1. **合规警告**：本工具的设计初衷仅限用于学术研究与**经明确授权**的设备安全测试。请勿将本项目用于任何对未经授权的生产环境或第三方设备的恶意攻击。
2. **隐私保护**：本项目已严格配置 `.gitignore`。开发者在进行本地测试及协同开发时，**切勿**将带有真实网络配置或凭据的 `.pcap` 抓包文件、包含个人隐私的 `.env` 密钥文件，以及未授权的商业闭源二进制固件上传至公开的代码仓库。
3. **责任限制**：因使用本工具带来的任何直接或间接的损害与法律责任，概由使用者自行承担。
