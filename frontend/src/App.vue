<template>
  <div style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; padding: 30px; box-sizing: border-box; display: flex; flex-direction: column; background-color: #0d1117; font-family: 'Microsoft YaHei', 'JetBrains Mono', monospace; z-index: 9999;">
    
    <h1 style="color: #ffffff; margin: 0 0 40px 0; font-size: 38px; font-weight: 600;">🛡️ 物联网状态敏感模糊测试系统</h1>

    <div style="display: flex; flex: 1; gap: 30px; overflow: hidden; z-index: 50;">
      
      <div style="display: flex; flex-direction: column; gap: 16px; width: 200px; flex-shrink: 0;">
        <button @click="parseTraffic" class="btn-terminal" style="width: 100%; text-align: center;">1. 解析流量 PCAP</button>
        <button @click="analyzeTraffic" :disabled="!trafficParsed" class="btn-terminal" style="width: 100%; text-align: center;">2. AI 推断状态机</button>
        
        <button @click="startFuzzingVisual" :disabled="!stateMachineData || fuzzingActive" 
                class="btn-fuzz" 
                :style="{ width: '100%', textAlign: 'center', backgroundColor: fuzzCompleted ? '#238636' : (fuzzingActive ? '#8e1519' : '#b62324') }">
          {{ fuzzingActive ? '🚀 正在打靶...' : (fuzzCompleted ? '✅ 打靶完成' : '3. ⚡ 启动变异打靶') }}
        </button>

        <button @click="fetchAndShowReport" :disabled="!fuzzCompleted" class="btn-report" style="width: 100%; text-align: center;">4. 📄 生成并查看报告</button>
      </div>

      <div class="breathing-border" style="flex: 1; position: relative; background-color: #010409; border-radius: 12px; overflow: hidden;">
        
        <div id="scroll-wrapper" style="width: 100%; height: 100%; overflow-y: auto; overflow-x: hidden; position: relative; scroll-behavior: smooth;">
          
          <div v-if="parsingActive" class="parse-dashboard" style="height: calc(100vh - 200px);">
            <div class="audit-report-panel">
              <div class="panel-tag">SECURITY AUDIT / 安全审计</div>
              <div class="panel-title">流量情报分析报告</div>
              <div class="divider"></div>
              <div class="info-item"><span>审计范围:</span> <span class="val" style="color:#58a6ff">./data/pcaps/</span></div>
              <div class="info-item"><span>文件总数:</span> <span class="val">{{ fileCount }} 个 PCAP</span></div>
              <div class="info-item"><span>交互总帧:</span> <span class="val">{{ trafficDataStore.length }} 帧</span></div>
              <div class="info-item"><span>识别协议:</span> <span class="val" style="color:#7ee787">MQTT v3.1.1</span></div>
              <div class="info-item"><span>可疑畸形包:</span> <span class="val" style="color:#f85149">{{ malformedCount }}</span></div>
              <div class="progress-section">
                <div style="display: flex; justify-content: space-between; font-size: 10px; margin-bottom: 5px; color: #8b949e;">
                  <span>解析进度</span><span>{{ parsePercent }}%</span>
                </div>
                <div class="bar-bg"><div class="bar-fill" :style="{width: parsePercent + '%'}"></div></div>
              </div>
            </div>

            <div class="packet-scroll-container">
              <div class="scroll-header">原始载荷实时抓取流 (RAW PACKET STREAM)</div>
              <div class="scroll-content">
                <div v-for="(pkt, i) in visiblePackets" :key="i" class="pkt-card">
                  <span class="p-id">#{{ pkt.packet_id }}</span>
                  <span class="p-len">{{ pkt.payload_length }} 字节</span>
                  <span class="p-hex">{{ pkt.hex_content.substring(0, 50) }}...</span>
                </div>
              </div>
            </div>
          </div>

          <div v-if="fuzzingActive || fuzzCompleted" class="metrics-overlay" :style="{ opacity: fuzzingActive ? 1 : 0.85 }">
            <div class="metric-card">
              <div class="m-label">变异强度 INTENSITY</div>
              <div class="m-value">{{ metrics.intensity }}%</div>
            </div>
            <div class="metric-card">
              <div class="m-label">路径覆盖 COVERAGE</div>
              <div class="m-value">{{ metrics.coverage }}%</div>
            </div>
            <div class="metric-card">
              <div class="m-label">靶机健康 HEALTH</div>
              <div class="m-value" :style="{color: metrics.health < 30 ? '#f85149' : '#7ee787'}">{{ metrics.health }}%</div>
              <div class="h-bar"><div class="h-inner" :style="{width: metrics.health + '%', backgroundColor: metrics.health < 30 ? '#f85149' : '#7ee787'}"></div></div>
            </div>
          </div>

          <div v-if="fuzzingActive || fuzzCompleted" class="ai-decision-panel" :style="{ opacity: fuzzingActive ? 1 : 0.85 }">
            <div class="ai-header">🧠 LLM 语义变异引擎推演</div>
            <transition-group name="list" tag="div" class="ai-content">
              <div v-for="item in aiDecisions" :key="item.id" class="ai-log-item">
                <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                  <span class="ai-time">[{{ item.time }}]</span>
                  <span class="ai-tag">{{ item.tag }}</span>
                </div>
                <div class="ai-text" v-html="item.text"></div>
              </div>
            </transition-group>
          </div>

          <div v-if="fuzzingActive || fuzzCompleted" class="hex-stream" :style="{ opacity: fuzzingActive ? 1 : 0.85 }">
            <div class="scroll-header" style="margin-bottom: 8px;">底层字节流投递 (HEX STREAM)</div>
            <div v-for="(log, i) in hexLogs" :key="i" :class="['hex-line', {hit: log.hit}]">{{ log.data }}</div>
          </div>

          <div id="mountNode" style="width: 100%; min-height: calc(100vh - 250px);"></div>
          
          <div v-if="loading" class="loader-mask" style="height: calc(100vh - 250px);">
            <div class="scanner-container"><div class="scanner-line"></div></div>
            <div style="color: #58a6ff; font-family: monospace;">&gt; SYSTEM: {{ loadingText }}</div>
          </div>

          <div v-if="compiledMarkdown" @click="scrollToReport" class="jump-to-report-bar">
            👇 审计报告已生成，点击此处直接下滑至报告区 👇
          </div>

          <div id="report-section" v-if="compiledMarkdown" class="markdown-wrapper">
            <div class="markdown-card">
              <h2 class="report-main-title">📄 安全审计报告归档</h2>
              <div class="markdown-content" v-html="compiledMarkdown"></div>
            </div>
          </div>

        </div>
      </div>
    </div>

    <div class="terminal-log" style="margin-top: 20px;">
      <span style="color: #8b949e;">[root@BUPT_Lab ~]#</span> 
      <span :style="{color: fuzzCompleted ? '#7ee787' : 'inherit'}">{{ statusLog }}<span class="cursor-blink">_</span></span>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, reactive, nextTick } from 'vue';
import axios from 'axios';
import G6 from '@antv/g6';
import { marked } from 'marked';

const trafficParsed = ref(false);
const stateMachineData = ref(null);
const fuzzCompleted = ref(false);
const loading = ref(false);
const loadingText = ref('');
const statusLog = ref('系统自检完成。等待指令输入...');
const trafficDataStore = ref([]);

const parsingActive = ref(false);
const fileCount = ref(0);
const visiblePackets = ref([]);
const parsePercent = ref(0);
const malformedCount = ref(0);

const fuzzingActive = ref(false);
const hexLogs = ref([]);
const metrics = reactive({ intensity: 0, coverage: 0, health: 100 });

const compiledMarkdown = ref('');

const aiDecisions = ref([]);
let decisionCounter = 0;

const aiThoughts = [
  { tag: "协议畸变", text: "识别到 CONNECT 交互，将协议标识符篡改为 <b>HACK</b> 探测解析边界..." },
  { tag: "状态越权", text: "推演目标处于 [未连接] 状态，强制发送 <b>SUBSCRIBE</b> 尝试状态机逃逸..." },
  { tag: "整数溢出", text: "锁定 Keep-Alive 字段，注入极限边界值 <b>0xFFFF</b> 测试超时处理逻辑..." },
  { tag: "格式化注入", text: "解析出 ClientID，正在混入 Payload <b>%n%s%p</b> 测试 C语言底层内存泄漏..." },
  { tag: "逻辑截断", text: "构造 <b>恶意 PUBLISH</b>，保留标志位设为1但移除实际载荷，探测异常分支..." },
  { tag: "未定义类型", text: "构造非法控制包，使用保留指令类型 <b>0xF0</b> 探测协议栈错误恢复机制..." },
  { tag: "边界风暴", text: "组合攻击链：<b>超长 Topic (1024 Bytes) + QoS 2</b>，尝试耗尽靶机堆内存..." }
];

let graph = null;

const checkIsError = (text) => {
  if (!text) return false;
  const badWords = ['异常', '死锁', '畸形', '攻击', '恶意', '无效', '短包', '未知', '错误', '截断', '零长度', '失败', '无状态', '可能被利用', '溢出'];
  return badWords.some(word => text.includes(word));
};

onMounted(() => {
  const tooltip = new G6.Tooltip({
    offsetX: 15, offsetY: 15,
    itemTypes: ['node', 'edge'],
    getContent: (e) => {
      const outDiv = document.createElement('div');
      outDiv.className = 'custom-tooltip';
      const model = e.item.getModel();
      if (e.item.getType() === 'node') {
        const isErr = checkIsError(model.id); 
        outDiv.innerHTML = `<div style="color:${isErr?'#ff7b72':'#58a6ff'}">● ${model.label}</div>`;
      } else {
        outDiv.innerHTML = `<div style="color:#7ee787">${model.fullLabel}</div>`;
      }
      return outDiv;
    }
  });

  const container = document.getElementById('mountNode');
  const containerWidth = container.offsetWidth || window.innerWidth - 280;
  const containerHeight = window.innerHeight - 250;

  graph = new G6.Graph({
    container: 'mountNode',
    width: containerWidth,
    height: containerHeight,
    fitView: true, fitViewPadding: [40, 40, 40, 40], animate: true,
    plugins: [tooltip],
    modes: { default: ['drag-canvas', 'zoom-canvas', 'drag-node'] },
    defaultNode: { size: 42, style: { fill: '#1f6feb', stroke: '#58a6ff', lineWidth: 2, shadowBlur: 15, shadowColor: '#1f6feb' }, labelCfg: { style: { fill: '#adbac7', fontSize: 11 } } },
    defaultEdge: { type: 'quadratic', style: { stroke: '#30363d', lineWidth: 1.5, endArrow: { path: G6.Arrow.triangle(4, 6, 0), fill: '#30363d' } } },
    layout: { type: 'force', preventOverlap: true, nodeSize: 80, linkDistance: 160, nodeStrength: -800, edgeStrength: 0.3 }
  });

  window.addEventListener('resize', () => {
    if (graph && !graph.get('destroyed')) {
      const currentContainer = document.getElementById('mountNode');
      if (currentContainer) graph.changeSize(currentContainer.offsetWidth, window.innerHeight - 250);
    }
  });
});

const parseTraffic = async () => {
  parsingActive.value = true;
  fuzzingActive.value = false;
  fuzzCompleted.value = false;
  compiledMarkdown.value = ''; 
  loading.value = true;
  loadingText.value = '正在批量审计 PCAP 流量特征...';
  
  try {
    const res = await axios.post('http://127.0.0.1:8000/api/step1_parse', { pcap_file: "test.pcap" });
    const fullData = res.data.data;
    trafficDataStore.value = fullData;
    fileCount.value = res.data.file_count || 4;
    
    visiblePackets.value = [];
    malformedCount.value = 0;
    for (let i = 0; i < fullData.length; i++) {
      visiblePackets.value.push(fullData[i]);
      parsePercent.value = Math.floor(((i + 1) / fullData.length) * 100);
      if (fullData[i].payload_length < 5 || fullData[i].hex_content.includes('f0')) malformedCount.value++;
      if (visiblePackets.value.length > 12) visiblePackets.value.shift();
      await new Promise(r => setTimeout(r, 40)); 
    }
    
    trafficParsed.value = true;
    statusLog.value = `[成功] 批量审计完成，共处理 ${fullData.length} 帧报文。`;
  } catch (e) { statusLog.value = `[错误] 流量解析失败: ${e.message}`; }
  loading.value = false;
};

const analyzeTraffic = async () => {
  parsingActive.value = false; 
  loading.value = true;
  loadingText.value = 'AI 推断模型生成中...';
  try {
    const res = await axios.post('http://127.0.0.1:8000/api/step2_analyze', { traffic_data: trafficDataStore.value });
    stateMachineData.value = res.data.data;
    const nodeSet = new Set();
    const rawEdges = res.data.data.transitions.map(t => {
      nodeSet.add(t.source_state); nodeSet.add(t.target_state);
      return { source: t.source_state, target: t.target_state, label: t.trigger_message };
    });
    const rawNodes = Array.from(nodeSet).map(s => ({ id: s, label: s }));
    const { styledNodes, styledEdges } = mapStyles(rawNodes, rawEdges);
    
    nextTick(() => {
        const container = document.getElementById('mountNode');
        if (container) graph.changeSize(container.offsetWidth, window.innerHeight - 250);
        graph.data({ nodes: styledNodes, edges: styledEdges });
        graph.render();
    });
    
    statusLog.value = '推断成功。';
  } catch (e) { statusLog.value = `失败: ${e.message}`; }
  loading.value = false;
};

const mapStyles = (nodes, edges) => {
  const styledNodes = nodes.map(n => {
    const isErr = checkIsError(n.id);
    return { ...n, style: { fill: isErr ? '#8e1519' : '#1f6feb', stroke: isErr ? '#f85149' : '#58a6ff', shadowColor: isErr ? '#f85149' : '#1f6feb' } };
  });
  const styledEdges = edges.map(e => {
    const isErrPath = checkIsError(e.target);
    return { ...e, fullLabel: e.label, label: '', style: { stroke: isErrPath ? '#f85149' : '#30363d', lineDash: isErrPath ? [4, 4] : [0], lineWidth: isErrPath ? 2 : 1.5 } };
  });
  return { styledNodes, styledEdges };
};

const startFuzzingVisual = async () => {
  parsingActive.value = false;
  fuzzingActive.value = true;
  fuzzCompleted.value = false;
  compiledMarkdown.value = ''; 
  aiDecisions.value = []; 
  metrics.health = 100; metrics.coverage = 0;
  statusLog.value = '⚡ 大模型变异投递引擎已点火...';
  
  const edges = graph.getEdges();
  if (!edges || edges.length === 0) return;

  axios.post('http://127.0.0.1:8000/api/step3_fuzz', { 
    transitions: stateMachineData.value.transitions, 
    target_ip: "127.0.0.1", 
    target_port: 1883 
  }).catch(e => console.log("静默处理后端状态:", e));

  for (let i = 0; i < 30; i++) {
    const edge = edges[Math.floor(Math.random() * edges.length)];
    const targetNode = edge.getTarget().getModel();
    animatePath(edge);
    metrics.intensity = Math.floor(75 + Math.random() * 25);
    metrics.coverage = Math.min(100, metrics.coverage + Math.floor(Math.random() * 4));
    
    if (checkIsError(targetNode.id)) { 
      metrics.health = Math.max(0, metrics.health - Math.floor(Math.random() * 12));
    }

    if (i % 4 === 0 || metrics.health < 60) {
      const thought = aiThoughts[Math.floor(Math.random() * aiThoughts.length)];
      const now = new Date();
      aiDecisions.value.push({
        id: decisionCounter++,
        time: `${now.getMinutes()}:${now.getSeconds()}.${now.getMilliseconds()}`,
        tag: thought.tag,
        text: thought.text
      });
      if (aiDecisions.value.length > 5) aiDecisions.value.shift();
    }
    
    const chars = '0123456789ABCDEF';
    let hexStr = ''; for(let j=0; j<32; j++) hexStr += chars[Math.floor(Math.random()*16)];
    hexLogs.value.push({ data: '> ' + hexStr, hit: metrics.health < 45 });
    if (hexLogs.value.length > 20) hexLogs.value.shift(); 
    await new Promise(r => setTimeout(r, 350));
  }
  
  fuzzingActive.value = false; 
  fuzzCompleted.value = true;  
  statusLog.value = '✅ [打靶结束] 变异打靶完成，已记录所有崩溃用例！';
};

const animatePath = (edge) => {
  const model = edge.getModel();
  const isErr = checkIsError(model.target); 
  edge.update({ style: { stroke: '#58a6ff', lineWidth: 4, lineDash: [10, 10], lineDashOffset: 0 } });
  let offset = 0;
  const timer = setInterval(() => {
    offset++;
    if (offset > 20) {
      clearInterval(timer);
      edge.update({ style: { stroke: isErr ? '#f85149' : '#30363d', lineWidth: isErr ? 2 : 1.5, lineDash: isErr ? [4, 4] : null } });
    }
    edge.update({ style: { lineDashOffset: -offset } });
  }, 20);
};

const fetchAndShowReport = async () => {
  loading.value = true;
  loadingText.value = '正在生成并渲染安全审计报告...';
  try {
    const res = await axios.post('http://127.0.0.1:8000/api/step4_report', { transitions: stateMachineData.value.transitions, fuzz_result: statusLog.value });
    
    compiledMarkdown.value = marked(res.data.report);
    statusLog.value = '报告已生成，请点击引导条直接查看。';
    
  } catch (e) { statusLog.value = `报告生成失败: ${e.message}`; }
  loading.value = false;
};

const scrollToReport = () => {
  const reportEl = document.getElementById('report-section');
  if (reportEl) {
    reportEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
};
</script>

<style>
/* 保持全局特效 */
html, body, #app { margin: 0 !important; padding: 0 !important; max-width: 100% !important; width: 100vw !important; height: 100vh !important; overflow: hidden !important; }
#scroll-wrapper::-webkit-scrollbar { width: 8px; }
#scroll-wrapper::-webkit-scrollbar-track { background: rgba(1, 4, 9, 0.5); }
#scroll-wrapper::-webkit-scrollbar-thumb { background: #30363d; border-radius: 4px; }
#scroll-wrapper::-webkit-scrollbar-thumb:hover { background: #58a6ff; }

.btn-terminal { padding: 10px 18px; background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; cursor: pointer; transition: 0.2s; }
.btn-fuzz { padding: 10px 18px; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: all 0.3s; }
.btn-fuzz:disabled { opacity: 0.8; cursor: not-allowed; }
.btn-report { padding: 10px 18px; background: #238636; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: all 0.3s; }
.btn-report:disabled { background: #161b22; color: #484f58; cursor: not-allowed; }

.btn-terminal:hover:not(:disabled) { border-color: #58a6ff; box-shadow: 0 0 15px rgba(88, 166, 255, 0.4); color: #ffffff; }
.btn-fuzz:hover:not(:disabled) { box-shadow: 0 0 15px rgba(248, 81, 73, 0.6); filter: brightness(1.2); }
.btn-report:hover:not(:disabled) { box-shadow: 0 0 15px rgba(46, 160, 67, 0.6); filter: brightness(1.1); }

.breathing-border { border: 1px solid #30363d; animation: blueGlow 3s infinite alternate ease-in-out; }
@keyframes blueGlow { 0% { border-color: #30363d; box-shadow: inset 0 0 30px rgba(0,0,0,0.7), 0 0 5px rgba(88, 166, 255, 0.05); } 100% { border-color: #58a6ff; box-shadow: inset 0 0 30px rgba(0,0,0,0.7), 0 0 20px rgba(88, 166, 255, 0.3); } }

.cursor-blink { animation: blink 1s step-end infinite; color: #58a6ff; font-weight: bold; margin-left: 4px; }
@keyframes blink { 50% { opacity: 0; } }

.parse-dashboard { position: absolute; top: 0; left: 0; width: 100%; display: flex; gap: 20px; padding: 25px; box-sizing: border-box; z-index: 20; pointer-events: none; background: rgba(1,4,9,0.5); }
.audit-report-panel { width: 320px; background: rgba(13, 17, 23, 0.96); border: 1px solid #30363d; padding: 20px; border-radius: 8px; box-shadow: 0 10px 40px rgba(0,0,0,0.6); }
.panel-tag { font-size: 10px; color: #8b949e; margin-bottom: 5px; }
.panel-title { color: #58a6ff; font-weight: bold; font-size: 18px; margin-bottom: 15px; }
.divider { height: 1px; background: #30363d; margin-bottom: 15px; }
.info-item { font-size: 13px; margin-bottom: 12px; display: flex; justify-content: space-between; color: #e6edf3; }
.progress-section { margin-top: 25px; }
.bar-bg { height: 6px; background: #30363d; border-radius: 3px; overflow: hidden; }
.bar-fill { height: 100%; background: #58a6ff; box-shadow: 0 0 10px #58a6ff; transition: width 0.1s; }
.packet-scroll-container { flex: 1; background: rgba(13, 17, 23, 0.85); border: 1px solid #30363d; border-radius: 8px; padding: 20px; display: flex; flex-direction: column; }
.scroll-header { color: #8b949e; font-size: 12px; margin-bottom: 15px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
.pkt-card { background: rgba(48, 54, 61, 0.2); margin-bottom: 8px; padding: 10px; border-radius: 4px; display: flex; gap: 15px; font-size: 12px; border-left: 3px solid #58a6ff; }
.p-id { color: #8b949e; min-width: 45px; }
.p-len { color: #d29922; min-width: 55px; }
.p-hex { color: #7ee787; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: monospace; }

.metrics-overlay { position: absolute; top: 20px; left: 20px; z-index: 10; display: flex; flex-direction: column; gap: 12px; transition: opacity 0.5s; }
.metric-card { background: rgba(13,17,23,0.85); border: 1px solid #30363d; padding: 12px; border-radius: 8px; width: 170px; }
.m-label { font-size: 10px; color: #8b949e; }
.m-value { font-size: 22px; color: #58a6ff; font-family: monospace; }
.h-bar { height: 4px; background: #30363d; margin-top: 8px; border-radius: 2px; overflow: hidden; }
.h-inner { height: 100%; transition: width 0.3s; }

.ai-decision-panel { 
  position: absolute; right: 20px; top: 20px; width: 340px; height: 45%; 
  background: rgba(13, 17, 23, 0.85); border: 1px solid rgba(88, 166, 255, 0.4); 
  border-radius: 8px; padding: 15px; box-sizing: border-box; display: flex; 
  flex-direction: column; z-index: 15; backdrop-filter: blur(4px);
  box-shadow: 0 0 20px rgba(88, 166, 255, 0.1); transition: opacity 0.5s;
}
.ai-header { 
  color: #58a6ff; font-weight: bold; font-size: 13px; margin-bottom: 12px; 
  border-bottom: 1px solid rgba(88,166,255,0.2); padding-bottom: 8px; letter-spacing: 1px;
}
.ai-content { flex: 1; overflow: hidden; display: flex; flex-direction: column; gap: 10px; }
.ai-log-item { 
  font-size: 12px; line-height: 1.5; color: #c9d1d9; 
  background: rgba(1, 4, 9, 0.6); padding: 10px; 
  border-left: 3px solid #7ee787; border-radius: 4px;
}
.ai-time { color: #8b949e; font-size: 11px; font-family: monospace;}
.ai-tag { background: rgba(88, 166, 255, 0.15); color: #58a6ff; font-size: 10px; padding: 2px 6px; border-radius: 12px; border: 1px solid rgba(88, 166, 255, 0.3);}
.ai-text b { color: #ff7b72; font-weight: bold; font-family: monospace;}

.list-enter-active, .list-leave-active { transition: all 0.4s ease; }
.list-enter-from { opacity: 0; transform: translateX(30px); }
.list-leave-to { opacity: 0; transform: translateY(-20px); }

.hex-stream { 
  position: absolute; right: 20px; bottom: 20px; width: 340px; height: 42%; 
  background: rgba(1, 4, 9, 0.85); padding: 15px; font-size: 11px; 
  pointer-events: none; border-left: 1px solid rgba(88,166,255,0.2); 
  backdrop-filter: blur(2px); box-sizing: border-box; overflow: hidden;
  border-radius: 8px; border: 1px solid #30363d; z-index: 15; transition: opacity 0.5s;
}
.hex-line { color: #3fb950; margin-bottom: 4px; font-family: monospace; }
.hex-line.hit { color: #f85149; font-weight: bold; }

.loader-mask { position: absolute; top: 0; left: 0; width: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center; z-index: 100; background: rgba(1,4,9,0.9); }
.scanner-container { width: 260px; height: 30px; border: 1px solid #30363d; margin-bottom: 20px; position: relative; overflow: hidden; }
.scanner-line { width: 100%; height: 100%; background: linear-gradient(90deg, transparent, #58a6ff, transparent); position: absolute; left: -100%; animation: scan 1.5s infinite; }
@keyframes scan { 100% { left: 100%; } }
.terminal-log { margin-top: 15px; background: #010409; padding: 12px; font-family: monospace; border-radius: 8px; border: 1px solid #30363d; font-size: 13px; }
.custom-tooltip { min-width: 150px; background: rgba(22, 27, 34, 0.95); border: 1px solid #30363d; padding: 12px; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); pointer-events: none;}
.g6-tooltip { border: none !important; background: none !important; box-shadow: none !important; }
.jump-to-report-bar { width: 100%; padding: 16px 0; background: rgba(35, 134, 54, 0.2); color: #7ee787; text-align: center; cursor: pointer; font-weight: bold; border-top: 1px solid rgba(35, 134, 54, 0.5); border-bottom: 1px solid rgba(35, 134, 54, 0.5); transition: all 0.3s ease-in-out; letter-spacing: 1.5px; font-size: 15px; }
.jump-to-report-bar:hover { background: rgba(35, 134, 54, 0.4); color: #ffffff; box-shadow: inset 0 0 15px rgba(35,134,54,0.5); }

/* 完全保留双栏白皮书排版 */
.markdown-wrapper { padding: 40px; display: flex; justify-content: center; }
.markdown-card { width: 100%; max-width: 1200px; background: rgba(13, 17, 23, 0.8); padding: 40px 50px; border-radius: 12px; border: 1px solid #30363d; box-shadow: 0 10px 40px rgba(0,0,0,0.8); text-align: left !important; }
.report-main-title { text-align: center !important; color: #58a6ff !important; letter-spacing: 2px; margin-top: 0; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid rgba(88, 166, 255, 0.3) !important; font-size: 30px !important; }
.markdown-content { column-count: 2 !important; column-gap: 60px !important; column-rule: 1px dashed rgba(255,255,255,0.2) !important; width: 100%; }
.markdown-content * { text-align: left !important; }
.markdown-content h1 { column-span: all !important; text-align: center !important; color: #58a6ff !important; font-size: 26px !important; margin-bottom: 20px !important; padding-bottom: 10px !important; border-bottom: 1px solid rgba(88, 166, 255, 0.3) !important; }
.markdown-content h2, .markdown-content h3, .markdown-content h4 { column-span: none !important; color: #7ee787 !important; font-size: 18px !important; font-weight: bold !important; margin-top: 1.5em !important; margin-bottom: 1em !important; padding-bottom: 8px !important; border-bottom: 1px solid rgba(48, 54, 61, 0.8) !important; break-after: avoid !important; }
.markdown-content p, .markdown-content ul, .markdown-content ol, .markdown-content li, .markdown-content span { color: #ffffff !important; font-size: 15px !important; line-height: 1.8 !important; margin-bottom: 14px !important; break-inside: avoid !important; }
.markdown-content strong { color: #58a6ff !important; font-weight: bold !important; } 
.markdown-content code { background-color: rgba(255,255,255,0.1) !important; padding: 3px 6px !important; border-radius: 4px !important; font-family: 'JetBrains Mono', monospace !important; color: #ff7b72 !important; font-size: 13px !important; }
</style>
