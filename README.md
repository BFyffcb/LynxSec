# 🐱 LynxSec

> 专精白帽安全的AI智能体——会用工具的AI，而不只是工具本身。

---

## 这是什么？

LynxSec是一个多Agent AI智能体，专注于白帽安全检测。

它能自主调用安全工具、分析漏洞、生成报告。
你只需要告诉它目标，它会帮你找到所有问题并告诉你怎么修。

| 对比项 | 传统安全工具 | LynxSec |
|--------|------------|---------|
| 本质 | 工具 | 会用工具的AI |
| 使用方式 | 命令行手动调用 | 对话式，自主决策 |
| 报告风格 | 技术日志 | 人话版+技术版双输出 |
| 目标用户 | 专业红队 | 普通开发者+专业人员 |

---

## 核心能力

- 🔍 **情报收集** — 端口扫描、子域名发现、指纹识别、CVE关联
- 🎯 **漏洞验证** — SQLi、XSS、命令注入、弱口令（授权下）
- 🧠 **智能审计** — 误报过滤、攻击链串联、CVSS评分
- 📋 **双版本报告** — 普通开发者看人话版，专业人员看技术版

---

## 快速开始

```bash
# 克隆项目
git clone https://github.com/BFyffcb/LynxSec.git
cd LynxSec

# 配置模型（支持任意OpenAI格式API）
cp config.env.example config.env
# 编辑config.env填入你的API Key和模型名称

# 安装依赖
pip install -r requirements.txt

# 启动
python ui/cli.py
```

---

## 使用示例

```
> 检测 https://example.com

[调度Agent] 解析任务，目标：example.com
[情报Agent] 正在扫描端口和指纹...
[渗透Agent] 发现80/443端口，开始漏洞验证...
[审计Agent] 过滤误报，评估影响...
[报告Agent] 生成报告完成 ✅

报告已保存至 outputs/reports/example.com_20260531.md
```

---

## 安全声明

⚠️ LynxSec仅用于**授权范围内**的安全测试。

启动扫描前必须确认目标授权，所有操作记录存档。
未经授权对任何系统进行测试是违法行为。

---

## 架构

多Agent协作，文件+Bridge通信模式：

```
调度Agent → 情报Agent → 渗透Agent → 审计Agent → 报告Agent
```

详见 [架构设计.md](./架构设计.md)

---

## 模型支持

兼容任意OpenAI格式API，不绑定任何厂商：

- DeepSeek V4-Pro ✅
- 千问3.7MAX ✅
- GPT-4o ✅
- 其他兼容模型 ✅

---

## 开发状态

🚧 **核心五件套已完成，进入联调验证阶段。**

### DVWA 本地测试（三阶段）

**Stage 1：流程测试（跳过渗透）**
```bash
python start_lynxsec.py --dry-run
# 输入: "扫描 http://localhost:80"
# 验证: dispatcher -> recon -> auditor -> reporter 完整链路
# 确认 pipeline.json、result 字段、双版本报告正常生成
```

**Stage 2：授权测试（pentest 放行）**
```bash
python start_lynxsec.py
# 输入: "测试 DVWA 登录漏洞"
# 验证: auth.json 授权硬闸、sqlmap 参数受限、auditor 评分
```

**Stage 3：中断恢复测试**
```bash
# 执行到一半 Ctrl+C，再重新 python start_lynxsec.py
# 验证: pipeline.json 从中断点恢复继续执行
```

---

## License

MIT License — 开源自由使用
