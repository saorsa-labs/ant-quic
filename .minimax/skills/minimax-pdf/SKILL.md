---
name: minimax-pdf
description: Professional PDF solution. Create PDFs using HTML+Paged.js (academic papers, reports, documents). Process existing PDFs using Python (read, extract, merge, split, fill forms). Supports KaTeX math formulas, Mermaid diagrams, three-line tables, citations, and other academic elements. Also use this skill when user explicitly requests LaTeX (.tex) or native LaTeX compilation.
---

## Route Selection

| Route | Trigger | Route File |
|-------|---------|------------|
| **HTML** (default) | All PDF creation requests | `handlers/html.md` |
| **LaTeX** | User explicitly requests LaTeX, .tex, or Tectonic | `handlers/latex.md` |
| **Process** | Work with existing PDFs (extract, merge, fill forms, etc.) | `handlers/process.md` |

**Default to HTML.** Only use LaTeX route when user explicitly requests it.

### MANDATORY: Use PDF Skill Scripts for Conversion

<system-reminder>
⛔ **HTML→PDF 转换必须使用本 skill 的脚本，严禁使用 convert_file 工具！**

当你写好 HTML 后，**必须**使用以下命令转换为 PDF：
```bash
bash .minimax/skills/minimax-pdf/scripts/pdf.sh html document.html --preserve-links
```

**禁止行为：**
- ❌ 调用 `convert_file` / `mcp__matrix__convert_file` 工具将 HTML 转为 PDF
- ❌ 使用任何其他方式（截图、打印等）将 HTML 转为 PDF

**原因：** `convert_file` 工具使用截图拼接方式生成 PDF，会导致：
- 表格/内容在页面边界被粗暴切割
- 前后页内容不连贯（对不上）
- 文字是光栅化截图（模糊、不可选中、不可搜索）

本 skill 的 `pdf.sh html` 使用 Paged.js + Playwright 原生 PDF 引擎，输出矢量文本、智能分页、CSS @page 支持。
</system-reminder>

### MANDATORY: Fix Errors Instead of Degrading

<system-reminder>
⛔ **Playwright/Chromium 报错时，必须修复依赖后重试，严禁降级到 convert_file！**

如果运行 `pdf.sh html` 或 `html_to_pdf.js` 时遇到以下错误：
- `Playwright module not found`
- `Chromium browser not found`
- `browserType.launch: Executable doesn't exist`

**正确做法（按顺序执行）：**
1. 安装 Playwright：`npm install -g playwright`
2. 安装 Chromium：`npx playwright install chromium`
3. **重试原来的转换命令**（`pdf.sh html` 或 `node html_to_pdf.js`）

**如果 `bash` 在 Windows 上不可用**（WSL 报错），直接用 node 调用：
```
node .minimax/skills/minimax-pdf/scripts/html_to_pdf.js document.html --output output.pdf --preserve-links
```

**绝对禁止的行为：**
- ❌ 遇到 Playwright 报错后改用 `convert_file` / `mcp__matrix__convert_file`
- ❌ 使用截图、打印、或任何其他方式替代
- ❌ 告诉用户"Playwright 不可用，已使用备选方案"

**为什么不能降级？** `convert_file` 是截图拼接，产出的 PDF 质量极差（模糊、不可选中文字、分页错乱）。
修复依赖只需 1-2 分钟，但降级产出的 PDF 无法使用。
</system-reminder>

### MANDATORY: Read Route File Before Implementation

<system-reminder>
You MUST read the corresponding route file before writing ANY code.
Route files contain critical implementation details NOT duplicated here.
Skipping this step leads to incorrect output (wrong scripts, missing CSS, broken layouts).
</system-reminder>

**Before implementation, you MUST:**
1. Determine the route (HTML / LaTeX / Process)
2. **Read the route file** (`handlers/html.md`, `handlers/latex.md`, or `handlers/process.md`)
3. Only then proceed with implementation

This file (SKILL.md) contains constraints and principles. Route files contain **how-to details**.

### Decision Rules

#### Route Selection
| User Says | Route |
|-----------|-------|
| "Create a PDF", "Make a report", "Write a paper" | HTML |
| "Use LaTeX", "Compile .tex", "Use Tectonic" | LaTeX |
| "Extract text from PDF", "Merge these PDFs", "Fill this form" | Process |

#### Cover Decision (HTML Route) — 写 HTML 前必须先确认

<system-reminder>
⛔ **每次生成 PDF 前，都必须先判断是否需要封面！不要默认加封面！**

按以下流程判断：

**Step 1: 用户是否提供了已有内容？**（翻译、转换、邮件转 PDF、文档转 PDF 等）
- → 是：**保持原文结构**，原文没封面就不加，原文有封面则还原其内容和布局。同时保留原文图片位置、图表编号等。
- → 否：进入 Step 2

**Step 2: 用户是否明确表达了封面意愿？**
- "加封面" / "做个好看的首页" → ✅ 加封面 → 选风格
- "不要封面" / "保持原样" / "保持不变" → ❌ 不加封面
- 没提到封面 → 进入 Step 3

**Step 3: 根据内容类型推断**
| 内容类型 | 封面决策 |
|---------|---------|
| 简短内容、邮件正文、备忘录 | ❌ 不加 |
| 从零创作的正式报告、研究报告、论文 | ✅ 推荐加 |
| 不确定 | 询问用户 |
</system-reminder>

**如果决定加封面，选择风格：**

| Context | Style |
|---------|-------|
| Academic paper, thesis, formal coursework | **Minimal** |
| Business reports, professional documents | **Corporate** |
| Technical reports, IT/tech documentation | **Tech** |
| Marketing, creative, design documents | **Creative** |

<system-reminder>
⛔ **如果要加封面，必须使用 html.md 中的完整模板代码！**

**禁止行为：**
- ❌ 自己设计 CSS 样式（如自创 `.cover-bg`, `.cover-gradient`, `.cover-header`, `.cover-category` 等类名）
- ❌ 自己写 `linear-gradient` / `radial-gradient` 背景
- ❌ 修改模板的 HTML 结构
- ❌ 省略模板中的任何 CSS 规则

**正确做法：**
1. 打开 html.md → 找到对应风格的 `⭐ TEMPLATE` 部分
2. **完整复制** HTML + CSS 代码
3. 只替换占位文字（标题、作者、日期）
4. 不做任何其他修改

**自检：** 如果你的 HTML 中有封面，class 必须是以下之一（否则你写错了）：
- `cover-minimal`
- `cover-corporate`
- `cover-tech`
- `cover-creative`

如果你发现自己写的 class 不在上面的列表中（例如 `.cover-header`、`.cover-category`、`.cover-meta`），**立即停止并使用模板重写**。
</system-reminder>

#### Hyperlink & Image Checklist (转换已有内容时必须执行)

<system-reminder>
⛔ **转换/翻译已有内容时，必须执行以下检查！**

**超链接保留：**
- 原文中的所有 `<a href="https://...">` 外部链接，翻译后**必须保留** `href` 属性
- 在 HTML 中写 `<a href="原始URL">翻译后的文字</a>`，不要丢掉链接只保留文字
- 转换命令**必须加 `--preserve-links`**，否则 PDF 中链接不可点击

**图片数量确认（三步核对）：**
1. **提取后核对**：从原文（EML/DOCX 等）提取图片后，记录图片数量和文件名列表
2. **写 HTML 后核对**：确认 HTML 中的 `<img src>` 数量与提取的图片数量一致，每张都引用到了
3. **转换后核对**：查看转换输出的 `Figures/Tables: X figures` 数字，确认与预期一致

如果任何一步数量不对，**停下来检查**，不要直接交付。
</system-reminder>

#### Citation Format Selection
| Document Language | Format |
|-------------------|--------|
| Chinese | GB/T 7714 (use [J][M][D] identifiers) |
| English | APA |
| Mixed | Chinese refs → GB/T 7714, English refs → APA |

---

## Quick Start

**Use the unified CLI for all operations (严禁使用 convert_file 工具替代)：**

```bash
# Check environment (JSON output, exit code 0=ok, 2=missing deps)
bash .minimax/skills/minimax-pdf/scripts/pdf.sh check

# Auto-fix missing dependencies (idempotent, safe to run multiple times)
bash .minimax/skills/minimax-pdf/scripts/pdf.sh fix

# Convert HTML to PDF (⚠️ 必须用这个命令，不要用 convert_file 工具!)
bash .minimax/skills/minimax-pdf/scripts/pdf.sh html input.html --preserve-links

# Compile LaTeX to PDF
bash .minimax/skills/minimax-pdf/scripts/pdf.sh latex input.tex

# Alternative: Direct node call for HTML conversion
node .minimax/skills/minimax-pdf/scripts/html_to_pdf.js input.html --output output.pdf --preserve-links
```

> **Note**: Use `bash script.sh` instead of `./script.sh` to avoid permission issues.
> **⚠️ CRITICAL**: HTML→PDF conversion MUST use the commands above. Do NOT use `convert_file` / `mcp__matrix__convert_file` tool — it produces low-quality screenshot-based PDFs with broken pagination.

**Exit codes:**
- `0` = success
- `1` = usage error
- `2` = dependency missing (run `pdf.sh fix`)
- `3` = runtime error

**Dependencies by route:**
- **HTML route**: Node.js, Playwright, Chromium
- **Process route**: Python 3, pikepdf, pdfplumber
- **LaTeX route**: Tectonic

---

## Core Constraints (Must Follow)

### 1. Output Language
**Output language must match user's query language.**
- User writes in Chinese → PDF content in Chinese
- User writes in English → PDF content in English
- User explicitly specifies language → Follow user's specification

### 2. Word Count and Page Constraints
- Strictly follow user-specified word/page count requirements
- Do not arbitrarily inflate content length

### 3. Citation and Search Standards

#### CRITICAL: Search Before Writing
**DO NOT fabricate information. When in doubt, SEARCH.**

If content involves ANY of these, you **MUST search FIRST** before writing:
- Statistics, numbers, percentages, rankings
- Policies, regulations, laws, standards
- Academic research, theories, methodologies
- Current events, recent developments
- **Anything you're not 100% certain about**

<system-reminder>
Never proceed with writing if you need statistics, research data, or policy information without searching first.
Making up facts is strictly prohibited. When uncertain, search.
</system-reminder>

#### When Search is Required
| Scenario | Search? | Notes |
|----------|---------|-------|
| Statistics, data | **Required** | e.g., "2024 employment rate" |
| Policies, regulations | **Required** | e.g., "startup subsidies" |
| Research, papers | **Required** | e.g., "effectiveness of method X" |
| Time-sensitive content | **Required** | Information after knowledge cutoff |
| **Uncertain facts** | **Required** | If unsure, always search |
| Common knowledge | Not needed | e.g., "water boils at 100°C" |

**Search workflow**:
1. Identify facts/data requiring verification
2. Search for authentic sources
3. If results insufficient, **iterate search** until reliable info obtained
4. Include real sources in references
5. **If search fails repeatedly, tell the user** instead of making up data

#### Citations Must Be Real
**Fabricating references is prohibited**. All citations must have:
- Correct author/institution names
- Accurate titles
- Verifiable year, journal/source

#### Cross-references (Must Be Clickable)
```html
As shown in <a href="#fig-1-1">Figure 1-1</a>...
From <a href="#eq-2-1">Equation (2-1)</a>...
See <a href="#sec3">Section 3</a>...
```
**Note**: `id` must be placed at container top (see CSS Counters section in html.md).

---

## Content Quality Constraints

### 1. Word/Page Count Constraints
**Must strictly follow user-specified word or page count requirements**:

| User Request | Execution Standard |
|--------------|-------------------|
| Specific word count (e.g., "3000 words") | Within ±20%, i.e., 2400-3600 words |
| Specific page count (e.g., "5 pages") | Exactly equal, last page may be partial |
| Word count range (e.g., "2000-3000 words") | Must fall within range |
| No explicit requirement | Infer reasonably by document type; prefer thorough over superficial |
| Minimum specified (e.g., "more than 5000 words") | No more than 2x, i.e., 5000-10000 words |

**Prohibited behaviors**:
- Arbitrarily shortening content ("concise" is not an excuse)
- Padding pages with excessive bullet lists (maintain high information density)
- Exceeding twice the user's requested length

**Special case - Resume/CV**:
- Resume should be **1 page** unless user specifies otherwise
- Use compact margins: `margin: 1.5cm`

### 2. Outline Adherence (Mandatory)
**When user provides outline**:
- **Strictly follow** the user-provided outline structure
- Section titles must match outline (minor wording adjustments OK, no level/order changes)
- Do not add or remove sections arbitrarily
- If outline seems problematic, **ask user first** before modifying

**When no user outline**:
- Use standard structures based on document type:
  - **Academic papers**: IMRaD (Introduction-Methods-Results-Discussion) or Introduction-Literature Review-Methods-Results-Discussion-Conclusion
  - **Business reports**: Conclusion-first (Executive Summary → Detailed Analysis → Recommendations)
  - **Technical docs**: Overview → Principles → Usage → Examples → FAQ
  - **Course assignments**: Follow assignment structure requirements
- Sections must have logical progression, no disconnects

---

## Tech Stack Overview

| Route | Tools | Purpose |
|-------|-------|---------|
| HTML | Playwright + Paged.js | HTML → PDF conversion |
| HTML | KaTeX, Mermaid | Math formulas, diagrams |
| Process | pikepdf | Form filling, page operations, metadata |
| Process | pdfplumber | Text and table extraction |
| Process | LibreOffice | Office → PDF conversion |
| LaTeX | Tectonic | LaTeX → PDF compilation |
