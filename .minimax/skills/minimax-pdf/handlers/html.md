# HTML to PDF Route

Create professional PDFs using HTML + Playwright + Paged.js.

---

## Step 0: Check & Install Dependencies (Do First)
**Run immediately before writing HTML**—package download takes time.

```bash
# Linux / macOS:
bash .minimax/skills/minimax-pdf/scripts/setup.sh

# Windows (if bash is unavailable):
node --version && npx playwright --version
```

The script only checks status, does not auto-install. If missing, install manually:
- Node.js: `brew install node` (macOS) / `apt install nodejs` (Ubuntu) / download from nodejs.org (Windows)
- Playwright: `npm install -g playwright && npx playwright install chromium`

Run in background while writing HTML.

<system-reminder>
⛔ **如果 `bash` 在 Windows 上报 WSL 错误（没有 Linux 发行版），不要放弃！**
直接使用以下命令检查环境：
```
node --version
npx playwright --version
```
转换 HTML 时不用 `bash pdf.sh`，直接用 `node`：
```
node .minimax/skills/minimax-pdf/scripts/html_to_pdf.js document.html --output output.pdf --preserve-links
```
</system-reminder>

## Step 1: Write HTML

<system-reminder>
⛔ **必须引入 base.css！** 这是所有 PDF 的基础样式，包含页面设置、图表编号、防溢出等关键规则。
不引入 base.css 会导致：图表没有标题编号、内容溢出页面、页眉显示 "undefined" 等问题。
</system-reminder>

**HTML 模板骨架**（每次写 HTML 都从这里开始）：

> **路径说明：** HTML 中的 `<link href>` 必须使用**绝对路径**，因为浏览器解析路径是相对于 HTML 文件位置的。
> 请将下面模板中的 `{WORKSPACE}` 替换为实际工作区绝对路径（即你的 `$WORKSPACE_DIR` 环境变量值，或通过 `pwd` 获取）。
> Shell 命令中可以直接用相对路径 `.minimax/...`（因为 cwd 就是工作区根目录）。

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="{WORKSPACE}/.minimax/skills/minimax-pdf/scripts/styles/base.css">
    <!-- 如果需要封面，再加一行对应的 cover CSS -->
    <!-- <link rel="stylesheet" href="{WORKSPACE}/.minimax/skills/minimax-pdf/scripts/styles/cover-corporate.css"> -->
    <style>
        /* 这里只写本文档特有的自定义样式，base.css 已包含的不要重复写 */
    </style>
</head>
<body>
    <!-- 如果需要封面，从 templates/ 目录复制对应 HTML 片段到这里 -->
    <!-- 正文内容 -->
</body>
</html>
```

**规则：**
1. **必须引入 base.css** — 包含页面设置、字体、图表编号、防溢出等所有基础规则
2. **Do NOT load Paged.js** — 转换脚本自动注入，重复加载会导致页数翻倍
3. **`<style>` 中只写自定义样式** — base.css 已有的规则不要重复（如 `figcaption::before`、`@page` 等）
4. **Diagrams and Charts**:
   - **Use Mermaid** for flowcharts, sequence diagrams, architecture diagrams (renders as static SVG; must set `theme:'neutral'`)
   - **Use `<img>` tags** for data charts (bar, line, pie) — pre-generate with matplotlib
   - **Prohibited**: ECharts, Chart.js, D3.js, Plotly, or any JS charting library that renders dynamically — causes layout conflicts with Paged.js pagination
   - **Chart size rule**: Always use **landscape figsize** (width > height), e.g., `figsize=(10, 6)`. Never use square or portrait. This prevents charts from overflowing the page.


## Step 2: Convert to PDF

<system-reminder>
⛔ **必须使用本 skill 的脚本来转换 HTML → PDF！**
⛔ **严禁调用 `convert_file` / `mcp__matrix__convert_file` 工具！**

`convert_file` 使用截图拼接，会导致内容被粗暴切割、页面对不上、文字模糊。
本 skill 的脚本使用 Paged.js + Playwright 原生 PDF 引擎，输出高质量矢量 PDF。
</system-reminder>

```bash
# 默认用法（保留超链接）— 必须用这个命令，不要用 convert_file
bash .minimax/skills/minimax-pdf/scripts/pdf.sh html document.html --preserve-links

# 指定输出文件名
bash .minimax/skills/minimax-pdf/scripts/pdf.sh html document.html --output output.pdf --preserve-links

# 或者直接调用 node 脚本（效果相同）
node .minimax/skills/minimax-pdf/scripts/html_to_pdf.js document.html --output output.pdf --preserve-links
```

<system-reminder>
⛔ **转换时必须加 `--preserve-links`！** 这样 PDF 中的超链接才能点击跳转。
不加此参数会导致：所有 `<a href>` 链接在 PDF 中变成纯文本，无法点击。
</system-reminder>

<system-reminder>
⛔ **如果转换报错 "Playwright module not found" 或 "Chromium not found"，必须修复后重试！**

**修复步骤：**
```bash
npm install -g playwright
npx playwright install chromium
```
然后**重新运行原来的转换命令**。

**绝对禁止降级：**
- ❌ 不要改用 `convert_file` / `mcp__matrix__convert_file`
- ❌ 不要使用任何截图/打印方式替代
- ❌ 不要告诉用户"已使用备选方案"

修复依赖只需 1-2 分钟。`convert_file` 产出的 PDF 质量极差（截图拼接、模糊、分页错乱），不可接受。
</system-reminder>

`--preserve-links` 保留 PDF 中的可点击超链接：
- **External links** (`https://...`): Opens in browser when clicked
- **Internal links** (`#section-id`): Jumps to the target page/position

Additional options:
- `--save-link-map`: Save link mapping to JSON file (for debugging)

After conversion, the script outputs:
- Page count, word statistics, figures/tables count
- **Overflow detection**: Warns if any `pre`, `table`, `figure`, `img`, etc. overflows page width
- **CSS Counter detection**: Warns if CSS counters are used (will break with Paged.js)
- Anomalous pages detection (blank, low-content)

If overflow is detected, add `max-width: 100%` to the offending element.

---

## Design Principles

### LaTeX Academic Style (Default)
Default output should approximate LaTeX academic paper style, not web/UI style.

#### Prohibited UI Components
| Prohibited | Alternative |
|------------|-------------|
| Card components (bordered + header) | Three-line tables or plain paragraphs |
| Statistics dashboards (number card grids) | Tables for data display |
| Dark title bars | Bold titles + thin border or left border |
| Timeline components | Numbered lists or tables |
| Dark-themed code blocks | Light gray background `#f5f5f5` |
| Rounded borders | Square or no borders |
| Shadow effects | No shadows |
| 同级内容用不同颜色区分 | 统一颜色，用粗体/缩进区分 |
| 五颜六色的标签/徽章 | 统一主题色，或纯文字标注 |
| 每章/每节不同色系 | 全文统一配色方案（最多3色）|

#### LaTeX-Style Patterns
**Theorem/Definition boxes** (left border, not dark title bar):
```css
.theorem {
    border-left: 3px solid #333;
    padding-left: 1em;
    margin: 1em 0;
}
.theorem-title { font-weight: bold; }
.theorem-content { font-style: italic; }
```

**Algorithm boxes** (thin border + white background):
```css
.algorithm {
    border: 1px solid #333;
    padding: 0.5em;
    background: white;
}
```

#### Color Standards — 三色体系

<system-reminder>
⛔ **整篇文档严格遵循三色体系：text + primary + secondary，严禁五颜六色！**

写 HTML 前，先在 `<style>` 中用 CSS 变量定义配色方案，全文所有颜色都通过变量引用：

```css
:root {
    /* text — 文字主色调，用于正文、标题、边框等所有文字内容 */
    --text: #1a202c;
    --text-90: rgba(26, 32, 44, 0.9);   /* 正文 */
    --text-70: rgba(26, 32, 44, 0.7);   /* 次要文字、图注 */
    --text-50: rgba(26, 32, 44, 0.5);   /* 辅助文字、页眉 */
    --text-30: rgba(26, 32, 44, 0.3);   /* 分割线、细边框 */
    --text-10: rgba(26, 32, 44, 0.1);   /* 表头背景、代码块背景 */
    --text-05: rgba(26, 32, 44, 0.05);  /* 极浅背景 */

    /* primary — 主强调色，用于表格高亮、图表、超链接 */
    --primary: #2c5282;
    --primary-light: rgba(44, 82, 130, 0.1);  /* 浅色背景变体 */

    /* secondary — 辅助强调色，用于次要高亮、第二数据系列 */
    --secondary: #8B0000;
    --secondary-light: rgba(139, 0, 0, 0.1);
}
```

**三色分工（严格遵守）：**

| 角色 | 变量 | 用途 | 备注 |
|------|------|------|------|
| **text** | `--text` 及其透明度 | H1-H4 标题、正文、列表、边框、分割线、表头背景 | 页面上 90% 的颜色都是 text 的不同透明度 |
| **primary** | `--primary` | 超链接、表格高亮行、图表主色、重要标记 | 少量使用，起点缀作用 |
| **secondary** | `--secondary` | 图表第二数据系列、次要高亮 | 更少使用，可以不用 |

**text 透明度用法：**
```css
body { color: var(--text-90); }
h1, h2, h3, h4 { color: var(--text); }          /* 100% — 标题 */
figcaption, .note { color: var(--text-70); }     /* 70% — 图注、备注 */
.page-header { color: var(--text-50); }          /* 50% — 页眉 */
hr, .divider { border-color: var(--text-30); }   /* 30% — 分割线 */
thead th { background: var(--text-10); }          /* 10% — 表头背景 */
blockquote { background: var(--text-05); }        /* 5% — 引用块背景 */
```

**primary / secondary 用法（仅用于高亮场景）：**
```css
a { color: var(--primary); }                      /* 超链接 */
.highlight-row { background: var(--primary-light); } /* 表格高亮行 */
/* 图表中：主数据系列用 primary，次数据系列用 secondary */
```

**推荐配色方案（选一种，只改变量值）：**
| 方案 | --text | --primary | --secondary | 适用场景 |
|------|--------|-----------|-------------|---------|
| 学术黑 | `#1a202c` | `#2c5282` | — | 论文、学术报告（默认）|
| 商务蓝 | `#1a202c` | `#1a56db` | `#7c3aed` | 商业报告、提案 |
| 正式红 | `#1a202c` | `#8B0000` | `#b45309` | 政府报告、正式文件 |
| 科技青 | `#0f172a` | `#0d6e6e` | `#6366f1` | 技术文档 |
| 纯灰度 | `#333333` | — | — | 极简文档（不使用 primary/secondary）|

**严禁行为：**
- ❌ H1 用蓝色、H2 用绿色、H3 用紫色 — 所有标题统一用 `var(--text)`
- ❌ 同级列表项/卡片用不同颜色背景 — 统一用 `var(--text-10)` 或无背景
- ❌ 不同章节用不同色系 — 全文只有 text/primary/secondary 三色
- ❌ 在正文中引入配色方案之外的颜色值（如随手写 `color: #ff6600`）
- ❌ 把 primary/secondary 用于正文文字或标题 — 它们只用于高亮/图表/链接

**自检：** 写完 HTML 后，搜索所有 `color:`、`background-color:`、`border-color:` 的值。除了 `var(--text*)`、`var(--primary*)`、`var(--secondary*)`、`white`、`transparent` 外，不应该出现其他颜色值。
</system-reminder>

**Cover**: Depends on document type (see below). Cover pages may use brand colors，不受三色体系限制。

#### Icons and Emoji
**PROHIBITED** (unless user explicitly requests): Do NOT use emoji or decorative icons. Emoji fails on Linux (missing fonts), and icons often look unprofessional in formal documents. Use plain text instead.

---

### Cover Design

**封面是可选的。大多数情况下不需要封面。** 请先参考 SKILL.md 的封面决策流程。

<system-reminder>
⛔ **不要默认加封面！写 HTML 前必须先按 SKILL.md 的流程判断是否需要封面！**

**判断流程（简化版）：**
1. 用户提供了已有内容（翻译、转换、邮件转 PDF）？→ 保持原文结构，原文没封面就不加
2. 用户明确说加/不加？→ 遵从用户
3. 简短内容、备忘录？→ 不加
4. 从零创作的正式报告/论文？→ 推荐加
5. 不确定？→ 询问用户
</system-reminder>

#### 如何添加封面（仅在决定加封面时）

**Step 1**: 在 `<head>` 中加一行 CSS 引用（选对应风格，`{WORKSPACE}` 替换为实际工作区绝对路径）：
```html
<link rel="stylesheet" href="{WORKSPACE}/.minimax/skills/minimax-pdf/scripts/styles/cover-corporate.css">
```

**Step 2**: 读取对应模板的 HTML 片段，复制到 `<body>` 开头，只替换占位文字：
```
.minimax/skills/minimax-pdf/scripts/templates/cover-corporate.html
```

| Style | CSS 文件 | HTML 模板 | 适用场景 |
|-------|---------|-----------|---------|
| **Minimal** | `styles/cover-minimal.css` | `templates/cover-minimal.html` | 学术论文、课程作业 |
| **Corporate** | `styles/cover-corporate.css` | `templates/cover-corporate.html` | 商业报告、研究报告 |
| **Tech** | `styles/cover-tech.css` | `templates/cover-tech.html` | 技术报告、IT 文档 |
| **Creative** | `styles/cover-creative.css` | `templates/cover-creative.html` | 营销、创意设计 |

> 路径前缀（Shell 命令/读取文件用相对路径）：`.minimax/skills/minimax-pdf/scripts/`
> HTML `<link href>` 中必须用绝对路径：`{WORKSPACE}/.minimax/skills/minimax-pdf/scripts/`

<system-reminder>
⛔ **禁止自己写封面 CSS！必须使用上述文件！**
- ❌ 自己写 `linear-gradient` 背景、自创 `.cover-header` 等类名
- ✅ 引用 CSS 文件 + 复制 HTML 模板 + 只改占位文字
</system-reminder>

---

#### Background Image (if needed)
If using an image instead of CSS, **do NOT use CSS `background-image`** — it breaks in Paged.js due to DOM restructuring.

**Must use `<img>` + absolute positioning**:
```html
<div class="cover">
    <img class="cover-bg" src="image.jpg" alt="">
    <div class="cover-content">...</div>
</div>
```
```css
.cover-bg {
    position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    object-fit: cover; object-position: center; z-index: 0;
}
.cover-content {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
    z-index: 1; text-align: center; width: 80%;
    color: white; text-shadow: 1px 1px 4px rgba(0,0,0,0.6);
}
```
**Why?** Paged.js restructures DOM into `.pagedjs_page → .pagedjs_sheet → .pagedjs_area → .pagedjs_page_content`, breaking CSS backgrounds. `<img>` with `position: absolute` ensures full-page coverage.

#### Typography Standards
- **Fonts**: Serif preferred (Georgia, "Noto Serif SC")
- **Font sizes**: Body 11pt, subheadings 14pt, headings 18-20pt
- **Line height**: 1.5-1.6
- **Alignment**: If using `text-align: justify`, **must** add `text-align-last: left` to prevent short lines from stretching character spacing

---

## Paged.js Pagination Features

### @page Rules
```css
@page {
    size: A4;
    margin: 2.5cm 2cm;
    @top-center { content: string(doctitle); }
    @bottom-center { content: counter(page); }
}
@page :first {
    @top-center { content: none; }
    @bottom-center { content: none; }
}

/* Named pages: hide header/footer on cover and TOC (supports multi-page) */
@page cover { @top-center { content: none; } @bottom-center { content: none; } }
@page toc { @top-center { content: none; } @bottom-center { content: none; } }
.cover { page: cover; }
.toc-page { page: toc; }

/* CRITICAL: Prevent "undefined" in header before h1 appears */
body { string-set: doctitle ""; }
h1 { string-set: doctitle content(); }
```

### Key Properties
| Property | Purpose |
|----------|---------|
| `string-set: doctitle ""` | Set on body, empty default to prevent "undefined" |
| `string-set: doctitle content()` | Set on h1, updates header with actual title |
| `page: cover` / `page: toc` | Assign element to named page (hides header/footer) |
| `page-break-after: always` | Force page break |
| `page-break-inside: avoid` | Prevent tables/figures from breaking |
| `page-break-after: avoid` | Prevent heading-content separation |
| `orphans: 2; widows: 2` | Control orphan lines |

**`page-break-inside: avoid` principle**: Only use on small atomic components; large containers cause entire blank pages.
```css
/* Correct: Only protect small components */
figure, .theorem, .algorithm { page-break-inside: avoid; }
tr { page-break-inside: avoid; }  /* Single row doesn't break */

/* Wrong: Large containers cause blank pages */
.section, .chapter { page-break-inside: avoid; }

/* Repeat table headers across pages */
thead { display: table-header-group; }
```

**Unexpected blank pages?** Common causes: `page-break-after: always` after cover or consecutive `page-break`. Solution: Use CSS selectors for pagination (e.g., `.abstract:first-of-type { page-break-before: always; }`) instead of explicit `<div class="page-break">`.

### Advanced TOC (with Page Numbers)
Use `target-counter()` for TOC with page numbers and leader dots:
```css
.toc a::after {
    content: leader('.') target-counter(attr(href url), page);
}
```
TOC items **must** be `<a href="#section-id">`, not plain text.

### Cross-reference Page Numbers
```css
a.pageref::after {
    content: target-counter(attr(href url), page);
}
```

---

## Math Formulas (KaTeX)
Include KaTeX CSS and JS, use auto-render extension for automatic rendering of `$...$` (inline) and `$$...$$` (block).

**Colors**: Formulas default to black `#333`, **no** color highlighting.
**Equation numbering**: Use flex layout + `data-*` attributes for right-side numbering (CSS counter breaks with Paged.js).
**Note**: Conversion script automatically triggers KaTeX rendering. If source code still shows, check CDN accessibility and don't wrap `renderMathInElement` in `DOMContentLoaded`.

---

## Diagrams (Mermaid)

### CRITICAL: Height Constraint
**Mermaid SVG that exceeds page height will break Paged.js pagination**, causing "undefined" errors and blank pages.

**Layout Selection (MUST follow)**:
| Layout | When to Use | Height Risk |
|--------|-------------|-------------|
| `flowchart LR` | **Default choice** - horizontal flow | Low |
| `flowchart TB` | Only for very simple diagrams (≤6 nodes, no subgraph) | High |

**Complexity Limits**:
| Constraint | Limit | Reason |
|------------|-------|--------|
| Subgraphs | ≤ 3 | Each subgraph adds vertical height |
| Nodes per subgraph | ≤ 5 | Prevents overflow |
| Total nodes | ≤ 12 | Keeps diagram compact |
| `<br>` in node text | Avoid | Increases node height |

### Configuration
```javascript
mermaid.initialize({
    startOnLoad: true,
    theme: 'neutral',  // Required!
    themeVariables: {
        primaryColor: '#f5f5f5',
        primaryTextColor: '#333',
        primaryBorderColor: '#999',
        lineColor: '#666'
    }
});
```

### Prohibited
- **Themes**: `default` (too blue), `forest` (high saturation), `dark`
- **Beta features**: `xychart-beta`, etc.
- **`flowchart TB` with >6 nodes or any subgraph**

### Complex Diagrams: Use Tables Instead
For "technical roadmap", "research framework", "system architecture" with many steps:

**DON'T**: Single complex Mermaid with 6 subgraphs
**DO**: Table + simplified Mermaid

```html
<!-- Table for details + simple Mermaid for overview -->
<table>
<caption data-label="Table X">Technical Roadmap Phases</caption>
<thead><tr><th>Phase</th><th>Tasks</th><th>Output</th></tr></thead>
<tbody>
<tr><td>Data Collection</td><td>Crawl reviews, gather sales</td><td>Raw database</td></tr>
<tr><td>Data Processing</td><td>Clean, tokenize, label</td><td>Labeled dataset</td></tr>
...
</tbody>
</table>

<div class="mermaid">
flowchart LR
    A[Collection] --> B[Processing] --> C[Training] --> D[Evaluation]
</div>
```

### Debugging
If PDF shows "undefined" or blank pages around diagrams:
1. Diagram too tall → Switch to `flowchart LR`
2. Too many subgraphs → Reduce to ≤3 or use table
3. Still failing → Replace with table entirely

---

## Professional Components
Use these components appropriately for more complete, professional documents.

### Academic Essentials
| Component | Use Case | Key Points |
|-----------|----------|------------|
| **Three-line tables** | Data display | Booktabs style: thick lines above/below `thead/tbody`, no vertical lines; **add `max-width: 100%`** |
| **Figure/table numbering** | Figure/table captions | **Use `data-*` attributes** (CSS Counter breaks with Paged.js) |
| **Equation numbering** | Math formulas | **Use `data-*` attributes**, right-side (2-1) format |
| **Section numbering** | Section headings | **Write manually** or use `data-*` attributes |
| **Cross-references** | Reference figures/tables/equations/sections | **Must use `<a href="#id">`**, `id` at container top |
| **Table of contents** | Section navigation | **TOC items must be `<a href="#section-id">`** for clickability |
| **Lists of figures/tables** | Figure/table directories | Same as above, separate page listing all figures/tables |
| **References** | Academic citations | Write manually, black superscript style |
| **Footnotes** | Supplementary notes | Paged.js specific syntax `float: footnote` |

### Layout Enhancements
| Component | Use Case | Key Points |
|-----------|----------|------------|
| **Two-column layout** | Academic papers | `column-count: 2`, span columns with `column-span: all` |
| **Drop caps** | Chapter openings | `::first-letter` + `float: left`, enhances aesthetics |
| **Code highlighting** | Code display | Prism.js, **must use light theme** `#f5f5f5` |
| **Appendices** | Supplementary material | A, B, C letter numbering, write manually |

### Auto-numbering Standards
| Type | Method | Notes |
|------|--------|-------|
| Sections | Write manually | Linear writing less error-prone |
| Figures/tables/equations | **`data-*` attributes** | CSS Counter is broken by Paged.js DOM reordering |
| References | Write manually | Must be real, must verify via search |

#### Why Not CSS Counter?
**PROHIBITED**: Do NOT use `counter-reset`, `counter-increment`, or `content: counter(...)` anywhere in CSS. This includes custom step lists, numbered badges, or any decorative numbering.

Paged.js reorders DOM during pagination, which breaks CSS counters. Common symptoms:
- All numbers show as 0 (e.g., "Figure 0", "Table 0", "Step 0")
- Numbers reset unexpectedly mid-document

**Always write numbers explicitly** in HTML or use `data-*` attributes.

#### Recommended: `data-*` Attributes
```html
<!-- Figures -->
<figure id="fig-1">
    <img src="chart.png" alt="...">
    <figcaption data-label="Figure 1">System Architecture</figcaption>
</figure>

<!-- Tables -->
<table>
    <caption data-label="Table 1">Performance Comparison</caption>
    ...
</table>

<!-- Equations -->
<div class="equation" data-label="(1)">
    $$E = mc^2$$
</div>
```

**CSS 规则已包含在 base.css 中**（`figcaption::before`、`caption::before`、`.equation::after`），引入 base.css 后自动生效，**不需要手动写这些 CSS**。

**Anchor placement**: `id` goes on `<figure>` not `<figcaption>`, for correct jump positioning.

#### Prevent Overflow (CRITICAL)
**All block elements must not exceed page width.** base.css 已包含所有防溢出规则（`max-width: 100%`、`word-break`、`pre-wrap` 等），引入 base.css 后自动生效。

The conversion script auto-detects overflow and warns. Fix any reported elements.

#### Vertical Centering (CRITICAL)
**PROHIBITED**: Do NOT use `line-height` or `vertical-align: middle` for centering text in fixed-size containers. These depend on font baseline and are unreliable—text often appears off-center.

**Required**: Use flexbox. This applies to ALL fixed-size containers with centered content: step numbers, badges, tags, avatar placeholders, icon wrappers, etc.

```css
/* WRONG - text shifts with different fonts */
.step-number {
    width: 1.5em; height: 1.5em;
    line-height: 1.5em;
    text-align: center;
}

/* CORRECT - universal pattern for any centered container */
.step-number {
    width: 1.5em; height: 1.5em;
    display: inline-flex;
    align-items: center;
    justify-content: center;
}
```


### Reference Standards
**All citations must be real, no mocking**—must verify via search, fabricating any author, title, year, or page number is prohibited.

#### Strict Correspondence Constraint
In-text `<a href="#ref-1">[1]</a>` must strictly correspond to end-of-document `<li id="ref-1">`:
- `id` must be unique and matching
- No empty links or dangling references

#### Citation Style (Black Superscript)
```css
a.cite { color: black; text-decoration: none; vertical-align: super; font-size: 0.75em; }
```

#### Hanging Indent (Professional Typesetting Mark)
```css
.references li {
    padding-left: 2em;
    text-indent: -2em;
}
```

#### Citation Format Selection
| Scenario | Format |
|----------|--------|
| Chinese academic papers, coursework | GB/T 7714 (use [J][M][D] etc. document type identifiers) |
| English papers, international journals | APA format |
| Mixed Chinese/English | Chinese uses GB/T 7714, English uses APA |

#### Italics Rules (APA)
Book titles, journal names must be italicized, use `<i>` tag:
```html
<li id="ref-1">Raymond, E. S. (2003). <i>The Art of Unix Programming</i>. Addison-Wesley.</li>
<li id="ref-2">Vaswani, A., et al. (2017). Attention is all you need. <i>NeurIPS</i>, 30, 5998-6008.</li>
```
**Italics scope**: Book titles, Journal names (yes), Article titles, Publishers (no)

### Footnotes (Paged.js Specific Syntax)
```css
.footnote-ref { float: footnote; }
.footnote-ref::footnote-call { content: counter(footnote); vertical-align: super; font-size: 0.75em; }
.footnote-ref::footnote-marker { content: counter(footnote) ". "; }
@page { @footnote { margin-top: 1em; border-top: 1px solid #ccc; padding-top: 0.5em; } }
```
```html
Body text<span class="footnote-ref">This is footnote content, automatically typeset at page bottom</span>.
```

### Table of Contents (Must Use Links for Clickability)
```html
<!-- Correct: Use <a> links -->
<ul class="toc">
    <li><a href="#sec1">1. Introduction</a></li>
    <li><a href="#sec2">2. Methods</a></li>
</ul>

<!-- Wrong: Plain text not clickable -->
<div class="toc-item">1. Introduction</div>
```
```css
/* TOC item: title + leader dots + auto page number */
.toc a::after {
    content: leader('.') target-counter(attr(href url), page);
}
```
**Wrong page numbers?** Use `target-counter()` instead of hardcoded page numbers; Paged.js calculates automatically.

### CJK Fonts
Server needs CJK fonts installed or use web fonts:
```html
<link href="https://fonts.googleapis.com/css2?family=Noto+Serif+SC&display=swap" rel="stylesheet">
```

### RTL Languages (Arabic, Persian, Hebrew)
```html
<html dir="rtl" lang="fa">
```
```css
body { direction: rtl; text-align: right; }
.toc a { display: flex; flex-direction: row-reverse; }
```
**Note**: Paged.js has limited support for RTL `leader('.')`. TOC may need table layout instead.

---

## Script Reference

| Script | Purpose |
|--------|---------|
| `html_to_pdf.js` | HTML to PDF (Playwright + Paged.js), includes page/word count and anomaly detection |
| `link_injector.js` | Link mapping and injection module (used by html_to_pdf.js with --preserve-links) |

## Tech Stack

| Library | Purpose | License |
|---------|---------|---------|
| Playwright | Browser automation | Apache-2.0 |
| Paged.js | CSS Paged Media polyfill | MIT |
| KaTeX | Math formula rendering | MIT |
| Mermaid | Diagram rendering | MIT |
| pdf-lib (optional) | PDF link injection | MIT |

---

## Important Notes

### Resource Requirements
| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 1 GB | 2+ GB |
| Disk | 500 MB (Chromium) | 1 GB |

**Chromium memory**: ~200-500MB per conversion. For large documents (50+ pages), expect higher usage.

### Large Document Strategy
For documents exceeding 50 pages:
1. **Split into sections**: Write separate HTML files, merge PDFs afterward
2. **Reduce complexity**: Fewer Mermaid diagrams, simpler tables
3. **Increase timeout**: Default 120s may not suffice

### Offline Operation
The conversion script bundles Paged.js locally (`paged.polyfill.js`). However:
- **KaTeX**: Requires CDN or local bundle
- **Mermaid**: Requires CDN or local bundle
- **Web fonts**: Require network or local installation

For fully offline operation, include KaTeX/Mermaid JS/CSS in your HTML file directly.

### Common Failure Modes
| Symptom | Cause | Solution |
|---------|-------|----------|
| Blank PDF | Paged.js timeout | Simplify content, increase timeout |
| "undefined" in PDF | Mermaid too tall | Use `flowchart LR`, reduce nodes |
| Missing fonts | CJK not installed | Install fonts or use web fonts |
| Truncated content | Element overflow | Add `max-width: 100%` |
| Numbers show as 0 | CSS Counter broken by Paged.js | Use `data-*` attributes or write numbers explicitly |
| Text off-center in circles | `line-height` centering unreliable | Use `display: inline-flex` + `align-items/justify-content: center` |
