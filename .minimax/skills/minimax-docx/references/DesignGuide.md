# Document Design Guide

---

## 1. Delivery Standards

**Generic styling = mediocre delivery.** Deliver studio-quality documents with deep thought on content, functionality, and styling.

### Required Elements by Default

| Element | Applicable Scenarios | Notes |
|---------|---------------------|-------|
| Cover/back cover | Formal documents (proposals, reports, contracts), creative documents (invitations) | Must have designer-quality background images |
| Header/footer | Almost all documents | Header: title/company name; Footer: page numbers |
| TOC | Long documents (3+ sections) | Must include refresh hint |

### Language Consistency

**Document language = User conversation language** (including filename, body text, headings, headers, TOC hints, chart labels, and all other text)

---

## 2. Color Schemes

**Low saturation tones**, avoid Word default blue and matplotlib default high saturation.

**Code Reference**: See `templates/ColorSchemes.cs` for all color definitions.

### Base Palettes (11)

| Style | Color Characteristics | Suitable Scenarios |
|-------|----------------------|-------------------|
| Morandi | Soft muted tones | Artistic, editorial |
| InkWash | Gray, zen tones | Traditional, contemplative |
| Corporate | Professional blue | Business, enterprise |
| Earth | Brown, olive, natural | Environmental, organic |
| Nordic | Cool gray, misty blue | Minimalist, tech |
| French | Off-white, dusty pink | Luxury, feminine |
| Industrial | Charcoal, rust, concrete | Manufacturing, engineering |
| Academic | Navy, burgundy, ivory | Research, education |
| Ocean | Misty blue, sand | Marine, wellness |
| Forest | Olive, moss green | Nature, sustainability |
| Desert | Ochre, sandy gold | Warm, regional |

### Extended Palettes (10)

| Style | Color Characteristics | Suitable Scenarios |
|-------|----------------------|-------------------|
| RedPower | China red, gold | Government, Party documents |
| Luxury | Black, gold | VIP invitations, real estate |
| Vibrant | Yellow, black | Recruitment, promotions |
| Innovation | Indigo, violet | Tech, SaaS, startups |
| Clinical | Teal, white | Medical, pharmaceutical |
| Minimalist | Monochrome | Resumes, legal, architecture |
| Vitality | Orange, green | Food, wellness, community |
| Midnight | Dark slate, neon | Cyber, gaming, developer |
| CoralReef | Coral, pink | Beauty, fashion, lifestyle |
| Financial | Deep green, slate | Banking, investment |

**Color scheme must be consistent within the same document.**

---

## 3. Background Image Design

### Design Flow

1. **Read example**: `tools/render_covers.py` to understand HTML/CSS techniques
2. **Choose direction**: Select style based on document scenario
3. **Create original**: Write new HTML/CSS from scratch, don't copy the example

⚠️ **Copying the example = all documents look the same = mediocre delivery**

### Style Reference

| Style | Key Elements | Scenarios |
|-------|--------------|-----------|
| MUJI | Thin borders + white space | Minimalist, Japanese |
| Bauhaus | Scattered geometric shapes | Art, design |
| Swiss Style | Grid lines + accent bars | Professional, corporate |
| Soft Blocks | Soft color rectangles, overlapping transparent | Warm, education |
| Rounded Geometry | Rounded rectangles, pill shapes | Tech, internet |
| Frosted Glass | Blur + transparency + subtle borders | Modern, premium |
| Gradient Ribbons | Soft gradient ellipses + small dots | Feminine, beauty |
| Dot Matrix | Regular dot pattern texture | Technical, data |
| Double Border | Nested borders + corner decorations | Traditional, legal |
| Waves | Bottom SVG waves + gradient background | Ocean, flowing |

### Technical Specs

- Playwright generates 794×1123px (`device_scale_factor=2`)
- Insert as floating Anchor with `BehindDoc=true`
- See `Sample.cs:BuildFloatingBackground()`
- **Background images must NOT contain text** (implement text in Word for editability)

---

## 4. Design Philosophy (Word Constraints & Strategies)

**技术规范是底线，不是上限。** OpenXML 规范解决的是"文档能不能打开"，不是"好不好看"。颜色要用 6 位十六进制，但选 `#1E3A5F` 还是 `#FF0000` 完全自由。

### Word 的隐性设计约束

| 约束类型 | 具体表现 | 对设计的影响 |
|---------|---------|------------|
| 字体安全 | 只能用系统预装字体 | 不能用"站酷高端黑"等设计字体 |
| 图形能力 | OpenXML 不支持复杂矢量图 | 不能用渐变形状、毛玻璃效果 |
| 版式限制 | 流式布局，非固定定位 | 不能像 InDesign 那样精确到像素 |
| 交互缺失 | 纯静态文档 | 不能有悬停效果、动态图表 |

### 在约束内做设计

既然 Word 原生图形能力有限，就**用色块、边框、留白来营造层次感**：

- **减少图形依赖** → 用排版本身做设计
- **文字即设计** → 字号对比、字重变化、颜色层级，OpenXML 完全支持
- **留白=专业度** → 模块间距、标题背景块，紧凑=廉价感
- **行业适配** → 场景决定风格，过度设计反而减分

**记住：在 Word 文档的语境下做到天花板，比追求 InDesign 效果更实际。**

---

## 5. Typography Standards

### Font Size Principle

**标题字号取决于它和什么共处一页。** 独立封面可大（36-48pt），混排页面（报纸、正文章节）需克制（报头24-32pt，章标题16-22pt），否则挤压其他内容。

### Layout Principles

- **White space**: Margins, paragraph spacing
- **Hierarchy**: H1 > H2 > body
- **Padding**: Text shouldn't touch borders

### Pagination Control

| Property | XML | Effect |
|----------|-----|--------|
| Keep with next | `<w:keepNext/>` | Heading stays on same page as following paragraph |
| Keep lines together | `<w:keepLines/>` | Paragraph won't break across pages |
| Page break before | `<w:pageBreakBefore/>` | Force new page (for H1) |
| Widow/orphan control | `<w:widowControl/>` | Prevent single lines at top/bottom of page |

### Table Pagination

```csharp
// Allow row to break across pages (avoid large blank areas)
new TableRowProperties(new CantSplit { Val = false })

// Repeat header row on each page
new TableRowProperties(new TableHeader())
```

### CJK Typography

- Body: Justify + 2-character first line indent
- English: Left align
- Table numbers: Right align
- Headings: No indent

---

## 6. Professional Elements

### Chart Selection

| Type | Method | Notes |
|------|--------|-------|
| Pie/bar/line charts | **Word native** | Editable, small file size |
| Heatmap/3D/radar | matplotlib | Word doesn't support |

Prefer native charts (editable, smaller files). matplotlib acceptable for data analysis scenarios.

### Table Styling

- Use light gray headers or three-line style
- Avoid Word default blue

### Links and References

- URLs must be clickable hyperlinks
- Multiple figures/tables add numbering and cross-references
- Academic/legal scenarios implement proper footnotes/endnotes

### TOC Refresh Hint

```
Table of Contents
─────────────────
Chapter 1 Overview .......................... 1
Chapter 2 Methods ........................... 3
...

(Hint: On first open, right-click the TOC and select "Update Field" to show correct page numbers)
```

Hint text: Gray color, smaller font size, unobtrusive

---

## 7. Content Constraints

### Word/Page Count Requirements

| User Request | Execution Standard |
|--------------|-------------------|
| Specific word count (e.g., "3000 words") | Actual output within ±20% |
| Specific page count (e.g., "5 pages") | Exact match |
| Range (e.g., "2000-3000 words") | Within range |
| Minimum (e.g., "at least 5000 words") | No more than 2x the requirement |

**Forbidden**: Padding word count with excessive bullet point lists

### Outline Adherence

- **User provides outline**: Follow strictly, no additions, deletions, or reordering
- **No outline provided**: Use standard structure
  - Academic: Introduction → Literature → Methods → Results → Discussion → Conclusion
  - Business: Executive Summary → Analysis → Recommendations
  - Technical: Overview → Principles → Usage → Examples → FAQ

### Scene Completeness

Think one step ahead of the user. Examples (not exhaustive):

- **Exam paper** → Name/class/ID fields, point allocation, grading section
- **Contract** → Signature areas for both parties, date, contract number, attachment list
- **Meeting minutes** → Attendees, absentees, action items with owners, next meeting time

---

## 8. Only Add When User Explicitly Requests

| Feature | Reason |
|---------|--------|
| Watermark | Changes visual state |
| Document protection | Restricts editing |
| Mail merge fields | Requires data source |
