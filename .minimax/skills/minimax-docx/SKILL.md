---
name: minimax-docx
description: "Professional Word document processing skill from MiniMax. Generate and edit Word documents (.docx). MUST be loaded for ANY Word/DOCX-related tasks. Supports professional documents including covers, charts, track-changes editing, and more. Suitable for any .docx creation or modification task. Tech stack: C# + OpenXML SDK (creation) / Python + lxml (editing), with complete validation toolchain (oxml build/validate). NOTE: This skill cannot be used standalone - it must be used within the 'docx processor' subagent."
---

<role>
You are a world-class document designer with expertise in professional Word document creation. You can handle a wide range of document-related tasks, especially those involving .docx files. Your goal is to deliver studio-quality, professionally designed Word documents.

- You must eventually deliver a Word document (.docx file)
- Ensure the overall deliverable is **professional** and **complete**, not template filling
- Default to adding professional elements: covers, TOC, headers/footers, page numbers

</role>

<Pre-Execution Rules>

## ⚠️ Pre-Execution Rules (Violating Any = Bug)

| # | Rule | Reason |
|---|------|--------|
| 1 | **Check dependencies first**: Run `python3 tools/oxml.py env`, if any required dependency missing, run `python3 tools/oxml.py init` | Build will fail without .NET SDK and lxml |
| 2 | **Always read first**: `CodingGuide.md` + `PitfallGuide.md` + `Quotes.cs` + `EditingGuide.md` | Contains critical patterns for both C# and Python |
| 3 | Build (C#): `python3 tools/oxml.py build` (never direct `dotnet`) | Script handles dependencies and validation |
| 4 | Validate (Python): `python3 tools/oxml.py validate <output.docx>` | Same validation as C# flow |
| 5 | Chinese quotes: `\u201c` `\u201d` (never `@""`) | Compiler treats them as string delimiters |
| 6 | Method calls: Verify parameter count against signature | Avoid CS1501 errors |
| 7 | Uncertain API: Check guides or example code | Never code from memory |
| 8 | Insert images: Read dimensions dynamically (never hardcode) | Avoid aspect ratio distortion |

</Pre-Execution Rules>

<Technology Stack>

## Technology Stack

| Task | Stack | Reference |
|------|-------|-----------|
| **Create new document** | C# + OpenXML SDK | `Sample.cs`, `Quotes.cs` |
| **Edit existing document** | Python + lxml | `references/EditingGuide.md` |

⚠️ **Never mix these.** Never use python-docx/docx-js.

### Markdown ↔ DOCX Conversion Rules

| Scenario | Allowed Method | Forbidden |
|----------|----------------|-----------|
| **User input is Markdown, wants DOCX** | Pandoc → DOCX, then C#/Python+lxml to adjust | — |
| **User input is DOCX, need to understand structure** | Unzip + Python lxml | Pandoc docx→md for structure analysis |
| **Temporarily converted MD from DOCX** | View only | **NEVER convert back to DOCX for delivery** |

⚠️ **Critical Rules:**
1. **DOCX → MD loses information.** Pandoc's docx-to-markdown is for basic text extraction ONLY. Any complex operations (styles, layout, structure) MUST unzip and parse XML with lxml.
2. **MD → DOCX is one-way.** Only use Pandoc md→docx when user provides markdown and wants it converted to docx.
3. **Never round-trip.** If you converted a user's DOCX to MD for viewing, that MD is READ-ONLY. Delivering it back as DOCX = data loss.

### How to Read DOCX Content

| Need | Method |
|------|--------|
| Text content only (summarize, analyze, translate) | Read tool is fine |
| **Any structural understanding** | **Unzip + Python lxml (ALWAYS prefer this)** |
| Need formatting info (copy styles, preserve layout) | Unzip and parse XML (Python + lxml) |
| Last resort: quick text-only preview | `pandoc input.docx -t markdown` (highly restricted) |

**⚠️ Pandoc docx→md Restrictions:**
- **Disabled by default** — always prefer unzip + lxml to parse XML directly
- Only consider when you need plain text preview with NO subsequent operations
- Output markdown is for human reading only, forbidden for any programmatic processing
- For tables, styles, paragraph structure, etc., **MUST use lxml to parse raw XML**

**⚠️ Never use `convert_docx_to_md`** — loses formatting information.

### Python Editing Setup

```bash
# From skill directory (auto-detected by oxml.py)
python3 -c "import sys; sys.path.insert(0, 'tools'); from core.markup import DocxSession, add_comment, insert_text"
```

</Technology Stack>

<Reference Document Index>

## Reference Document Index

| Document | Content | When to Read |
|----------|---------|--------------|
| `references/CodingGuide.md` | C# coding standards, API reference, common errors | **Before writing any code** |
| `references/PitfallGuide.md` | Common mistakes, wrong vs correct patterns | **Before writing any code** |
| `references/DesignGuide.md` | Design standards, colors, typography, backgrounds | When designing document appearance |
| `references/EditingGuide.md` | Python editing, comments, track changes | When editing existing docx |
| `templates/ColorSchemes.cs` | 21 color palettes (Morandi, Corporate, RedPower, etc.) | When choosing document colors |
| `templates/Quotes.cs` | CJK content patterns (quote escaping, fonts) | **Before writing any code** |
| `templates/Sample.cs` | Complete example (cover→TOC→body→back cover) | When learning document structure |

</Reference Document Index>

<File Structure>

## File Structure

```
minimax-docx/
├── SKILL.md                      ← Entry point (this file)
├── references/
│   ├── CodingGuide.md            → C# coding standards, API reference
│   ├── PitfallGuide.md           → Common mistakes, wrong vs correct patterns
│   ├── DesignGuide.md            → Design standards, colors, typography
│   └── EditingGuide.md           → Python editing tutorial (uses core.markup)
├── tools/
│   ├── oxml.py                   → Cross-platform entry script (build/validate)
│   ├── check_all.py              → Unified validation
│   ├── render_covers.py          → Background image generation (Morandi style)
│   ├── render_charts.py          → Complex charts via matplotlib
│   ├── color_schemes.py          → Python color palettes
│   └── core/                     → Python core library
│       ├── namespaces.py         → XML namespace definitions
│       ├── schema_fixer.py       → Element order auto-fix logic
│       ├── integrity.py          → Business rule validation logic
│       └── markup/               → High-level editing API
├── templates/
│   ├── Sample.cs                 → Complete example (cover→TOC→body→back cover)
│   ├── Quotes.cs                 → CJK content patterns (MUST READ)
│   ├── ColorSchemes.cs           → 21 color palettes
│   └── DocxEntry.cs              → Empty entry template
└── docxchecker/                  → OpenXML validator DLLs
```

</File Structure>

<Build Process>

## Build Process

**Must use `python3 tools/oxml.py build`**, never direct `dotnet build && dotnet run`.

| Step | Description |
|------|-------------|
| 1. Compile | `dotnet build` |
| 2. Generate | `dotnet run -- <output path>` |
| 3. Auto-fix | `repair_schema.py` |
| 4. OpenXML validation | Must pass |
| 5. Business rule validation | Must pass |

### Environment Setup

**Before any build operation, you MUST ensure all dependencies are installed.**

#### Step 1: Check Environment
```bash
python3 tools/oxml.py env   # Shows dependency status
```

#### Step 2: Initialize (if dependencies missing)
```bash
python3 tools/oxml.py init  # Auto-installs missing dependencies
```

#### Required Dependencies

| Dependency | Purpose | Auto-Install | Manual Install |
|------------|---------|--------------|----------------|
| **.NET SDK 6+** | C# compilation & document generation | ✓ via `oxml.py init` | [dotnet.microsoft.com](https://dotnet.microsoft.com/download) |
| **Python 3.8+** | Script execution | ✗ | System package manager |
| **lxml** | XML parsing for document editing | ✓ via `oxml.py init` | `pip install lxml` |

#### Optional Dependencies

| Dependency | Purpose | Install Command |
|------------|---------|-----------------|
| **pandoc** | Content verification, MD↔DOCX conversion | `brew install pandoc` / `apt install pandoc` |
| **matplotlib** | Complex chart generation | `pip install matplotlib numpy` |
| **playwright** | Background image rendering | `pip install playwright && playwright install` |

⚠️ **If `oxml.py init` fails**: Check network connectivity and manually install dependencies listed above.

### Path Conventions (Dynamic)

The `oxml.py` script dynamically determines paths:

| Variable | Source | Example |
|----------|--------|---------|
| `SKILL_DIR` | `Path(__file__).parent.parent` | `.minimax/skills/minimax-docx/` |
| `WORKSPACE_DIR` | `$WORKSPACE_DIR` env or `cwd()` | `/Users/john/project/` |
| `WORK_DIR` | `{WORKSPACE_DIR}/.oxml/` | `/Users/john/project/.oxml/` |
| `OUTPUT_DIR` | `{WORKSPACE_DIR}/output/` | `/Users/john/project/output/` |

**Run `python3 tools/oxml.py env` to see resolved paths.**

</Build Process>

<Design Standards>

## Design Standards (Required by Default)

**核心原则：专业交付 ≠ 模板填充。** Unless user explicitly declines, these elements are MANDATORY:

| Element | Description | Why |
|---------|-------------|-----|
| **页码** | Footer centered or bottom-right | Basic navigation |
| **页眉** | Document title/chapter/org name | Document identity |
| Cover/back cover | Professional background image | First/last impression |
| TOC | For documents with 3+ chapters | Navigation |

⚠️ **缺少页眉页脚页码 = 半成品**

### Design Principles

- **Low saturation colors** (avoid Word default blue)
- **⚠️ White space is NON-NEGOTIABLE**
  - Margins: Top≥90pt, Left/Right/Bottom≥72pt
  - Paragraph spacing: Body After≥10pt, Heading Before≥20pt
  - Line spacing: Body≥1.5x, never single-spaced
- **Clear hierarchy** (H1 > H2 > body)

### Pagination Control

| Element | Required Property | Purpose |
|---------|-------------------|---------|
| H1 heading | `PageBreakBefore` + `KeepNext` | Chapter separation |
| H2/H3 heading | `KeepNext` | Bind with following content |
| Table/image intro | `KeepNext` | Keep with table/image |

</Design Standards>

<Technical Reference>

## Key Schema Rules

| Parent | Rule |
|--------|------|
| `sectPr` | `headerRef` → `footerRef` before `pgSz` → `pgMar` |
| `Table` | Must have `tblGrid` between `tblPr` and `tr` |

## Table Requirements

```csharp
var table = new Table();
table.Append(new TableProperties(...));
table.Append(new TableGrid(           // Required!
    new GridColumn { Width = "4680" },
    new GridColumn { Width = "4680" }
));
table.Append(new TableRow(...));
```

## Sample.cs Function Index

| Feature | Function |
|---------|----------|
| Style definitions | `AddStyles()` |
| Cover page | `AddCoverSection()` |
| Table of contents | `AddTocSection()` |
| Body content | `AddContentSection()` |
| Back cover | `AddBackcoverSection()` |
| Floating background | `BuildFloatingBackground()` |
| Inline image | `AddInlineImage()` |
| Charts | `AddPieChart()`, `AddBarChart()` |

</Technical Reference>

<Validation Checklist>

## Pre-Delivery Checklist

| Item | Requirement |
|------|-------------|
| Chinese quotes `""` | Punctuation → `\u201c\u201d`; Text → keep as literal |
| Bookmark | Place directly in Paragraph, never in pPr |
| docPr ID | Must be globally unique (`docPrId++`) |
| Background images | Call `tools/render_covers.py` |
| Headers/Footers | Must exist (not half-finished) |
| Page numbers | Must exist in footer |

**Validate with pandoc before delivery:**
```bash
pandoc output.docx -t plain   # Verify content completeness
```

</Validation Checklist>
