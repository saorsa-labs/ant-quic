# Pitfall Guide - Common Mistakes & Correct Patterns

> This guide is compiled from real user feedback. All issues listed have high occurrence rates.

---

## 1. FontSize is Half-Points

**FontSize.Val uses half-points, NOT points!**

| Val | Actual Size | Use Case |
|-----|-------------|----------|
| `"144"` | 72pt | Extra large title |
| `"72"` | 36pt | Large title |
| `"44"` | 22pt | Medium title |
| `"24"` | 12pt | Body text |
| `"22"` | 11pt | Body text |
| `"20"` | 10pt | Footnote |

```csharp
// ❌ Wrong - Expecting Val="44" to be 44pt
new FontSize { Val = "44" }  // Actually only 22pt!

// ✓ Correct - For 44pt, set Val to 88
new FontSize { Val = "88" }  // 44pt
```

**Formula**: `Val = pt × 2`

---

## 1.5. 空白控制

**禁止用大字号的空行/空格撑空白。** 要留白用 `SpacingBetweenLines.Before/After`，不要创建72pt的空Run。

`Before = "6000"` 这种巨大段前间距，只适用于页面内容很少的场景。用之前先估算：这一页还要放多少内容？放得下吗？

---

## 1.6. TOC必须用Field Code

**禁止用超链接列表模拟目录。** 必须用 `FieldChar(Begin) → FieldCode(" TOC \\o \"1-3\" ") → FieldChar(Separate) → ... → FieldChar(End)` 结构，见 `Sample.cs:AddTocSection()`。

---

## 2. Landscape Page Setup
**Key**: Width/Height values are swapped from portrait.

```csharp
// ❌ Wrong - Using portrait dimensions directly
new PageSize { Width = 11906, Height = 16838 }  // Still portrait!

// ✓ Correct - Swap dimensions + set Orient
new PageSize {
    Width = (UInt32Value)16838U,   // Portrait height → Landscape width
    Height = (UInt32Value)11906U,  // Portrait width → Landscape height
    Orient = PageOrientationValues.Landscape
}
```

**Landscape Checklist**:
- [ ] PageSize.Width = Portrait height value
- [ ] PageSize.Height = Portrait width value
- [ ] PageSize.Orient = Landscape
- [ ] SectionProperties placed at end of Body

---

## 3. C# Constructor Multi-Element Syntax
**OpenXML constructors accept multiple child elements. Bracket positions are error-prone.**

```csharp
// ❌ Wrong - Closing bracket misplaced
new Run(new RunProperties(new Bold(), new Color { Val = "333333" }),
new Text("content")
));  // Extra closing bracket

// ✓ Correct - All child elements at same bracket level
new Run(
    new RunProperties(new Bold(), new Color { Val = "333333" }),
    new Text("content")
)

// ❌ Wrong - Missing Append closing bracket
body.Append(new Paragraph(
    new Run(new Text("content"))
);

// ✓ Correct - Complete bracket closure at each level
body.Append(new Paragraph(
    new Run(new Text("content"))
));
```

**Tip**: Use IDE auto-format to align brackets.

---

## 4. Working Directory
**`python3 tools/oxml.py build` reads from `{WORKSPACE}/.oxml/` directory.**

Paths are dynamically resolved. Run `python3 tools/oxml.py env` to see current paths.

```bash
# Standard workflow
1. Edit file: {WORKSPACE}/.oxml/DocxEntry.cs
2. Build: python3 tools/oxml.py build output/doc.docx
3. Verify: pandoc {WORKSPACE}/output/doc.docx -t plain

# Backup if needed (optional)
cp {WORKSPACE}/.oxml/DocxEntry.cs {WORKSPACE}/backup/
```

⚠️ **Note**: Hardcoded paths like `/workspace/` or `/tmp/docx-work/` are deprecated.

---

## 5. Multi-Column Layout
**Columns are set via SectionProperties.**

```csharp
// Option 1: True columns (recommended)
new SectionProperties(
    new Columns { ColumnCount = (Int16Value)2, Space = "720" },  // 2 cols, 720 twips gap
    new PageSize { ... },
    new PageMargin { ... }
)

// Option 2: Table-simulated columns (better compatibility)
var table = new Table(
    new TableProperties(new TableBorders()),
    new TableGrid(
        new GridColumn { Width = "4680" },
        new GridColumn { Width = "4680" }
    ),
    new TableRow(
        new TableCell(new Paragraph(new Run(new Text("Left column")))),
        new TableCell(new Paragraph(new Run(new Text("Right column"))))
    )
);
```

⚠️ **Note**: A single Paragraph won't auto-break across columns.

---

## 6. Compile Error Quick Reference

| Error Code | Meaning | Solution |
|------------|---------|----------|
| CS1003 | Chinese quotes as delimiter | Use `\u201c\u201d` escaping |
| CS0246 | Type not found | Check namespace or use full qualified name |
| CS1026 | Missing closing bracket | Check constructor bracket matching |
| CS1501 | Wrong argument count | Check correct signature in Sample.cs |
| CS0029 | Type conversion failed | Use `(UInt32Value)(uint)` |
| CS0104 | Ambiguous call | Use namespace aliases `DW.`/`A.` |

---

## 7. Wrong vs Correct Patterns Summary

### 7.1 FontSize

```csharp
// ❌ Wrong
new FontSize { Val = "36" }  // Expecting 36pt, gets 18pt

// ✓ Correct
new FontSize { Val = "72" }  // For 36pt
```

### 7.2 Type Conversion

```csharp
// ❌ Wrong
new TableRowHeight { Val = 400 }

// ✓ Correct
new TableRowHeight { Val = (UInt32Value)(uint)400 }

// ❌ Wrong - Conditional without cast
new TableRowHeight { Val = row == 0 ? 400 : 300 }

// ✓ Correct
new TableRowHeight { Val = (UInt32Value)(uint)(row == 0 ? 400 : 300) }
```

### 7.3 Table Width Matching

```csharp
// ❌ Wrong - GridColumn and TableCellWidth type mismatch
new GridColumn { Width = "2500" };  // Pct implied
new TableCellWidth { Width = "4680", Type = TableWidthUnitValues.Dxa };

// ✓ Correct - Same value and type
int[] widths = { 2000, 3680, 3680 };
new GridColumn { Width = widths[0].ToString() };
new TableCellWidth { Width = widths[0].ToString(), Type = TableWidthUnitValues.Dxa };
```

### 7.4 Chinese Quotes

```csharp
// ❌ Wrong - CS1003 compile error
new Text("Click "OK" button")

// ✓ Correct
new Text("Click \u201cOK\u201d button")
```

### 7.5 Bookmark Placement

```csharp
// ❌ Wrong - Inside ParagraphProperties
new Paragraph(
    new ParagraphProperties(
        new BookmarkStart { Id = "100", Name = "Fig1" }
    ),
    ...
)

// ✓ Correct - Direct child of Paragraph
new Paragraph(
    new ParagraphProperties(...),
    new BookmarkStart { Id = "100", Name = "Fig1" },
    new Run(new Text("Figure 1")),
    new BookmarkEnd { Id = "100" }
)
```

### 7.6 Page Break

```csharp
// ❌ Wrong - Class doesn't exist
new PageBreak()

// ✓ Correct
new Run(new Break { Type = BreakValues.Page })
```

### 7.7 Justification Values

```csharp
// ❌ Wrong - Enum value doesn't exist
new Justification { Val = JustificationValues.Justify }

// ✓ Correct - "Both" means justified
new Justification { Val = JustificationValues.Both }
```

---

## 8. Color Recommendations

**Use low saturation colors for legal/formal documents:**

```csharp
// ❌ Avoid
new Color { Val = "FF0000" }  // Pure red, too bright
new Color { Val = "0066CC" }  // Pure blue, too vivid

// ✓ Recommended
new Color { Val = "4A6B4A" }  // Soft olive green (for "New" labels)
new Color { Val = "5A6B7A" }  // Muted gray-blue (for "Revised" labels)
new Color { Val = "1A1A2E" }  // Dark gray (body text)
new Color { Val = "5a6b62" }  // Neutral gray (secondary text)
```

**See `templates/ColorSchemes.cs` for Corporate color scheme.**

---

## 9. Schema Auto-Fix Limitations

The `python3 tools/oxml.py build` auto-fixes element order issues, but **cannot fix**:

| Auto-Fixed | NOT Auto-Fixed |
|------------|----------------|
| Element order in RunProperties | Table width type mismatch |
| Element order in SectionProperties | Missing TableGrid |
| HeaderRef/FooterRef ordering | Duplicate docPr IDs |

**Best Practice**: Write code in correct order from the start rather than relying on auto-fix.
