// Quotes.cs - 中文学术研究报告示例（含引号处理）
// 场景：学术研究报告
// 配色：Academic 学术配色方案
//
// ============================================================================
// ⚠️ CJK 核心规则（必读）
// ============================================================================
//
// 1. 中文引号 "" 会导致 CS1003 编译错误
//    ❌ new Text("请点击"确定"按钮")     // 编译失败
//    ✓  new Text("请点击\u201c确定\u201d按钮")  // 使用 Unicode 转义
//
// 2. 禁止使用 @"" 逐字字符串（\u 转义不生效）
//    ❌ @"她说\u201c你好\u201d"  → 输出原始 \u201c
//    ✓  "她说\u201c你好\u201d"   → 输出 "你好"
//
// 3. 长文本用 + 拼接，中文字体用 SimHei(黑体)/Microsoft YaHei(雅黑)
//
// ============================================================================
// 函数索引（按功能分类）- 学术研究报告场景
// ============================================================================
//
// 【文档结构】
// Generate()                    主入口，组装完整文档
// AddStyles()                   样式定义（Normal, Heading1-3, Caption, TOC）
// AddNumbering()                编号定义（有序列表）
//
// 【页面区块】
// AddCoverSection()             封面（背景图+标题+机构+日期）
// AddTocSection()               目录（学术报告结构）
// AddContentSection()           正文（研究背景/文献综述/研究方法/实验分析）
// AddBackcoverSection()         封底（学术机构信息）
//
// 【视觉元素】
// BuildFloatingBackground()     浮动背景图（置于文字下方）
// AddImage()                    添加图片到文档
// AddPieChart()                 饼图（数据集来源分布）
// BuildPieChartSpace()          饼图数据结构
//
// 【表格】- 学术论文风格
// BuildModelComparisonTable()   模型对比表格（参数量/BLEU/年份）
// BuildExperimentResultTable()  实验结果表格（配置/准确率/备注）
// BuildTableHeaderRow()         表头行（三线表样式）
// BuildTableDataRow()           数据行
//
// 【辅助函数】
// BuildHeading1/2/3()           标题构建（带书签）
// BuildNumberedItem()           编号列表项
// BuildPageNumberRun()          页码域代码
// BuildTotalPagesRun()          总页数域代码
// BuildCrossReference()         交叉引用
// AddFootnote()                 脚注
// SetUpdateFieldsOnOpen()       设置打开时更新域
//
// 【页面尺寸】
// BuildPortraitPageSize()       竖版页面尺寸
// BuildLandscapePageSize()      横版页面尺寸（宽高互换+Orient）
//
// 【表格管理】
// BuildPercentTableWidth()      百分比表格宽度（0-100）
// BuildFixedTableWidth()        固定表格宽度（Twips）
// BuildPercentCellWidth()       百分比单元格宽度
// BuildFixedCellWidth()         固定单元格宽度
// BuildFixedTableLayout()       固定布局（列宽不随内容变）
// BuildHorizontalMerge()        水平合并（跨列 GridSpan）
// BuildVerticalMergeStart()     垂直合并起始
// BuildVerticalMergeContinue()  垂直合并后续
//
// 【目录与大纲】
// BuildTocFieldStart()          TOC域开始（可配置级别范围）
// BuildTocFieldEnd()            TOC域结束
// BuildTocEntry()               目录条目（可配置样式前缀）
// BuildHeadingProps()           标题段落属性（含OutlineLevel）
// BuildHeadingWithBookmark()    带书签的标题（目录跳转）
// BuildFieldCode()              通用域代码（PAGE/DATE等）
//
// 【引用】
// BuildBookmark()               创建书签锚点（start, end）
// BuildPageRef()                PAGEREF域（引用页码）
// BuildCrossReference()         REF域（引用内容）
//
// 【字体与文字】
// BuildFonts()                  中英文混排字体
// BuildFontSize()               字号（输入pt值）
// BuildRunProps()               完整RunProperties（字体/字号/颜色/粗斜体）
//
// 【段落格式】
// BuildSpacing()                段落间距（段前/段后/行距倍数）
// BuildIndent()                 缩进（左缩进/首行缩进）
// BuildChineseBodyIndent()      中文正文标准缩进（首行2字符）
//
// 【分页分节分栏】
// BuildPageBreak()              分页符
// BuildColumnBreak()            分栏符
// BuildSectionBreak()           分节符段落
// BuildSectionProps()           完整分节属性（尺寸/方向/分栏）
// BuildEqualColumns()           等宽分栏
// BuildSectionEndParagraph()    结束当前节的段落
//
// 【页边距】
// BuildPageMargin()             页边距（输入pt值）
// BuildSymmetricMargin()        对称页边距
// BuildZeroMargin()             无边距（全出血）
//
// 【单位换算】
// PtToTwips()                   点转Twips
// TwipsToEmu()                  Twips转EMU
// InchToTwips()                 英寸转Twips
// CmToTwips()                   厘米转Twips
//
// ============================================================================
// 常见错误速查（复制正确写法）
// ============================================================================
//
// | 错误写法                              | 正确写法                                    |
// |---------------------------------------|---------------------------------------------|
// | Numbering­FormatValues.Decimal         | NumberFormatValues.Decimal                  |
// | new Level(0)                          | new Level() { LevelIndex = 0 }              |
// | sectPr.TitlePage = new TitlePage()    | sectPr.Append(new TitlePage())              |
// | new Paragraph(run1, run2)             | para.Append(run1); para.Append(run2);       |
// | new FontSize { Val = 24 }             | new FontSize { Val = "24" }                 |
// | JustificationValues.Justify           | JustificationValues.Both                    |
// | new PageBreak()                       | new Break { Type = BreakValues.Page }       |
//
// ============================================================================
// 单位换算速查
// ============================================================================
//
// 【基础换算】
//   1 英寸 = 72 pt = 1440 Twips = 914400 EMU
//   1 pt = 20 Twips = 12700 EMU
//   1 cm ≈ 567 Twips
//   1 Twip = 635 EMU
//
// 【常用值】
//   FontSize Val: 半点 (half-point), 如 Val="24" = 12pt
//   PageMargin: Twips
//   TableWidth Dxa: Twips
//   Drawing Extent: EMU
//
// ============================================================================
// ⚠️⚠️⚠️ 核心设计原则：留白 = 专业度 ⚠️⚠️⚠️
// ============================================================================
//
// 紧凑布局 = 廉价感 = 低质量交付
// 专业文档必须有足够的"呼吸空间"：
//
// 【强制最小值】
//   页边距: Top≥1800(90pt), Left/Right/Bottom≥1440(72pt)
//   段间距: 正文After≥200(10pt), 标题Before≥400(20pt)
//   行距: 正文≥1.5倍(Line="360")，切勿单倍行距
//
// 【绝对禁止】
//   ❌ 页边距<1000 Twips (50pt)
//   ❌ 段间距=0
//   ❌ 单倍行距 (Line="240") 用于正文
//   ❌ 文字贴边、表格撑满、图片无间距
//
// 只有用户明确说"紧凑""省纸""密集"时才可减少留白
//
// ============================================================================
// 术语映射速查（设计/排版术语 → 技术术语）
// ============================================================================
//
// 【页面方向】⚠️ 横版需要3处配套修改
//   竖版/Portrait(默认): PageSize { Width=11906, Height=16838 } 无需Orient
//   横版/Landscape: 必须同时设置：
//     1. PageSize { Width=高值, Height=宽值, Orient=Landscape } ← 宽高互换+Orient
//     2. PageMargin 的 Left/Right 可能需要调整（横版通常上下边距小，左右大）
//     3. 背景图 Extent { Cx=高值EMU, Cy=宽值EMU } ← 图片尺寸也要互换
//   横竖混排: 用分节符隔开，每节独立设置 SectionProperties
//
// 【常见尺寸别名】
//   PPT尺寸/幻灯片/16:9 → 宽10080 x 高5670 Twips (或自定义)
//   PPT 4:3 → 宽9144 x 高6858 Twips
//   海报/Poster → A3/A2 或更大
//   名片 → 90×54mm (约5103×3062 Twips)
//   三折页/宣传册 → A4 Landscape + 3等宽栏
//   便签/卡片 → A6 或更小
//   信纸 → Letter (12240×15840 Twips)
//   公文/法律文件 → Legal (12240×20160 Twips)
//
// 【页面布局】⚠️ 默认使用宽松布局，紧凑布局需用户明确要求
//   出血/满版/全屏/无边框 → 仅封面封底用 BuildZeroMargin()
//   留白/边距/页边 → PageMargin (上右下左)，默认≥72pt
//   窄边距 → 约36pt各边（仅用户要求"紧凑"时才用）
//   宽边距/大留白/专业版式 → 约72-90pt各边（默认选择）
//   分栏/多栏/双栏/三栏 → 需要在 SectionProperties 中设置：
//     1. new Columns { ColumnCount=n, EqualWidth=true, Space="720" }
//     2. 分栏切换用 SectionMarkValues.Continuous（不换页）
//     3. 栏内换栏用 Break { Type=BreakValues.Column }
//   栏间距/栏间隔 → Columns.Space (Twips, 720=0.5英寸)
//   装订线/内边距 → PageMargin.Gutter
//
// 【段落格式】
//   首行缩进/段首缩进 → FirstLine = "420" (2字符)
//   悬挂缩进 → Hanging
//   行距/行间距 → SpacingBetweenLines.Line + LineRule
//   单倍行距 → Line="240"
//   1.5倍行距 → Line="360"
//   双倍行距 → Line="480"
//   段前/段后间距 → Before/After (Twips)
//   两端对齐 → JustificationValues.Both (非Justify!)
//
// 【分页分节】
//   换页/分页/新页 → Break { Type = BreakValues.Page }
//   分节/新节 → SectionProperties + SectionMarkValues
//   奇数页起/章节起始 → SectionMarkValues.OddPage
//   连续分节 → SectionMarkValues.Continuous
//   首页不同/封面特殊 → TitlePage
//   奇偶页不同 → EvenAndOddHeaders
//
// 【页眉页脚】⚠️ 专业文档必备，体现交付标准
//   页眉/顶部信息 → HeaderPart + HeaderReference
//   页脚/底部信息 → FooterPart + FooterReference
//   页码/页数 → PAGE / NUMPAGES 域代码
//   第X页共Y页 → PAGE + " / " + NUMPAGES
//
//   💡 E2E交付标准：除非用户明确说不要，否则默认添加：
//      - 页码（至少页脚居中页码）
//      - 页眉（文档标题/章节名/机构名）
//      - 封面/封底（正式文档）
//      - 目录（3+章节的长文档）
//   这些元素区分"模板填充"与"专业交付"
//
// ============================================================================
// 纸张尺寸速查
// ============================================================================
//
// 竖版 Portrait（宽 x 高）:
//   A3: 16838 x 23811 Twips | 10692000 x 15120000 EMU
//   A4: 11906 x 16838 Twips | 7560000 x 10692000 EMU
//   A5: 8391 x 11906 Twips  | 5328000 x 7560000 EMU
//   Letter: 12240 x 15840   | Legal: 12240 x 20160
//
// 【竖版A4标准配置示例】（默认使用此配置）
//   PageSize:
//     new PageSize { Width=11906, Height=16838 }  // 无需Orient
//   PageMargin (专业留白):
//     new PageMargin { Top=1800, Right=1440, Bottom=1440, Left=1440, Header=720, Footer=720 }
//     // Top=90pt, Right/Left/Bottom=72pt
//   背景图Extent (EMU):
//     new A.Extents { Cx=7560000L, Cy=10692000L }  // Cx<Cy
//
// 横版 Landscape: 宽高互换 + PageSize.Orient = PageOrientationValues.Landscape
//
// 【横版A4完整配置示例】
//   PageSize:
//     new PageSize { Width=16838, Height=11906, Orient=PageOrientationValues.Landscape }
//   PageMargin (横版常用，保持足够留白):
//     new PageMargin { Top=1440, Right=1800, Bottom=1440, Left=1800, Header=720, Footer=720 }
//   背景图Extent (EMU):
//     new A.Extents { Cx=10692000L, Cy=7560000L }  // 注意Cx>Cy
//   ⚠️ 三者必须配套，否则背景图变形或页面错乱
//
// ============================================================================
// 表格管理要点
// ============================================================================
//
// 宽度类型 TableWidthUnitValues:
//   Pct: 百分比(5000=100%), Dxa: Twips固定值, Auto: 自动
//
// 合并单元格:
//   水平: GridSpan { Val = n }
//   垂直: VerticalMerge { Val = Restart } 起始, new VerticalMerge() 后续
//
// 固定布局: TableLayout { Type = TableLayoutValues.Fixed }
//
// ============================================================================
// 目录 (TOC) 最佳实践
// ============================================================================
//
// 【目录域代码】
//   TOC \o "1-3"  基于大纲级别1-3生成
//   TOC \h        创建超链接
//   TOC \z        隐藏页码（Web视图）
//   TOC \u        使用应用的段落大纲级别
//   完整: " TOC \\o \"1-3\" \\h \\z \\u "
//
// 【目录结构】
//   FieldChar.Begin → FieldCode → FieldChar.Separate → 占位条目 → FieldChar.End
//
// 【目录样式】
//   TOC1/TOC2/TOC3 分别对应一级/二级/三级目录项
//   Tab + 前导符: TabStop { Leader = TabStopLeaderCharValues.Dot }
//
// 【自动更新】
//   UpdateFieldsOnOpen { Val = true } 打开时刷新目录
//
// ============================================================================
// 大纲与标题层级
// ============================================================================
//
// 【OutlineLevel】关联目录生成，0=一级, 1=二级, 2=三级...
//   new StyleParagraphProperties(new OutlineLevel { Val = 0 })  // Heading1
//
// 【标题样式要点】
//   KeepNext: 标题与下段同页
//   KeepLines: 段落不跨页断开
//   SpacingBetweenLines: Before/After 控制段前段后
//   Indentation { FirstLine = "0" }: 标题不首行缩进
//
// 【书签与标题绑定】实现目录跳转
//   para.Append(BookmarkStart { Id, Name = "_TocXXX" });
//   para.Append(new Run(new Text("标题文字")));
//   para.Append(BookmarkEnd { Id });
//
// ============================================================================
// 引用与交叉引用
// ============================================================================
//
// 【书签定义】被引用的锚点
//   new BookmarkStart { Id = "1", Name = "Figure1" }
//   new BookmarkEnd { Id = "1" }
//
// 【交叉引用域代码】
//   REF BookmarkName \h    引用书签内容（带超链接）
//   REF BookmarkName \p    引用相对位置（上方/下方）
//   PAGEREF BookmarkName   引用书签所在页码
//
// 【引用结构】
//   FieldChar.Begin → FieldCode(" REF name \\h ") → Separate → 显示文本 → End
//
// 【脚注 Footnote】
//   1. FootnotesPart 需先添加 Separator(-1) 和 ContinuationSeparator(0)
//   2. 正文插入 FootnoteReference { Id = n }
//   3. FootnotesPart 添加 Footnote { Id = n } 含内容
//
// 【尾注 Endnote】结构同脚注，使用 EndnotesPart
//
// ============================================================================
// 字体与文字格式
// ============================================================================
//
// 【RunFonts 字体设置】
//   Ascii: 西文字符 (A-Z, 0-9)
//   HighAnsi: 扩展拉丁字符
//   EastAsia: 中日韩字符（中文必设）
//   ComplexScript: 阿拉伯/希伯来等复杂文字
//   示例: new RunFonts { Ascii = "Calibri", EastAsia = "Microsoft YaHei" }
//
// 【常用中文字体】
//   SimHei (黑体): 标题、强调
//   SimSun (宋体): 正文、印刷
//   Microsoft YaHei (微软雅黑): 屏幕显示、现代风格
//   KaiTi (楷体): 引用、注释
//   FangSong (仿宋): 公文、正式文档
//
// 【FontSize 字号】单位：半点 (half-point)
//   Val="21" = 10.5pt (中文正文标准)
//   Val="24" = 12pt, Val="28" = 14pt, Val="32" = 16pt
//   Val="36" = 18pt, Val="44" = 22pt, Val="72" = 36pt
//   公式: half-points = pt * 2
//
// 【FontSizeComplexScript】复杂文字字号，通常与FontSize相同
//
// 【文字效果 RunProperties】
//   Bold / Italic / Underline / Strike
//   Color { Val = "FF0000" }  RGB十六进制
//   Highlight { Val = HighlightColorValues.Yellow }
//   VerticalTextAlignment { Val = Superscript/Subscript }
//   Spacing { Val = 20 }  字符间距(Twips)
//
// ============================================================================
// 标题与段落格式
// ============================================================================
//
// 【段落间距 SpacingBetweenLines】
//   Before/After: 段前段后(Twips), 如 "200" = 10pt
//   Line: 行距值, LineRule: 行距类型
//     Auto: Line="240"=单倍, "360"=1.5倍, "480"=双倍
//     Exact: 固定值(Twips)
//     AtLeast: 最小值(Twips)
//
// 【缩进 Indentation】单位Twips
//   Left/Right: 左右缩进
//   FirstLine: 首行缩进 (中文常用 "420" ≈ 2字符)
//   Hanging: 悬挂缩进（与FirstLine互斥）
//
// 【对齐 Justification】
//   Left / Center / Right / Both(两端对齐)
//   注意: 无 Justify，用 Both
//
// 【分页控制属性 - 必须正确使用！】
//   KeepNext: 与下段同页（H1/H2/H3标题、表格前导文字、图表说明必加）
//   KeepLines: 段内不分页（长段落必加）
//   PageBreakBefore: 段前分页（H1章节标题）
//   WidowControl: 孤行控制
//
//   ⚠️ 不加KeepNext的标题 = 标题在页尾孤悬，内容跑到下一页
//   ⚠️ 表格前"如下表所示"不加KeepNext = 引导文字和表格分离
//
// ============================================================================
// 分页、分节、分栏
// ============================================================================
//
// 【分页 Break】
//   new Break { Type = BreakValues.Page }      // 分页符
//   new Break { Type = BreakValues.Column }    // 分栏符
//   new Break { Type = BreakValues.TextWrapping } // 换行符
//   注意: 无 new PageBreak()，必须用 Break + Type
//
// 【分节符 SectionProperties】
//   SectionMarkValues.NextPage      下一页（最常用）
//   SectionMarkValues.Continuous    连续（不换页，用于分栏切换）
//   SectionMarkValues.EvenPage      偶数页开始
//   SectionMarkValues.OddPage       奇数页开始
//
// 【分节符位置】
//   1. 放在 Paragraph.ParagraphProperties 内 → 结束当前节
//   2. 放在 Body 最后（直接子元素）→ 文档最终节属性
//
// 【分节符结构示例】
//   new Paragraph(new ParagraphProperties(
//       new SectionProperties(
//           new SectionType { Val = SectionMarkValues.NextPage },
//           new PageSize { ... },
//           new PageMargin { ... },
//           new Columns { ... }  // 可选：分栏设置
//       )
//   ))
//
// 【分栏 Columns】
//   new Columns { ColumnCount = 2, Space = "720" }  // 2栏，栏间距720 Twips
//   new Columns { EqualWidth = true, ColumnCount = 3 }  // 3等宽栏
//   自定义栏宽:
//     new Columns(
//         new Column { Width = "4000", Space = "500" },
//         new Column { Width = "4000" }
//     ) { EqualWidth = false }
//
// 【每节独立设置】
//   页面尺寸/方向、页边距、页眉页脚、分栏、行号、页码起始
//   HeaderReference/FooterReference 绑定页眉页脚
//
// 【首页不同 TitlePage】
//   sectPr.Append(new TitlePage())  // 首页使用独立页眉页脚
//   配合 HeaderFooterValues.First 使用
//
// 【奇偶页不同】
//   DocumentSettingsPart: new EvenAndOddHeaders()
//   配合 HeaderFooterValues.Even / Default(奇数页)
//
// ============================================================================
// OpenXML 核心模式
// ============================================================================
//
// 构建: new Element(children) 或 element.Append(child)
// 属性: 简单值用 { Val = "x" }, 复杂结构用 Append
// ID唯一性: DocProperties.Id, Bookmark.Id, RelationshipId 各自独立
// 分节符: 在 Paragraph.ParagraphProperties 内结束当前节
// 浮动图: Anchor + BehindDoc=true 做背景, RelativeHeight 控制层叠
// 域代码: Begin + FieldCode + Separate + 显示文本 + End
//
// ============================================================================

using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using DW = DocumentFormat.OpenXml.Drawing.Wordprocessing;
using A = DocumentFormat.OpenXml.Drawing;
using PIC = DocumentFormat.OpenXml.Drawing.Pictures;
using C = DocumentFormat.OpenXml.Drawing.Charts;

namespace DocxProject;

public static class Quotes
{
    // ============================================================================
    // 配色方案别名 - 修改此行切换配色
    // 基础: Morandi, InkWash, Corporate, Earth, Nordic, French, Academic, Ocean, Forest, Industrial, Desert
    // 扩展: RedPower, Luxury, Vibrant, Innovation, Clinical, Minimalist, Vitality, Midnight, CoralReef, Financial
    // ============================================================================
    private static class Colors
    {
        public const string Primary = ColorSchemes.Academic.Primary;
        public const string Secondary = ColorSchemes.Academic.Secondary;
        public const string Accent = ColorSchemes.Academic.Accent;
        public const string Dark = ColorSchemes.Academic.Dark;
        public const string Mid = ColorSchemes.Academic.Mid;
        public const string Light = ColorSchemes.Academic.Light;
        public const string Border = ColorSchemes.Academic.Border;
        public const string TableHeader = ColorSchemes.Academic.TableHeader;
    }

    // ============================================================================
    // 纸张尺寸常量（Twips 和 EMU）
    // ============================================================================
    // 竖版尺寸 - Twips (1/20 点)
    private const int A3WidthTwips = 16838, A3HeightTwips = 23811;
    private const int A4WidthTwips = 11906, A4HeightTwips = 16838;
    private const int A5WidthTwips = 8391, A5HeightTwips = 11906;
    private const int LetterWidthTwips = 12240, LetterHeightTwips = 15840;
    private const int LegalWidthTwips = 12240, LegalHeightTwips = 20160;

    // 竖版尺寸 - EMU (English Metric Units, 1 Twip = 635 EMU)
    private const long A3WidthEmu = 10692000L, A3HeightEmu = 15120000L;
    private const long A4WidthEmu = 7560000L, A4HeightEmu = 10692000L;
    private const long A5WidthEmu = 5328000L, A5HeightEmu = 7560000L;
    private const long LetterWidthEmu = 7772400L, LetterHeightEmu = 10058400L;

    // ============================================================================
    // 页面尺寸辅助方法
    // ============================================================================
    /// <summary>创建竖版 PageSize</summary>
    private static PageSize BuildPortraitPageSize(int widthTwips, int heightTwips) =>
        new() { Width = (UInt32Value)(uint)widthTwips, Height = (UInt32Value)(uint)heightTwips };

    /// <summary>创建横版 PageSize（宽高互换 + Orient）</summary>
    private static PageSize BuildLandscapePageSize(int widthTwips, int heightTwips) =>
        new() { Width = (UInt32Value)(uint)heightTwips, Height = (UInt32Value)(uint)widthTwips,
                Orient = PageOrientationValues.Landscape };

    // ============================================================================
    // 表格宽度辅助方法
    // ============================================================================
    /// <summary>百分比宽度 (percent: 0-100)</summary>
    private static TableWidth BuildPercentTableWidth(int percent) =>
        new() { Width = (percent * 50).ToString(), Type = TableWidthUnitValues.Pct };

    /// <summary>固定宽度 Twips</summary>
    private static TableWidth BuildFixedTableWidth(int twips) =>
        new() { Width = twips.ToString(), Type = TableWidthUnitValues.Dxa };

    /// <summary>单元格百分比宽度</summary>
    private static TableCellWidth BuildPercentCellWidth(int percent) =>
        new() { Width = (percent * 50).ToString(), Type = TableWidthUnitValues.Pct };

    /// <summary>单元格固定宽度</summary>
    private static TableCellWidth BuildFixedCellWidth(int twips) =>
        new() { Width = twips.ToString(), Type = TableWidthUnitValues.Dxa };

    /// <summary>创建固定布局表格属性（列宽不随内容变化）</summary>
    private static TableLayout BuildFixedTableLayout() =>
        new() { Type = TableLayoutValues.Fixed };

    // ============================================================================
    // 单元格合并辅助方法
    // ============================================================================
    /// <summary>水平合并（跨列）</summary>
    private static GridSpan BuildHorizontalMerge(int columnSpan) =>
        new() { Val = columnSpan };

    /// <summary>垂直合并起始单元格</summary>
    private static VerticalMerge BuildVerticalMergeStart() =>
        new() { Val = MergedCellValues.Restart };

    /// <summary>垂直合并后续单元格</summary>
    private static VerticalMerge BuildVerticalMergeContinue() =>
        new(); // 等同于 Val = MergedCellValues.Continue

    // ============================================================================
    // 目录辅助方法
    // ============================================================================
    /// <summary>创建TOC域代码（可配置大纲级别范围）</summary>
    private static IEnumerable<Run> BuildTocFieldStart(int fromLevel = 1, int toLevel = 3, bool hyperlink = true)
    {
        var switches = $"\\o \"{fromLevel}-{toLevel}\"";
        if (hyperlink) switches += " \\h";
        switches += " \\z \\u";
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Begin });
        yield return new Run(new FieldCode($" TOC {switches} ") { Space = SpaceProcessingModeValues.Preserve });
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Separate });
    }

    private static Run BuildTocFieldEnd() =>
        new(new FieldChar { FieldCharType = FieldCharValues.End });

    /// <summary>创建目录条目（带前导符点线）</summary>
    private static Paragraph BuildTocEntry(string text, string pageNum, int level, string? stylePrefix = "TOC")
    {
        var styleId = $"{stylePrefix}{level}";
        return new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = styleId }),
            new Run(new Text(text)),
            new Run(new TabChar()),
            new Run(new Text(pageNum))
        );
    }

    // ============================================================================
    // 通用域代码辅助方法
    // ============================================================================
    /// <summary>创建通用域代码（PAGE/NUMPAGES/DATE/TIME等）</summary>
    private static IEnumerable<Run> BuildFieldCode(string fieldCode, string placeholder = "")
    {
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Begin });
        yield return new Run(new FieldCode($" {fieldCode} ") { Space = SpaceProcessingModeValues.Preserve });
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Separate });
        yield return new Run(new Text(placeholder));
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.End });
    }

    // ============================================================================
    // 大纲标题辅助方法
    // ============================================================================
    /// <summary>创建标题段落属性（含大纲级别）</summary>
    private static ParagraphProperties BuildHeadingProps(string styleId, int outlineLevel) =>
        new(
            new ParagraphStyleId { Val = styleId },
            new KeepNext(),
            new KeepLines(),
            new OutlineLevel { Val = outlineLevel }
        );

    /// <summary>创建带书签的标题（用于目录跳转）</summary>
    private static Paragraph BuildHeadingWithBookmark(string text, string styleId, string bookmarkId, string bookmarkName)
    {
        return new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = styleId }),
            new BookmarkStart { Id = bookmarkId, Name = bookmarkName },
            new Run(new Text(text)),
            new BookmarkEnd { Id = bookmarkId }
        );
    }

    // ============================================================================
    // 交叉引用辅助方法
    // ============================================================================
    /// <summary>创建书签锚点</summary>
    private static (BookmarkStart start, BookmarkEnd end) BuildBookmark(string id, string name) =>
        (new BookmarkStart { Id = id, Name = name }, new BookmarkEnd { Id = id });

    /// <summary>创建PAGEREF域（引用书签所在页码）</summary>
    private static IEnumerable<Run> BuildPageRef(string bookmarkName)
    {
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Begin });
        yield return new Run(new FieldCode($" PAGEREF {bookmarkName} \\h ") { Space = SpaceProcessingModeValues.Preserve });
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Separate });
        yield return new Run(new Text("0")); // 占位，打开时更新
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.End });
    }

    // ============================================================================
    // 字体辅助方法
    // ============================================================================
    /// <summary>创建中英文混排字体</summary>
    private static RunFonts BuildFonts(string ascii, string eastAsia) =>
        new() { Ascii = ascii, HighAnsi = ascii, EastAsia = eastAsia };

    /// <summary>创建字号（输入pt值）</summary>
    private static FontSize BuildFontSize(double pt) =>
        new() { Val = ((int)(pt * 2)).ToString() };

    /// <summary>创建完整RunProperties</summary>
    private static RunProperties BuildRunProps(
        string? ascii = null, string? eastAsia = null,
        double? pt = null, string? color = null,
        bool bold = false, bool italic = false)
    {
        var rp = new RunProperties();
        if (ascii != null || eastAsia != null)
            rp.Append(new RunFonts { Ascii = ascii, HighAnsi = ascii, EastAsia = eastAsia });
        if (pt.HasValue)
            rp.Append(new FontSize { Val = ((int)(pt.Value * 2)).ToString() });
        if (color != null)
            rp.Append(new Color { Val = color });
        if (bold) rp.Append(new Bold());
        if (italic) rp.Append(new Italic());
        return rp;
    }

    // ============================================================================
    // 段落格式辅助方法
    // ============================================================================
    /// <summary>创建段落间距</summary>
    private static SpacingBetweenLines BuildSpacing(int? beforePt = null, int? afterPt = null, double lineMultiple = 1.0) =>
        new()
        {
            Before = beforePt.HasValue ? (beforePt.Value * 20).ToString() : null,
            After = afterPt.HasValue ? (afterPt.Value * 20).ToString() : null,
            Line = ((int)(lineMultiple * 240)).ToString(),
            LineRule = LineSpacingRuleValues.Auto
        };

    /// <summary>创建缩进（中文首行缩进2字符 ≈ 420 Twips）</summary>
    private static Indentation BuildIndent(int? leftPt = null, int? firstLineTwips = null) =>
        new()
        {
            Left = leftPt.HasValue ? (leftPt.Value * 20).ToString() : null,
            FirstLine = firstLineTwips?.ToString()
        };

    /// <summary>中文正文标准缩进（首行2字符）</summary>
    private static Indentation BuildChineseBodyIndent() =>
        new() { FirstLine = "420" };

    // ============================================================================
    // 分页分节辅助方法
    // ============================================================================
    /// <summary>分页符</summary>
    private static Break BuildPageBreak() =>
        new() { Type = BreakValues.Page };

    /// <summary>分栏符</summary>
    private static Break BuildColumnBreak() =>
        new() { Type = BreakValues.Column };

    /// <summary>创建分节符段落（下一页）</summary>
    private static Paragraph BuildSectionBreak(SectionMarkValues type = SectionMarkValues.NextPage) =>
        new(new ParagraphProperties(
            new SectionProperties(new SectionType { Val = type })
        ));

    /// <summary>创建完整分节属性</summary>
    private static SectionProperties BuildSectionProps(
        int widthTwips, int heightTwips,
        bool landscape = false,
        SectionMarkValues type = SectionMarkValues.NextPage,
        int? columns = null,
        int columnSpaceTwips = 720)
    {
        var sectPr = new SectionProperties();
        sectPr.Append(new SectionType { Val = type });

        if (landscape)
            sectPr.Append(new PageSize
            {
                Width = (UInt32Value)(uint)heightTwips,
                Height = (UInt32Value)(uint)widthTwips,
                Orient = PageOrientationValues.Landscape
            });
        else
            sectPr.Append(new PageSize
            {
                Width = (UInt32Value)(uint)widthTwips,
                Height = (UInt32Value)(uint)heightTwips
            });

        if (columns.HasValue && columns.Value > 1)
            sectPr.Append(new Columns { ColumnCount = (short)columns.Value, EqualWidth = true, Space = columnSpaceTwips.ToString() });

        return sectPr;
    }

    /// <summary>创建等宽分栏</summary>
    private static Columns BuildEqualColumns(int count, int spaceTwips = 720) =>
        new() { ColumnCount = (short)count, EqualWidth = true, Space = spaceTwips.ToString() };

    /// <summary>创建带分节符的段落（用于结束当前节）</summary>
    private static Paragraph BuildSectionEndParagraph(SectionProperties sectPr) =>
        new(new ParagraphProperties(sectPr));

    // ============================================================================
    // 页边距辅助方法
    // ============================================================================
    /// <summary>创建页边距（输入pt值，内部转Twips）</summary>
    private static PageMargin BuildPageMargin(int topPt, int rightPt, int bottomPt, int leftPt, int headerPt = 36, int footerPt = 36) =>
        new()
        {
            Top = topPt * 20,
            Right = (uint)(rightPt * 20),
            Bottom = bottomPt * 20,
            Left = (uint)(leftPt * 20),
            Header = (uint)(headerPt * 20),
            Footer = (uint)(footerPt * 20)
        };

    /// <summary>创建对称页边距</summary>
    private static PageMargin BuildSymmetricMargin(int verticalPt, int horizontalPt, int headerFooterPt = 36) =>
        BuildPageMargin(verticalPt, horizontalPt, verticalPt, horizontalPt, headerFooterPt, headerFooterPt);

    /// <summary>无边距（用于全出血背景）</summary>
    private static PageMargin BuildZeroMargin() =>
        new() { Top = 0, Right = 0, Bottom = 0, Left = 0, Header = 0, Footer = 0 };

    // ============================================================================
    // 单位换算辅助方法
    // ============================================================================
    /// <summary>点(pt)转Twips</summary>
    private static int PtToTwips(double pt) => (int)(pt * 20);

    /// <summary>Twips转EMU</summary>
    private static long TwipsToEmu(int twips) => twips * 635L;

    /// <summary>英寸转Twips</summary>
    private static int InchToTwips(double inch) => (int)(inch * 1440);

    /// <summary>厘米转Twips</summary>
    private static int CmToTwips(double cm) => (int)(cm * 567);

    // ============================================================================
    // 添加图片
    // ============================================================================
    private static string AddImage(MainDocumentPart mainPart, string imagePath)
    {
        var imagePart = mainPart.AddImagePart(ImagePartType.Png);
        using var stream = new FileStream(imagePath, FileMode.Open);
        imagePart.FeedData(stream);
        return mainPart.GetIdOfPart(imagePart);
    }

    // ============================================================================
    // 创建浮动背景图 - 置于文字下方
    // ============================================================================
    private static Drawing BuildFloatingBackground(string imageId, uint docPrId, string name)
    {
        return new Drawing(
            new DW.Anchor(
                new DW.SimplePosition { X = 0, Y = 0 },
                new DW.HorizontalPosition(new DW.PositionOffset("0"))
                { RelativeFrom = DW.HorizontalRelativePositionValues.Page },
                new DW.VerticalPosition(new DW.PositionOffset("0"))
                { RelativeFrom = DW.VerticalRelativePositionValues.Page },
                new DW.Extent { Cx = A4WidthEmu, Cy = A4HeightEmu },
                new DW.EffectExtent { LeftEdge = 0, TopEdge = 0, RightEdge = 0, BottomEdge = 0 },
                new DW.WrapNone(),
                new DW.DocProperties { Id = docPrId, Name = name },
                new DW.NonVisualGraphicFrameDrawingProperties(
                    new A.GraphicFrameLocks { NoChangeAspect = true }
                ),
                new A.Graphic(
                    new A.GraphicData(
                        new PIC.Picture(
                            new PIC.NonVisualPictureProperties(
                                new PIC.NonVisualDrawingProperties { Id = 0, Name = $"{name}.png" },
                                new PIC.NonVisualPictureDrawingProperties()
                            ),
                            new PIC.BlipFill(
                                new A.Blip { Embed = imageId },
                                new A.Stretch(new A.FillRectangle())
                            ),
                            new PIC.ShapeProperties(
                                new A.Transform2D(
                                    new A.Offset { X = 0, Y = 0 },
                                    new A.Extents { Cx = A4WidthEmu, Cy = A4HeightEmu }
                                ),
                                new A.PresetGeometry { Preset = A.ShapeTypeValues.Rectangle }
                            )
                        )
                    )
                    { Uri = "http://schemas.openxmlformats.org/drawingml/2006/picture" }
                )
            )
            {
                DistanceFromTop = 0,
                DistanceFromBottom = 0,
                DistanceFromLeft = 0,
                DistanceFromRight = 0,
                SimplePos = false,
                RelativeHeight = 251658240,
                BehindDoc = true,  // 关键：置于文字下方
                Locked = false,
                LayoutInCell = true,
                AllowOverlap = true
            }
        );
    }

    public static void Generate(string outputPath, string bgDir)
    {
        using var doc = WordprocessingDocument.Create(outputPath, WordprocessingDocumentType.Document);
        var mainPart = doc.AddMainDocumentPart();
        mainPart.Document = new Document(new Body());
        var body = mainPart.Document.Body!;

        AddStyles(mainPart);
        AddNumbering(mainPart);

        // 添加背景图关系
        var coverImageId = AddImage(mainPart, Path.Combine(bgDir, "cover_bg.png"));
        var bodyImageId = AddImage(mainPart, Path.Combine(bgDir, "body_bg.png"));
        var backcoverImageId = AddImage(mainPart, Path.Combine(bgDir, "backcover_bg.png"));

        // ========== 封面 ==========
        AddCoverSection(body, coverImageId);

        // ========== 目录 ==========
        AddTocSection(body, mainPart);

        // ========== 正文 ==========
        AddContentSection(doc, body, mainPart, bgDir);

        // ========== 封底 ==========
        AddBackcoverSection(body, backcoverImageId);

        SetUpdateFieldsOnOpen(mainPart);
        doc.Save();
        Console.WriteLine($"生成完成: {outputPath}");
    }

    // ============================================================================
    // 样式定义 - 中文字体配置
    // ============================================================================
    private static void AddStyles(MainDocumentPart mainPart)
    {
        var stylesPart = mainPart.AddNewPart<StyleDefinitionsPart>();
        stylesPart.Styles = new Styles();

        // 正文样式 - 中文正文使用宋体或微软雅黑
        stylesPart.Styles.Append(new Style(
            new StyleName { Val = "Normal" },
            new StyleParagraphProperties(
                new SpacingBetweenLines { After = "200", Line = "360", LineRule = LineSpacingRuleValues.Auto },
                new Indentation { FirstLine = "420" }  // 中文段落首行缩进2字符
            ),
            new StyleRunProperties(
                // EastAsia 字体用于中文显示
                new RunFonts { Ascii = "Calibri", HighAnsi = "Calibri", EastAsia = "Microsoft YaHei" },
                new FontSize { Val = "21" },  // 10.5pt - 中文正文标准字号
                new Color { Val = Colors.Dark }
            )
        )
        { Type = StyleValues.Paragraph, StyleId = "Normal", Default = true });

        // 标题1 - 中文标题使用黑体或微软雅黑加粗
        stylesPart.Styles.Append(new Style(
            new StyleName { Val = "heading 1" },
            new BasedOn { Val = "Normal" },
            new StyleParagraphProperties(
                new KeepNext(),
                new KeepLines(),
                new SpacingBetweenLines { Before = "600", After = "300", Line = "240", LineRule = LineSpacingRuleValues.Auto },
                new Indentation { FirstLine = "0" },  // 标题不缩进
                new OutlineLevel { Val = 0 }
            ),
            new StyleRunProperties(
                new RunFonts { EastAsia = "SimHei" },  // 黑体用于标题
                new Bold(),
                new Color { Val = Colors.Primary },
                new FontSize { Val = "32" }  // 16pt
            )
        )
        { Type = StyleValues.Paragraph, StyleId = "Heading1" });

        // 标题2
        stylesPart.Styles.Append(new Style(
            new StyleName { Val = "heading 2" },
            new BasedOn { Val = "Normal" },
            new StyleParagraphProperties(
                new KeepNext(),
                new KeepLines(),
                new SpacingBetweenLines { Before = "400", After = "200" },
                new Indentation { FirstLine = "0" },
                new OutlineLevel { Val = 1 }
            ),
            new StyleRunProperties(
                new RunFonts { EastAsia = "SimHei" },
                new Bold(),
                new Color { Val = Colors.Dark },
                new FontSize { Val = "28" }  // 14pt
            )
        )
        { Type = StyleValues.Paragraph, StyleId = "Heading2" });

        // 标题3
        stylesPart.Styles.Append(new Style(
            new StyleName { Val = "heading 3" },
            new BasedOn { Val = "Normal" },
            new StyleParagraphProperties(
                new KeepNext(),
                new KeepLines(),
                new SpacingBetweenLines { Before = "280", After = "120" },
                new Indentation { FirstLine = "0" },
                new OutlineLevel { Val = 2 }
            ),
            new StyleRunProperties(
                new Bold(),
                new Color { Val = Colors.Mid },
                new FontSize { Val = "24" }  // 12pt
            )
        )
        { Type = StyleValues.Paragraph, StyleId = "Heading3" });

        // 图表标题
        stylesPart.Styles.Append(new Style(
            new StyleName { Val = "Caption" },
            new BasedOn { Val = "Normal" },
            new StyleParagraphProperties(
                new KeepLines(),
                new Justification { Val = JustificationValues.Center },
                new SpacingBetweenLines { Before = "60", After = "400" },
                new Indentation { FirstLine = "0" }
            ),
            new StyleRunProperties(
                new Color { Val = Colors.Mid },
                new FontSize { Val = "20" }  // 10pt
            )
        )
        { Type = StyleValues.Paragraph, StyleId = "Caption" });

        // 目录样式
        stylesPart.Styles.Append(new Style(
            new StyleName { Val = "toc 1" },
            new BasedOn { Val = "Normal" },
            new StyleParagraphProperties(
                new Tabs(new TabStop { Val = TabStopValues.Right, Leader = TabStopLeaderCharValues.Dot, Position = 9350 }),
                new SpacingBetweenLines { Before = "200", After = "60" },
                new Indentation { FirstLine = "0" }
            ),
            new StyleRunProperties(
                new Bold(),
                new Color { Val = Colors.Dark }
            )
        )
        { Type = StyleValues.Paragraph, StyleId = "TOC1" });

        stylesPart.Styles.Append(new Style(
            new StyleName { Val = "toc 2" },
            new BasedOn { Val = "Normal" },
            new StyleParagraphProperties(
                new Tabs(new TabStop { Val = TabStopValues.Right, Leader = TabStopLeaderCharValues.Dot, Position = 9350 }),
                new SpacingBetweenLines { Before = "60", After = "60" },
                new Indentation { Left = "420", FirstLine = "0" }
            ),
            new StyleRunProperties(
                new Color { Val = Colors.Mid }
            )
        )
        { Type = StyleValues.Paragraph, StyleId = "TOC2" });
    }

    // ============================================================================
    // 编号定义
    // ============================================================================
    private static void AddNumbering(MainDocumentPart mainPart)
    {
        var numberingPart = mainPart.AddNewPart<NumberingDefinitionsPart>();
        numberingPart.Numbering = new Numbering(
            new AbstractNum(
                new Level(
                    new StartNumberingValue { Val = 1 },  // 从1开始，不是0
                    new NumberingFormat { Val = NumberFormatValues.Decimal },
                    new LevelText { Val = "%1." },
                    new LevelJustification { Val = LevelJustificationValues.Left },
                    new ParagraphProperties(new Indentation { Left = "720", Hanging = "360" })
                ) { LevelIndex = 0 }
            ) { AbstractNumberId = 1 },
            new NumberingInstance(new AbstractNumId { Val = 1 }) { NumberID = 1 }
        );
    }

    // ============================================================================
    // 封面 - 中文项目封面
    // ============================================================================
    private static void AddCoverSection(Body body, string coverImageId)
    {
        // 背景图
        body.Append(new Paragraph(new Run(BuildFloatingBackground(coverImageId, 1, "CoverBackground"))));

        // 大间距
        body.Append(new Paragraph(
            new ParagraphProperties(new SpacingBetweenLines { Before = "6000" }),
            new Run()
        ));

        // 主标题 - 学术研究报告场景
        body.Append(new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center },
                new SpacingBetweenLines { After = "400" }
            ),
            new Run(
                new RunProperties(
                    new RunFonts { EastAsia = "SimHei" },
                    new FontSize { Val = "72" },  // 36pt
                    new Color { Val = Colors.Primary }
                ),
                new Text("研究报告")
            )
        ));

        // 副标题 - 演示引号的正确使用
        // ❌ Wrong: new Text("基于"深度学习"的研究")  // CS1003 编译错误
        // ✓ Correct: 使用 Unicode 转义
        body.Append(new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center },
                new SpacingBetweenLines { After = "3000" }
            ),
            new Run(
                new RunProperties(
                    new FontSize { Val = "28" },
                    new Color { Val = Colors.Secondary }
                ),
                // 中文引号使用 \u201c \u201d
                new Text("基于\u201c深度学习\u201d的自然语言处理研究")
            )
        ));

        // 作者/机构
        body.Append(new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center },
                new SpacingBetweenLines { After = "120" }
            ),
            new Run(
                new RunProperties(
                    new FontSize { Val = "24" },
                    new Color { Val = Colors.Light }
                ),
                new Text("XX大学计算机科学与技术学院")
            )
        ));

        // 日期
        body.Append(new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center }
            ),
            new Run(
                new RunProperties(
                    new FontSize { Val = "21" },
                    new Color { Val = Colors.Light }
                ),
                new Text("2024年12月")
            )
        ));

        // 封面分节符
        body.Append(new Paragraph(
            new ParagraphProperties(
                new SectionProperties(
                    new SectionType { Val = SectionMarkValues.NextPage },
                    new PageSize { Width = (UInt32Value)(uint)A4WidthTwips, Height = (UInt32Value)(uint)A4HeightTwips },
                    new PageMargin { Top = 0, Right = 0, Bottom = 0, Left = 0, Header = 0, Footer = 0 }
                )
            )
        ));
    }

    // ============================================================================
    // 目录
    // ============================================================================
    private static void AddTocSection(Body body, MainDocumentPart mainPart)
    {
        // 目录标题
        body.Append(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = "Heading1" }),
            new BookmarkStart { Id = "0", Name = "_Toc000" },
            new Run(new Text("目录")),
            new BookmarkEnd { Id = "0" }
        ));

        // 目录刷新提示 - 这是最常出错的地方！
        // ❌ Wrong: new Text("右键点击目录选择"更新域"刷新页码")  // CS1003 编译错误！
        // ✓ Correct: 使用 \u201c 和 \u201d
        body.Append(new Paragraph(
            new ParagraphProperties(new SpacingBetweenLines { After = "300" }),
            new Run(
                new RunProperties(
                    new Color { Val = Colors.Light },
                    new FontSize { Val = "18" }
                ),
                // 正确写法示例1：直接使用 Unicode 转义
                new Text("（注：目录页码需在Word中右键选择\u201c刷新域\u201d进行更新）")
            )
        ));

        // 目录域代码
        body.Append(new Paragraph(
            new Run(new FieldChar { FieldCharType = FieldCharValues.Begin }),
            new Run(new FieldCode(" TOC \\o \"1-3\" \\h \\z \\u ") { Space = SpaceProcessingModeValues.Preserve }),
            new Run(new FieldChar { FieldCharType = FieldCharValues.Separate })
        ));

        // 目录占位条目 - 学术研究报告结构
        string[,] tocEntries = {
            { "研究背景", "1", "3" },
            { "文献综述", "1", "4" },
            { "国内研究现状", "2", "4" },
            { "国际研究进展", "2", "5" },
            { "研究方法", "1", "6" },
            { "实验与分析", "1", "8" },
            { "结论与展望", "1", "10" }
        };

        foreach (var i in Enumerable.Range(0, tocEntries.GetLength(0)))
        {
            var level = tocEntries[i, 1];
            var styleId = level == "1" ? "TOC1" : "TOC2";

            body.Append(new Paragraph(
                new ParagraphProperties(new ParagraphStyleId { Val = styleId }),
                new Run(new Text(tocEntries[i, 0])),
                new Run(new TabChar()),
                new Run(new Text(tocEntries[i, 2]))
            ));
        }

        // 目录域结束
        body.Append(new Paragraph(
            new Run(new FieldChar { FieldCharType = FieldCharValues.End })
        ));

        // 目录分节符
        body.Append(new Paragraph(
            new ParagraphProperties(
                new SectionProperties(
                    new SectionType { Val = SectionMarkValues.NextPage },
                    new PageSize { Width = (UInt32Value)(uint)A4WidthTwips, Height = (UInt32Value)(uint)A4HeightTwips },
                    new PageMargin { Top = 1800, Right = 1440, Bottom = 1440, Left = 1440, Header = 720, Footer = 720 }
                )
            )
        ));
    }

    // ============================================================================
    // 正文内容 - 演示各种中文引号场景
    // ============================================================================
    private static void AddContentSection(WordprocessingDocument doc, Body body, MainDocumentPart mainPart, string bgDir)
    {
        // 创建页眉（含正文背景图）
        var headerPart = mainPart.AddNewPart<HeaderPart>();
        var headerId = mainPart.GetIdOfPart(headerPart);

        // 将背景图添加到 HeaderPart
        var headerImagePart = headerPart.AddImagePart(ImagePartType.Png);
        using (var stream = new FileStream(Path.Combine(bgDir, "body_bg.png"), FileMode.Open))
            headerImagePart.FeedData(stream);
        var headerImageId = headerPart.GetIdOfPart(headerImagePart);

        headerPart.Header = new Header(
            // 背景图
            new Paragraph(new Run(BuildFloatingBackground(headerImageId, 2, "BodyBackground"))),
            // 页眉文字 - 学术报告
            new Paragraph(
                new ParagraphProperties(
                    new Justification { Val = JustificationValues.Right }
                ),
                new Run(
                    new RunProperties(
                        new FontSize { Val = "18" },
                        new Color { Val = Colors.Light }
                    ),
                    new Text("深度学习与自然语言处理研究")
                ),
                new Run(
                    new RunProperties(
                        new FontSize { Val = "18" },
                        new Color { Val = Colors.Primary }
                    ),
                    new Text("  |  ") { Space = SpaceProcessingModeValues.Preserve }
                ),
                new Run(
                    new RunProperties(
                        new FontSize { Val = "18" },
                        new Color { Val = Colors.Light }
                    ),
                    new Text("XX大学")
                )
            )
        );

        // 创建页脚
        var footerPart = mainPart.AddNewPart<FooterPart>();
        var footerId = mainPart.GetIdOfPart(footerPart);
        var footerPara = new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center }
            )
        );
        footerPara.Append(BuildPageNumberRun());
        footerPara.Append(new Run(new Text(" / ") { Space = SpaceProcessingModeValues.Preserve }));
        footerPara.Append(BuildTotalPagesRun());
        footerPart.Footer = new Footer(footerPara);

        // ===== 第一章：研究背景 =====
        body.Append(BuildHeading1("研究背景", "_Toc001"));

        // 研究背景 - 长段落示例，展示多引号长文本的正确拼接方式
        // 注意：不使用 @"" 逐字字符串，用 + 拼接，引号用 \u201c \u201d
        var backgroundPara = new Paragraph(
            new Run(new Text(
                "随着人工智能技术的飞速发展，自然语言处理（NLP）领域取得了显著突破。" +
                "2017年，Vaswani等人提出了\u201cTransformer\u201d架构，" +
                "彻底改变了序列建模的范式。" +
                "此后，BERT、GPT等预训练模型相继问世，" +
                "学界将这一时期称为\u201c大模型时代\u201d。" +
                "正如OpenAI在论文中指出：" +
                "\u201c规模化是通往通用人工智能的关键路径之一\u201d。"
            ))
        );
        body.Append(backgroundPara);
        AddFootnote(doc, backgroundPara, "参见Vaswani et al., \u201cAttention Is All You Need\u201d, NeurIPS 2017.");

        // 书名号示例 - 《》不需要转义，可以直接使用
        body.Append(new Paragraph(
            new Run(new Text("相关综述可参阅《深度学习》及《自然语言处理综论》。"))
            // ✓ 书名号《》可以直接使用，不会导致编译错误
        ));

        body.Append(new Paragraph(new Run(new Break { Type = BreakValues.Page })));

        // ===== 第二章：文献综述 =====
        body.Append(BuildHeading1("文献综述", "_Toc002"));
        body.Append(BuildHeading2("国内研究现状"));

        // 学术引用示例 - 引号用 \u201c \u201d
        body.Append(new Paragraph(
            new Run(new Text("清华大学团队提出的\u201cChatGLM\u201d模型在中文理解任务上表现优异。"))
        ));

        // 编号列表 - 学术风格
        body.Append(BuildNumberedItem(1, "模型架构", "采用\u201c稀疏注意力\u201d机制优化长文本处理"));
        body.Append(BuildNumberedItem(1, "训练策略", "引入\u201c课程学习\u201d提升收敛速度"));
        body.Append(BuildNumberedItem(1, "应用场景", "覆盖\u201c问答生成\u201d与\u201c文本摘要\u201d等任务"));

        body.Append(BuildHeading2("国际研究进展"));

        // 表格 - 论文对比
        body.Append(new Paragraph(
            new ParagraphProperties(
                new KeepNext(),
                new SpacingBetweenLines { Before = "200" }
            ),
            new Run(new Text("主流预训练模型性能对比如下："))
        ));

        body.Append(BuildModelComparisonTable());

        body.Append(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = "Caption" }),
            new Run(new Text("表1：预训练模型性能对比"))
        ));

        body.Append(new Paragraph(new Run(new Break { Type = BreakValues.Page })));

        // ===== 第三章：研究方法 =====
        body.Append(BuildHeading1("研究方法", "_Toc003"));

        // 方法论描述中的引号
        body.Append(new Paragraph(
            new Run(new Text("本研究采用\u201c对比实验\u201d方法，基于\u201c消融分析\u201d验证各模块贡献度。评估指标选用业界标准的\u201cBLEU\u201d与\u201cROUGE\u201d分数。"))
        ));

        // 添加饼图 - 数据集分布
        var chartRef = new Paragraph(
            new ParagraphProperties(
                new KeepNext(),
                new SpacingBetweenLines { Before = "200" }
            ),
            new Run(new Text("训练数据集来源分布如下（"))
        );
        foreach (var run in BuildCrossReference("Figure1", "图1"))
            chartRef.Append(run);
        chartRef.Append(new Run(new Text("）：")));
        body.Append(chartRef);

        AddPieChart(body, mainPart);

        body.Append(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = "Caption" }),
            new BookmarkStart { Id = "100", Name = "Figure1" },
            new Run(new Text("图1：训练数据集来源分布")),
            new BookmarkEnd { Id = "100" }
        ));

        body.Append(new Paragraph(new Run(new Break { Type = BreakValues.Page })));

        // ===== 第四章：实验与分析 =====
        body.Append(BuildHeading1("实验与分析", "_Toc004"));

        body.Append(BuildHeading3("实验环境配置"));
        body.Append(new Paragraph(
            new Run(new Text("实验在\u201cNVIDIA A100\u201d集群上进行，使用\u201cPyTorch 2.0\u201d框架。"))
        ));

        body.Append(BuildHeading3("结果分析"));
        body.Append(new Paragraph(
            new Run(new Text("实验表明，引入\u201c多头注意力\u201d机制后，模型性能提升约12%。"))
        ));

        body.Append(BuildHeading3("消融实验"));
        body.Append(new Paragraph(
            new Run(new Text("通过\u201c逐层冻结\u201d策略验证了底层特征的迁移性。"))
        ));

        // 实验结果表格
        body.Append(new Paragraph(
            new ParagraphProperties(
                new KeepNext(),
                new SpacingBetweenLines { Before = "280" }
            ),
            new Run(new Text("各实验配置的结果对比如下："))
        ));

        body.Append(BuildExperimentResultTable());

        body.Append(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = "Caption" }),
            new Run(new Text("表2：实验结果对比"))
        ));

        // 正文分节符
        body.Append(new Paragraph(
            new ParagraphProperties(
                new SectionProperties(
                    new SectionType { Val = SectionMarkValues.NextPage },
                    new HeaderReference { Type = HeaderFooterValues.Default, Id = headerId },
                    new FooterReference { Type = HeaderFooterValues.Default, Id = footerId },
                    new PageSize { Width = (UInt32Value)(uint)A4WidthTwips, Height = (UInt32Value)(uint)A4HeightTwips },
                    new PageMargin { Top = 1800, Right = 1440, Bottom = 1440, Left = 1440, Header = 720, Footer = 720 }
                )
            )
        ));
    }

    // ============================================================================
    // 封底
    // ============================================================================
    private static void AddBackcoverSection(Body body, string backcoverImageId)
    {
        // 背景图
        body.Append(new Paragraph(new Run(BuildFloatingBackground(backcoverImageId, 3, "BackcoverBackground"))));

        // 大间距
        body.Append(new Paragraph(
            new ParagraphProperties(new SpacingBetweenLines { Before = "8000" }),
            new Run()
        ));

        // 学术机构名称
        body.Append(new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center },
                new SpacingBetweenLines { After = "400" }
            ),
            new Run(
                new RunProperties(
                    new RunFonts { EastAsia = "SimHei" },
                    new FontSize { Val = "36" },
                    new Color { Val = Colors.Dark }
                ),
                new Text("XX大学计算机科学与技术学院")
            )
        ));

        // 联系方式
        body.Append(new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center },
                new SpacingBetweenLines { After = "200" }
            ),
            new Run(
                new RunProperties(
                    new FontSize { Val = "18" },
                    new Color { Val = Colors.Light }
                ),
                new Text("nlp-lab@xxu.edu.cn  \u00b7  +86 10-1234-5678")
            )
        ));

        // 版权
        body.Append(new Paragraph(
            new ParagraphProperties(
                new Justification { Val = JustificationValues.Center }
            ),
            new Run(
                new RunProperties(
                    new FontSize { Val = "16" },
                    new Color { Val = Colors.Light }
                ),
                new Text("\u00a9 2024 版权所有")
            )
        ));

        // 最终分节符
        body.Append(new SectionProperties(
            new PageSize { Width = (UInt32Value)(uint)A4WidthTwips, Height = (UInt32Value)(uint)A4HeightTwips },
            new PageMargin { Top = 0, Right = 0, Bottom = 0, Left = 0, Header = 0, Footer = 0 }
        ));
    }

    // ============================================================================
    // 辅助方法
    // ============================================================================
    private static Paragraph BuildHeading1(string text, string bookmarkName)
    {
        var bookmarkId = bookmarkName.Replace("_Toc", "");
        return new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = "Heading1" }),
            new BookmarkStart { Id = bookmarkId, Name = bookmarkName },
            new Run(new Text(text)),
            new BookmarkEnd { Id = bookmarkId }
        );
    }

    private static Paragraph BuildHeading2(string text)
    {
        return new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = "Heading2" }),
            new Run(new Text(text))
        );
    }

    private static Paragraph BuildHeading3(string text)
    {
        return new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = "Heading3" }),
            new Run(new Text(text))
        );
    }

    private static Paragraph BuildNumberedItem(int numId, string title, string description)
    {
        return new Paragraph(
            new ParagraphProperties(
                new NumberingProperties(
                    new NumberingLevelReference { Val = 0 },
                    new NumberingId { Val = numId }
                )
            ),
            new Run(new RunProperties(new Bold()), new Text(title)),
            new Run(new Text("：" + description))  // 使用中文冒号
        );
    }

    // ============================================================================
    // 模型对比表格 - 学术论文风格
    // ============================================================================
    private static Table BuildModelComparisonTable()
    {
        var table = new Table();

        table.Append(new TableProperties(
            new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct },
            new TableBorders(
                new TopBorder { Val = BorderValues.Single, Size = 12, Color = Colors.Primary },
                new BottomBorder { Val = BorderValues.Single, Size = 12, Color = Colors.Primary },
                new LeftBorder { Val = BorderValues.Nil },
                new RightBorder { Val = BorderValues.Nil },
                new InsideHorizontalBorder { Val = BorderValues.Nil },
                new InsideVerticalBorder { Val = BorderValues.Nil }
            ),
            new TableCellMarginDefault(
                new TopMargin { Width = "150", Type = TableWidthUnitValues.Dxa },
                new TableCellLeftMargin { Width = 200, Type = TableWidthValues.Dxa },
                new BottomMargin { Width = "150", Type = TableWidthUnitValues.Dxa },
                new TableCellRightMargin { Width = 200, Type = TableWidthValues.Dxa }
            )
        ));

        table.Append(new TableGrid(
            new GridColumn { Width = "2400" },
            new GridColumn { Width = "2000" },
            new GridColumn { Width = "2000" },
            new GridColumn { Width = "1600" }
        ));

        var widths = new[] { "2400", "2000", "2000", "1600" };

        // 学术表头
        table.Append(BuildTableHeaderRow(new[] { "模型", "参数量", "BLEU", "发表年份" }, widths));
        table.Append(BuildTableDataRow(new[] { "BERT", "340M", "42.3", "2018" }, widths));
        table.Append(BuildTableDataRow(new[] { "GPT-3", "175B", "51.2", "2020" }, widths));
        table.Append(BuildTableDataRow(new[] { "ChatGLM", "6B", "48.7", "2023" }, widths));
        table.Append(BuildTableDataRow(new[] { "Llama 2", "70B", "52.8", "2023" }, widths));

        return table;
    }

    // ============================================================================
    // 实验结果表格 - 学术论文风格
    // ============================================================================
    private static Table BuildExperimentResultTable()
    {
        var table = new Table();

        table.Append(new TableProperties(
            new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct },
            new TableBorders(
                new TopBorder { Val = BorderValues.Single, Size = 12, Color = Colors.Primary },
                new BottomBorder { Val = BorderValues.Single, Size = 12, Color = Colors.Primary },
                new LeftBorder { Val = BorderValues.Nil },
                new RightBorder { Val = BorderValues.Nil },
                new InsideHorizontalBorder { Val = BorderValues.Nil },
                new InsideVerticalBorder { Val = BorderValues.Nil }
            ),
            new TableCellMarginDefault(
                new TopMargin { Width = "150", Type = TableWidthUnitValues.Dxa },
                new TableCellLeftMargin { Width = 200, Type = TableWidthValues.Dxa },
                new BottomMargin { Width = "150", Type = TableWidthUnitValues.Dxa },
                new TableCellRightMargin { Width = 200, Type = TableWidthValues.Dxa }
            )
        ));

        table.Append(new TableGrid(
            new GridColumn { Width = "2800" },
            new GridColumn { Width = "2400" },
            new GridColumn { Width = "2800" }
        ));

        var widths = new[] { "2800", "2400", "2800" };

        table.Append(BuildTableHeaderRow(new[] { "实验配置", "准确率", "备注" }, widths));
        table.Append(BuildTableDataRow(new[] { "Baseline", "78.2%", "标准Transformer" }, widths));
        table.Append(BuildTableDataRow(new[] { "+多头注意力", "84.6%", "\u201c最佳\u201d配置" }, widths));
        table.Append(BuildTableDataRow(new[] { "+残差连接", "82.1%", "收敛更稳定" }, widths));
        table.Append(BuildTableDataRow(new[] { "+层归一化", "85.3%", "最终方案" }, widths));

        return table;
    }

    private static TableRow BuildTableHeaderRow(string[] cells, string[] widths)
    {
        var row = new TableRow();
        row.Append(new TableRowProperties(
            new TableHeader(),
            new TableRowHeight { Val = 400, HeightType = HeightRuleValues.AtLeast }
        ));

        for (int i = 0; i < cells.Length; i++)
        {
            var cell = new TableCell(
                new TableCellProperties(
                    new TableCellWidth { Width = widths[i], Type = TableWidthUnitValues.Dxa },
                    new Shading { Val = ShadingPatternValues.Clear, Fill = Colors.TableHeader },
                    new TableCellVerticalAlignment { Val = TableVerticalAlignmentValues.Center },
                    new TableCellBorders(
                        new BottomBorder { Val = BorderValues.Single, Size = 6, Color = Colors.Primary }
                    )
                ),
                new Paragraph(
                    new ParagraphProperties(
                        new Justification { Val = JustificationValues.Center },
                        new SpacingBetweenLines { Before = "0", After = "0" }
                    ),
                    new Run(
                        new RunProperties(
                            new Bold(),
                            new Color { Val = Colors.Dark },
                            new FontSize { Val = "21" }
                        ),
                        new Text(cells[i])
                    )
                )
            );
            row.Append(cell);
        }

        return row;
    }

    private static TableRow BuildTableDataRow(string[] cells, string[] widths)
    {
        var row = new TableRow();
        row.Append(new TableRowProperties(
            new TableRowHeight { Val = 380, HeightType = HeightRuleValues.AtLeast }
        ));

        for (int i = 0; i < cells.Length; i++)
        {
            var cell = new TableCell(
                new TableCellProperties(
                    new TableCellWidth { Width = widths[i], Type = TableWidthUnitValues.Dxa },
                    new TableCellVerticalAlignment { Val = TableVerticalAlignmentValues.Center }
                ),
                new Paragraph(
                    new ParagraphProperties(
                        new Justification { Val = i == 0 ? JustificationValues.Center : JustificationValues.Left },
                        new SpacingBetweenLines { Before = "0", After = "0" }
                    ),
                    new Run(
                        new RunProperties(
                            new Color { Val = Colors.Dark },
                            new FontSize { Val = "21" }
                        ),
                        new Text(cells[i])
                    )
                )
            );
            row.Append(cell);
        }

        return row;
    }

    // ============================================================================
    // 饼图 - 中文标签
    // ============================================================================
    private static void AddPieChart(Body body, MainDocumentPart mainPart)
    {
        var chartPart = mainPart.AddNewPart<ChartPart>();
        string chartId = mainPart.GetIdOfPart(chartPart);

        chartPart.ChartSpace = BuildPieChartSpace();

        long chartWidth = 4572000;
        long chartHeight = 3429000;

        var drawing = new Drawing(
            new DW.Inline(
                new DW.Extent { Cx = chartWidth, Cy = chartHeight },
                new DW.EffectExtent { LeftEdge = 0, TopEdge = 0, RightEdge = 0, BottomEdge = 0 },
                new DW.DocProperties { Id = 11, Name = "Chart Pie" },
                new DW.NonVisualGraphicFrameDrawingProperties(
                    new A.GraphicFrameLocks { NoChangeAspect = true }
                ),
                new A.Graphic(
                    new A.GraphicData(
                        new C.ChartReference { Id = chartId }
                    )
                    { Uri = "http://schemas.openxmlformats.org/drawingml/2006/chart" }
                )
            )
            { DistanceFromTop = 0, DistanceFromBottom = 0, DistanceFromLeft = 0, DistanceFromRight = 0 }
        );

        body.Append(new Paragraph(
            new ParagraphProperties(new Justification { Val = JustificationValues.Center }),
            new Run(drawing)
        ));
    }

    private static C.ChartSpace BuildPieChartSpace()
    {
        var chartSpace = new C.ChartSpace();
        chartSpace.AddNamespaceDeclaration("c", "http://schemas.openxmlformats.org/drawingml/2006/chart");
        chartSpace.AddNamespaceDeclaration("a", "http://schemas.openxmlformats.org/drawingml/2006/main");

        var chart = new C.Chart();
        var plotArea = new C.PlotArea();

        var pieChart = new C.PieChart(
            new C.VaryColors { Val = true }
        );

        var series = new C.PieChartSeries();
        series.Append(new C.Index { Val = 0 });
        series.Append(new C.Order { Val = 0 });
        series.Append(new C.SeriesText(new C.NumericValue("数据来源")));

        // 使用 ColorSchemes.Academic 配色
        string[] colors = { ColorSchemes.Academic.Primary, ColorSchemes.Academic.Secondary,
            ColorSchemes.Academic.Accent, ColorSchemes.Academic.Mid, ColorSchemes.Academic.Light };
        // 中文标签 - 学术数据集来源
        string[] categories = { "学术论文", "网络语料", "书籍文献", "新闻数据", "其他" };
        double[] values = { 35, 28, 18, 12, 7 };

        for (uint i = 0; i < colors.Length; i++)
        {
            series.Append(new C.DataPoint(
                new C.Index { Val = i },
                new C.Bubble3D { Val = false },
                new C.ChartShapeProperties(
                    new A.SolidFill(new A.RgbColorModelHex { Val = colors[i] })
                )
            ));
        }

        var categoryData = new C.CategoryAxisData();
        var strRef = new C.StringReference();
        var strCache = new C.StringCache();
        strCache.Append(new C.PointCount { Val = (uint)categories.Length });
        for (int i = 0; i < categories.Length; i++)
        {
            strCache.Append(new C.StringPoint(new C.NumericValue(categories[i])) { Index = (uint)i });
        }
        strRef.Append(strCache);
        categoryData.Append(strRef);
        series.Append(categoryData);

        var valuesData = new C.Values();
        var numRef = new C.NumberReference();
        var numCache = new C.NumberingCache();
        numCache.Append(new C.FormatCode("General"));
        numCache.Append(new C.PointCount { Val = (uint)values.Length });
        for (int i = 0; i < values.Length; i++)
        {
            numCache.Append(new C.NumericPoint(new C.NumericValue(values[i].ToString())) { Index = (uint)i });
        }
        numRef.Append(numCache);
        valuesData.Append(numRef);
        series.Append(valuesData);

        pieChart.Append(series);
        plotArea.Append(pieChart);
        chart.Append(plotArea);

        chart.Append(new C.Legend(
            new C.LegendPosition { Val = C.LegendPositionValues.Right },
            new C.Overlay { Val = false }
        ));

        chart.Append(new C.PlotVisibleOnly { Val = true });
        chartSpace.Append(chart);

        return chartSpace;
    }

    // ============================================================================
    // 页码域
    // ============================================================================
    private static Run BuildPageNumberRun()
    {
        return new Run(
            new FieldChar { FieldCharType = FieldCharValues.Begin },
            new FieldCode(" PAGE ") { Space = SpaceProcessingModeValues.Preserve },
            new FieldChar { FieldCharType = FieldCharValues.Separate },
            new Text("1"),
            new FieldChar { FieldCharType = FieldCharValues.End }
        );
    }

    private static Run BuildTotalPagesRun()
    {
        return new Run(
            new FieldChar { FieldCharType = FieldCharValues.Begin },
            new FieldCode(" NUMPAGES ") { Space = SpaceProcessingModeValues.Preserve },
            new FieldChar { FieldCharType = FieldCharValues.Separate },
            new Text("1"),
            new FieldChar { FieldCharType = FieldCharValues.End }
        );
    }

    // ============================================================================
    // 交叉引用
    // ============================================================================
    private static IEnumerable<Run> BuildCrossReference(string bookmarkName, string displayText)
    {
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Begin });
        yield return new Run(new FieldCode($" REF {bookmarkName} \\h ") { Space = SpaceProcessingModeValues.Preserve });
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.Separate });
        yield return new Run(
            new RunProperties(new Color { Val = Colors.Primary }),
            new Text(displayText)
        );
        yield return new Run(new FieldChar { FieldCharType = FieldCharValues.End });
    }

    // ============================================================================
    // 脚注
    // ============================================================================
    private static void AddFootnote(WordprocessingDocument doc, Paragraph para, string noteText)
    {
        var mainPart = doc.MainDocumentPart!;

        if (mainPart.FootnotesPart == null)
        {
            var fnPart = mainPart.AddNewPart<FootnotesPart>();
            fnPart.Footnotes = new Footnotes(
                new Footnote(
                    new Paragraph(new Run(new SeparatorMark()))
                ) { Type = FootnoteEndnoteValues.Separator, Id = -1 },
                new Footnote(
                    new Paragraph(new Run(new ContinuationSeparatorMark()))
                ) { Type = FootnoteEndnoteValues.ContinuationSeparator, Id = 0 }
            );
        }

        var footnotes = mainPart.FootnotesPart!.Footnotes!;
        int newId = (int)(footnotes.Elements<Footnote>().Max(fn => fn.Id?.Value ?? 0) + 1);

        footnotes.Append(new Footnote(
            new Paragraph(
                new Run(
                    new RunProperties(new VerticalTextAlignment { Val = VerticalPositionValues.Superscript }),
                    new FootnoteReferenceMark()
                ),
                new Run(new Text(" " + noteText) { Space = SpaceProcessingModeValues.Preserve })
            )
        ) { Id = newId });

        para.Append(new Run(
            new RunProperties(new VerticalTextAlignment { Val = VerticalPositionValues.Superscript }),
            new FootnoteReference { Id = newId }
        ));
    }

    // ============================================================================
    // 设置打开时更新域
    // ============================================================================
    private static void SetUpdateFieldsOnOpen(MainDocumentPart mainPart)
    {
        var settingsPart = mainPart.AddNewPart<DocumentSettingsPart>();
        settingsPart.Settings = new Settings(
            new UpdateFieldsOnOpen { Val = true },
            new DisplayBackgroundShape()
        );
    }
}
