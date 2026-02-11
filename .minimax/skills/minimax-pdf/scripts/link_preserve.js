#!/usr/bin/env node
/**
 * Link Preserver - 链接保留工具
 * 
 * 用于在翻译过程中保留超链接信息。
 * 
 * 工作流程：
 * 1. 从原始HTML中提取所有链接 (extractLinks)
 * 2. 翻译HTML内容（外部工具）
 * 3. 将链接重新注入翻译后的HTML (restoreLinks)
 * 
 * 使用方式：
 *   node link_preserver.js extract source.html --output links.json
 *   node link_preserver.js restore translated.html links.json --output final.html
 */

const fs = require('fs');
const path = require('path');

/**
 * 从HTML中提取所有链接信息
 * @param {string} html - HTML内容
 * @returns {Array} 链接信息数组
 */
function extractLinksFromHTML(html) {
  const links = [];
  
  // 匹配 <a> 标签
  const anchorRegex = /<a\s+([^>]*href\s*=\s*["']([^"']+)["'][^>]*)>([^<]*(?:<[^a][^<]*)*)<\/a>/gi;
  
  let match;
  while ((match = anchorRegex.exec(html)) !== null) {
    const [fullMatch, attributes, href, innerContent] = match;
    
    // 提取链接文本（去除HTML标签）
    const text = innerContent.replace(/<[^>]+>/g, '').trim();
    
    if (!text || !href) continue;
    
    // 提取其他属性
    const targetMatch = attributes.match(/target\s*=\s*["']([^"']+)["']/i);
    const titleMatch = attributes.match(/title\s*=\s*["']([^"']+)["']/i);
    
    links.push({
      href,
      text,
      textNormalized: normalizeText(text),
      target: targetMatch ? targetMatch[1] : null,
      title: titleMatch ? titleMatch[1] : null,
      isExternal: href.startsWith('http://') || href.startsWith('https://'),
      isInternal: href.startsWith('#'),
      position: match.index
    });
  }
  
  return links;
}

/**
 * 标准化文本用于匹配
 * @param {string} text 
 * @returns {string}
 */
function normalizeText(text) {
  return text
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[^\w\u4e00-\u9fa5\s]/g, '')  // 保留中英文和数字
    .trim();
}

/**
 * 在翻译后的HTML中恢复链接
 * @param {string} html - 翻译后的HTML
 * @param {Array} links - 原始链接信息
 * @param {Object} options - 选项
 * @returns {Object} 恢复结果
 */
function restoreLinksToHTML(html, links, options = {}) {
  const {
    fuzzyMatch = true,        // 模糊匹配
    minSimilarity = 0.6,      // 最小相似度
    preserveExternal = true,  // 保留外部链接
    preserveInternal = true,  // 保留内部链接
  } = options;
  
  let result = html;
  const restored = [];
  const notFound = [];
  
  for (const link of links) {
    if (!preserveExternal && link.isExternal) continue;
    if (!preserveInternal && link.isInternal) continue;
    
    // 尝试精确匹配
    let found = false;
    const escapedText = escapeRegex(link.text);
    
    // 先尝试精确匹配
    const exactRegex = new RegExp(`(?<!<a[^>]*>)${escapedText}(?![^<]*</a>)`, 'g');
    if (exactRegex.test(result)) {
      result = result.replace(exactRegex, (match) => {
        found = true;
        return createAnchorTag(link, match);
      });
    }
    
    // 如果没找到且启用模糊匹配，尝试模糊匹配
    if (!found && fuzzyMatch) {
      // 尝试查找相似文本
      const similarMatch = findSimilarText(result, link.text, minSimilarity);
      if (similarMatch) {
        const similarRegex = new RegExp(`(?<!<a[^>]*>)${escapeRegex(similarMatch)}(?![^<]*</a>)`, 'g');
        result = result.replace(similarRegex, (match) => {
          found = true;
          return createAnchorTag(link, match);
        });
      }
    }
    
    if (found) {
      restored.push(link);
    } else {
      notFound.push(link);
    }
  }
  
  return {
    html: result,
    stats: {
      total: links.length,
      restored: restored.length,
      notFound: notFound.length
    },
    restored,
    notFound
  };
}

/**
 * 转义正则表达式特殊字符
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * 创建锚点标签
 */
function createAnchorTag(link, text) {
  let attrs = `href="${link.href}"`;
  if (link.target) attrs += ` target="${link.target}"`;
  if (link.title) attrs += ` title="${link.title}"`;
  if (link.isExternal) attrs += ` rel="noopener noreferrer"`;
  return `<a ${attrs}>${text}</a>`;
}

/**
 * 在文本中查找相似内容
 * @param {string} html 
 * @param {string} targetText 
 * @param {number} minSimilarity 
 * @returns {string|null}
 */
function findSimilarText(html, targetText, minSimilarity) {
  // 提取HTML中的纯文本片段
  const textContent = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  const words = targetText.split(/\s+/);
  
  if (words.length === 0) return null;
  
  // 对于短文本，尝试查找包含关键词的片段
  if (words.length <= 3) {
    const mainWord = words.reduce((a, b) => a.length > b.length ? a : b);
    const regex = new RegExp(`[^<>]{0,20}${escapeRegex(mainWord)}[^<>]{0,20}`, 'gi');
    const matches = html.match(regex);
    
    if (matches) {
      for (const match of matches) {
        const cleanMatch = match.replace(/<[^>]+>/g, '').trim();
        if (calculateSimilarity(cleanMatch, targetText) >= minSimilarity) {
          return cleanMatch;
        }
      }
    }
  }
  
  return null;
}

/**
 * 计算两个字符串的相似度 (Dice coefficient)
 */
function calculateSimilarity(str1, str2) {
  const s1 = normalizeText(str1);
  const s2 = normalizeText(str2);
  
  if (s1 === s2) return 1;
  if (s1.length < 2 || s2.length < 2) return 0;
  
  const bigrams1 = new Set();
  for (let i = 0; i < s1.length - 1; i++) {
    bigrams1.add(s1.substring(i, i + 2));
  }
  
  let intersection = 0;
  for (let i = 0; i < s2.length - 1; i++) {
    const bigram = s2.substring(i, i + 2);
    if (bigrams1.has(bigram)) {
      intersection++;
      bigrams1.delete(bigram);
    }
  }
  
  return (2 * intersection) / (s1.length + s2.length - 2);
}

/**
 * 创建翻译占位符映射
 * 在翻译前将链接替换为占位符，翻译后恢复
 */
function createPlaceholderMap(html) {
  const placeholders = [];
  let result = html;
  let index = 0;
  
  const anchorRegex = /<a\s+[^>]*href\s*=\s*["'][^"']+["'][^>]*>[\s\S]*?<\/a>/gi;
  
  result = result.replace(anchorRegex, (match) => {
    const placeholder = `[[LINK_PLACEHOLDER_${index}]]`;
    placeholders.push({
      placeholder,
      original: match,
      index
    });
    index++;
    return placeholder;
  });
  
  return {
    html: result,
    placeholders
  };
}

/**
 * 从占位符映射恢复链接
 */
function restoreFromPlaceholders(html, placeholders) {
  let result = html;
  let restored = 0;
  
  for (const { placeholder, original } of placeholders) {
    if (result.includes(placeholder)) {
      result = result.replace(placeholder, original);
      restored++;
    }
  }
  
  return {
    html: result,
    restored,
    total: placeholders.length
  };
}

// ============================================================================
// CLI 命令
// ============================================================================

function printHelp() {
  console.log(`
Link Preserver - 翻译过程中保留超链接

用法:
  node link_preserver.js <command> [options]

命令:
  extract <input.html>              从HTML提取链接信息
    --output, -o <file>             输出JSON文件路径

  restore <input.html> <links.json> 将链接恢复到翻译后的HTML
    --output, -o <file>             输出HTML文件路径
    --fuzzy                         启用模糊匹配 (默认开启)
    --no-fuzzy                      禁用模糊匹配
    --similarity <0-1>              最小相似度阈值 (默认0.6)

  placeholder <input.html>          用占位符替换链接（翻译前）
    --output, -o <file>             输出HTML文件路径
    --map, -m <file>                输出映射JSON文件路径

  unplaceholder <input.html> <map>  从占位符恢复链接（翻译后）
    --output, -o <file>             输出HTML文件路径

示例:
  # 方法1: 提取-翻译-恢复
  node link_preserver.js extract original.html -o links.json
  # ... 翻译 original.html 得到 translated.html ...
  node link_preserver.js restore translated.html links.json -o final.html

  # 方法2: 占位符保护
  node link_preserver.js placeholder original.html -o temp.html -m map.json
  # ... 翻译 temp.html 得到 translated.html ...
  node link_preserver.js unplaceholder translated.html map.json -o final.html
  `);
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    printHelp();
    process.exit(0);
  }
  
  const command = args[0];
  
  switch (command) {
    case 'extract': {
      const inputFile = args[1];
      if (!inputFile) {
        console.error('错误: 请指定输入HTML文件');
        process.exit(1);
      }
      
      let outputFile = null;
      for (let i = 2; i < args.length; i++) {
        if (args[i] === '--output' || args[i] === '-o') {
          outputFile = args[++i];
        }
      }
      
      if (!outputFile) {
        outputFile = inputFile.replace(/\.html?$/i, '.links.json');
      }
      
      const html = fs.readFileSync(inputFile, 'utf-8');
      const links = extractLinksFromHTML(html);
      
      fs.writeFileSync(outputFile, JSON.stringify(links, null, 2));
      
      console.log(`提取完成:`);
      console.log(`  总链接数: ${links.length}`);
      console.log(`  外部链接: ${links.filter(l => l.isExternal).length}`);
      console.log(`  内部链接: ${links.filter(l => l.isInternal).length}`);
      console.log(`  输出文件: ${outputFile}`);
      break;
    }
    
    case 'restore': {
      const inputFile = args[1];
      const linksFile = args[2];
      
      if (!inputFile || !linksFile) {
        console.error('错误: 请指定翻译后的HTML和链接JSON文件');
        process.exit(1);
      }
      
      let outputFile = null;
      let fuzzyMatch = true;
      let minSimilarity = 0.6;
      
      for (let i = 3; i < args.length; i++) {
        if (args[i] === '--output' || args[i] === '-o') {
          outputFile = args[++i];
        } else if (args[i] === '--no-fuzzy') {
          fuzzyMatch = false;
        } else if (args[i] === '--fuzzy') {
          fuzzyMatch = true;
        } else if (args[i] === '--similarity') {
          minSimilarity = parseFloat(args[++i]);
        }
      }
      
      if (!outputFile) {
        outputFile = inputFile.replace(/\.html?$/i, '.linked.html');
      }
      
      const html = fs.readFileSync(inputFile, 'utf-8');
      const links = JSON.parse(fs.readFileSync(linksFile, 'utf-8'));
      
      const result = restoreLinksToHTML(html, links, { fuzzyMatch, minSimilarity });
      
      fs.writeFileSync(outputFile, result.html);
      
      console.log(`恢复完成:`);
      console.log(`  原始链接: ${result.stats.total}`);
      console.log(`  已恢复: ${result.stats.restored}`);
      console.log(`  未找到: ${result.stats.notFound}`);
      console.log(`  输出文件: ${outputFile}`);
      
      if (result.notFound.length > 0) {
        console.log(`\n未能恢复的链接:`);
        result.notFound.slice(0, 10).forEach(l => {
          console.log(`  - "${l.text}" -> ${l.href}`);
        });
        if (result.notFound.length > 10) {
          console.log(`  ... 还有 ${result.notFound.length - 10} 个`);
        }
      }
      break;
    }
    
    case 'placeholder': {
      const inputFile = args[1];
      if (!inputFile) {
        console.error('错误: 请指定输入HTML文件');
        process.exit(1);
      }
      
      let outputFile = null;
      let mapFile = null;
      
      for (let i = 2; i < args.length; i++) {
        if (args[i] === '--output' || args[i] === '-o') {
          outputFile = args[++i];
        } else if (args[i] === '--map' || args[i] === '-m') {
          mapFile = args[++i];
        }
      }
      
      if (!outputFile) {
        outputFile = inputFile.replace(/\.html?$/i, '.placeholder.html');
      }
      if (!mapFile) {
        mapFile = inputFile.replace(/\.html?$/i, '.linkmap.json');
      }
      
      const html = fs.readFileSync(inputFile, 'utf-8');
      const result = createPlaceholderMap(html);
      
      fs.writeFileSync(outputFile, result.html);
      fs.writeFileSync(mapFile, JSON.stringify(result.placeholders, null, 2));
      
      console.log(`占位符替换完成:`);
      console.log(`  替换链接数: ${result.placeholders.length}`);
      console.log(`  输出HTML: ${outputFile}`);
      console.log(`  映射文件: ${mapFile}`);
      break;
    }
    
    case 'unplaceholder': {
      const inputFile = args[1];
      const mapFile = args[2];
      
      if (!inputFile || !mapFile) {
        console.error('错误: 请指定翻译后的HTML和映射JSON文件');
        process.exit(1);
      }
      
      let outputFile = null;
      for (let i = 3; i < args.length; i++) {
        if (args[i] === '--output' || args[i] === '-o') {
          outputFile = args[++i];
        }
      }
      
      if (!outputFile) {
        outputFile = inputFile.replace(/\.html?$/i, '.final.html');
      }
      
      const html = fs.readFileSync(inputFile, 'utf-8');
      const placeholders = JSON.parse(fs.readFileSync(mapFile, 'utf-8'));
      
      const result = restoreFromPlaceholders(html, placeholders);
      
      fs.writeFileSync(outputFile, result.html);
      
      console.log(`占位符恢复完成:`);
      console.log(`  总占位符: ${result.total}`);
      console.log(`  已恢复: ${result.restored}`);
      console.log(`  输出文件: ${outputFile}`);
      break;
    }
    
    default:
      console.error(`未知命令: ${command}`);
      printHelp();
      process.exit(1);
  }
}

// 导出模块函数
module.exports = {
  extractLinksFromHTML,
  restoreLinksToHTML,
  createPlaceholderMap,
  restoreFromPlaceholders,
  normalizeText,
  calculateSimilarity
};

// CLI 入口
if (require.main === module) {
  main();
}
