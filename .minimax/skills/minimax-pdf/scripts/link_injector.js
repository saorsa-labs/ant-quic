#!/usr/bin/env node
/**
 * PDF Link Injector - 链接映射和注入工具
 * 
 * 用于在HTML转PDF后，将超链接信息重新注入到PDF中。
 * 
 * 功能：
 * 1. 提取HTML中所有超链接的位置信息
 * 2. 将链接作为PDF注解添加到生成的PDF中
 * 
 * 使用方式：
 *   // 在 html_to_pdf.js 中集成
 *   const { extractLinks, injectLinks } = require('./link_injector');
 */

const fs = require('fs');
const path = require('path');

/**
 * 在Paged.js分页后提取所有链接信息
 * @param {Page} page - Playwright page对象
 * @returns {Promise<Array>} 链接信息数组
 */
async function extractLinksFromPage(page) {
  return await page.evaluate(() => {
    const links = [];
    const pages = document.querySelectorAll('.pagedjs_page');
    
    // A4尺寸 (mm转为pt: 1mm = 2.834645pt)
    const PAGE_WIDTH_PT = 595.28;   // 210mm
    const PAGE_HEIGHT_PT = 841.89;  // 297mm
    
    pages.forEach((pageEl, pageIndex) => {
      // 获取页面内容区域
      const pageContent = pageEl.querySelector('.pagedjs_page_content') || pageEl;
      const pageRect = pageContent.getBoundingClientRect();
      
      // 查找该页面内的所有链接
      const anchors = pageContent.querySelectorAll('a[href]');
      
      anchors.forEach(anchor => {
        const href = anchor.getAttribute('href');
        if (!href) return;
        
        // 获取链接在页面中的位置
        const rect = anchor.getBoundingClientRect();
        
        // 检查链接是否在当前页面可见范围内
        if (rect.width === 0 || rect.height === 0) return;
        if (rect.top < pageRect.top || rect.bottom > pageRect.bottom) return;
        
        // 计算相对于页面的坐标 (转换为PDF坐标系)
        // PDF坐标系：原点在左下角，y轴向上
        const relativeX = rect.left - pageRect.left;
        const relativeY = rect.top - pageRect.top;
        
        // 计算缩放比例
        const scaleX = PAGE_WIDTH_PT / pageRect.width;
        const scaleY = PAGE_HEIGHT_PT / pageRect.height;
        
        // 转换为PDF坐标
        const pdfX = relativeX * scaleX;
        const pdfY = PAGE_HEIGHT_PT - (relativeY + rect.height) * scaleY;  // 翻转Y轴
        const pdfWidth = rect.width * scaleX;
        const pdfHeight = rect.height * scaleY;
        
        // 判断链接类型
        const isInternal = href.startsWith('#');
        const isExternal = href.startsWith('http://') || href.startsWith('https://');
        
        links.push({
          href,
          type: isInternal ? 'internal' : (isExternal ? 'external' : 'relative'),
          pageNumber: pageIndex + 1,  // 1-based
          // PDF坐标 (左下角为原点)
          rect: {
            x: Math.max(0, pdfX),
            y: Math.max(0, pdfY),
            width: pdfWidth,
            height: pdfHeight
          },
          // 原始文本
          text: anchor.textContent?.trim() || '',
          // 如果是内部链接，尝试找到目标位置
          targetId: isInternal ? href.slice(1) : null
        });
      });
    });
    
    return links;
  });
}

/**
 * 提取内部链接目标的位置信息
 * @param {Page} page - Playwright page对象
 * @returns {Promise<Object>} 目标ID到位置的映射
 */
async function extractLinkTargets(page) {
  return await page.evaluate(() => {
    const targets = {};
    const pages = document.querySelectorAll('.pagedjs_page');
    
    const PAGE_HEIGHT_PT = 841.89;
    
    pages.forEach((pageEl, pageIndex) => {
      const pageContent = pageEl.querySelector('.pagedjs_page_content') || pageEl;
      const pageRect = pageContent.getBoundingClientRect();
      
      // 查找所有带ID的元素
      const elementsWithId = pageContent.querySelectorAll('[id]');
      
      elementsWithId.forEach(el => {
        const id = el.getAttribute('id');
        if (!id) return;
        
        const rect = el.getBoundingClientRect();
        if (rect.top < pageRect.top || rect.top > pageRect.bottom) return;
        
        const relativeY = rect.top - pageRect.top;
        const scaleY = PAGE_HEIGHT_PT / pageRect.height;
        const pdfY = PAGE_HEIGHT_PT - relativeY * scaleY;
        
        targets[id] = {
          pageNumber: pageIndex + 1,
          y: Math.max(0, pdfY)
        };
      });
    });
    
    return targets;
  });
}

/**
 * 生成链接映射数据
 * @param {Page} page - Playwright page对象
 * @returns {Promise<Object>} 完整的链接映射数据
 */
async function generateLinkMap(page) {
  const links = await extractLinksFromPage(page);
  const targets = await extractLinkTargets(page);
  
  // 将内部链接与目标位置关联
  links.forEach(link => {
    if (link.type === 'internal' && link.targetId) {
      const target = targets[link.targetId];
      if (target) {
        link.targetPage = target.pageNumber;
        link.targetY = target.y;
      }
    }
  });
  
  return {
    links,
    targets,
    stats: {
      total: links.length,
      internal: links.filter(l => l.type === 'internal').length,
      external: links.filter(l => l.type === 'external').length,
      relative: links.filter(l => l.type === 'relative').length
    }
  };
}

/**
 * 使用pdf-lib将链接注入到PDF
 * @param {string} pdfPath - PDF文件路径
 * @param {Object} linkMap - 链接映射数据
 * @returns {Promise<void>}
 */
async function injectLinksIntoPdf(pdfPath, linkMap) {
  // 动态导入 pdf-lib
  let PDFDocument, rgb;
  try {
    const pdfLib = require('pdf-lib');
    PDFDocument = pdfLib.PDFDocument;
    rgb = pdfLib.rgb;
  } catch (err) {
    console.warn('⚠️  pdf-lib 未安装，跳过链接注入');
    console.warn('   安装: npm install pdf-lib');
    return;
  }
  
  // 读取PDF
  const pdfBytes = fs.readFileSync(pdfPath);
  const pdfDoc = await PDFDocument.load(pdfBytes);
  const pages = pdfDoc.getPages();
  
  let injectedCount = 0;
  
  for (const link of linkMap.links) {
    const pageIndex = link.pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= pages.length) continue;
    
    const page = pages[pageIndex];
    const { x, y, width, height } = link.rect;
    
    try {
      if (link.type === 'external' && link.href) {
        // 外部链接：创建URI注解
        page.node.addAnnot(
          pdfDoc.context.obj({
            Type: 'Annot',
            Subtype: 'Link',
            Rect: [x, y, x + width, y + height],
            Border: [0, 0, 0],
            A: {
              Type: 'Action',
              S: 'URI',
              URI: link.href
            }
          })
        );
        injectedCount++;
      } else if (link.type === 'internal' && link.targetPage) {
        // 内部链接：创建GoTo注解
        const targetPageIndex = link.targetPage - 1;
        if (targetPageIndex >= 0 && targetPageIndex < pages.length) {
          const targetPage = pages[targetPageIndex];
          page.node.addAnnot(
            pdfDoc.context.obj({
              Type: 'Annot',
              Subtype: 'Link',
              Rect: [x, y, x + width, y + height],
              Border: [0, 0, 0],
              Dest: [targetPage.ref, 'XYZ', null, link.targetY || null, null]
            })
          );
          injectedCount++;
        }
      }
    } catch (err) {
      // 忽略单个链接注入失败
      console.warn(`  链接注入失败: ${link.href}`);
    }
  }
  
  // 保存修改后的PDF
  const modifiedPdfBytes = await pdfDoc.save();
  fs.writeFileSync(pdfPath, modifiedPdfBytes);
  
  return injectedCount;
}

/**
 * 保存链接映射到JSON文件（用于调试或后续处理）
 * @param {string} outputPath - 输出路径
 * @param {Object} linkMap - 链接映射数据
 */
function saveLinkMap(outputPath, linkMap) {
  const jsonPath = outputPath.replace(/\.pdf$/i, '.links.json');
  fs.writeFileSync(jsonPath, JSON.stringify(linkMap, null, 2));
  return jsonPath;
}

module.exports = {
  extractLinksFromPage,
  extractLinkTargets,
  generateLinkMap,
  injectLinksIntoPdf,
  saveLinkMap
};

// 独立运行测试
if (require.main === module) {
  console.log('Link Injector 模块');
  console.log('此模块需要在 html_to_pdf.js 中集成使用');
  console.log('');
  console.log('功能:');
  console.log('  - extractLinksFromPage(page): 提取页面中所有链接');
  console.log('  - generateLinkMap(page): 生成完整链接映射');
  console.log('  - injectLinksIntoPdf(pdfPath, linkMap): 将链接注入PDF');
}
