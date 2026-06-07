/// AXML (Android Binary XML) 修复模块
///
/// 针对 Apktool 常见失败场景：
/// 1. EOFException - 文件大小字段被篡改
/// 2. Invalid Chunk Type - Chunk 头部损坏
/// 3. StringPool 索引越界 - 计数字段错误

use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use colored::Colorize;
use std::io::{Cursor, Read};

/// AXML 魔数（所有 Android Binary XML 文件的开头）
const AXML_MAGIC: u32 = 0x00080003;

/// AXML Chunk 类型
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
enum ChunkType {
    StringPool = 0x001C0001,
    ResourceMap = 0x00180001,
    StartNamespace = 0x00100100,
    EndNamespace = 0x00100101,
    StartTag = 0x00100102,
    EndTag = 0x00100103,
    Text = 0x00100104,
}

impl ChunkType {
    fn from_u32(val: u32) -> Option<Self> {
        match val {
            0x001C0001 => Some(Self::StringPool),
            0x00180001 => Some(Self::ResourceMap),
            0x00100100 => Some(Self::StartNamespace),
            0x00100101 => Some(Self::EndNamespace),
            0x00100102 => Some(Self::StartTag),
            0x00100103 => Some(Self::EndTag),
            0x00100104 => Some(Self::Text),
            _ => None,
        }
    }

    fn is_valid(val: u32) -> bool {
        Self::from_u32(val).is_some()
    }
}

/// AXML 修复报告
#[derive(Debug, Default)]
pub struct AxmlFixReport {
    pub magic_fixed: bool,
    pub file_size_fixed: bool,
    pub truncated_chunks_removed: usize,
    pub invalid_chunks_fixed: usize,
    pub original_size: usize,
    pub final_size: usize,
}

impl AxmlFixReport {
    pub fn has_fixes(&self) -> bool {
        self.magic_fixed
            || self.file_size_fixed
            || self.truncated_chunks_removed > 0
            || self.invalid_chunks_fixed > 0
    }

    pub fn print_summary(&self) {
        if !self.has_fixes() {
            println!("  {} AXML 文件格式正常", "✓".green().bold());
            return;
        }

        println!("\n{}", "  AXML 修复详情:".yellow());

        if self.magic_fixed {
            println!("    {} 修复了文件头魔数 (0x00080003)", "✓".green());
        }

        if self.file_size_fixed {
            println!("    {} 修正了文件大小字段 ({} → {})",
                     "✓".green(), self.original_size, self.final_size);
        }

        if self.truncated_chunks_removed > 0 {
            println!("    {} 移除了 {} 个截断的 Chunk",
                     "✓".green(), self.truncated_chunks_removed);
        }

        if self.invalid_chunks_fixed > 0 {
            println!("    {} 修复了 {} 个无效 Chunk 头部",
                     "✓".green(), self.invalid_chunks_fixed);
        }
    }
}

/// 检测 AXML 文件是否损坏
pub fn detect_axml_issues(data: &[u8]) -> Result<Vec<String>> {
    let mut issues = Vec::new();

    if data.len() < 8 {
        issues.push(format!("文件过小 ({} bytes)，无法包含有效的 AXML 头部", data.len()));
        return Ok(issues);
    }

    let mut cursor = Cursor::new(data);

    // 检查魔数
    let magic = cursor.read_u32::<LittleEndian>()?;
    if magic != AXML_MAGIC {
        issues.push(format!("无效的 AXML 魔数: 0x{:08x} (期望 0x{:08x})", magic, AXML_MAGIC));
    }

    // 检查文件大小
    let declared_size = cursor.read_u32::<LittleEndian>()? as usize;
    if declared_size != data.len() {
        issues.push(format!(
            "文件大小不匹配: 声明 {} bytes，实际 {} bytes ({})",
            declared_size,
            data.len(),
            if declared_size > data.len() { "截断" } else { "填充" }
        ));
    }

    // 检查 Chunk 完整性
    if magic == AXML_MAGIC {
        match validate_chunks(&data[8..], &mut issues) {
            Ok(_) => {}
            Err(e) => {
                issues.push(format!("Chunk 解析失败: {}", e));
            }
        }
    }

    Ok(issues)
}

/// 验证 Chunk 链的完整性
fn validate_chunks(data: &[u8], issues: &mut Vec<String>) -> Result<()> {
    let mut cursor = Cursor::new(data);
    let mut chunk_count = 0;

    while cursor.position() < data.len() as u64 {
        let chunk_start = cursor.position() as usize;

        // 至少需要 8 字节 (chunk_type + chunk_size)
        if data.len() - chunk_start < 8 {
            issues.push(format!(
                "Chunk #{} 头部截断 (偏移 0x{:x}, 剩余 {} bytes)",
                chunk_count, chunk_start, data.len() - chunk_start
            ));
            break;
        }

        let chunk_type = cursor.read_u32::<LittleEndian>()?;
        let chunk_size = cursor.read_u32::<LittleEndian>()? as usize;

        // 检查 Chunk 类型
        if !ChunkType::is_valid(chunk_type) {
            issues.push(format!(
                "Chunk #{} 类型无效: 0x{:08x} (偏移 0x{:x})",
                chunk_count, chunk_type, chunk_start
            ));
        }

        // 检查 Chunk 大小
        if chunk_size < 8 {
            issues.push(format!(
                "Chunk #{} 大小异常: {} bytes (最小 8 bytes)",
                chunk_count, chunk_size
            ));
            break;
        }

        // 检查是否超出文件范围
        if chunk_start + chunk_size > data.len() {
            issues.push(format!(
                "Chunk #{} 超出文件范围: 偏移 0x{:x}, 大小 {} bytes, 文件剩余 {} bytes",
                chunk_count, chunk_start, chunk_size, data.len() - chunk_start
            ));
            break;
        }

        // 跳到下一个 Chunk（当前位置已经在 +8，需要再跳 chunk_size-8）
        cursor.set_position((chunk_start + chunk_size) as u64);
        chunk_count += 1;
    }

    Ok(())
}

/// 修复 AXML 文件（策略：保守修复，优先保留数据）
pub fn fix_axml(data: &[u8]) -> Result<(Vec<u8>, AxmlFixReport)> {
    let mut report = AxmlFixReport {
        original_size: data.len(),
        ..Default::default()
    };

    if data.len() < 8 {
        bail!("文件过小 ({} bytes)，无法修复", data.len());
    }

    let mut fixed = Vec::with_capacity(data.len());
    let mut cursor = Cursor::new(data);

    // Step 1: 修复文件头
    let magic = cursor.read_u32::<LittleEndian>()?;
    let declared_size = cursor.read_u32::<LittleEndian>()? as usize;

    // 修复魔数
    if magic != AXML_MAGIC {
        println!("  {} 检测到损坏的魔数 0x{:08x}，尝试修复...", "!".yellow(), magic);
        fixed.write_u32::<LittleEndian>(AXML_MAGIC)?;
        report.magic_fixed = true;
    } else {
        fixed.write_u32::<LittleEndian>(magic)?;
    }

    // 暂时写入占位的文件大小，后续会更新
    let size_offset = fixed.len();
    fixed.write_u32::<LittleEndian>(0)?;

    // Step 2: 修复 Chunk 链
    let chunks_data = &data[8..];
    let mut chunk_cursor = Cursor::new(chunks_data);
    let mut chunk_count = 0;

    while chunk_cursor.position() < chunks_data.len() as u64 {
        let chunk_start = chunk_cursor.position() as usize;

        // 检查是否有足够空间读取 Chunk 头部
        if chunks_data.len() - chunk_start < 8 {
            println!("  {} Chunk #{} 头部截断，丢弃剩余 {} bytes",
                     "!".yellow(), chunk_count, chunks_data.len() - chunk_start);
            report.truncated_chunks_removed += 1;
            break;
        }

        let chunk_type = chunk_cursor.read_u32::<LittleEndian>()?;
        let chunk_size = chunk_cursor.read_u32::<LittleEndian>()? as usize;

        // 检查 Chunk 类型有效性
        if !ChunkType::is_valid(chunk_type) {
            println!("  {} Chunk #{} 类型无效 (0x{:08x})，尝试跳过",
                     "!".yellow(), chunk_count, chunk_type);
            report.invalid_chunks_fixed += 1;

            // 尝试搜索下一个有效的 Chunk 魔数
            let search_start = chunk_start + 4;
            if let Some(next_valid) = find_next_valid_chunk(&chunks_data[search_start..]) {
                chunk_cursor.set_position((search_start + next_valid) as u64);
                continue;
            } else {
                println!("  {} 未找到后续有效 Chunk，截断于此", "!".yellow());
                break;
            }
        }

        // 检查 Chunk 大小合理性
        if chunk_size < 8 || chunk_start + chunk_size > chunks_data.len() {
            println!("  {} Chunk #{} 大小异常 ({} bytes)，截断于此",
                     "!".yellow(), chunk_count, chunk_size);
            report.truncated_chunks_removed += 1;
            break;
        }

        // 复制完整的 Chunk（包括头部）
        chunk_cursor.set_position(chunk_start as u64);
        let mut chunk_data = vec![0u8; chunk_size];
        chunk_cursor.read_exact(&mut chunk_data)?;
        fixed.extend_from_slice(&chunk_data);

        chunk_count += 1;
    }

    // Step 3: 修正文件大小字段
    let actual_size = fixed.len();
    if actual_size != declared_size {
        report.file_size_fixed = true;
    }

    // 回写正确的文件大小
    let mut size_bytes = [0u8; 4];
    (&mut size_bytes[..]).write_u32::<LittleEndian>(actual_size as u32)?;
    fixed[size_offset..size_offset + 4].copy_from_slice(&size_bytes);

    report.final_size = actual_size;

    Ok((fixed, report))
}

/// 查找下一个有效的 Chunk 起始位置
fn find_next_valid_chunk(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(8) {
        let chunk_type = u32::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
        ]);

        if ChunkType::is_valid(chunk_type) {
            let chunk_size = u32::from_le_bytes([
                data[i + 4],
                data[i + 5],
                data[i + 6],
                data[i + 7],
            ]) as usize;

            // 确保大小合理
            if chunk_size >= 8 && i + chunk_size <= data.len() {
                return Some(i);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_invalid_magic() {
        let mut data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x08, 0x00, 0x00, 0x00];
        let issues = detect_axml_issues(&data).unwrap();
        assert!(issues.len() > 0);
        assert!(issues[0].contains("魔数"));
    }

    #[test]
    fn test_fix_truncated_file() {
        // 创建一个声明 1024 字节但实际只有 100 字节的文件
        let mut data = Vec::new();
        data.extend_from_slice(&AXML_MAGIC.to_le_bytes());
        data.extend_from_slice(&1024u32.to_le_bytes());
        data.resize(100, 0x00);

        let (fixed, report) = fix_axml(&data).unwrap();
        assert!(report.file_size_fixed);
        assert_eq!(fixed.len(), 8); // 只有头部，没有有效 Chunk
    }

    #[test]
    fn test_fix_corrupted_magic() {
        let mut data = vec![
            0x99, 0x88, 0x77, 0x66, // 错误的魔数
            0x08, 0x00, 0x00, 0x00, // file_size = 8
        ];

        let (fixed, report) = fix_axml(&data).unwrap();
        assert!(report.magic_fixed);
        assert_eq!(&fixed[0..4], &AXML_MAGIC.to_le_bytes());
    }
}
