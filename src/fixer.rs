use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Cursor;
use colored::Colorize;

use crate::compression::CompressionMethod;
use crate::zip_structures::{CentralDirectoryHeader, EndOfCentralDirectory};

/// 修复统计信息
#[derive(Debug, Default)]
pub struct FixReport {
    pub compression_fixed: usize,
    pub encryption_fixed: usize,
    pub zipbomb_removed: usize,
    pub original_entries: usize,
    pub final_entries: usize,
    pub original_size: usize,
    pub final_size: usize,
}

impl FixReport {
    pub fn print_summary(&self) {
        println!("\n{}", "═══════════════════════════════════════════════".bold());
        println!("{}", "           修复完成报告".bold().green());
        println!("{}", "═══════════════════════════════════════════════".bold());

        if self.compression_fixed > 0 {
            println!("  {} 修复了 {} 个非标准压缩方法 → Deflate(8)",
                     "✓".green().bold(), self.compression_fixed);
        }

        if self.encryption_fixed > 0 {
            println!("  {} 清除了 {} 个伪造加密标志 (bit 0)",
                     "✓".green().bold(), self.encryption_fixed);
        }

        if self.zipbomb_removed > 0 {
            println!("  {} 移除了 {} 个 Zip Bomb 诱饵条目",
                     "✓".green().bold(), self.zipbomb_removed);
        }

        println!("\n  条目数变化: {} → {}",
                 self.original_entries, self.final_entries);
        println!("  文件大小:   {} → {} ({:.2}%)",
                 format_size(self.original_size as u64),
                 format_size(self.final_size as u64),
                 (self.final_size as f64 / self.original_size as f64) * 100.0);

        println!();
    }
}

/// 一键修复所有问题
pub fn fix_all(data: &[u8], ratio_threshold: f64) -> Result<(Vec<u8>, FixReport)> {
    let mut report = FixReport {
        original_size: data.len(),
        ..Default::default()
    };

    // Step 1: 解析原始结构
    let eocd_pos = EndOfCentralDirectory::find(data)?;
    let mut cursor = Cursor::new(&data[eocd_pos..]);
    let eocd = EndOfCentralDirectory::parse(&mut cursor)?;

    report.original_entries = eocd.cd_records_total as usize;

    let cd_start = eocd.cd_offset as usize;
    let mut cursor = Cursor::new(&data[cd_start..]);

    // Step 2: 读取所有 CDH，同时修复和过滤
    let mut fixed_entries = Vec::new();

    for i in 0..eocd.cd_records_total {
        let mut cdh = CentralDirectoryHeader::parse(&mut cursor)
            .with_context(|| format!("解析第 {} 个 CDH 失败", i))?;

        // 检测 Zip Bomb（先过滤，避免浪费修复资源）
        let ratio = cdh.compression_ratio();
        if ratio > ratio_threshold {
            report.zipbomb_removed += 1;
            continue; // 跳过此条目
        }

        // 修复 1: 非标准压缩方法
        if !CompressionMethod::is_valid(cdh.compression_method) {
            cdh.compression_method = CompressionMethod::RECOMMENDED_FIX;
            report.compression_fixed += 1;
        }

        // 修复 2: 伪造加密标志
        if cdh.flags & 0x0001 != 0 {
            cdh.flags &= 0xFFFE; // 清除 bit 0
            report.encryption_fixed += 1;
        }

        fixed_entries.push(cdh);
    }

    report.final_entries = fixed_entries.len();

    // Step 3: 构建新文件
    let mut new_data = Vec::with_capacity(data.len());

    // 3.1 复制 Local File Headers 区域（保持不变）
    new_data.extend_from_slice(&data[..cd_start]);

    // 3.2 修复 Local File Headers 中的压缩方法和加密标志
    for cdh in &fixed_entries {
        let lfh_offset = cdh.local_header_offset as usize;

        // 修复 LFH compression_method (offset +8)
        let method_offset = lfh_offset + 8;
        if method_offset + 2 <= new_data.len() {
            new_data[method_offset..method_offset + 2]
                .copy_from_slice(&cdh.compression_method.to_le_bytes());
        }

        // 修复 LFH flags (offset +6)
        let flags_offset = lfh_offset + 6;
        if flags_offset + 2 <= new_data.len() {
            new_data[flags_offset..flags_offset + 2]
                .copy_from_slice(&cdh.flags.to_le_bytes());
        }
    }

    // 3.3 写入新的 Central Directory
    let new_cd_offset = new_data.len();
    for cdh in &fixed_entries {
        let serialized = cdh.serialize()?;
        new_data.extend_from_slice(&serialized);
    }
    let new_cd_size = new_data.len() - new_cd_offset;

    // 3.4 写入新的 EOCD
    let new_eocd = EndOfCentralDirectory {
        signature: EndOfCentralDirectory::SIGNATURE,
        disk_number: eocd.disk_number,
        cd_start_disk: eocd.cd_start_disk,
        cd_records_on_disk: fixed_entries.len() as u16,
        cd_records_total: fixed_entries.len() as u16,
        cd_size: new_cd_size as u32,
        cd_offset: new_cd_offset as u32,
        comment_length: eocd.comment_length,
        comment: eocd.comment.clone(),
    };

    new_data.extend_from_slice(&new_eocd.serialize()?);

    report.final_size = new_data.len();

    Ok((new_data, report))
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
