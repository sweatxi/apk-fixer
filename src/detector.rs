use anyhow::{Context, Result};
use std::io::Cursor;
use colored::Colorize;

use crate::compression::CompressionMethod;
use crate::zip_structures::{CentralDirectoryHeader, EndOfCentralDirectory};

/// 问题检测结果
#[derive(Debug, Default)]
pub struct IssueReport {
    pub invalid_compression_methods: Vec<CompressionIssue>,
    pub fake_encryption_flags: Vec<EncryptionIssue>,
    pub zipbomb_entries: Vec<ZipBombIssue>,
}

#[derive(Debug)]
pub struct CompressionIssue {
    pub index: usize,
    pub filename: String,
    pub method: u16,
    pub cdh_offset: usize,
    pub lfh_offset: u32,
}

#[derive(Debug)]
pub struct EncryptionIssue {
    pub index: usize,
    pub filename: String,
    pub flags: u16,
    pub cdh_offset: usize,
    pub lfh_offset: u32,
}

#[derive(Debug)]
pub struct ZipBombIssue {
    pub index: usize,
    pub filename: String,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub ratio: f64,
}

impl IssueReport {
    pub fn has_issues(&self) -> bool {
        !self.invalid_compression_methods.is_empty()
            || !self.fake_encryption_flags.is_empty()
            || !self.zipbomb_entries.is_empty()
    }

    pub fn print_summary(&self) {
        println!("\n{}", "═══════════════════════════════════════════════".bold());
        println!("{}", "        APK 安全特征检测报告".bold().cyan());
        println!("{}", "═══════════════════════════════════════════════".bold());

        if !self.has_issues() {
            println!("\n  {} 未检测到任何保护特征", "✓".green().bold());
            return;
        }

        // 特征 1
        if !self.invalid_compression_methods.is_empty() {
            println!("\n  {} 检测到 {} 个非标准压缩方法条目",
                     "⚠".yellow().bold(),
                     self.invalid_compression_methods.len());
            for (i, issue) in self.invalid_compression_methods.iter().take(5).enumerate() {
                println!("      [{:3}] {} (方法: 0x{:04x} - {})",
                         issue.index,
                         truncate_str(&issue.filename, 45),
                         issue.method,
                         CompressionMethod::name(issue.method));
            }
            if self.invalid_compression_methods.len() > 5 {
                println!("      ... 还有 {} 个", self.invalid_compression_methods.len() - 5);
            }
        }

        // 特征 2
        if !self.fake_encryption_flags.is_empty() {
            println!("\n  {} 检测到 {} 个伪造加密标志条目",
                     "⚠".yellow().bold(),
                     self.fake_encryption_flags.len());
            for issue in self.fake_encryption_flags.iter().take(5) {
                println!("      [{:3}] {} (flags: 0x{:04x}, bit0={})",
                         issue.index,
                         truncate_str(&issue.filename, 45),
                         issue.flags,
                         if issue.flags & 0x0001 != 0 { "1" } else { "0" });
            }
            if self.fake_encryption_flags.len() > 5 {
                println!("      ... 还有 {} 个", self.fake_encryption_flags.len() - 5);
            }
        }

        // 特征 3
        if !self.zipbomb_entries.is_empty() {
            println!("\n  {} 检测到 {} 个 Zip Bomb 诱饵条目",
                     "⚠".yellow().bold(),
                     self.zipbomb_entries.len());
            println!("      {:<10}  {:<12}  {:<15}  {}",
                     "压缩比", "压缩后", "声称解压后", "文件名");
            println!("      {}  {}  {}  {}",
                     "-".repeat(10), "-".repeat(12), "-".repeat(15), "-".repeat(40));
            for issue in self.zipbomb_entries.iter().take(5) {
                println!("      {:>9.0}x  {:>12}  {:>15}  {}",
                         issue.ratio,
                         format_size(issue.compressed_size as u64),
                         format_size(issue.uncompressed_size as u64),
                         truncate_str(&issue.filename, 40));
            }
            if self.zipbomb_entries.len() > 5 {
                println!("      ... 还有 {} 个", self.zipbomb_entries.len() - 5);
            }
        }

        println!();
    }
}

/// 检测 APK 中的所有保护特征
pub fn detect_issues(data: &[u8], ratio_threshold: f64) -> Result<IssueReport> {
    let mut report = IssueReport::default();

    // 定位 EOCD
    let eocd_pos = EndOfCentralDirectory::find(data)?;
    let mut cursor = Cursor::new(&data[eocd_pos..]);
    let eocd = EndOfCentralDirectory::parse(&mut cursor)?;

    // 遍历 Central Directory
    let cd_start = eocd.cd_offset as usize;
    let mut cursor = Cursor::new(&data[cd_start..]);

    for i in 0..eocd.cd_records_total {
        let pos_before = cursor.position() as usize;
        let cdh = CentralDirectoryHeader::parse(&mut cursor)
            .with_context(|| format!("解析第 {} 个 CDH 失败", i))?;

        let cdh_global_offset = cd_start + pos_before;
        let filename = cdh.filename_str();

        // 检测 1: 非标准压缩方法
        if !CompressionMethod::is_valid(cdh.compression_method) {
            report.invalid_compression_methods.push(CompressionIssue {
                index: i as usize,
                filename: filename.clone(),
                method: cdh.compression_method,
                cdh_offset: cdh_global_offset + 10, // compression_method 偏移
                lfh_offset: cdh.local_header_offset + 8, // LFH compression_method 偏移
            });
        }

        // 检测 2: 伪造加密标志
        if cdh.flags & 0x0001 != 0 {
            report.fake_encryption_flags.push(EncryptionIssue {
                index: i as usize,
                filename: filename.clone(),
                flags: cdh.flags,
                cdh_offset: cdh_global_offset + 8, // flags 偏移
                lfh_offset: cdh.local_header_offset + 6, // LFH flags 偏移
            });
        }

        // 检测 3: Zip Bomb
        let ratio = cdh.compression_ratio();
        if ratio > ratio_threshold {
            report.zipbomb_entries.push(ZipBombIssue {
                index: i as usize,
                filename,
                compressed_size: cdh.compressed_size,
                uncompressed_size: cdh.uncompressed_size,
                ratio,
            });
        }
    }

    Ok(report)
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
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
