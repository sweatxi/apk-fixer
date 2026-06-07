use anyhow::{Context, Result};
use std::io::Cursor;
use colored::Colorize;

use crate::axml_fixer;
use crate::compression::CompressionMethod;
use crate::zip_structures::{CentralDirectoryHeader, EndOfCentralDirectory};

/// 问题检测结果
#[derive(Debug, Default)]
pub struct IssueReport {
    pub invalid_compression_methods: Vec<CompressionIssue>,
    pub fake_encryption_flags: Vec<EncryptionIssue>,
    pub zipbomb_entries: Vec<ZipBombIssue>,
    pub axml_issues: Vec<AxmlIssue>,
}

#[derive(Debug)]
pub struct CompressionIssue {
    pub index: usize,
    pub filename: String,
    pub method: u16,
}

#[derive(Debug)]
pub struct EncryptionIssue {
    pub index: usize,
    pub filename: String,
    pub flags: u16,
}

#[derive(Debug)]
pub struct ZipBombIssue {
    pub filename: String,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub ratio: f64,
}

#[derive(Debug)]
pub struct AxmlIssue {
    pub filename: String,
    pub problems: Vec<String>,
}

// CLI binary 使用这些方法；GUI binary 直接打印日志而不调用 print_summary
#[allow(dead_code)]
impl IssueReport {
    pub fn has_issues(&self) -> bool {
        !self.invalid_compression_methods.is_empty()
            || !self.fake_encryption_flags.is_empty()
            || !self.zipbomb_entries.is_empty()
            || !self.axml_issues.is_empty()
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
            for issue in self.invalid_compression_methods.iter().take(5) {
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

        // 特征 4: AXML 损坏
        if !self.axml_issues.is_empty() {
            println!("\n  {} 检测到 {} 个损坏的 AXML 文件",
                     "⚠".yellow().bold(),
                     self.axml_issues.len());
            for issue in self.axml_issues.iter().take(5) {
                println!("      {}", issue.filename.cyan());
                for problem in &issue.problems {
                    println!("        • {}", problem);
                }
            }
            if self.axml_issues.len() > 5 {
                println!("      ... 还有 {} 个", self.axml_issues.len() - 5);
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
        let cdh = CentralDirectoryHeader::parse(&mut cursor)
            .with_context(|| format!("解析第 {} 个 CDH 失败", i))?;

        let filename = cdh.filename_str();

        // 检测 1: 非标准压缩方法
        if !CompressionMethod::is_valid(cdh.compression_method) {
            report.invalid_compression_methods.push(CompressionIssue {
                index: i as usize,
                filename: filename.clone(),
                method: cdh.compression_method,
            });
        }

        // 检测 2: 伪造加密标志
        if cdh.flags & 0x0001 != 0 {
            report.fake_encryption_flags.push(EncryptionIssue {
                index: i as usize,
                filename: filename.clone(),
                flags: cdh.flags,
            });
        }

        // 检测 3: Zip Bomb
        let ratio = cdh.compression_ratio();
        if ratio > ratio_threshold {
            report.zipbomb_entries.push(ZipBombIssue {
                filename: filename.clone(),
                compressed_size: cdh.compressed_size,
                uncompressed_size: cdh.uncompressed_size,
                ratio,
            });
        }

        // 检测 4: AXML 文件损坏
        if filename == "AndroidManifest.xml" ||
           (filename.starts_with("res/") && filename.ends_with(".xml")) {

            let lfh_offset = cdh.local_header_offset as usize;

            // 计算实际数据偏移
            if lfh_offset + 30 <= data.len() {
                let fname_len = u16::from_le_bytes([data[lfh_offset + 26], data[lfh_offset + 27]]) as usize;
                let extra_len = u16::from_le_bytes([data[lfh_offset + 28], data[lfh_offset + 29]]) as usize;
                let data_offset = lfh_offset + 30 + fname_len + extra_len;
                let data_end = data_offset + cdh.compressed_size as usize;

                if data_end <= data.len() {
                    let xml_data = &data[data_offset..data_end];

                    // 检查是否为 AXML 格式（通过魔数）
                    if xml_data.len() >= 4 {
                        let magic = u32::from_le_bytes([xml_data[0], xml_data[1], xml_data[2], xml_data[3]]);

                        // 如果是 AXML 或疑似 AXML，进行详细检测
                        if magic == 0x00080003 || (magic & 0x0000FFFF) == 0x0003 {
                            match axml_fixer::detect_axml_issues(xml_data) {
                                Ok(issues) => {
                                    if !issues.is_empty() {
                                        report.axml_issues.push(AxmlIssue {
                                            filename: filename.clone(),
                                            problems: issues,
                                        });
                                    }
                                }
                                Err(e) => {
                                    report.axml_issues.push(AxmlIssue {
                                        filename: filename.clone(),
                                        problems: vec![format!("检测失败: {}", e)],
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(report)
}

#[allow(dead_code)]
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[allow(dead_code)]
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
