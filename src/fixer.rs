use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Cursor;
use colored::Colorize;
use crc32fast::Hasher;

use crate::axml_fixer;
use crate::compression::CompressionMethod;
use crate::compression_detector;
use crate::zip_structures::{CentralDirectoryHeader, EndOfCentralDirectory};

/// 修复统计信息
#[derive(Debug, Default)]
pub struct FixReport {
    pub compression_fixed: usize,
    pub encryption_fixed: usize,
    pub zipbomb_removed: usize,
    pub lfh_signature_fixed: usize,
    pub axml_fixed: usize,
    pub axml_reports: Vec<(String, axml_fixer::AxmlFixReport)>,
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

        if self.lfh_signature_fixed > 0 {
            println!("  {} 修复了 {} 个损坏的 LFH 签名",
                     "✓".green().bold(), self.lfh_signature_fixed);
        }

        if self.axml_fixed > 0 {
            println!("  {} 修复了 {} 个损坏的 AXML 文件",
                     "✓".green().bold(), self.axml_fixed);

            for (filename, axml_report) in &self.axml_reports {
                if axml_report.has_fixes() {
                    println!("\n    {}", filename.cyan());
                    axml_report.print_summary();
                }
            }
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
            // 读取实际数据，检测真实压缩方法
            let lfh_offset = cdh.local_header_offset as usize;

            // 跳过 LFH 固定头（30 字节）+ 文件名 + 扩展字段，找到实际数据
            if lfh_offset + 30 <= data.len() {
                let fname_len = u16::from_le_bytes([data[lfh_offset + 26], data[lfh_offset + 27]]) as usize;
                let extra_len = u16::from_le_bytes([data[lfh_offset + 28], data[lfh_offset + 29]]) as usize;
                let data_offset = lfh_offset + 30 + fname_len + extra_len;
                let data_end = data_offset + cdh.compressed_size as usize;

                if data_end <= data.len() {
                    let actual_data = &data[data_offset..data_end];
                    let (real_method, actual_uncomp_size) = compression_detector::detect_real_compression(
                        actual_data,
                        cdh.uncompressed_size
                    );
                    cdh.compression_method = real_method;

                    // 对于 Store 方法，修正 uncompressed_size 使其等于 compressed_size
                    if real_method == 0 {
                        cdh.uncompressed_size = actual_uncomp_size;
                    }
                } else {
                    cdh.compression_method = 0; // 默认 Store
                    cdh.uncompressed_size = cdh.compressed_size; // Store: uncomp == comp
                }
            } else {
                cdh.compression_method = 0; // 默认 Store
                cdh.uncompressed_size = cdh.compressed_size; // Store: uncomp == comp
            }
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

    // Step 3: 修复 AXML 文件内容（在构建新 ZIP 之前）
    let mut axml_fixed_data_map: std::collections::HashMap<usize, Vec<u8>> = std::collections::HashMap::new();
    let mut axml_new_crc_map: std::collections::HashMap<usize, u32> = std::collections::HashMap::new();
    let mut axml_new_size_map: std::collections::HashMap<usize, u32> = std::collections::HashMap::new();

    for cdh in &fixed_entries {
        let filename = cdh.filename_str();

        // 只处理 XML 文件（AndroidManifest.xml 和 res/ 下的 XML）
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

                    // 检测是否需要修复（根据魔数判断是否为 AXML）
                    if xml_data.len() >= 8 {
                        let magic = u32::from_le_bytes([xml_data[0], xml_data[1], xml_data[2], xml_data[3]]);

                        // 如果是 AXML 格式（或疑似损坏的 AXML）
                        if magic == 0x00080003 || (magic & 0x0000FFFF) == 0x0003 {
                            match axml_fixer::fix_axml(xml_data) {
                                Ok((fixed_xml, axml_report)) => {
                                    if axml_report.has_fixes() {
                                        println!("  {} 修复 AXML: {}", "→".cyan(), filename);
                                        report.axml_fixed += 1;
                                        report.axml_reports.push((filename.clone(), axml_report));

                                        // 计算新的 CRC32
                                        let mut hasher = Hasher::new();
                                        hasher.update(&fixed_xml);
                                        let new_crc = hasher.finalize();

                                        axml_new_crc_map.insert(lfh_offset, new_crc);
                                        axml_new_size_map.insert(lfh_offset, fixed_xml.len() as u32);
                                        axml_fixed_data_map.insert(lfh_offset, fixed_xml);
                                    }
                                }
                                Err(e) => {
                                    println!("  {} AXML 修复失败 {}: {}", "✗".yellow(), filename, e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Step 4: 构建新文件（完全重构 LFH 区域，使用 CDH 中的正确元数据）
    let mut new_data = Vec::with_capacity(data.len());
    let mut new_lfh_offsets = Vec::with_capacity(fixed_entries.len());

    // 4.1 重新构建所有 LFH + 数据
    for cdh in &fixed_entries {
        let lfh_offset = cdh.local_header_offset as usize;

        // 记录新的 LFH 偏移
        new_lfh_offsets.push(new_data.len() as u32);

        if lfh_offset + 30 > data.len() {
            continue; // 跳过不完整的条目
        }

        // 读取原始 LFH 签名
        let lfh_signature = u32::from_le_bytes([
            data[lfh_offset],
            data[lfh_offset + 1],
            data[lfh_offset + 2],
            data[lfh_offset + 3],
        ]);

        const LFH_SIGNATURE: u32 = 0x04034b50;

        // 检查并报告签名问题
        if lfh_signature != LFH_SIGNATURE {
            println!("  {} 修复损坏的 LFH 签名: {} (0x{:08x} → 0x{:08x})",
                     "→".cyan(),
                     cdh.filename_str(),
                     lfh_signature,
                     LFH_SIGNATURE);
            report.lfh_signature_fixed += 1;
        }

        // 获取原始 LFH 中的文件名和扩展字段长度（用于定位数据）
        let lfh_fname_len = u16::from_le_bytes([data[lfh_offset + 26], data[lfh_offset + 27]]) as usize;
        let lfh_extra_len = u16::from_le_bytes([data[lfh_offset + 28], data[lfh_offset + 29]]) as usize;
        let data_offset = lfh_offset + 30 + lfh_fname_len + lfh_extra_len;
        let data_end = data_offset + cdh.compressed_size as usize;

        // ===== 写入修复后的 LFH（使用 CDH 中的正确元数据）=====

        // 写入正确的签名
        new_data.write_u32::<LittleEndian>(LFH_SIGNATURE)?;

        // 写入版本
        let version = u16::from_le_bytes([data[lfh_offset + 4], data[lfh_offset + 5]]);
        new_data.write_u16::<LittleEndian>(version)?;

        // 写入修复后的 flags 和 compression_method
        new_data.write_u16::<LittleEndian>(cdh.flags)?;
        new_data.write_u16::<LittleEndian>(cdh.compression_method)?;

        // 复制时间和日期
        new_data.write_u16::<LittleEndian>(cdh.last_mod_time)?;
        new_data.write_u16::<LittleEndian>(cdh.last_mod_date)?;

        // 写入 CRC32（如果 AXML 被修复，使用新的 CRC）
        let final_crc = axml_new_crc_map.get(&lfh_offset).copied().unwrap_or(cdh.crc32);
        new_data.write_u32::<LittleEndian>(final_crc)?;

        // 写入大小字段（如果 AXML 被修复，使用新的大小）
        let final_comp_size = axml_new_size_map.get(&lfh_offset).copied().unwrap_or(cdh.compressed_size);
        let final_uncomp_size = axml_new_size_map.get(&lfh_offset).copied().unwrap_or(cdh.uncompressed_size);

        new_data.write_u32::<LittleEndian>(final_comp_size)?;
        new_data.write_u32::<LittleEndian>(final_uncomp_size)?;

        // 写入文件名和扩展字段长度（使用 CDH 中的值）
        new_data.write_u16::<LittleEndian>(cdh.filename_length)?;
        new_data.write_u16::<LittleEndian>(cdh.extra_field_length)?;

        // 写入文件名和扩展字段（使用 CDH 中的正确数据）
        new_data.extend_from_slice(&cdh.filename);
        new_data.extend_from_slice(&cdh.extra_field);

        // ===== 写入文件数据 =====

        // 优先使用修复后的 AXML 数据
        if let Some(fixed_xml) = axml_fixed_data_map.get(&lfh_offset) {
            // 注意：AXML 修复可能改变了数据大小，需要更新 CDH
            new_data.extend_from_slice(fixed_xml);
        } else if data_end <= data.len() {
            new_data.extend_from_slice(&data[data_offset..data_end]);
        }
    }

    // Step 5: 写入新的 Central Directory（更新 LFH 偏移和 AXML 修复后的元数据）
    let new_cd_offset = new_data.len();

    for (idx, cdh) in fixed_entries.iter().enumerate() {
        let mut updated_cdh = cdh.clone();
        let lfh_offset = cdh.local_header_offset as usize;

        // 更新为新的 LFH 偏移
        updated_cdh.local_header_offset = new_lfh_offsets[idx];

        // 如果 AXML 被修复，更新 CRC 和大小
        if let Some(&new_crc) = axml_new_crc_map.get(&lfh_offset) {
            updated_cdh.crc32 = new_crc;
        }
        if let Some(&new_size) = axml_new_size_map.get(&lfh_offset) {
            updated_cdh.compressed_size = new_size;
            updated_cdh.uncompressed_size = new_size; // AXML 是 Store 方法，两者相等
        }

        let serialized = updated_cdh.serialize()?;
        new_data.extend_from_slice(&serialized);
    }
    let new_cd_size = new_data.len() - new_cd_offset;

    // Step 6: 写入新的 EOCD
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