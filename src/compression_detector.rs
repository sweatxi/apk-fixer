use std::io::{Cursor, Read};
use flate2::read::DeflateDecoder;

/// 检测数据的真实压缩方法
/// 返回：(compression_method, actual_uncompressed_size)
pub fn detect_real_compression(data: &[u8], declared_uncompressed_size: u32) -> (u16, u32) {
    // 1. 检查是否是未压缩数据（Store）
    if is_likely_uncompressed(data, declared_uncompressed_size) {
        // Store 方法下，compressed_size == uncompressed_size
        return (0, data.len() as u32);
    }

    // 2. 尝试 Deflate 解压
    if let Some(size) = can_deflate_decompress(data, declared_uncompressed_size) {
        return (8, size); // Deflate
    }

    // 3. 默认返回 Store（最安全的选择）
    (0, data.len() as u32)
}

/// 检查数据是否可能是未压缩的
fn is_likely_uncompressed(data: &[u8], declared_uncompressed_size: u32) -> bool {
    if data.is_empty() {
        return true;
    }

    // 检查 Android Binary XML 头（AXML）
    if data.len() >= 8 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let file_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // AXML magic: 0x00080003
        if magic == 0x00080003 {
            // 文件大小应该匹配实际数据大小（未压缩）
            if file_size as usize == data.len() || file_size == declared_uncompressed_size {
                return true;
            }
        }
    }

    // 检查 DEX 头
    if data.len() >= 8 {
        if &data[0..4] == b"dex\n" {
            // DEX 文件的大小字段
            let file_size = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
            if file_size as usize == data.len() {
                return true;
            }
        }
    }

    // 检查其他常见未压缩文件格式
    // PNG: 89 50 4E 47
    // JPEG: FF D8 FF
    // ZIP: 50 4B 03 04
    if data.len() >= 4 {
        let header = &data[0..4];
        if header == b"\x89PNG" || header[0..3] == [0xFF, 0xD8, 0xFF] || header == b"PK\x03\x04" {
            return true;
        }
    }

    false
}

/// 检查数据是否可以用 Deflate 解压
/// 返回解压后的大小（如果成功）
fn can_deflate_decompress(data: &[u8], declared_uncompressed_size: u32) -> Option<u32> {
    if data.is_empty() {
        return None;
    }

    let mut decoder = DeflateDecoder::new(Cursor::new(data));
    let mut decompressed = Vec::new();

    match decoder.read_to_end(&mut decompressed) {
        Ok(size) => {
            // 成功解压，且大小合理
            if size > 0 && (size == declared_uncompressed_size as usize || declared_uncompressed_size == 0) {
                return Some(size as u32);
            }
            None
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_axml() {
        // AXML header
        let data = [
            0x03, 0x00, 0x08, 0x00, // magic: 0x00080003
            0x10, 0x00, 0x00, 0x00, // file_size: 16
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        assert_eq!(detect_real_compression(&data, 16), (0, 16));
    }

    #[test]
    fn test_detect_dex() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(b"dex\n");
        data[32..36].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(detect_real_compression(&data, 40), (0, 40));
    }
}
