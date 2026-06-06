// ZIP 标准压缩方法枚举
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum CompressionMethod {
    Store = 0,      // 无压缩
    Shrunk = 1,     // 收缩（已弃用）
    Reduced1 = 2,   // 减少因子 1（已弃用）
    Reduced2 = 3,   // 减少因子 2（已弃用）
    Reduced3 = 4,   // 减少因子 3（已弃用）
    Reduced4 = 5,   // 减少因子 4（已弃用）
    Imploded = 6,   // 内爆（已弃用）
    Reserved = 7,   // 保留
    Deflate = 8,    // Deflate（最常用）★
    Deflate64 = 9,  // Enhanced Deflate
    PKWARE = 10,    // PKWARE DCL Implode（已弃用）
    Reserved2 = 11, // 保留
    Bzip2 = 12,     // Bzip2
    Reserved3 = 13, // 保留
    Lzma = 14,      // LZMA
    Reserved4 = 15, // 保留
    Cmpsc = 16,     // IBM CMPSC（z/OS）
    Reserved5 = 17, // 保留
    Terse = 18,     // IBM TERSE（已弃用）
    Lz77 = 19,      // IBM LZ77
    Zstd = 93,      // Zstandard（2020 年提案）
    Mp3 = 94,       // MP3（已弃用）
    Xz = 95,        // XZ
    Jpeg = 96,      // JPEG 变体
    WavPack = 97,   // WavPack
    Ppmd = 98,      // PPMd 版本 I
    Aex = 99,       // AE-x 加密标记
}

impl CompressionMethod {
    /// 判断压缩方法是否为标准/有效的
    pub fn is_valid(value: u16) -> bool {
        matches!(
            value,
            0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 93 | 94 | 95 | 96 | 97 | 98 | 99
        )
    }

    /// 判断压缩方法是否为 APK 中常见的
    pub fn is_apk_common(value: u16) -> bool {
        matches!(
            value,
            0 | 8  // Store 或 Deflate
        )
    }

    /// 将 u16 转换为名称字符串
    pub fn name(value: u16) -> &'static str {
        match value {
            0 => "Store (无压缩)",
            1 => "Shrunk (已弃用)",
            2 => "Reduced1 (已弃用)",
            3 => "Reduced2 (已弃用)",
            4 => "Reduced3 (已弃用)",
            5 => "Reduced4 (已弃用)",
            6 => "Imploded (已弃用)",
            7 => "Reserved",
            8 => "Deflate (标准)",
            9 => "Deflate64",
            10 => "PKWARE DCL (已弃用)",
            11 => "Reserved",
            12 => "Bzip2",
            13 => "Reserved",
            14 => "LZMA",
            15 => "Reserved",
            16 => "IBM CMPSC",
            17 => "Reserved",
            18 => "IBM TERSE (已弃用)",
            19 => "IBM LZ77",
            93 => "Zstandard",
            94 => "MP3 (已弃用)",
            95 => "XZ",
            96 => "JPEG",
            97 => "WavPack",
            98 => "PPMd I",
            99 => "AE-x 加密标记",
            _ => "UNKNOWN (非标准)",
        }
    }

    /// 推荐的修复目标（Deflate 8 是最安全的选择）
    pub const RECOMMENDED_FIX: u16 = 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_methods() {
        assert!(CompressionMethod::is_valid(0));
        assert!(CompressionMethod::is_valid(8));
        assert!(!CompressionMethod::is_valid(0x7777));
        assert!(!CompressionMethod::is_valid(65535));
    }

    #[test]
    fn test_apk_common() {
        assert!(CompressionMethod::is_apk_common(0));
        assert!(CompressionMethod::is_apk_common(8));
        assert!(!CompressionMethod::is_apk_common(12)); // Bzip2 虽然有效，但在 APK 中罕见
    }
}
