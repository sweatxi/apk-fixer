#[cfg(test)]
mod tests {
    use super::*;

    /// 测试标准压缩方法验证
    #[test]
    fn test_standard_compression_methods() {
        // 标准方法
        assert!(CompressionMethod::is_valid(0));  // Store
        assert!(CompressionMethod::is_valid(8));  // Deflate
        assert!(CompressionMethod::is_valid(12)); // Bzip2
        assert!(CompressionMethod::is_valid(14)); // LZMA
        assert!(CompressionMethod::is_valid(93)); // Zstd

        // 非标准方法
        assert!(!CompressionMethod::is_valid(0x7777)); // 人为构造
        assert!(!CompressionMethod::is_valid(255));    // 未定义
        assert!(!CompressionMethod::is_valid(1000));   // 超出范围
    }

    /// 测试 APK 常见压缩方法
    #[test]
    fn test_apk_common_methods() {
        assert!(CompressionMethod::is_apk_common(0));  // Store
        assert!(CompressionMethod::is_apk_common(8));  // Deflate

        // 虽然有效，但在 APK 中罕见
        assert!(!CompressionMethod::is_apk_common(12)); // Bzip2
        assert!(!CompressionMethod::is_apk_common(14)); // LZMA
    }

    /// 测试压缩方法名称获取
    #[test]
    fn test_compression_method_names() {
        assert_eq!(CompressionMethod::name(0), "Store (无压缩)");
        assert_eq!(CompressionMethod::name(8), "Deflate (标准)");
        assert_eq!(CompressionMethod::name(93), "Zstandard");
        assert!(CompressionMethod::name(0x7777).contains("UNKNOWN"));
    }

    /// 测试推荐修复值
    #[test]
    fn test_recommended_fix() {
        assert_eq!(CompressionMethod::RECOMMENDED_FIX, 8); // Deflate
        assert!(CompressionMethod::is_valid(CompressionMethod::RECOMMENDED_FIX));
        assert!(CompressionMethod::is_apk_common(CompressionMethod::RECOMMENDED_FIX));
    }
}
