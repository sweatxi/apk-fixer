use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

/// ZIP Central Directory Header 结构
#[derive(Debug, Clone)]
pub struct CentralDirectoryHeader {
    pub signature: u32,           // +0:  0x02014b50
    pub version_made_by: u16,     // +4:  制作版本
    pub version_needed: u16,      // +6:  所需版本
    pub flags: u16,               // +8:  通用标志位 ★
    pub compression_method: u16,  // +10: 压缩方法 ★
    pub last_mod_time: u16,       // +12: 最后修改时间
    pub last_mod_date: u16,       // +14: 最后修改日期
    pub crc32: u32,               // +16: CRC-32
    pub compressed_size: u32,     // +20: 压缩后大小 ★
    pub uncompressed_size: u32,   // +24: 未压缩大小 ★
    pub filename_length: u16,     // +28: 文件名长度
    pub extra_field_length: u16,  // +30: 扩展字段长度
    pub comment_length: u16,      // +32: 注释长度
    pub disk_number_start: u16,   // +34: 起始磁盘号
    pub internal_attrs: u16,      // +36: 内部文件属性
    pub external_attrs: u32,      // +38: 外部文件属性
    pub local_header_offset: u32, // +42: Local Header 偏移 ★
    pub filename: Vec<u8>,        // +46: 文件名
    pub extra_field: Vec<u8>,     // 扩展字段
    pub comment: Vec<u8>,         // 注释
}

impl CentralDirectoryHeader {
    pub const SIGNATURE: u32 = 0x02014b50;
    pub const FIXED_SIZE: usize = 46;

    /// 从字节流解析 CDH
    pub fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let signature = cursor.read_u32::<LittleEndian>()?;
        if signature != Self::SIGNATURE {
            anyhow::bail!("无效的 CDH 签名: 0x{:08x}", signature);
        }

        let version_made_by = cursor.read_u16::<LittleEndian>()?;
        let version_needed = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u16::<LittleEndian>()?;
        let compression_method = cursor.read_u16::<LittleEndian>()?;
        let last_mod_time = cursor.read_u16::<LittleEndian>()?;
        let last_mod_date = cursor.read_u16::<LittleEndian>()?;
        let crc32 = cursor.read_u32::<LittleEndian>()?;
        let compressed_size = cursor.read_u32::<LittleEndian>()?;
        let uncompressed_size = cursor.read_u32::<LittleEndian>()?;
        let filename_length = cursor.read_u16::<LittleEndian>()?;
        let extra_field_length = cursor.read_u16::<LittleEndian>()?;
        let comment_length = cursor.read_u16::<LittleEndian>()?;
        let disk_number_start = cursor.read_u16::<LittleEndian>()?;
        let internal_attrs = cursor.read_u16::<LittleEndian>()?;
        let external_attrs = cursor.read_u32::<LittleEndian>()?;
        let local_header_offset = cursor.read_u32::<LittleEndian>()?;

        let mut filename = vec![0u8; filename_length as usize];
        cursor.read_exact(&mut filename)?;

        let mut extra_field = vec![0u8; extra_field_length as usize];
        cursor.read_exact(&mut extra_field)?;

        let mut comment = vec![0u8; comment_length as usize];
        cursor.read_exact(&mut comment)?;

        Ok(Self {
            signature,
            version_made_by,
            version_needed,
            flags,
            compression_method,
            last_mod_time,
            last_mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename_length,
            extra_field_length,
            comment_length,
            disk_number_start,
            internal_attrs,
            external_attrs,
            local_header_offset,
            filename,
            extra_field,
            comment,
        })
    }

    /// 序列化为字节
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.filename.len() + self.extra_field.len() + self.comment.len());

        buf.write_u32::<LittleEndian>(self.signature)?;
        buf.write_u16::<LittleEndian>(self.version_made_by)?;
        buf.write_u16::<LittleEndian>(self.version_needed)?;
        buf.write_u16::<LittleEndian>(self.flags)?;
        buf.write_u16::<LittleEndian>(self.compression_method)?;
        buf.write_u16::<LittleEndian>(self.last_mod_time)?;
        buf.write_u16::<LittleEndian>(self.last_mod_date)?;
        buf.write_u32::<LittleEndian>(self.crc32)?;
        buf.write_u32::<LittleEndian>(self.compressed_size)?;
        buf.write_u32::<LittleEndian>(self.uncompressed_size)?;
        buf.write_u16::<LittleEndian>(self.filename_length)?;
        buf.write_u16::<LittleEndian>(self.extra_field_length)?;
        buf.write_u16::<LittleEndian>(self.comment_length)?;
        buf.write_u16::<LittleEndian>(self.disk_number_start)?;
        buf.write_u16::<LittleEndian>(self.internal_attrs)?;
        buf.write_u32::<LittleEndian>(self.external_attrs)?;
        buf.write_u32::<LittleEndian>(self.local_header_offset)?;
        buf.extend_from_slice(&self.filename);
        buf.extend_from_slice(&self.extra_field);
        buf.extend_from_slice(&self.comment);

        Ok(buf)
    }

    /// 获取文件名字符串
    pub fn filename_str(&self) -> String {
        String::from_utf8_lossy(&self.filename).to_string()
    }

    /// 计算压缩比
    pub fn compression_ratio(&self) -> f64 {
        if self.compressed_size == 0 {
            // compressed_size=0 但 uncompressed_size>0 是典型反分析手法：
            // 声称有内容但无压缩数据，工具解压后得 0 字节而报错
            if self.uncompressed_size > 0 {
                f64::INFINITY
            } else {
                0.0
            }
        } else {
            self.uncompressed_size as f64 / self.compressed_size as f64
        }
    }
}

/// ZIP End of Central Directory 结构
#[derive(Debug, Clone)]
pub struct EndOfCentralDirectory {
    pub signature: u32,               // +0:  0x06054b50
    pub disk_number: u16,             // +4:  当前磁盘号
    pub cd_start_disk: u16,           // +6:  CD 起始磁盘号
    pub cd_records_on_disk: u16,      // +8:  本磁盘 CD 记录数 ★
    pub cd_records_total: u16,        // +10: 总 CD 记录数 ★
    pub cd_size: u32,                 // +12: CD 大小 ★
    pub cd_offset: u32,               // +16: CD 偏移 ★
    pub comment_length: u16,          // +20: 注释长度
    pub comment: Vec<u8>,             // +22: 注释
}

impl EndOfCentralDirectory {
    pub const SIGNATURE: u32 = 0x06054b50;
    pub const FIXED_SIZE: usize = 22;

    /// 查找 EOCD（从文件末尾向前搜索）
    pub fn find(data: &[u8]) -> Result<usize> {
        let sig_bytes = Self::SIGNATURE.to_le_bytes();

        // 从文件末尾向前搜索
        // EOCD 最小是 22 字节，最多可能有 64KB 的注释
        // 所以搜索范围是最后 (22 + 65535) 字节
        let search_len = std::cmp::min(data.len(), 65557);
        let search_start = data.len().saturating_sub(search_len);

        // 从后往前搜索
        for i in (search_start..=data.len().saturating_sub(Self::FIXED_SIZE)).rev() {
            if data.len() >= i + 4 && &data[i..i+4] == &sig_bytes {
                return Ok(i);
            }
        }

        anyhow::bail!("EOCD signature not found")
    }

    /// 从字节流解析 EOCD
    pub fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let signature = cursor.read_u32::<LittleEndian>()?;
        if signature != Self::SIGNATURE {
            anyhow::bail!("无效的 EOCD 签名: 0x{:08x}", signature);
        }

        let disk_number = cursor.read_u16::<LittleEndian>()?;
        let cd_start_disk = cursor.read_u16::<LittleEndian>()?;
        let cd_records_on_disk = cursor.read_u16::<LittleEndian>()?;
        let cd_records_total = cursor.read_u16::<LittleEndian>()?;
        let cd_size = cursor.read_u32::<LittleEndian>()?;
        let cd_offset = cursor.read_u32::<LittleEndian>()?;
        let comment_length = cursor.read_u16::<LittleEndian>()?;

        let mut comment = vec![0u8; comment_length as usize];
        cursor.read_exact(&mut comment)?;

        Ok(Self {
            signature,
            disk_number,
            cd_start_disk,
            cd_records_on_disk,
            cd_records_total,
            cd_size,
            cd_offset,
            comment_length,
            comment,
        })
    }

    /// 序列化为字节
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.comment.len());

        buf.write_u32::<LittleEndian>(self.signature)?;
        buf.write_u16::<LittleEndian>(self.disk_number)?;
        buf.write_u16::<LittleEndian>(self.cd_start_disk)?;
        buf.write_u16::<LittleEndian>(self.cd_records_on_disk)?;
        buf.write_u16::<LittleEndian>(self.cd_records_total)?;
        buf.write_u32::<LittleEndian>(self.cd_size)?;
        buf.write_u32::<LittleEndian>(self.cd_offset)?;
        buf.write_u16::<LittleEndian>(self.comment_length)?;
        buf.extend_from_slice(&self.comment);

        Ok(buf)
    }
}
