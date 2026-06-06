mod compression;
mod detector;
mod fixer;
mod zip_structures;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "apk-fixer",
    version = "0.1.0",
    about = "APK 保护特征检测与一键修复工具",
    long_about = "检测并移除 APK 中的反分析保护特征:\n\
                  1. 非标准压缩方法 (例如 0x7777)\n\
                  2. 伪造加密标志 (flags bit 0)\n\
                  3. Zip Bomb 诱饵条目\n\n\
                  通用于所有使用类似保护的 ZIP/APK 文件"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 检测 APK 中的保护特征（只扫描，不修改）
    Detect {
        /// 输入 APK 文件路径
        #[arg(value_name = "APK_FILE")]
        input: PathBuf,

        /// Zip Bomb 压缩比阈值（默认 100x）
        #[arg(short = 'r', long, default_value = "100.0")]
        ratio: f64,
    },

    /// 一键修复 APK（检测 + 自动修复所有问题）
    Fix {
        /// 输入 APK 文件路径
        #[arg(value_name = "APK_FILE")]
        input: PathBuf,

        /// 输出文件路径（可选，默认添加 _fixed 后缀）
        #[arg(short = 'o', long, value_name = "OUTPUT")]
        output: Option<PathBuf>,

        /// Zip Bomb 压缩比阈值（默认 100x）
        #[arg(short = 'r', long, default_value = "100.0")]
        ratio: f64,

        /// 强制覆盖输出文件（如果已存在）
        #[arg(short = 'f', long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Detect { input, ratio } => cmd_detect(input, ratio),
        Commands::Fix {
            input,
            output,
            ratio,
            force,
        } => cmd_fix(input, output, ratio, force),
    }
}

/// 检测命令实现
fn cmd_detect(input: PathBuf, ratio_threshold: f64) -> Result<()> {
    println!("{}", "APK 保护特征检测工具".bold().cyan());
    println!("输入文件: {}", input.display());
    println!();

    // 读取文件
    print!("正在读取 APK...");
    let data = fs::read(&input).context("无法读取 APK 文件")?;
    println!(" {} ({} bytes)", "✓".green(), data.len());

    // 检测问题
    print!("正在扫描保护特征...");
    let report = detector::detect_issues(&data, ratio_threshold)?;
    println!(" {}", "✓".green());

    // 显示报告
    report.print_summary();

    if report.has_issues() {
        println!("{}", "提示: 使用 'apk-fixer fix' 命令一键修复所有问题".yellow());
        std::process::exit(1);
    } else {
        println!("{}", "✓ APK 文件正常，无需修复".green().bold());
        Ok(())
    }
}

/// 修复命令实现
fn cmd_fix(
    input: PathBuf,
    output: Option<PathBuf>,
    ratio_threshold: f64,
    force: bool,
) -> Result<()> {
    println!("{}", "APK 一键修复工具".bold().cyan());
    println!("输入文件: {}", input.display());

    // 确定输出路径
    let output = output.unwrap_or_else(|| {
        let stem = input.file_stem().unwrap().to_string_lossy();
        let ext = input.extension().unwrap_or_default().to_string_lossy();
        let parent = input.parent().unwrap_or_else(|| std::path::Path::new("."));
        parent.join(format!("{}_fixed.{}", stem, ext))
    });

    println!("输出文件: {}", output.display());

    // 检查输出文件是否存在
    if output.exists() && !force {
        anyhow::bail!(
            "输出文件已存在: {}\n使用 -f 或 --force 强制覆盖",
            output.display()
        );
    }

    println!();

    // 读取文件
    print!("正在读取 APK...");
    let data = fs::read(&input).context("无法读取 APK 文件")?;
    println!(" {} ({} bytes)", "✓".green(), data.len());

    // 先检测问题
    print!("正在检测保护特征...");
    let issues = detector::detect_issues(&data, ratio_threshold)?;
    println!(" {}", "✓".green());

    issues.print_summary();

    if !issues.has_issues() {
        println!("{}", "✓ APK 文件正常，无需修复".green().bold());
        return Ok(());
    }

    // 开始修复
    println!("{}", "开始修复...".bold().yellow());
    let (fixed_data, report) = fixer::fix_all(&data, ratio_threshold)?;

    // 写入文件
    print!("正在写入修复后的文件...");
    fs::write(&output, &fixed_data).context("无法写入输出文件")?;
    println!(" {}", "✓".green());

    // 显示修复报告
    report.print_summary();

    println!("{}", format!("✓ 修复完成: {}", output.display()).green().bold());

    Ok(())
}
