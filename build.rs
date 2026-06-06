fn main() {
    // 只在 Windows 平台编译 GUI 时嵌入图标
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("1.ico");
        res.compile().unwrap();
    }
}
