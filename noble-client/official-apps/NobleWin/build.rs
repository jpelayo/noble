fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        // Only embed an icon when one is present — avoid a phantom reference to a
        // file that isn't in the tree. To ship an icon, convert the shared brand
        // asset to .ico and drop it at assets/icon.ico, e.g.:
        //   magick ../../noble-client-libraries/Artwork/applogo.png \
        //     -define icon:auto-resize=16,32,48,256 assets/icon.ico
        if std::path::Path::new("assets/icon.ico").exists() {
            res.set_icon("assets/icon.ico");
        }
        res.set("ProductName", "Noble");
        res.set("FileDescription", "Noble Document Client");
        res.set("CompanyName", "InfiniteContext");
        res.set("LegalCopyright", "Copyright 2026 InfiniteContext.com");
        // DPI awareness manifest
        res.set_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
    </windowsSettings>
  </application>
</assembly>"#,
        );
        if let Err(e) = res.compile() {
            eprintln!("winres compile warning: {e}");
        }
    }
}
