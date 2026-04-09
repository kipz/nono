import AppKit

let app = NSApplication.shared
// Suppress dock icon — equivalent to LSUIElement=YES in Info.plist
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
