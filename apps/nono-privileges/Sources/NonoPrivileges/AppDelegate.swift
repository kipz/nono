import AppKit
import SwiftUI

/// Blocks NSPopover from observing preferredContentSize changes so it never repositions.
/// The getter returns a locked size set explicitly before each show.
class LockedSizeHostingController<Content: View>: NSHostingController<Content> {
    var lockedSize = NSSize(width: 260, height: 200)

    override var preferredContentSize: NSSize {
        get { lockedSize }
        set { } // block SwiftUI from notifying NSPopover
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var hostingController: LockedSizeHostingController<MenuBarView>?
    private var timer: Timer?
    private var eventMonitor: Any?
    private var sessionStore = SessionStore()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        self.statusItem = statusItem

        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "key.horizontal", accessibilityDescription: "nono YOLO mode")
            button.action = #selector(togglePopover)
            button.target = self
        }

        let hc = LockedSizeHostingController(rootView: MenuBarView(store: sessionStore))
        self.hostingController = hc

        let popover = NSPopover()
        popover.contentViewController = hc
        popover.behavior = .applicationDefined
        popover.animates = false
        self.popover = popover

        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            self?.refreshIcon()
        }
        sessionStore.refresh()
    }

    @objc func togglePopover() {
        guard let button = statusItem?.button, let popover, let hc = hostingController else { return }
        if popover.isShown {
            closePopover()
        } else {
            sessionStore.refresh()
            // Measure the current content synchronously so the locked size is correct
            // before show() — NSPopover positions once and never repositions.
            let measured = hc.sizeThatFits(in: NSSize(width: 260, height: CGFloat.infinity))
            hc.lockedSize = measured.height > 10 ? measured : NSSize(width: 260, height: 200)
            popover.contentSize = hc.lockedSize
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            eventMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
                self?.closePopover()
            }
        }
    }

    private func closePopover() {
        popover?.performClose(nil)
        if let monitor = eventMonitor {
            NSEvent.removeMonitor(monitor)
            eventMonitor = nil
        }
    }

    private func refreshIcon() {
        sessionStore.refresh()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let self, let button = self.statusItem?.button else { return }
            let anyActive = self.sessionStore.hasAnyAdminActive()
            let symbolName = anyActive ? "key.horizontal.fill" : "key.horizontal"
            button.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "nono YOLO mode")
            button.contentTintColor = anyActive ? .systemOrange : nil
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
        if let monitor = eventMonitor {
            NSEvent.removeMonitor(monitor)
        }
    }
}
