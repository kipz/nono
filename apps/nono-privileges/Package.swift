// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NonoPrivileges",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "NonoPrivileges",
            path: "Sources/NonoPrivileges",
            exclude: ["Info.plist"]
        )
    ]
)
