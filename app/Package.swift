// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MamoriBar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "MamoriBar",
            path: "Sources/MamoriBar"
        )
    ]
)
