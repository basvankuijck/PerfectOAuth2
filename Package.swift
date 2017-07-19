// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "PerfectOAuth2",
    targets: [],
    dependencies: [
        .Package(url: "https://github.com/PerfectlySoft/Perfect-HTTPServer.git", majorVersion: 2),
        .Package(url: "https://github.com/PerfectlySoft/Perfect-Logger.git", majorVersion: 1),
        .Package(url: "https://github.com/SwiftORM/StORM.git", majorVersion: 1)
    ]
)
