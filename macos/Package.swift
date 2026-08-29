// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "HeimdallMacControl",
  platforms: [
    .macOS(.v11)
  ],
  products: [
    .library(name: "HeimdallMacControl", targets: ["HeimdallMacControl"])
  ],
  targets: [
    .target(name: "HeimdallMacControl"),
    .testTarget(
      name: "HeimdallMacControlTests",
      dependencies: ["HeimdallMacControl"]
    ),
  ]
)
