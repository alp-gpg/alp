#!/usr/bin/env swift
// Ed25519 signer for release.json — replaces Sparkle's sign_update.
// No external dependencies beyond CryptoKit (shipped with macOS).
//
// Usage: sign-release.swift <manifest-path>
//
// Reads the Ed25519 private key from the ALP_UPDATE_PRIVATE_KEY env var
// (base64-encoded 32-byte raw seed). Passing secrets via env rather than
// CLI args avoids exposure in the process list.
//
// Output: base64-encoded 64-byte Ed25519 signature on stdout
//
// The matching public key is embedded in Alp.app's Info.plist as
// AlpUpdatePublicKey. UpdateChecker verifies the signature over the
// raw manifest bytes with CryptoKit Curve25519.Signing.

import CryptoKit
import Foundation

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("Usage: sign-release.swift <manifest>\n".utf8))
    FileHandle.standardError.write(Data("Set ALP_UPDATE_PRIVATE_KEY env var to the base64 Ed25519 private key.\n".utf8))
    exit(1)
}

let manifestPath = CommandLine.arguments[1]

guard let keyBase64 = ProcessInfo.processInfo.environment["ALP_UPDATE_PRIVATE_KEY"]?
    .trimmingCharacters(in: .whitespacesAndNewlines),
    !keyBase64.isEmpty
else {
    FileHandle.standardError.write(Data("Error: ALP_UPDATE_PRIVATE_KEY env var not set\n".utf8))
    exit(1)
}

guard let manifest = FileManager.default.contents(atPath: manifestPath) else {
    FileHandle.standardError.write(Data("Error: cannot read \(manifestPath)\n".utf8))
    exit(1)
}

guard let keyData = Data(base64Encoded: keyBase64) else {
    FileHandle.standardError.write(Data("Error: invalid base64 private key\n".utf8))
    exit(1)
}

do {
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
    let signature = try privateKey.signature(for: manifest)
    print(signature.base64EncodedString())
} catch {
    FileHandle.standardError.write(Data("Error: \(error)\n".utf8))
    exit(1)
}
