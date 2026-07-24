import Foundation

/// Pure colon-listing / status-line parsers for GPGHelper, split out of
/// GPGHelper.swift to keep that file within the lint length budget.
/// These touch no actor state — they transform gpg output into value types.
extension GPGHelper {
    /// Parses gpg's `--status-fd` output for a single signature.
    ///
    /// `isValid` is true ONLY for a `GOODSIG` — a cryptographically-good
    /// signature from a key that is neither expired nor revoked. This is the
    /// crux of the fix: gpg also emits a `VALIDSIG` line for expired-key
    /// (`EXPKEYSIG`), revoked-key (`REVKEYSIG`), and expired-signature
    /// (`EXPSIG`) cases, so validity must NEVER be inferred from `VALIDSIG`
    /// presence — doing so reports a revoked-key signature as "valid", which
    /// is exactly the forgery a verifying mail client must not accept.
    ///
    /// Exactly one of GOODSIG / EXPSIG / EXPKEYSIG / REVKEYSIG / BADSIG / ERRSIG
    /// accompanies each checked signature (GnuPG doc/DETAILS).
    func signatureVerdict(from statusText: String) -> (isValid: Bool, fingerprint: String?, displayName: String?) {
        var validSigFingerprint: String? // full 40-hex fingerprint from VALIDSIG
        var signerKeyID: String? // long key-id from the status keyword line
        var displayName: String?
        var sawGood = false
        var sawBadOrError = false // BADSIG / ERRSIG / EXP*SIG / REVKEYSIG

        for line in statusText.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: " ")
            // VALIDSIG <fpr> ... — only trust it as a fingerprint when it is a
            // real 40-hex value, never as a proxy for validity.
            if let idx = parts.firstIndex(of: "VALIDSIG"), parts.count > idx + 1 {
                let candidate = parts[idx + 1]
                if candidate.count == 40, candidate.allSatisfy(\.isHexDigit) {
                    validSigFingerprint = candidate
                }
            }
            // <KEYWORD> <long_keyid> <username...>
            for keyword in ["GOODSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG"] {
                guard let idx = parts.firstIndex(of: keyword) else { continue }
                if parts.count > idx + 1 {
                    signerKeyID = parts[idx + 1]
                }
                if parts.count > idx + 2 {
                    let name = parts[(idx + 2)...].joined(separator: " ")
                        .trimmingCharacters(in: .whitespaces)
                    if !name.isEmpty {
                        displayName = name
                    }
                }
                if keyword == "GOODSIG" {
                    sawGood = true
                } else {
                    sawBadOrError = true
                }
            }
            // ERRSIG carries no username (key missing / unsupported algo).
            if parts.contains("ERRSIG") {
                sawBadOrError = true
            }
        }

        let isValid = sawGood && !sawBadOrError
        return (isValid, validSigFingerprint ?? signerKeyID, displayName)
    }

    /// Decodes gpg `--with-colons` field escaping. gpg escapes `:`, `\`, and
    /// control / non-printable bytes as `\xNN`. Without decoding, a UID with an
    /// escaped colon renders as literal `\x3a`, and a crafted UID can embed
    /// `\x0a`/`\x0d`/`\x3e` text that the downstream `<…>`-email extraction
    /// mis-parses. Escapes are decoded to raw bytes then read back as UTF-8 so
    /// multi-byte sequences (e.g. `\xc3\xa9` → "é") survive.
    static func decodeColonField(_ field: String) -> String {
        guard field.contains("\\x") else { return field }
        var bytes: [UInt8] = []
        let scalars = Array(field.unicodeScalars)
        var i = 0
        while i < scalars.count {
            if scalars[i] == "\\", i + 3 < scalars.count, scalars[i + 1] == "x",
               let hi = Character(scalars[i + 2]).hexDigitValue,
               let lo = Character(scalars[i + 3]).hexDigitValue
            {
                bytes.append(UInt8(hi * 16 + lo))
                i += 4
            } else {
                bytes.append(contentsOf: Array(String(scalars[i]).utf8))
                i += 1
            }
        }
        return String(bytes: bytes, encoding: .utf8) ?? field
    }

    func parseColonKeyListing(_ text: String) -> [GPGKeyInfo] {
        var keys: [GPGKeyInfo] = []

        var primaryFingerprint: String?
        var primaryUIDs: [String] = []
        var primaryCapabilities = ""
        var primaryExpiry: Date?
        var primaryOwnerTrust: String?
        var primaryCreated: Date?
        var primaryAlgorithm: String?
        var subkeys: [GPGSubkey] = []

        // Staging area for the subkey we're currently filling in. We can't
        // build the final `GPGSubkey` until its `fpr` line arrives because
        // the subkey's full fingerprint appears on a subsequent record.
        struct PendingSubkey {
            var fingerprint: String = ""
            var capabilities: String = ""
            var expiry: Date?
            var algorithm: String?
            var isRevoked: Bool = false
        }
        var pendingSubkey: PendingSubkey?

        func flushSubkey() {
            guard let pending = pendingSubkey, !pending.fingerprint.isEmpty else {
                pendingSubkey = nil
                return
            }
            subkeys.append(GPGSubkey(
                fingerprint: pending.fingerprint,
                capabilities: pending.capabilities,
                expiryDate: pending.expiry,
                algorithm: pending.algorithm,
                isRevoked: pending.isRevoked,
            ))
            pendingSubkey = nil
        }

        func flushPrimary() {
            flushSubkey()
            guard let fp = primaryFingerprint, !fp.isEmpty else { return }
            keys.append(GPGKeyInfo(
                fingerprint: fp,
                userIDs: primaryUIDs,
                capabilities: primaryCapabilities,
                expiryDate: primaryExpiry,
                subkeys: subkeys,
                ownerTrustCode: primaryOwnerTrust,
                creationDate: primaryCreated,
                algorithm: primaryAlgorithm,
            ))
            primaryFingerprint = nil
            primaryUIDs = []
            primaryCapabilities = ""
            primaryExpiry = nil
            primaryOwnerTrust = nil
            primaryCreated = nil
            primaryAlgorithm = nil
            subkeys = []
        }

        for raw in text.components(separatedBy: "\n") {
            let fields = raw.trimmingCharacters(in: .init(charactersIn: "\r"))
                .components(separatedBy: ":")
            guard let recordType = fields.first, !recordType.isEmpty else { continue }

            if recordType.hasPrefix("pub") || recordType.hasPrefix("sec") {
                flushPrimary()
                primaryCapabilities = fields.count > 11 ? fields[11] : ""
                if fields.count > 6, let ts = TimeInterval(fields[6]), ts > 0 {
                    primaryExpiry = Date(timeIntervalSince1970: ts)
                } else {
                    primaryExpiry = nil
                }
                // Field 9 of the pub colon record is the ownertrust code.
                if fields.count > 8, !fields[8].isEmpty {
                    primaryOwnerTrust = fields[8]
                } else {
                    primaryOwnerTrust = nil
                }
                // Field 6 (creation timestamp) and the bits/algo/curve
                // triple feed the inspector view's metadata block.
                if fields.count > 5, let ts = TimeInterval(fields[5]), ts > 0 {
                    primaryCreated = Date(timeIntervalSince1970: ts)
                } else {
                    primaryCreated = nil
                }
                primaryAlgorithm = Self.formatAlgorithm(
                    id: fields.count > 3 ? fields[3] : "",
                    bits: fields.count > 2 ? fields[2] : "",
                    curve: fields.count > 16 ? fields[16] : "",
                )
            } else if recordType.hasPrefix("sub") || recordType.hasPrefix("ssb") {
                flushSubkey()
                var pending = PendingSubkey()
                pending.isRevoked = fields.count > 1 && fields[1] == "r"
                pending.capabilities = fields.count > 11 ? fields[11] : ""
                if fields.count > 6, let ts = TimeInterval(fields[6]), ts > 0 {
                    pending.expiry = Date(timeIntervalSince1970: ts)
                }
                pending.algorithm = Self.formatAlgorithm(
                    id: fields.count > 3 ? fields[3] : "",
                    bits: fields.count > 2 ? fields[2] : "",
                    curve: fields.count > 16 ? fields[16] : "",
                )
                pendingSubkey = pending
            } else if recordType == "fpr" {
                if pendingSubkey != nil {
                    if fields.count > 9 {
                        pendingSubkey?.fingerprint = fields[9]
                    }
                } else if primaryFingerprint == nil, fields.count > 9 {
                    primaryFingerprint = fields[9]
                }
            } else if recordType == "uid" {
                if fields.count > 9, !fields[9].isEmpty {
                    primaryUIDs.append(Self.decodeColonField(fields[9]))
                }
            }
        }
        flushPrimary()
        return keys
    }

    /// Maps gpg's numeric algorithm id + bit size + curve name to a
    /// human-readable label, e.g. "RSA 3072" or "Ed25519".
    ///
    /// Algorithm ids come from RFC 4880 + gpg extensions:
    ///   1 = RSA, 16 = ElGamal, 17 = DSA, 18 = ECDH, 19 = ECDSA, 22 = EdDSA.
    static func formatAlgorithm(id: String, bits: String, curve: String) -> String? {
        guard let algoId = Int(id) else { return nil }
        let name: String
        switch algoId {
        case 1: name = "RSA"
        case 16: name = "ElGamal"
        case 17: name = "DSA"
        case 18: name = "ECDH"
        case 19: name = "ECDSA"
        case 22: name = "EdDSA"
        default: return nil
        }
        // ECC keys prefer the curve name when it's present — "Ed25519" is
        // more useful than "EdDSA 255".
        if [18, 19, 22].contains(algoId), !curve.isEmpty {
            return curve.capitalized
        }
        if !bits.isEmpty {
            return "\(name) \(bits)"
        }
        return name
    }
}
