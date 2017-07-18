//
//  UUID.swift
//  Perfect-App-Template
//
//  Created by Bas van Kuijck on 18/07/2017.
//
//

import Foundation
import PerfectCrypto

extension UUID {
    public static var token: String {
        func stringValue(from uint8Array: [UInt8]?) -> String? {
            guard let uint8Array = uint8Array else {
                return nil
            }
            return uint8Array.reduce("", { $0 + String(format: "%c", $1)})
        }
        guard let sha1 = stringValue(from: UUID().uuidString.digest(.sha1)?.encode(.hex)),
            let sha2 = stringValue(from: UUID().uuidString.digest(.sha1)?.encode(.hex)) else {
                return ""
        }
        let str = "\(sha1)\(sha2)"
        return str.substring(to: str.index(str.startIndex, offsetBy: 64))
    }
}
