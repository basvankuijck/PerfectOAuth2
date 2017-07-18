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
        guard let sha1 = stringValue(from: UUID().uuidString.digest(.sha1)?.encode(.hex)),
            let sha2 = stringValue(from: UUID().uuidString.digest(.sha1)?.encode(.hex)) else {
                return ""
        }
        let str = "\(sha1)\(sha2)"
        return str.substring(to: str.index(str.startIndex, offsetBy: 64))
    }
}
