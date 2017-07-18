//
//  Array.swift
//  Perfect-App-Template
//
//  Created by Bas van Kuijck on 18/07/2017.
//
//

import Foundation

public func stringValue(from obj: Any?) -> String? {
    if let uint8Array = obj as? [UInt8] {
        return uint8Array.reduce("", { $0! + String(format: "%c", $1)})

    } else if let str = obj as? String {
        return str
        
    }
    return nil
}
