//
//  JSONRepresentable.swift
//  Perfect-App-Template
//
//  Created by Bas van Kuijck on 18/07/2017.
//
//

import Foundation

public typealias JSONObjectOptionalValue = [String: Any?]

public protocol JSONRepresentable {
    var json: JSONObjectOptionalValue { get }
}
