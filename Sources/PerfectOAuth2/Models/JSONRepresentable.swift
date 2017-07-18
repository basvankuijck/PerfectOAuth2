//
//  JSONRepresentable.swift
//  Perfect-App-Template
//
//  Created by Bas van Kuijck on 18/07/2017.
//
//

import Foundation

public protocol JSONRepresentable {
    var json: [String: Any?] { get }
}
