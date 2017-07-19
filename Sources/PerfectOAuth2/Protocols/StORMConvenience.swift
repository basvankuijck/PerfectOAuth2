//
//  File.swift
//  Perfect-App-Template
//
//  Created by Bas van Kuijck on 19/07/2017.
//
//

import Foundation
import StORM

public protocol StORMConvenience: class, StORMProtocol {
    init()
    func setup(_ str: String) throws

    func find(_ data: [String: Any]) throws
    func find(_ data: [(String, Any)]) throws

    func get(_ id: Any) throws
    func get() throws

    func save(set: (_ id: Any)->Void) throws

    func delete() throws
    func delete(_ id: Any) throws

    @discardableResult func update(data: [(String, Any)], idName: String, idValue: Any) throws -> Bool
    @discardableResult func update(cols: [String], params: [Any], idName: String, idValue: Any) throws -> Bool
}
