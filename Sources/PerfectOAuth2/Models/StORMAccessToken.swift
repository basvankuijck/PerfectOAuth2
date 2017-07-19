//
//  StORMAccessToken.swift
//  Perfect-App-Template
//
//  Created by Bas van Kuijck on 18/07/2017.
//
//

import Foundation
import StORM

public protocol StORMConvenience: class {
    init()
    func find(_ data: [String: Any]) throws
    func save(set: (_ id: Any)->Void) throws
    func setup(_ str: String) throws
    func delete() throws
}

public protocol StORMAccessToken: StORMConvenience, JSONRepresentable, StORMProtocol {
    var id: Int { get set }
    var userID: Int { get set }
    var accessToken: String { get set }
    var refreshToken: String { get set }
    var scope: String { get set }
    var accessTokenExpirationDate: Date { get set }
    var refreshTokenExpirationDate: Date { get set }
}

extension StORMAccessToken {

    public func has(scope: String) -> Bool {
        return has(scopes: [ scope ])
    }

    public func has(scopes: [String]) -> Bool {
        return scope
            .components(separatedBy: " ")
            .filter { scopes.contains($0) }
            .count == scopes.count
    }

    public var json: [String: Any?] {
        var ret: [String: Any?] = [
            "access_token" : accessToken,
            "refresh_token": refreshToken,
            "expires_in": Int(accessTokenExpirationDate.timeIntervalSince(Date())),
            "token_type": TokenType.bearer.rawValue,
            "scope": nil
        ]
        if scope.characters.count > 0 {
            ret["scope"] = scope
        }
        return ret
    }
}
