//
//  ClientAuthorization.swift
//  Perfect-App-Template
//
//  Created by Bas van Kuijck on 20/07/2017.
//
//

import Foundation
import PerfectLogger
import PerfectHTTP

public struct ClientAuthorization {
    public var clientID: String
    public var clientSecret: String

    public init?(request: HTTPRequest) {
        if let authorization = request.header(.authorization) {
            let authorizationBasic = authorization.components(separatedBy: " ")
            guard let base64EncodedString = authorizationBasic.last,
                authorizationBasic.count == 2,
                authorizationBasic.first == TokenType.basic.rawValue,
                let base64EncodedData = Data(base64Encoded: base64EncodedString),
                let base64DecodedString = String(data: base64EncodedData, encoding: .utf8) else {
                    LogFile.error("PerfectOAuth2: Missing 'Authorization: Basic <base64_encoded>' header")
                    return nil
            }

            let keySecretArray = base64DecodedString.components(separatedBy: ":")
            guard keySecretArray.count == 2,
                let clientID = keySecretArray.first,
                let clientSecret = keySecretArray.last else {
                    return nil
            }

            self.clientID = clientID
            self.clientSecret = clientSecret

            // client_id and client_secret are send through regular post/get values
        } else if let clientID = request.param(name: "client_id"), let clientSecret = request.param(name: "client_secret") {
            LogFile.debug("PerfectOAuth2: Checking client_id and client_secret from POST request parameters")
            self.clientID = clientID
            self.clientSecret = clientSecret
            return
        }
        return nil
    }
}
