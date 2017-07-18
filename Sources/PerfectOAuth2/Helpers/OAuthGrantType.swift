//
//  OAuthGrantType.swift
//  PerfectTemplate
//
//  Created by Bas van Kuijck on 09/02/2017.
//
//

import Foundation

public enum OAuthGrantType: String {
    case clientCredentials = "client_credentials"
    case refreshToken = "refresh_token"
    case authorizationCode = "authorization_code"
    case password = "password"
}


