//
//  OAuthError.swift
//  PerfectTemplate
//
//  Created by Bas van Kuijck on 09/02/2017.
//
//

import Foundation
import PerfectLib
import PerfectHTTP
import PerfectHTTPServer

public enum OAuthError: Error {
    /// If client_id and/or client_secret are invalid
    case invalidClient

    /// Missing parameter.
    ///
    /// For instance when a `grant_type` is missing.
    case missingParameters([String])

    /// Invalid grant_type
    ///
    /// Available grant_types:
    /// - `client_credentials`
    /// - `refresh_token`
    /// - `authorization_code`
    /// - `password`
    case invalidGrantType

    /// Invalid username and/or password
    case invalidUsernamePassword

    /// Using an access_token which is invalid or expired
    case invalidAccessToken

    /// Using a refresh_token which is invalid or expired
    case invalidRefreshToken

    /// OAuth2 authentication required
    case accessDenied

    /// If the access token doesn't have scope privileges
    case invalidScope([String])    
    
    public var errorCode: String {
        switch (self) {
        case .invalidUsernamePassword, .invalidRefreshToken, .invalidAccessToken: return "invalid_grant"
        case .invalidClient: return "invalid_client"
        case .missingParameters: return "invalid_request"
        case .invalidGrantType: return "unsupported_grant_type"
        case .accessDenied: return "access_denied"
        case .invalidScope: return "invalid_scope"
        }
    }

    public var description: String {
        switch (self) {
        case .invalidRefreshToken: return "Invalid refresh token"
        case .invalidClient: return "Client id was not found in the headers or body"
        case .invalidUsernamePassword: return "Invalid username and password combination"
        case .missingParameters(var parameters):
            guard let lastParameter = parameters.last else {
                return ""
            }
            parameters.removeLast()
            var params = ""
            var s = ""
            if parameters.count > 0 {
                s = "s"
                params = parameters.joined(separator: "\", \"") + "\" and \""
            }
            params = params + lastParameter
            return "Missing parameter\(s). \"\(params)\" required"
            
        case .invalidGrantType: return "The authorization grant type is not supported by the authorization server"
        case .accessDenied: return "OAuth2 authentication required"
        case .invalidAccessToken: return "Invalid access token"
        case .invalidScope(let scopes): return "Not authorized to request the scopes [\(scopes.joined(separator: " ,"))]"
        }
    }
    
    public var httpResponseStatus: HTTPResponseStatus {
        switch (self) {
        case .accessDenied, .invalidAccessToken: return .unauthorized
        default: return .badRequest
        }
    }
}

extension HTTPResponse {
    public func `throw`(`with` error: OAuthError) {
        
        let jsonResponse: [String:Any] = [
            "error": error.errorCode,
            "error_description": error.description
        ]
        self.status = error.httpResponseStatus
        self.setHeader(.contentType, value: "application/json")
        do {
            try self.setBody(json: jsonResponse)
        } catch { }
        self.completed()
    }

    public func `throw`(from status: HTTPResponseStatus, message:String?=nil) {
        let jsonResponse: [String: Any] = [
            "status": "error",
            "data": [
                "code": status.code,
                "message": message ?? status.description
            ]
        ]
        self.status = status
        self.setHeader(.contentType, value: "application/json")
        do {
            try self.setBody(json: jsonResponse)
        } catch { }
        self.completed()
    }
}
