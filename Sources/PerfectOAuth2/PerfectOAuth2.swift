//
//  OAuthAuthorisationHandler.swift
//  PerfectTemplate
//
//  Created by Bas van Kuijck on 09/02/2017.
//
//

import PerfectLib
import PerfectHTTP
import PerfectHTTPServer
import Foundation
import StORM

/// Create a Perfect OAuth2 Handler with an `StORMAccessToken` generic
///
/// The generic should conform to the `StORMAccessToken` protocol
///
/// ## Example
///
///     import Foundation
///     import StORM
///     import MySQLStORM
///     import PerfectOAuth2
///
///     class AccessToken: MySQLStORM, StORMAccessToken {
///
///        public var id: Int = 0
///            var userID: Int = 0
///            var accessToken: String = UUID.token
///            var refreshToken: String = UUID.token
///            var accessTokenExpirationDate: Date = Date(timeIntervalSinceNow: TimeInterval(3600))
///            var refreshTokenExpirationDate: Date = Date(timeIntervalSinceNow: TimeInterval(60*60*24*182))
///            var scope: String = ""
///
///            override open func table() -> String { return "access_tokens" }
///
///            override public func to(_ this: StORMRow) {
///                id = Int(exactly: this.data["id"] as? Int32 ?? 0) ?? 0
///                userID = Int(exactly: this.data["userID"] as? Int32 ?? 0) ?? 0
///                accessToken = (this.data["accessToken"] as? String) ?? ""
///                refreshToken = (this.data["refreshToken"] as? String) ?? ""
///                scope = (this.data["scope"] as? String) ?? ""
///
///                if let dateString = this.data["accessTokenExpirationDate"] as? String,
///                    let date = DateFormatter.mySQL.date(from: dateString) {
///                    accessTokenExpirationDate = date
///                }
///
///                if let dateString = this.data["refreshTokenExpirationDate"] as? String,
///                    let date = DateFormatter.mySQL.date(from: dateString) {
///                    refreshTokenExpirationDate = date
///                }
///            }
///        }
///        
///        public func rows() -> [AccessToken] {
///            var rows = [AccessToken]()
///            for i in 0..<self.results.rows.count {
///                let row = AccessToken()
///                row.to(self.results.rows[i])
///                rows.append(row)
///            }
///            return rows
///        }
///     }
///
///     let perfectOAuth2Handler = PerfectOAuth2<AccessToken>()
///     // ... etc
///
/// This way you can use any StORM object as you wish.
open class PerfectOAuth2<T: StORMAccessToken> {

    public init() {
        try? T.init().setup("")
    }

    /// See if a `Perfect.HTTPRequest` has the correct authorization.
    ///
    ///## Example:
    ///     let confData = [
    ///        "servers": [
    ///        [
    ///           "name": "localhost",
    ///           "port": HTTPport,
    ///           "routes":[
    ///                [ "method": "get", "uri": "/user/me", "handler": authHandler ]
    ///            ]
    ///         ]
    ///     ]
    ///
    ///     do {
    ///         try HTTPServer.launch(configurationData: confData)
    ///     } catch {
    ///         fatalError("\(error)")
    ///     }
    ///
    ///     func authHandler(data: [String:Any]) throws -> RequestHandler {
    ///         return { request, response in
    ///             do {
    ///                 let accessToken = try oauthHandler.authorize(request: request, scopes: ["profile"])
    ///                 // At this point you can use the `accessToken` and its underlying `userID`
    ///                 response.completed()
    ///
    ///             } catch let error as OAuthError {
    ///                 response.throw(with: error)
    ///
    ///             } catch {
    ///                 response.throw(with: .notFound)}
    ///             }
    ///         }
    ///     }
    ///
    ///
    /// - Note: This function checks if a bearer access_token is provided and validates it
    /// - Seealso: OAuthError
    ///
    /// - Parameters:
    ///   - request: HTTPRequest
    ///   - scopes: (Optional) What scope(s) is used
    /// - Returns: `AccessToken`. Returns the `AccessToken` that is used to authorize / authenticate.
    /// - Throws: See `OAuthError`
    @discardableResult open func authorize(request: HTTPRequest, scopes: [String]?=nil) throws -> T {
        guard let authorization = request.header(.authorization) else {
            throw OAuthError.accessDenied
        }
        
        let authorizationBasic = authorization.components(separatedBy: " ")
        guard let accessTokenString = authorizationBasic.last,
            authorizationBasic.count == 2,
            authorizationBasic.first == TokenType.bearer.rawValue else {
                throw OAuthError.accessDenied
        }

        let accesToken = T.init()

        let findObj = [
            "accessToken": accessTokenString
        ]
        do {
            try accesToken.find(findObj)
            if accesToken.id == 0 {
                print("Cannot find access_token '\(accessTokenString)'")
                throw OAuthError.invalidAccessToken
            }
            if let scopes = scopes {
                if !accesToken.has(scopes: scopes) {
                    throw OAuthError.invalidScope(scopes)
                }
            }

            let now = Date()
            if accesToken.accessTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970
                || accesToken.refreshTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970 {
                if accesToken.refreshTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970 {
                    try invalidate(accessToken: accesToken)
                }
                print("access_token is expired '\(accessTokenString)'")
                throw OAuthError.invalidAccessToken
            }
            return accesToken
        } catch let error {
            print("Authorize error: \(error)")
            throw error
        }
    }
    
    /// Handles an '/oauth/token' authorization call
    ///
    /// ## Example:
    ///     let confData = [
    ///        "servers": [
    ///        [
    ///           "name": "localhost",
    ///           "port": HTTPport,
    ///           "routes":[
    ///              [ "method": "post", "uri": "/oauth/token", "handler": loginHandler ]
    ///            ]
    ///         ]
    ///     ]
    ///
    ///     do {
    ///         try HTTPServer.launch(configurationData: confData)
    ///     } catch {
    ///         fatalError("\(error)")
    ///     }
    ///
    ///     func loginHandler(data: [String:Any]) throws -> RequestHandler {
    ///         return try oauthHandler.handleAuthorization(data: data, authClosure: { (grantType, clientID, clientSecret) -> Bool in
    ///             return clientID == "id" && clientSecret == "secret"
    ///         }, userClosure: { (username, password) -> Int? in
    ///             // Validate the user.
    ///             return 1
    ///         })
    ///     }
    ///
    /// - Parameters:
    ///   - data: The data (`[String: Any]`) that was passed along the `Perfect` route handler
    ///   - authClosure: The closure to be called to verify a specific grant_type, client_id and client_secret. Return `Bool` if succesful.
    ///   - userClosure: The closure to be called to verify a specific username and password. Return the `userID` if succesful, otherwise return `nil`. (Optional). Only used for `password` grant_types
    /// - Returns: The actual `Perfect.RequestHandler`
    /// - Throws: See `OAuthError`
    open func handleAuthorization(data: [String:Any], authClosure: @escaping ((_ grantType: OAuthGrantType, _ clientID: String, _ clientSecret: String) -> Bool), userClosure: ((_ username: String, _ password: String) -> Int?)?=nil) throws -> RequestHandler {
        return {
            request, response in
            
            do {
                guard let grantTypeString = request.param(name: "grant_type") else {
                    throw OAuthError.missingParameters(["grant_type"])
                }

                guard let grantType = OAuthGrantType(rawValue: grantTypeString) else {
                    throw OAuthError.invalidGrantType
                }

                // client_id and client_secret are send through 'Authorization: Basic <base64_encdode>' header
                if let authorization = request.header(.authorization) {
                    let authorizationBasic = authorization.components(separatedBy: " ")
                    guard let base64EncodedString = authorizationBasic.last,
                        authorizationBasic.count == 2,
                        authorizationBasic.first == TokenType.basic.rawValue,
                        let base64EncodedData = Data(base64Encoded: base64EncodedString),
                        let base64DecodedString = String(data: base64EncodedData, encoding: .utf8) else {
                            throw OAuthError.invalidClient
                    }
                    
                    let keySecretArray = base64DecodedString.components(separatedBy: ":")
                    guard keySecretArray.count == 2,
                        let clientID = keySecretArray.first,
                        let clientSecret = keySecretArray.last else {
                            throw OAuthError.invalidClient
                    }
                    
                    
                    if authClosure(grantType, clientID, clientSecret) == false {
                        throw OAuthError.invalidClient
                    }
                    
                // client_id and client_secret are send through regular post values
                } else if let clientID = request.param(name: "client_id"), let clientSecret = request.param(name: "client_secret") {
                    if authClosure(grantType, clientID, clientSecret) == false {
                        throw OAuthError.invalidClient
                    }
                }
                var scope = request.param(name: "scope")
                var userID:Int?
                switch (grantType) {
                case .clientCredentials:
                    break
                    
                case .password:
                    guard let username = request.param(name: "username"),
                        let password = request.param(name: "password") else {
                            throw OAuthError.missingParameters(["username", "password"])
                    }
                    guard let tuserID = userClosure?(username, password) else {
                        throw OAuthError.invalidUsernamePassword
                    }
                    userID = tuserID

                    
                case .refreshToken:
                    guard let refreshToken = request.param(name: "refresh_token") else {
                        throw OAuthError.missingParameters(["refresh_token"])
                    }
                    let accessToken = try self.authorize(refreshToken: refreshToken)
                    userID = accessToken.userID
                    scope = accessToken.scope
                    try self.invalidate(accessToken: accessToken)
                    
                default:
                    break
                }

                do {
                    let accessToken = T.init()
                    accessToken.userID = userID ?? 0
                    accessToken.scope = scope ?? ""
                    try accessToken.save { id in accessToken.id = id as! Int }
                    response.setHeader(.contentType, value: "application/json")
                    
                    try response.setBody(json: accessToken.json)
                } catch let error {
                    throw error
                }
                
                response.completed()
            } catch let error as OAuthError {
                response.throw(with: error)
            } catch { }
        }
    }

    fileprivate func authorize(refreshToken: String) throws -> T {

        let accesToken = T.init()

        let findObj = [
            "refreshToken": refreshToken
        ]
        do {
            try accesToken.find(findObj)
            if accesToken.id == 0 {
                throw OAuthError.invalidRefreshToken
            }
            let now = Date()
            if accesToken.refreshTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970 {
                try invalidate(accessToken: accesToken)
                throw OAuthError.invalidRefreshToken
            }
            return accesToken
        } catch {
            throw OAuthError.invalidRefreshToken
        }
    }

    /// Invalidates an `accessToken`
    ///
    /// - Parameter accessToken: `AccessToken`
    /// - Throws: If for some reason the accessToken cannot be removed. An error will be thrown.
    public func invalidate(accessToken: T) throws {
        try accessToken.delete()
    }
}
