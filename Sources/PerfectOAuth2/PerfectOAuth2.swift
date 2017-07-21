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
import PerfectLogger
import StORM


/// How should refreshtoken cycles be handled?
public enum RefreshTokenCycle {
    /// Once a refresh_token is used the attached access_token is invalidated immediatelly
    case invalidateImmediatelly

    /// The 'previous' access_token and refresh_token are still valid,
    ///  useable for a short period of time and a new refresh_token / access_token are generated.
    /// Once the new access_token is used, the previous one is invalidated.
    /// This makes sure the user actually gets the new access_token and is using it.
    case wait
}

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
        LogFile.info("PerfectOAuth2 initialized")
        try? T.init().setup("")
        clearExpiredRefreshTokens()
    }

    /// See `RefreshTokenCycle`
    public var refreshTokenCycle:RefreshTokenCycle = .invalidateImmediatelly

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
        LogFile.debug("PerfectOAuth2: Validating authorization in request \(request.method) \(request.path)")
        guard let authorization = request.header(.authorization) else {
            throw OAuthError.accessDenied
        }
        
        let authorizationBasic = authorization.components(separatedBy: " ")
        guard let accessTokenString = authorizationBasic.last,
            authorizationBasic.count == 2,
            authorizationBasic.first == TokenType.bearer.rawValue else {
                throw OAuthError.accessDenied
        }

        let accessToken = T.init()

        let findObj = [
            "accessToken": accessTokenString
        ]
        do {
            try accessToken.find(findObj)
            if accessToken.id == 0 {
                LogFile.error("PerfectOAuth2: Cannot find access_token '\(accessTokenString)'")
                throw OAuthError.invalidAccessToken
            }
            if let scopes = scopes {
                if !accessToken.has(scopes: scopes) {
                    LogFile.error("PerfectOAuth2: \(String(describing: accessToken)) does not have the correct scopes: \(scopes)")
                    throw OAuthError.invalidScope(scopes)
                }
            }

            let now = Date()
            if accessToken.accessTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970
                || accessToken.refreshTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970 {
                if accessToken.refreshTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970 {
                    LogFile.error("PerfectOAuth2: refresh_token is expired")
                    try invalidate(accessToken: accessToken)
                }
                LogFile.warning("PerfectOAuth2: access_token is expired '\(accessTokenString)'")
                throw OAuthError.invalidAccessToken
            }

            if accessToken.parentID > 0 {
                let parentAccessToken = T.init()
                try parentAccessToken.get(accessToken.parentID)
                try parentAccessToken.delete()
                accessToken.parentID = 0
                try accessToken.update(data: [ ( "parentID", 0) ], idName: "id", idValue: accessToken.id)
            }
            return accessToken
        } catch let error {
            LogFile.error("PerfectOAuth2: Authorize error: \(error)")
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
    open func handleAuthorization(data: [String:Any]?=nil, authClosure: @escaping ((_ clientAuthentication: ClientAuthorization) -> Bool), userClosure: ((_ username: String, _ password: String) -> Int?)?=nil) -> RequestHandler {
        return {
            request, response in
            
            do {
                guard let grantTypeString = request.param(name: "grant_type") else {
                    throw OAuthError.missingParameters(["grant_type"])
                }

                guard let grantType = OAuthGrantType(rawValue: grantTypeString) else {
                    LogFile.error("PerfectOAuth2: Invalid grant_type: \(grantTypeString)")
                    throw OAuthError.invalidGrantType
                }

                guard let clientAuthentication = ClientAuthorization(request: request) else {
                    LogFile.error("PerfectOAuth2: client_id and/or client_secret are invalid / unknown")
                    throw OAuthError.invalidClient

                }
                LogFile.debug("PerfectOAuth2: Checking client_id and client_secret from 'Authorization' header")
                if authClosure(clientAuthentication) == false {
                    LogFile.error("PerfectOAuth2: client_id and/or client_secret are invalid / unknown")
                    throw OAuthError.invalidClient
                }

                var scope = request.param(name: "scope")
                var userID: Int?
                var parentAccessTokenID: Int = 0
                switch (grantType) {
                case .clientCredentials:
                    break
                    
                case .password:
                    guard let username = request.param(name: "username"),
                        let password = request.param(name: "password") else {
                            throw OAuthError.missingParameters(["username", "password"])
                    }
                    guard let tuserID = userClosure?(username, password) else {
                        LogFile.error("PerfectOAuth2: Invalid username (\(username)) and/or password (***)")
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
                    switch self.refreshTokenCycle {
                    case .invalidateImmediatelly:
                        try self.invalidate(accessToken: accessToken)

                    case .wait:
                        parentAccessTokenID = accessToken.id
                        try accessToken.update(data: [ ("refreshTokenExpirationDate", Date(timeIntervalSinceNow: 60*60)) ], idName: "id", idValue: accessToken.id)
                        let findToken = T.init()
                        try findToken.find([ "parentID": String(describing: parentAccessTokenID) ])
                        for row in findToken.results.rows {
                            let token = T.init()
                            token.to(row)
                            try token.delete(token.id)
                        }
                    }


                case .authorizationCode:
                    break
                }

                do {
                    let accessToken = T.init()
                    accessToken.userID = userID ?? 0
                    accessToken.scope = scope ?? ""
                    accessToken.parentID = parentAccessTokenID
                    try accessToken.save { id in accessToken.id = id as! Int }
                    response.setHeader(.contentType, value: "application/json")

                    LogFile.info("PerfectOAuth2: Generated \(String(describing: accessToken))")
                    try response.setBody(json: accessToken.json)
                } catch let error {
                    throw error
                }
                
                response.completed()
            } catch let error as OAuthError {
                LogFile.error("PerfectOAuth2: error: \(error)")
                response.throw(with: error)
            } catch let error {
                LogFile.error("PerfectOAuth2: error: \(error)")
            }
        }
    }

    fileprivate func authorize(refreshToken: String) throws -> T {

        let accessToken = T.init()

        let findObj = [
            "refreshToken": refreshToken
        ]
        do {
            try accessToken.find(findObj)
            if accessToken.id == 0 {
                LogFile.error("PerfectOAuth2: Cannot find an access_token with the refresh_token \(refreshToken)")
                throw OAuthError.invalidRefreshToken
            }
            let now = Date()
            if accessToken.refreshTokenExpirationDate.timeIntervalSince1970 < now.timeIntervalSince1970 {
                try invalidate(accessToken: accessToken)
                LogFile.error("PerfectOAuth2: refresh_token is expired")
                throw OAuthError.invalidRefreshToken
            }
            return accessToken
        } catch {
            throw OAuthError.invalidRefreshToken
        }
    }

    /// Invalidates an `accessToken`
    ///
    /// - Parameter accessToken: `AccessToken`
    /// - Throws: If for some reason the accessToken cannot be removed. An error will be thrown.
    public func invalidate(accessToken: T) throws {
        LogFile.debug("PerfectOAuth2: Invalidate access_token \(accessToken.accessToken)")
        try accessToken.delete()
    }


    /// Clears all the access_tokens where the refresh_tokens have expired
    public func clearExpiredRefreshTokens() {
        LogFile.debug("Clearing expired refresh_tokens...")
        do {
            let accessToken = T.init()
            try accessToken.findAll()
            let date = Date()
            for row in accessToken.results.rows {
                let token = T.init()
                token.to(row)
                if token.refreshTokenExpirationDate.timeIntervalSince1970 < date.timeIntervalSince1970 {
                    try token.delete()
                }
            }
        } catch let error {
            LogFile.error("Error clearing expired refresh tokens: \(String(describing: error))")
        }
    }
}
