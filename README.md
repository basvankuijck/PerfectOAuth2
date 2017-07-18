[![forthebadge](http://forthebadge.com/images/badges/made-with-swift.svg)](http://forthebadge.com)
[![forthebadge](http://forthebadge.com/images/badges/winter-is-coming.svg)](http://forthebadge.com)

# PerfectOAuth2

Creates and utilizes an OAuth2 implementation on your Perfect webserver.

## Example

###  `main.swift`
```swift
import PerfectLib
import PerfectHTTP
import PerfectHTTPServer
import PerfectRequestLogger
import PerfectLogger
import StORM
import PerfectOAuth2
import MySQLStORM
import PerfectCrypto

MySQLConnector.host	= "127.0.0.1"
MySQLConnector.username	= "root"
MySQLConnector.password = "password"
MySQLConnector.database	= "perfect"
MySQLConnector.port	= 3306

let oauthHandler = PerfectOAuth2<AccessToken>()

func loginHandler(data: [String:Any]) throws -> RequestHandler {
    return try oauthHandler.handleAuthorization(data: data,
               authClosure: { (grantType, clientID, clientSecret) -> Bool in
        return clientID == "id" && clientSecret == "secret"
        
    }) { (username, password) -> Int? in
        // Validate the user.
        if username == "basvankuijck" && password == "pass" {
        	return 1
        }
        return nil
    }
}

func authHandler(data: [String:Any]) throws -> RequestHandler {
    return  { request, response in
        do {
            let accessToken = try oauthHandler.authorize(request: request)
            // Get the user from the `accessToken.userID` value
            
            response.setHeader(.contentType, value: "application/json")
            try response.setBody(json: [
                "status": "success",
                "user": [
                    "username": "basvankuijck"
                ]
            ])
            response.completed()

        } catch let error as OAuthError {
            response.throw(with: error)

        } catch {  }
        response.throw(from: .notFound)
    }
}

let confData = [
   "servers": [
   [
      "name": "localhost",
      "port": 8080,
      "routes": [
         [ "method": "post", "uri": "/oauth/token", "handler": loginHandler ],
         [ "method": "get", "uri": "/user/me", "handler": authHandler ],
       ]
    ]
]

do {
    try HTTPServer.launch(configurationData: confData)
} catch {
    fatalError("\(error)")
}
```

### `AccessToken.swift`

```swift
import Foundation
import StORM
import MySQLStORM
import PerfectOAuth2

class AccessToken: MySQLStORM, StORMAccessToken {

    var id: Int = 0
    var userID: Int = 0
    var accessToken: String = UUID.token
    var refreshToken: String = UUID.token
    var accessTokenExpirationDate: Date = Date(timeIntervalSinceNow: TimeInterval(3600))
    var refreshTokenExpirationDate: Date = Date(timeIntervalSinceNow: TimeInterval(60*60*24*182))
    var scope: String = ""

    override open func table() -> String { return "access_tokens" }

    override public func to(_ this: StORMRow) {
        id = (this.data["id"] as? Int) ?? 0
        userID = (this.data["userID"] as? Int) ?? 0
        scope = (this.data["scope"] as? String) ?? ""
        refreshToken = (this.data["refreshToken"] as? String) ?? ""
        refreshToken = (this.data["refreshToken"] as? String) ?? ""

        if let dateString = this.data["accessTokenExpirationDate"] as? String,
            let date = DateFormatter.mySQL.date(from: dateString) {
            accessTokenExpirationDate = date
        }

        if let dateString = this.data["refreshTokenExpirationDate"] as? String,
            let date = DateFormatter.mySQL.date(from: dateString) {
            refreshTokenExpirationDate = date
        }
    }
}

```