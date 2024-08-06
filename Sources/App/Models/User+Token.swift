import JWT
import Vapor

extension User {
    struct Token: JWTPayload {
        static let issuer = "gigbuddy-server"

        enum CodingKeys: String, CodingKey {
            case subject = "sub"
            case expiration = "exp"
            case issuer = "iss"
            case issuedAt = "iat"
            case userID = "uid"
        }

        var subject: SubjectClaim
        var expiration: ExpirationClaim
        var issuer: IssuerClaim
        var issuedAt: IssuedAtClaim
        var userID: UUID

        func verify(using algorithm: some JWTAlgorithm) async throws {
            guard issuer.value == Token.issuer else {
                throw JWTError.claimVerificationFailure(failedClaim: issuer, reason: "not a valid issuer")
            }

            try expiration.verifyNotExpired()
        }
    }
}
