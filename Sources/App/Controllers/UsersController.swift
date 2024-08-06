import Vapor
import Fluent

struct UserBasicAuthenticator: AsyncBasicAuthenticator {
    func authenticate(basic: BasicAuthorization, for request: Request) async throws {
        guard let user = try await User.query(on: request.db)
            .filter(\.$email, .custom("ILIKE"), basic.username)
            .first()
        else {
            return
        }

        guard try Bcrypt.verify(basic.password, created: user.passwordHash) else {
            return
        }

        request.auth.login(user)
    }
}

struct UserJWTAuthenticator: AsyncBearerAuthenticator {
    func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        let payload = try await request.jwt.verify(as: User.Token.self)
        guard let user = try await User.find(payload.userID, on: request.db) else {
            return
        }

        request.auth.login(user)
    }
}

struct UsersController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let users = routes.grouped("users")

        users.post(use: create)
        users.post("login", use: login)

        let protected = users
            .grouped(UserBasicAuthenticator())
            .grouped(UserJWTAuthenticator())
            .grouped(User.guardMiddleware())

        protected.get("me", use: show)
    }

    @Sendable
    func create(_ req: Request) async throws -> User.Response {
        try User.CreatePayload.validate(content: req)

        let payload = try req.content.decode(User.CreatePayload.self)
        guard payload.password == payload.passwordConfirmation else {
            throw Abort(.badRequest, reason: "Passwords did not match")
        }

        let user = try User(
            email: payload.email,
            passwordHash: Bcrypt.hash(payload.password)
        )
        try await user.save(on: req.db)

        return try user.response
    }

    @Sendable
    func login(_ req: Request) async throws -> [String: String] {
        let loginPayload = try req.content.decode(User.LoginPayload.self)
        guard let user = try await User.query(on: req.db)
            .filter(\.$email, .custom("ILIKE"), loginPayload.email)
            .first() else {
            throw Abort(.unauthorized)
        }

        guard try Bcrypt.verify(loginPayload.password, created: user.passwordHash) else {
            throw Abort(.unauthorized)
        }

        let jwt = User.Token(
            subject: .init(value: user.email),
            expiration: .init(value: .now.addingTimeInterval(50)),
            issuer: .init(value: User.Token.issuer),
            issuedAt: .init(value: .now),
            userID: try user.requireID()
        )

        let encodedJWT = try await req.jwt.sign(jwt)

        return [
            "token": encodedJWT
        ]
    }

    @Sendable
    func show(_ req: Request) async throws -> User.Response {
        let user = try req.auth.require(User.self)
        return try user.response
    }
}

