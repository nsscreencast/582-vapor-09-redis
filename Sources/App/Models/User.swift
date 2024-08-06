import Vapor
import Fluent

final class User: Model, Content, Authenticatable {
    static let schema = "users"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "email")
    var email: String

    @Field(key: "password_hash")
    var passwordHash: String

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {
    }

    init(id: UUID? = nil, email: String, passwordHash: String) {
        self.id = id
        self.email = email
        self.passwordHash = passwordHash
    }
}

extension User {
    struct CreatePayload: Content, Validatable {
        var email: String
        var password: String
        var passwordConfirmation: String

        static func validations(_ validations: inout Validations) {
            validations.add("email", as: String.self, is: .email)
            validations.add("password", as: String.self, is: .count(8...1000))
        }
    }

    struct LoginPayload: Content, Validatable {
        var email: String
        var password: String

        static func validations(_ validations: inout Validations) {
            validations.add("email", as: String.self, is: !.empty)
            validations.add("password", as: String.self, is: !.empty)
        }
    }

    struct Response: Content {
        let id: UUID
        let email: String

        init(user: User) throws {
            self.id = try user.requireID()
            self.email = user.email
        }
    }

    var response: Response {
        get throws { try Response(user: self) }
    }
}


