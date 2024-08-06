import Fluent
import Vapor

final class Band: Model, Content {
    static let schema = "bands"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "name")
    var name: String

    @Field(key: "slug")
    var slug: String

    @Children(for: \.$band)
    var artists: [Artist]

    @Children(for: \.$band)
    var songs: [Song]

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {
    }

    init(id: UUID? = nil, name: String, slug: String, createdAt: Date? = nil, updatedAt: Date? = nil) {
        self.id = id
        self.name = name
        self.slug = slug
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

extension Band {
    static func findBySlug(_ slug: String, on db: Database) async throws -> Band? {
        try await Band.query(on: db)
            .filter(\.$slug == slug)
            .limit(1)
            .first()
    }
}
