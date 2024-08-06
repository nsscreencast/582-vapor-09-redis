import Fluent

struct CreateBands: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema("bands")
            .id()
            .field("name", .string, .required)
            .field("slug", .string, .required)
            .unique(on: "slug")
            .timestamps()
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("bands").delete()
    }
}

