import Fluent

struct CreateSongs: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema("songs")
            .id()
            .field("title", .string, .required)
            .field("band_id", .uuid, .references("bands", .id))
            .timestamps()
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("songs").delete()
    }
}
