import Fluent

struct CreateArtists: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema("artists")
            .id()
            .timestamps()
            .field("name", .string, .required)
            .field("band_id", .uuid, .references("bands", "id"))
            .create()

        try await database.schema("songs")
            .field("artist_id", .uuid, .references("artists", "id"))
            .update()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("songs")
            .deleteField("artist_id")
            .update()

        try await database.schema("artists").delete()
    }
}
