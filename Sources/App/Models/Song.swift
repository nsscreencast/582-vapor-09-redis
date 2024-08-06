import Fluent
import Vapor

final class Song: Model, Content {
    static let schema = "songs"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "title")
    var title: String

    @Parent(key: "artist_id")
    var artist: Artist

    @Parent(key: "band_id")
    var band: Band

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {
    }

    init(id: UUID? = nil, title: String, artistID: UUID, bandID: UUID, createdAt: Date? = nil, updatedAt: Date? = nil) {
        self.id = id
        self.title = title
        self.$artist.id = artistID
        self.$band.id = bandID
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}
