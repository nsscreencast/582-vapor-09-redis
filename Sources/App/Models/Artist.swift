import Fluent
import Vapor

final class Artist: Model, Content {
    static let schema = "artists"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "name")
    var name: String

    @Parent(key: "band_id")
    var band: Band

    @Children(for: \.$artist)
    var songs: [Song]

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {
    }

    init(id: UUID? = nil, name: String, bandID: UUID, createdAt: Date? = nil, updatedAt: Date? = nil) {
        self.id = id
        self.name = name
        self.$band.id = bandID
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}
