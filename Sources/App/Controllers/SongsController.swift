import Vapor
import Fluent

struct SongsController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let songs = routes.grouped("songs")

        songs.get(use: index)
        songs.post(use: create)
    }

    @Sendable
    func index(req: Request) async throws -> [Song] {
        let slug = try req.parameters.require("slug")
        guard let band = try await Band.findBySlug(slug, on: req.db) else {
            throw Abort(.notFound)
        }

        return try await band.$songs.query(on: req.db).all()
    }

    @Sendable
    func create(req: Request) async throws -> Song {
        let slug = try req.parameters.require("slug")
        guard let band = try await Band.findBySlug(slug, on: req.db) else {
            throw Abort(.notFound)
        }

        let payload = try req.content.decode(CreateSongPayload.self)

        let existingArtist = try await band.$artists.query(on: req.db)
            .filter(\.$name, .custom("ILIKE"), payload.artistName)
            .first() 

        let artist: Artist
        if let existingArtist {
            artist = existingArtist
        } else {
            artist = Artist(name: payload.artistName, bandID: try band.requireID())
            try await artist.save(on: req.db)
        }

        let song = Song(title: payload.songTitle, artistID: try artist.requireID(), bandID: try band.requireID())
        try await song.save(on: req.db)

        return song
    }
}

struct CreateSongPayload: Content {
    var songTitle: String
    var artistName: String

    mutating func afterDecode() throws {
        let artistName = artistName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !artistName.isEmpty else {
            throw Abort(.badRequest, reason: "artist_name is required")
        }
        self.artistName = artistName

        let songTitle = songTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !songTitle.isEmpty else {
            throw Abort(.badRequest, reason: "song_title is required")
        }
        self.songTitle = songTitle
    }
}
