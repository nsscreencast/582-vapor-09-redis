import Vapor
import Fluent

struct BandsController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let band = routes.grouped("band").grouped(":slug")
        
        band.get(use: show)
        try band.register(collection: SongsController())
    }

    @Sendable
    func show(req: Request) async throws -> Band {
        let slug = try req.parameters.require("slug")
        guard let band = try await Band.findBySlug(slug, on: req.db) else {
            throw Abort(.notFound)
        }

        return band
    }
}

