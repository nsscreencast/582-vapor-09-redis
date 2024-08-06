import Fluent
import Redis
import Vapor

func routes(_ app: Application) throws {
    app.middleware.use(CountRequestMiddleware())

    try app.register(collection: BandsController())
    try app.register(collection: UsersController())
}

struct CountRequestMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let path = request.url.path
        let key = RedisKey("request:\(path)")

        let count = try await request.redis.increment(key).get()
        print("Count for \(key) is now \(count)")

        return try await next.respond(to: request)
    }
}
