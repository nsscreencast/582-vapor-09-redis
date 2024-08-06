import NIOSSL
import Fluent
import FluentPostgresDriver
import JWT
import Redis
import Vapor

private enum AppError: Error {
    case missingDatabaseCredentials
    case missingJWTSigningSecret
    case missingRedisCredentials
}

// configures your application
public func configure(_ app: Application) async throws {
    // uncomment to serve files from /Public folder
    // app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))

    try await configureDatabase(app)
    try configureRedis(app)

    guard let signingSecret = Environment.get("JWT_SIGNING_SECRET") else {
        throw AppError.missingJWTSigningSecret
    }
    await app.jwt.keys.add(hmac: HMACKey(from: signingSecret), digestAlgorithm: .sha256)

    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dateDecodingStrategy = .iso8601

    let encoder = JSONEncoder()
    encoder.keyEncodingStrategy = .convertToSnakeCase
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = .prettyPrinted

    ContentConfiguration.global.use(decoder: decoder, for: .json)
    ContentConfiguration.global.use(encoder: encoder, for: .json)
}

private func configureDatabase(_ app: Application) async throws {
    guard
        let dbUser = Environment.get("DATABASE_USERNAME"),
        let dbPass = Environment.get("DATABASE_PASSWORD"),
        let dbName = Environment.get("DATABASE_NAME")
    else {
        throw AppError.missingDatabaseCredentials
    }

    app.databases.use(DatabaseConfigurationFactory.postgres(configuration: .init(
        hostname: Environment.get("DATABASE_HOST") ?? "localhost",
        port: Environment.get("DATABASE_PORT").flatMap(Int.init(_:)) ?? SQLPostgresConfiguration.ianaPortNumber,
        username: dbUser,
        password: dbPass,
        database: dbName,
        tls: .prefer(try .init(configuration: .clientDefault)))
    ), as: .psql)

    app.migrations.add(CreateBands())
    app.migrations.add(CreateSongs())
    app.migrations.add(CreateArtists())
    app.migrations.add(CreateUsers())

    // register routes
    try routes(app)

}
private func configureRedis(_ app: Application) throws {
    let host = Environment.get("REDIS_HOST") ?? "localhost"

    guard
       let port = Int(Environment.get("REDIS_PORT") ?? "6379"),
       let pass = Environment.get("REDIS_PASSWORD") else {
           throw AppError.missingRedisCredentials
       }

    let config = try RedisConfiguration(
        hostname: host,
        port: port,
        password: pass
    )

    app.redis.configuration = config
}
