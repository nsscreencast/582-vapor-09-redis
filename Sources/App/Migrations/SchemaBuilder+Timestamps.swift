import Fluent

extension SchemaBuilder {
    func timestamps() -> Self {
        self
            .field("created_at", .datetime, .required, .custom("DEFAULT CURRENT_TIMESTAMP"))
            .field("updated_at", .datetime, .required, .custom("DEFAULT CURRENT_TIMESTAMP"))
    }
}
