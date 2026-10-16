//! JSON Schema for every record (spec §9), so an app in another language can
//! check its reading of the format. The files under `schema/` are generated
//! from these types; the conformance suite fails when they drift.

use schemars::{JsonSchema, Schema, SchemaGenerator};

use crate::handshake::wire::Message;
use crate::records::{Aad, Consent, Device, KeyEnvelope, Manifest, Persona, Profile};
use crate::store::Head;

/// Every schema the crate ships: file stem and schema. The records, the
/// envelope's associated data, the head a device remembers, and the
/// handshake's wire messages.
pub fn schemas() -> Vec<(&'static str, Schema)> {
    fn one<T: JsonSchema>(name: &'static str) -> (&'static str, Schema) {
        (name, SchemaGenerator::default().into_root_schema_for::<T>())
    }
    vec![
        one::<Profile>("profile"),
        one::<Persona>("persona"),
        one::<Device>("device"),
        one::<KeyEnvelope>("key-envelope"),
        one::<Consent>("consent"),
        one::<Manifest>("manifest"),
        one::<Aad>("aad"),
        one::<Head>("head"),
        one::<Message>("handshake-message"),
    ]
}

/// A schema as the file under `schema/` holds it: pretty JSON, one trailing newline.
pub fn to_json(schema: &Schema) -> String {
    let mut text = serde_json::to_string_pretty(schema.as_value()).unwrap_or_default();
    text.push('\n');
    text
}
