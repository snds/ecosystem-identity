//! The JSON Schema files under `schema/` must match the types. Regenerate
//! with `UPDATE_SCHEMAS=1 cargo test -p ecosystem-identity --test schema`.

use std::path::Path;

use ecosystem_identity::schema::{schemas, to_json};

#[test]
fn schema_files_are_fresh() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema");
    let update = std::env::var_os("UPDATE_SCHEMAS").is_some();
    let mut stale = Vec::new();
    for (name, schema) in schemas() {
        let path = dir.join(format!("{name}.schema.json"));
        let want = to_json(&schema);
        if update {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &want).unwrap();
            continue;
        }
        let have = std::fs::read_to_string(&path).unwrap_or_default();
        if have != want {
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "stale schema files: {stale:?}. Run `UPDATE_SCHEMAS=1 cargo test -p ecosystem-identity --test schema` and commit."
    );
    let on_disk: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    for file in on_disk {
        let stem = file.trim_end_matches(".schema.json");
        assert!(
            schemas().iter().any(|(n, _)| *n == stem),
            "{file} has no record behind it; remove it"
        );
    }
}

#[test]
fn schemas_say_what_the_records_hold() {
    let all = schemas();
    let text = |n: &str| to_json(&all.iter().find(|(name, _)| *name == n).unwrap().1);
    let envelope = text("key-envelope");
    for field in [
        "key_id",
        "wrapped_by",
        "alg",
        "aad",
        "nonce",
        "ciphertext",
        "purpose",
        "created_at",
        "sig",
    ] {
        assert!(
            envelope.contains(&format!("\"{field}\"")),
            "key-envelope schema lacks {field}"
        );
    }
    assert!(envelope.contains("xchacha20poly1305") && envelope.contains("hpke-x25519-mlkem768"));
    assert!(text("persona").contains("x25519-mlkem768"));
    assert!(
        text("profile").contains("additionalProperties"),
        "unknown fields are allowed by the schema"
    );
    assert!(text("aad").contains("\"persona_id\""));
}
