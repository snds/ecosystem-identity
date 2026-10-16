//! The conformance suite (spec §9). Every app that embeds the crate runs it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ciborium::Value;
use ecosystem_identity::attach::signing_key;
use ecosystem_identity::ed25519_dalek::SigningKey;
use ecosystem_identity::kdf::{Argon2Params, FLOOR_DESKTOP, FLOOR_TEST, stretch};
use ecosystem_identity::kem::{DEFAULT_KEM, KemAlg, kem};
use ecosystem_identity::keys::{self, DeviceUnlockKey, SymmetricKey};
use ecosystem_identity::keystore::DeviceKeystore;
use ecosystem_identity::records::{Aad, EnrolledBy, ManifestEntry, RECORD_V, Tombstone, WrapAlg};
use ecosystem_identity::store::{Contents, Probe};
use ecosystem_identity::{
    AccountCredentials, AppDataKey, Attach, Consent, CrownJewelKey, Device, Error, FileKeystore,
    Id, Identity, Irk, KeyEnvelope, KeyRef, KeyRefKind, LocalStubAuth, Manifest, Persona,
    PersonaKey, PersonaKind, Platform, Profile, Purpose, Record, RecoveryKit, RecoveryState, Store,
    Timestamp,
};
use tempfile::TempDir;

const APP: &str = "test-app";

struct Box_ {
    _dir: TempDir,
    root: PathBuf,
    keystore: FileKeystore,
}

fn device(name: &str) -> Box_ {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("identity");
    let keystore =
        FileKeystore::open_or_create(&dir.path().join(format!("{name}.device-key.cbor"))).unwrap();
    Box_ {
        _dir: dir,
        root,
        keystore,
    }
}

fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn restore(root: &Path, snapshot: &BTreeMap<String, Vec<u8>>) {
    std::fs::remove_dir_all(root).unwrap();
    for (path, bytes) in snapshot {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, bytes).unwrap();
    }
}

fn test_isk() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn sample_profile(isk: &SigningKey) -> Profile {
    let mut p = Profile {
        v: RECORD_V,
        profile_id: Id::new(),
        created_at: Timestamp(1_760_000_000),
        recovery: RecoveryState::Created,
        manager: Some("lockdown".into()),
        format_v: 1,
        isk_pub: isk.verifying_key().to_bytes(),
        kdf: FLOOR_DESKTOP,
        extra: Default::default(),
        sig: Vec::new(),
    };
    p.sign(isk).unwrap();
    p
}

/// Builds a store by hand, the way a different implementation would, and
/// returns what a test needs to open it. `extra` goes on the profile.
fn hand_built_store(
    root: &Path,
    keystore: &dyn DeviceKeystore,
    kdf: Argon2Params,
    extra: Vec<(&str, Value)>,
) -> (Irk, Id) {
    let irk = Irk::generate().unwrap();
    let isk = signing_key(&irk).unwrap();
    let profile_id = Id::new();
    let irk_id = Id::new();
    let mut profile = Profile {
        v: RECORD_V,
        profile_id,
        created_at: Timestamp::now(),
        recovery: RecoveryState::None,
        manager: None,
        format_v: 1,
        isk_pub: isk.verifying_key().to_bytes(),
        kdf,
        extra: extra.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        sig: Vec::new(),
    };
    profile.sign(&isk).unwrap();
    let mut device = Device {
        v: RECORD_V,
        device_id: keystore.device_id(),
        name: "Hand-built".into(),
        platform: keystore.platform(),
        attestation: None,
        device_pub: keystore.device_pub(),
        kem_pub: keystore.kem_pub(),
        enrolled_at: Timestamp::now(),
        enrolled_by: EnrolledBy::Creator,
        revoked_at: None,
        extra: Default::default(),
        sig: Vec::new(),
    };
    device.sign(&isk).unwrap();
    let unlock = keystore.unlock().unwrap();
    let mut wrap = keys::wrap(
        irk.expose(),
        &unlock,
        KeyRef::new(KeyRefKind::Device, keystore.device_id()),
        &keys::aad(profile_id, None, irk_id, Purpose::Irk),
    )
    .unwrap();
    wrap.sign(&isk).unwrap();
    let mut contents = Contents {
        profile: Some(profile),
        ..Default::default()
    };
    contents.devices.insert(device.device_id, device);
    contents.put_envelope(wrap);
    let store = Store::at(root);
    store.init().unwrap();
    store.write(&contents, &isk, keystore.device_id()).unwrap();
    (irk, profile_id)
}

#[test]
fn every_record_round_trips_and_verifies() {
    let isk = test_isk();
    let other = SigningKey::from_bytes(&[43u8; 32]);
    let profile = sample_profile(&isk);
    let bytes = profile.to_bytes().unwrap();
    let back = Profile::from_bytes(&bytes).unwrap();
    assert_eq!(back, profile);
    back.verify(&isk.verifying_key()).unwrap();
    assert!(matches!(
        back.verify(&other.verifying_key()),
        Err(Error::BadSignature(_))
    ));
    assert_eq!(
        back.to_bytes().unwrap(),
        bytes,
        "a rewrite is byte-identical"
    );

    let (_, kem_pub) = kem(DEFAULT_KEM).keypair([1u8; 32]).unwrap();
    let mut persona = Persona {
        v: RECORD_V,
        persona_id: Id::new(),
        label: "Work".into(),
        kind: PersonaKind::Work,
        created_by_app: APP.into(),
        identity_key_ref: KeyRef::new(KeyRefKind::Irk, Id::new()),
        kem_pub,
        color: Some("#0a84ff".into()),
        extra: Default::default(),
        sig: Vec::new(),
    };
    persona.sign(&isk).unwrap();
    let back = Persona::from_bytes(&persona.to_bytes().unwrap()).unwrap();
    assert_eq!(back, persona);
    back.verify(&isk.verifying_key()).unwrap();
    assert_eq!(back.kem_pub.alg, KemAlg::X25519MlKem768);

    let (_, x_pub) = kem(KemAlg::X25519).keypair([2u8; 32]).unwrap();
    let mut device = Device {
        v: RECORD_V,
        device_id: Id::new(),
        name: "Laptop".into(),
        platform: Platform::Linux,
        attestation: Some(vec![1, 2, 3]),
        device_pub: [7u8; 32],
        kem_pub: x_pub,
        enrolled_at: Timestamp(1),
        enrolled_by: EnrolledBy::Device { id: Id::new() },
        revoked_at: Some(Timestamp(2)),
        extra: Default::default(),
        sig: Vec::new(),
    };
    device.sign(&isk).unwrap();
    let back = Device::from_bytes(&device.to_bytes().unwrap()).unwrap();
    assert_eq!(back, device);
    back.verify(&isk.verifying_key()).unwrap();

    let aad = Aad {
        profile_id: profile.profile_id,
        persona_id: Some(persona.persona_id),
        key_id: Id::new(),
        purpose: Purpose::AppData,
        app: APP.into(),
        v: RECORD_V,
    };
    let mut envelope = KeyEnvelope {
        v: RECORD_V,
        key_id: aad.key_id,
        wrapped_by: KeyRef::new(KeyRefKind::Persona, persona.persona_id),
        alg: WrapAlg::XChaCha20Poly1305,
        aad: aad.to_bytes().unwrap(),
        nonce: vec![9; 24],
        ciphertext: vec![8; 48],
        enc: None,
        purpose: Purpose::AppData,
        app: APP.into(),
        created_at: Timestamp(3),
        extra: Default::default(),
        sig: Vec::new(),
    };
    envelope.sign(&isk).unwrap();
    let back = KeyEnvelope::from_bytes(&envelope.to_bytes().unwrap()).unwrap();
    assert_eq!(back, envelope);
    back.verify(&isk.verifying_key()).unwrap();
    assert_eq!(
        back.file_name(),
        format!("{}.persona.{}.cbor", aad.key_id, persona.persona_id)
    );
    let aad_back: Aad = ecosystem_identity::cbor::from_slice(&back.aad).unwrap();
    assert_eq!(aad_back, aad);

    let mut consent = Consent {
        v: RECORD_V,
        bridge: "steam-codes".into(),
        disclosure_version: 2,
        granted_at: Timestamp(4),
        device_id: device.device_id,
        extra: Default::default(),
        sig: Vec::new(),
    };
    consent.sign(&isk).unwrap();
    let back = Consent::from_bytes(&consent.to_bytes().unwrap()).unwrap();
    assert_eq!(back, consent);
    back.verify(&isk.verifying_key()).unwrap();

    let mut manifest = Manifest {
        v: RECORD_V,
        seq: 3,
        prev: vec![5; 32],
        entries: vec![ManifestEntry {
            path: "profile.cbor".into(),
            hash: vec![6; 32],
            version: 1,
        }],
        tombstones: vec![Tombstone {
            path: "envelopes/old.cbor".into(),
            hash: vec![7; 32],
            seq: 2,
            retired_at: Timestamp(4),
        }],
        written_at: Timestamp(5),
        written_by: device.device_id,
        extra: Default::default(),
        sig: Vec::new(),
    };
    manifest.sign(&isk).unwrap();
    let back = Manifest::from_bytes(&manifest.to_bytes().unwrap()).unwrap();
    assert_eq!(back, manifest);
    back.verify(&isk.verifying_key()).unwrap();

    // A record from a later major is refused, with the version in the message.
    let mut future = profile.clone();
    future.v = 2;
    let err = Profile::from_bytes(&future.to_bytes().unwrap()).unwrap_err();
    assert!(
        matches!(
            err,
            Error::RecordTooNew {
                record: "profile",
                found: 2,
                supported: 1
            }
        ),
        "{err}"
    );
}

#[test]
fn a_moved_envelope_does_not_open() {
    let b = device("a");
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    let personal = id.personas().next().unwrap().persona_id;
    let work = id
        .create_persona("Work", PersonaKind::Work)
        .unwrap()
        .persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = id.wrap_app_key(personal, APP, &adk).unwrap();
    assert_eq!(
        id.unwrap_app_key(personal, APP, key_id).unwrap().expose(),
        adk.expose()
    );

    // Same key id, asked for under another persona or purpose: refused, by name.
    assert!(
        matches!(
            id.unwrap_app_key(work, APP, key_id),
            Err(Error::NotFound(_))
        ),
        "the wall: work has no such envelope"
    );
    assert!(matches!(
        id.unwrap_crown_jewel_key(personal, APP, key_id),
        Err(Error::EnvelopeMoved(_))
    ));

    // At the envelope level: the stored aad names personal/app-data; a store
    // that renames the file to work's cannot make it open there.
    let envelope = id.envelopes().find(|e| e.key_id == key_id).unwrap().clone();
    let pk_personal = id.persona_key(personal).unwrap();
    let pk_work = id.persona_key(work).unwrap();
    let profile_id = id.profile().profile_id;
    let moved = keys::app_aad(profile_id, work, key_id, Purpose::AppData, APP);
    let err = keys::unwrap(&envelope, &pk_work, &moved).unwrap_err();
    assert!(matches!(err, Error::EnvelopeMoved(_)), "{err}");
    assert!(
        err.to_string().contains(&personal.to_string()),
        "names where it belongs: {err}"
    );
    let repurposed = keys::aad(profile_id, Some(personal), key_id, Purpose::CrownJewel);
    assert!(matches!(
        keys::unwrap(&envelope, &pk_personal, &repurposed),
        Err(Error::EnvelopeMoved(_))
    ));
    let other_profile = keys::aad(Id::new(), Some(personal), key_id, Purpose::AppData);
    assert!(matches!(
        keys::unwrap(&envelope, &pk_personal, &other_profile),
        Err(Error::EnvelopeMoved(_))
    ));
    // And rewriting the stored aad to match the new place fails the tag.
    let mut forged = envelope.clone();
    forged.aad = moved.to_bytes().unwrap();
    assert!(matches!(
        keys::unwrap(&forged, &pk_work, &moved),
        Err(Error::WrongKey)
    ));
    // The right place still opens.
    assert!(
        keys::unwrap(
            &envelope,
            &pk_personal,
            &keys::app_aad(profile_id, personal, key_id, Purpose::AppData, APP)
        )
        .is_ok()
    );
    assert!(matches!(
        keys::unwrap(
            &envelope,
            &pk_work,
            &keys::app_aad(profile_id, personal, key_id, Purpose::AppData, APP)
        ),
        Err(Error::WrongKey)
    ));
}

#[test]
fn a_tampered_manifest_is_detected() {
    let b = device("a");
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    let head1 = id.head();
    let clean = files(&b.root);
    id.create_persona("Work", PersonaKind::Work).unwrap();
    let head2 = id.head();
    assert_eq!(head2.seq, head1.seq + 1);
    let with_work = files(&b.root);
    drop(id);
    let attach = |remembered| Identity::attach(&b.root, APP, &b.keystore, remembered);

    // 1. A flipped byte in the manifest.
    let manifest = b.root.join("manifest.cbor");
    let mut bytes = std::fs::read(&manifest).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&manifest, &bytes).unwrap();
    let err = attach(None).unwrap_err();
    assert!(
        matches!(err, Error::BadSignature(_) | Error::Decode(_)),
        "{err}"
    );
    restore(&b.root, &with_work);
    assert!(matches!(attach(Some(head2)).unwrap(), Attach::Attached(_)));

    // 2. A record changed under a manifest that still lists its old hash.
    let persona_file = with_work
        .keys()
        .find(|k| k.starts_with("personas/"))
        .unwrap()
        .clone();
    let mut bytes = with_work[&persona_file].clone();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(b.root.join(&persona_file), &bytes).unwrap();
    let err = attach(Some(head2)).unwrap_err();
    assert!(matches!(err, Error::Tampered(_)), "{err}");
    assert!(err.to_string().contains("was changed"), "{err}");
    restore(&b.root, &with_work);

    // 3. A file the manifest does not list.
    std::fs::write(
        b.root
            .join("envelopes")
            .join(format!("{}.peer.{}.cbor", Id::new(), Id::new())),
        b"x",
    )
    .unwrap();
    let err = attach(Some(head2)).unwrap_err();
    assert!(
        matches!(err, Error::Tampered(_)) && err.to_string().contains("isn't in the manifest"),
        "{err}"
    );
    restore(&b.root, &with_work);

    // 4. An older manifest put back over newer files: the unlisted persona
    // gives it away, with or without a remembered head.
    std::fs::write(&manifest, &clean["manifest.cbor"]).unwrap();
    let err = attach(Some(head2)).unwrap_err();
    assert!(
        matches!(err, Error::Tampered(_)) && err.to_string().contains("isn't in the manifest"),
        "{err}"
    );
    assert!(matches!(attach(None).unwrap_err(), Error::Tampered(_)));
    restore(&b.root, &with_work);

    // 5. The whole store rolled back to before the persona existed: only the
    // remembered head catches it, and it does.
    restore(&b.root, &clean);
    let err = attach(Some(head2)).unwrap_err();
    assert!(
        matches!(
            err,
            Error::RolledBack {
                found: 1,
                remembered: 2
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("rolled back"));
    assert!(
        matches!(attach(Some(head1)).unwrap(), Attach::Attached(_)),
        "a device that never saw seq 2 cannot tell"
    );

    // 6. A missing manifest.
    restore(&b.root, &with_work);
    std::fs::remove_file(&manifest).unwrap();
    assert!(matches!(attach(None).unwrap_err(), Error::Tampered(_)));
}

#[test]
fn argon2id_below_the_floor_is_refused() {
    let below = Argon2Params {
        m_cost_kib: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };
    assert!(!below.meets(&FLOOR_DESKTOP));
    assert!(
        !Argon2Params {
            m_cost_kib: 64 * 1024,
            t_cost: 2,
            p_cost: 4
        }
        .meets(&FLOOR_DESKTOP),
        "one parameter short is short"
    );
    assert!(
        Argon2Params {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4
        }
        .meets(&FLOOR_DESKTOP)
    );

    // In this build the floor is FLOOR_TEST (the insecure-test-kdf feature,
    // on only for the crate's own tests). Below it, stretching refuses.
    let weak = Argon2Params {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    assert!(!weak.meets(&FLOOR_TEST));
    let err = stretch(b"code", b"salt-salt-salt", &weak).unwrap_err();
    assert!(matches!(err, Error::KdfBelowFloor(_)), "{err}");
    assert!(err.to_string().contains("weaker than the floor"), "{err}");

    // A whole store whose signed profile carries weak parameters is refused on load.
    let b = device("a");
    hand_built_store(&b.root, &b.keystore, weak, vec![]);
    let err = Identity::attach(&b.root, APP, &b.keystore, None).unwrap_err();
    assert!(matches!(err, Error::KdfBelowFloor(_)), "{err}");

    // And a kit made against such a profile would refuse too.
    let kit = RecoveryKit::generate(Id::new()).unwrap();
    assert!(matches!(kit.kit_key(&weak), Err(Error::KdfBelowFloor(_))));
    assert!(kit.kit_key(&FLOOR_TEST).is_ok());
}

#[test]
fn create_then_attach_on_the_same_root_needs_no_kit() {
    let b = device("a");
    assert!(matches!(
        Identity::attach(&b.root, APP, &b.keystore, None).unwrap(),
        Attach::Nothing
    ));
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    assert_eq!(Store::at(&b.root).probe().unwrap(), Probe::Present);
    assert_eq!(
        std::fs::read_to_string(b.root.join("FORMAT"))
            .unwrap()
            .trim(),
        "ecosystem-identity/1"
    );
    assert_eq!(id.profile().manager, None);
    assert_eq!(id.profile().recovery, RecoveryState::None);
    assert!(id.profile().kdf.meets(&FLOOR_TEST));
    let personas: Vec<_> = id.personas().collect();
    assert_eq!(personas.len(), 1);
    assert_eq!(
        (
            personas[0].kind,
            personas[0].label.as_str(),
            personas[0].created_by_app.as_str()
        ),
        (PersonaKind::Personal, "Personal", APP)
    );
    let personal = personas[0].persona_id;
    assert_eq!(id.devices().count(), 1);
    assert_eq!(
        id.devices().next().unwrap().enrolled_by,
        EnrolledBy::Creator
    );
    let adk = AppDataKey::generate().unwrap();
    let key_id = id.wrap_app_key(personal, APP, &adk).unwrap();
    let cjk = CrownJewelKey::generate().unwrap();
    let cj_id = id.wrap_crown_jewel_key(personal, APP, &cjk).unwrap();
    let head = id.head();
    drop(id);

    // Same device, same root, no kit: the device unlock opens it.
    let Attach::Attached(id) =
        Identity::attach(&b.root, "another-app", &b.keystore, Some(head)).unwrap()
    else {
        panic!("expected to attach")
    };
    assert_eq!(
        id.unwrap_app_key(personal, APP, key_id).unwrap().expose(),
        adk.expose()
    );
    assert_eq!(
        id.unwrap_crown_jewel_key(personal, APP, cj_id)
            .unwrap()
            .expose(),
        cjk.expose()
    );
    assert_eq!(id.head(), head);
    assert_eq!(id.app(), "another-app");
    drop(id);
    let id = Identity::open_or_create(&b.root, APP, "Laptop", &b.keystore, Some(head)).unwrap();
    assert_eq!(
        id.head(),
        head,
        "open_or_create attached rather than creating"
    );
    drop(id);

    // Another device on the same root: readable, not openable.
    let other = FileKeystore::open_or_create(&b._dir.path().join("other.device-key.cbor")).unwrap();
    match Identity::attach(&b.root, APP, &other, None).unwrap() {
        Attach::NotEnrolled { profile } => assert_eq!(profile.recovery, RecoveryState::None),
        other => panic!("expected NotEnrolled, got {other:?}"),
    }
    assert!(matches!(
        Identity::open_or_create(&b.root, APP, "Other", &other, None),
        Err(Error::DeviceNotEnrolled)
    ));
    assert!(
        matches!(
            Identity::create(&b.root, APP, "Other", &other),
            Err(Error::Invalid(_))
        ),
        "no second identity on one root"
    );

    // The receiving key a persona publishes is the one its Persona Key derives.
    let Attach::Attached(id) = Identity::attach(&b.root, APP, &b.keystore, Some(head)).unwrap()
    else {
        panic!()
    };
    let persona = id.personas().next().unwrap().clone();
    let secret = id.persona_kem_secret(personal).unwrap();
    let (ct, ss1) = kem(persona.kem_pub.alg)
        .encapsulate(&persona.kem_pub)
        .unwrap();
    assert_eq!(
        kem(persona.kem_pub.alg)
            .decapsulate(&secret, &ct)
            .unwrap()
            .expose(),
        ss1.expose()
    );
}

#[test]
fn recover_with_the_kit_on_an_empty_root() {
    let a = device("a");
    let mut id = Identity::create(&a.root, APP, "Laptop", &a.keystore).unwrap();
    let personal = id.personas().next().unwrap().persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = id.wrap_app_key(personal, APP, &adk).unwrap();
    let kit = id.create_recovery_kit().unwrap();
    assert_eq!(id.profile().recovery, RecoveryState::Created);
    let mut auth = LocalStubAuth::generate().unwrap();
    id.enable_account_unlock(
        &mut auth,
        "correct horse battery",
        Some(kit.secret_key().expose()),
    )
    .unwrap();
    id.mark_recovery_drilled().unwrap();
    assert_eq!(id.profile().recovery, RecoveryState::Drilled);
    let backup = id.export_backup();
    assert!(
        backup
            .envelopes
            .iter()
            .all(|e| e.wrapped_by.kind != KeyRefKind::Device),
        "device wraps stay on the device"
    );
    assert_eq!(
        backup
            .envelopes
            .iter()
            .filter(|e| e.purpose == Purpose::Irk)
            .count(),
        2,
        "kit and account wraps"
    );
    let backup = ecosystem_identity::Backup::from_bytes(&backup.to_bytes().unwrap()).unwrap();

    // The printed page, typed back in on a brand-new device.
    let typed = RecoveryKit::from_text(
        kit.profile_id(),
        &kit.secret_key_text(),
        &kit.recovery_code_text(),
    )
    .unwrap();
    let b = device("b");
    assert!(Store::at(&b.root).is_empty().unwrap());
    let recovered =
        Identity::recover_with_kit(&b.root, "second-app", "Phone", &b.keystore, &typed, &backup)
            .unwrap();
    assert_eq!(recovered.profile(), id.profile());
    assert_eq!(
        recovered
            .unwrap_app_key(personal, APP, key_id)
            .unwrap()
            .expose(),
        adk.expose()
    );
    assert_eq!(recovered.devices().count(), 2);
    assert_eq!(
        recovered
            .devices()
            .find(|d| d.device_id == b.keystore.device_id())
            .unwrap()
            .enrolled_by,
        EnrolledBy::Kit
    );
    assert_eq!(recovered.head().seq, 1, "a fresh chain on the new root");
    drop(recovered);
    assert!(
        matches!(
            Identity::attach(&b.root, APP, &b.keystore, None).unwrap(),
            Attach::Attached(_)
        ),
        "and it attaches afterwards without the kit"
    );

    // A wrong code is refused; so is a non-empty root.
    let wrong = RecoveryKit::generate(kit.profile_id()).unwrap();
    let c = device("c");
    assert!(matches!(
        Identity::recover_with_kit(&c.root, APP, "Tablet", &c.keystore, &wrong, &backup),
        Err(Error::KitRejected)
    ));
    assert!(matches!(
        Identity::recover_with_kit(&b.root, APP, "Phone", &b.keystore, &typed, &backup),
        Err(Error::Invalid(_))
    ));

    // The account slot: password + Secret Key on yet another device.
    let d = device("d");
    let creds = AccountCredentials {
        auth: &mut auth,
        password: "correct horse battery",
        secret_key: Some(kit.secret_key().expose()),
    };
    let via_account =
        Identity::recover_with_account(&d.root, APP, "Desk", &d.keystore, creds, &backup).unwrap();
    assert_eq!(
        via_account
            .unwrap_app_key(personal, APP, key_id)
            .unwrap()
            .expose(),
        adk.expose()
    );
    let e = device("e");
    let wrong_pw = AccountCredentials {
        auth: &mut auth,
        password: "wrong horse battery",
        secret_key: Some(kit.secret_key().expose()),
    };
    assert!(matches!(
        Identity::recover_with_account(&e.root, APP, "Desk", &e.keystore, wrong_pw, &backup),
        Err(Error::WrongKey)
    ));
    let no_sk = AccountCredentials {
        auth: &mut auth,
        password: "correct horse battery",
        secret_key: None,
    };
    assert!(
        matches!(
            Identity::recover_with_account(&e.root, APP, "Desk", &e.keystore, no_sk, &backup),
            Err(Error::WrongKey)
        ),
        "the Secret Key is half of the key"
    );
}

#[test]
fn adopt_sets_manager_and_nothing_else() {
    let b = device("a");
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    let personal = id.personas().next().unwrap().persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = id.wrap_app_key(personal, APP, &adk).unwrap();
    id.create_recovery_kit().unwrap();
    let before = files(&b.root);
    let profile_before = id.profile().clone();
    drop(id);

    // Lockdown attaches on the same device and adopts.
    let Attach::Attached(mut lockdown) =
        Identity::attach(&b.root, "lockdown", &b.keystore, None).unwrap()
    else {
        panic!()
    };
    lockdown.adopt("lockdown").unwrap();
    let after = files(&b.root);
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "no file appeared or vanished"
    );
    for (path, bytes) in &before {
        if path == "profile.cbor" || path == "manifest.cbor" {
            continue;
        }
        assert_eq!(&after[path], bytes, "{path} changed byte for byte");
    }
    let profile_after = Profile::from_bytes(&after["profile.cbor"]).unwrap();
    assert_eq!(profile_after.manager.as_deref(), Some("lockdown"));
    let mut normalized = profile_after.clone();
    normalized.manager = None;
    normalized.sig = Vec::new();
    let mut expected = profile_before.clone();
    expected.sig = Vec::new();
    assert_eq!(
        normalized, expected,
        "only manager (and so the signature) changed"
    );
    assert_eq!(
        lockdown
            .unwrap_app_key(personal, APP, key_id)
            .unwrap()
            .expose(),
        adk.expose(),
        "nothing was re-encrypted"
    );
    drop(lockdown);

    // Other apps keep reading and writing their own keys; the profile is the manager's.
    let Attach::Attached(mut mail) = Identity::attach(&b.root, APP, &b.keystore, None).unwrap()
    else {
        panic!()
    };
    assert_eq!(mail.profile().manager.as_deref(), Some("lockdown"));
    let adk2 = AppDataKey::generate().unwrap();
    let key2 = mail.wrap_app_key(personal, APP, &adk2).unwrap();
    assert_eq!(
        mail.unwrap_app_key(personal, APP, key2).unwrap().expose(),
        adk2.expose()
    );
    let err = mail.adopt(APP).unwrap_err();
    assert!(err.to_string().contains("managed by lockdown"), "{err}");
    assert!(mail.unlink().is_err());
    drop(mail);

    // Unlinking sets manager back to none.
    let Attach::Attached(mut lockdown) =
        Identity::attach(&b.root, "lockdown", &b.keystore, None).unwrap()
    else {
        panic!()
    };
    lockdown.unlink().unwrap();
    assert_eq!(lockdown.profile().manager, None);
}

#[test]
fn unknown_fields_survive_a_rewrite() {
    // At the record level: a newer writer's field comes back out.
    let isk = test_isk();
    let mut profile = sample_profile(&isk);
    profile
        .extra
        .insert("future_field".into(), Value::Text("kept".into()));
    profile.extra.insert(
        "future_list".into(),
        Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![2, 3])]),
    );
    profile.sign(&isk).unwrap();
    let bytes = profile.to_bytes().unwrap();
    let mut read = Profile::from_bytes(&bytes).unwrap();
    read.verify(&isk.verifying_key()).unwrap();
    assert_eq!(
        read.extra.get("future_field"),
        Some(&Value::Text("kept".into()))
    );
    read.recovery = RecoveryState::Drilled;
    read.sign(&isk).unwrap();
    let rewritten: Value = ecosystem_identity::cbor::from_slice(&read.to_bytes().unwrap()).unwrap();
    let Value::Map(entries) = rewritten else {
        panic!()
    };
    assert!(
        entries
            .iter()
            .any(|(k, v)| k == &Value::Text("future_field".into())
                && v == &Value::Text("kept".into()))
    );
    assert!(
        entries
            .iter()
            .any(|(k, _)| k == &Value::Text("future_list".into()))
    );

    // Through the store: a hand-built profile with a field this crate does
    // not know, adopted (which rewrites and re-signs the profile), read back.
    let b = device("a");
    hand_built_store(
        &b.root,
        &b.keystore,
        FLOOR_TEST,
        vec![("future_field", Value::Text("kept".into()))],
    );
    let Attach::Attached(mut id) =
        Identity::attach(&b.root, "lockdown", &b.keystore, None).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        id.profile().extra.get("future_field"),
        Some(&Value::Text("kept".into()))
    );
    id.adopt("lockdown").unwrap();
    id.create_persona("Work", PersonaKind::Work).unwrap();
    drop(id);
    let Attach::Attached(id) = Identity::attach(&b.root, APP, &b.keystore, None).unwrap() else {
        panic!()
    };
    assert_eq!(id.profile().manager.as_deref(), Some("lockdown"));
    assert_eq!(
        id.profile().extra.get("future_field"),
        Some(&Value::Text("kept".into())),
        "survived adopt"
    );
}

#[test]
fn a_newer_format_major_is_refused_with_a_clear_error() {
    let b = device("a");
    Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    std::fs::write(b.root.join("FORMAT"), "ecosystem-identity/2\n").unwrap();
    let err = Identity::attach(&b.root, APP, &b.keystore, None).unwrap_err();
    assert!(
        matches!(
            err,
            Error::FormatTooNew {
                found: 2,
                supported: 1
            }
        ),
        "{err}"
    );
    assert_eq!(
        err.to_string(),
        "this identity store uses format 2, newer than this app understands (format 1); update the app that created it"
    );
    assert!(matches!(
        Store::at(&b.root).probe(),
        Err(Error::FormatTooNew { .. })
    ));

    std::fs::write(b.root.join("FORMAT"), "something-else/1\n").unwrap();
    let err = Identity::attach(&b.root, APP, &b.keystore, None).unwrap_err();
    assert!(matches!(err, Error::FormatUnknown(_)), "{err}");
    assert!(
        err.to_string()
            .contains("isn't an ecosystem identity store")
    );

    std::fs::write(b.root.join("FORMAT"), "ecosystem-identity/1\n").unwrap();
    assert!(matches!(
        Identity::attach(&b.root, APP, &b.keystore, None).unwrap(),
        Attach::Attached(_)
    ));
}

#[test]
fn consents_and_refresh() {
    let b = device("a");
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    let consent = id.record_consent("steam-codes", 2).unwrap();
    assert_eq!(consent.file_name(), "steam-codes.2.cbor");
    assert!(b.root.join("consents/steam-codes.2.cbor").exists());
    assert!(id.record_consent("../etc", 1).is_err());
    let head = id.head();
    // A second app writes on the same device; the first sees it on refresh.
    let Attach::Attached(mut other) =
        Identity::attach(&b.root, "other", &b.keystore, Some(head)).unwrap()
    else {
        panic!()
    };
    other
        .create_persona("Business", PersonaKind::Business)
        .unwrap();
    assert_eq!(id.personas().count(), 1);
    id.refresh().unwrap();
    assert_eq!(id.personas().count(), 2);
    assert_eq!(id.consents().count(), 1);
    assert!(id.head().seq > head.seq);
}

#[test]
fn the_persona_key_is_the_wall() {
    let b = device("a");
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    let personal = id.personas().next().unwrap().persona_id;
    let work = id
        .create_persona("Work", PersonaKind::Work)
        .unwrap()
        .persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = id.wrap_app_key(work, APP, &adk).unwrap();
    let envelope = id.envelopes().find(|e| e.key_id == key_id).unwrap().clone();
    let aad = keys::app_aad(id.profile().profile_id, work, key_id, Purpose::AppData, APP);
    let pk_work = id.persona_key(work).unwrap();
    let pk_personal = id.persona_key(personal).unwrap();
    assert!(keys::unwrap(&envelope, &pk_work, &aad).is_ok());
    assert!(matches!(
        keys::unwrap(&envelope, &pk_personal, &aad),
        Err(Error::WrongKey)
    ));
    assert_ne!(pk_work.expose(), pk_personal.expose());
    // A device unlock key opens the IRK wrap only; it is no persona key.
    let unlock: DeviceUnlockKey = b.keystore.unlock().unwrap();
    assert!(matches!(
        keys::unwrap(&envelope, &unlock, &aad),
        Err(Error::WrongKey)
    ));
    let pk: PersonaKey = PersonaKey::generate().unwrap();
    assert!(matches!(
        keys::unwrap(&envelope, &pk, &aad),
        Err(Error::WrongKey)
    ));
}

#[test]
fn an_envelope_relabelled_to_another_app_does_not_open() {
    let b = device("a");
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    let personal = id.personas().next().unwrap().persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = id.wrap_app_key(personal, APP, &adk).unwrap();
    let other = AppDataKey::generate().unwrap();
    let other_id = id.wrap_app_key(personal, "other-app", &other).unwrap();
    assert_eq!(id.app_keys(personal, APP), vec![key_id]);
    assert_eq!(id.app_keys(personal, "other-app"), vec![other_id]);
    assert!(id.app_keys(personal, "nobody").is_empty());
    assert!(matches!(
        id.wrap_app_key(personal, "", &adk),
        Err(Error::Invalid(_))
    ));

    // Asked for as another app: refused by name, before decryption.
    let err = id
        .unwrap_app_key(personal, "other-app", key_id)
        .unwrap_err();
    assert!(
        matches!(&err, Error::EnvelopeMoved(place) if place.contains(&format!("for app {APP}"))),
        "{err}"
    );
    let envelope = id.envelopes().find(|e| e.key_id == key_id).unwrap().clone();
    assert_eq!(envelope.app, APP);
    let stored: Aad = ecosystem_identity::cbor::from_slice(&envelope.aad).unwrap();
    assert_eq!(stored.app, APP, "the label is inside the associated data");

    // Re-labelled on disk by someone holding the signing key: the aad is
    // rewritten to match and the record re-signed, and it still fails,
    // because the label was sealed into the tag.
    let pk = id.persona_key(personal).unwrap();
    let theirs = keys::app_aad(
        id.profile().profile_id,
        personal,
        key_id,
        Purpose::AppData,
        "other-app",
    );
    let mut relabelled = envelope.clone();
    relabelled.app = "other-app".into();
    relabelled.aad = theirs.to_bytes().unwrap();
    assert!(matches!(
        keys::unwrap(&relabelled, &pk, &theirs),
        Err(Error::WrongKey)
    ));
    assert_eq!(
        keys::unwrap_key::<AppDataKey, _>(
            &envelope,
            &pk,
            &keys::app_aad(
                id.profile().profile_id,
                personal,
                key_id,
                Purpose::AppData,
                APP
            )
        )
        .unwrap()
        .expose(),
        adk.expose()
    );
}

#[test]
fn a_retired_envelope_leaves_a_tombstone_and_cannot_come_back() {
    let b = device("a");
    let mut id = Identity::create(&b.root, APP, "Laptop", &b.keystore).unwrap();
    let personal = id.personas().next().unwrap().persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = id.wrap_app_key(personal, APP, &adk).unwrap();
    let keep = AppDataKey::generate().unwrap();
    let keep_id = id.wrap_app_key(personal, APP, &keep).unwrap();
    let wrapped_by = KeyRef::new(KeyRefKind::Persona, personal);
    let file = format!("envelopes/{key_id}.{wrapped_by}.cbor");
    let backup_copy = std::fs::read(b.root.join(&file)).unwrap();
    let head_before = id.head();

    id.retire_envelope(key_id, wrapped_by).unwrap();
    assert!(!b.root.join(&file).exists(), "the file is gone");
    assert_eq!(id.head().seq, head_before.seq + 1, "the head advanced");
    assert!(matches!(
        id.unwrap_app_key(personal, APP, key_id),
        Err(Error::NotFound(_))
    ));
    assert_eq!(id.app_keys(personal, APP), vec![keep_id]);
    assert!(matches!(
        id.retire_envelope(key_id, wrapped_by),
        Err(Error::NotFound(_))
    ));
    let head = id.head();
    drop(id);

    // The manifest explains the removal.
    let loaded = Store::at(&b.root).load().unwrap();
    assert_eq!(loaded.manifest.tombstones.len(), 1);
    let tomb = &loaded.manifest.tombstones[0];
    assert_eq!(tomb.path, file);
    assert_eq!(tomb.seq, head.seq);
    assert_eq!(
        tomb.hash,
        ecosystem_identity::store::sha256(&backup_copy).to_vec()
    );
    assert!(!loaded.manifest.entries.iter().any(|e| e.path == file));

    // Attach still works; the kept key still opens.
    let Attach::Attached(id) = Identity::attach(&b.root, APP, &b.keystore, Some(head)).unwrap()
    else {
        panic!("attach after retire")
    };
    assert_eq!(
        id.unwrap_app_key(personal, APP, keep_id).unwrap().expose(),
        keep.expose()
    );
    drop(id);

    // A backup copy of the retired file put back is an unlisted file.
    std::fs::write(b.root.join(&file), &backup_copy).unwrap();
    let err = Identity::attach(&b.root, APP, &b.keystore, Some(head)).unwrap_err();
    assert!(
        matches!(&err, Error::Tampered(what) if what.contains("isn't in the manifest")),
        "{err}"
    );
    std::fs::remove_file(b.root.join(&file)).unwrap();

    // Rolling the whole store back to before the retirement is caught too.
    let Attach::Attached(_) = Identity::attach(&b.root, APP, &b.keystore, Some(head)).unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        Identity::attach(
            &b.root,
            APP,
            &b.keystore,
            Some(ecosystem_identity::Head {
                seq: head.seq + 1,
                ..head
            })
        ),
        Err(Error::RolledBack { .. })
    ));
}
