//! Argon2id parameters only ever rise (04-security §4, D26): the head a
//! device remembers carries the last accepted parameters, and a profile
//! below them is refused on attach and on refresh.

use std::time::Duration;

use ecosystem_identity::attach::signing_key;
use ecosystem_identity::kdf::{Argon2Params, FLOOR_TEST, calibrate, calibrate_at_least, floor};
use ecosystem_identity::keystore::DeviceKeystore;
use ecosystem_identity::records::{EnrolledBy, RECORD_V};
use ecosystem_identity::store::Contents;
use ecosystem_identity::{
    Attach, Device, Error, FileKeystore, Head, Id, Identity, Irk, KeyRef, KeyRefKind, Profile,
    Purpose, Record, RecoveryState, Store, SymmetricKey, Timestamp, keys,
};

const APP: &str = "test-app";

fn higher(p: Argon2Params) -> Argon2Params {
    Argon2Params {
        t_cost: p.t_cost + 1,
        ..p
    }
}

fn lower(p: Argon2Params) -> Argon2Params {
    Argon2Params {
        m_cost_kib: p.m_cost_kib / 2,
        ..p
    }
}

#[test]
fn the_head_remembers_the_parameters_and_attach_refuses_a_drop() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("identity");
    let keystore = FileKeystore::open_or_create(&dir.path().join("device-key.cbor")).unwrap();
    let id = Identity::create(&root, APP, "Laptop", &keystore).unwrap();
    let kdf = id.profile().kdf;
    let head = id.head();
    assert_eq!(head.kdf, Some(kdf), "the head carries what was accepted");
    drop(id);

    // Equal: fine.
    assert!(matches!(
        Identity::attach(&root, APP, &keystore, Some(head)).unwrap(),
        Attach::Attached(_)
    ));
    // The profile is higher than what was remembered (a raise): fine.
    let remembered_lower = Head {
        kdf: Some(lower(kdf)),
        ..head
    };
    assert!(matches!(
        Identity::attach(&root, APP, &keystore, Some(remembered_lower)).unwrap(),
        Attach::Attached(_)
    ));
    // An older build remembered no parameters: only the floor applies.
    assert!(matches!(
        Identity::attach(&root, APP, &keystore, Some(Head::new(head.seq, head.hash))).unwrap(),
        Attach::Attached(_)
    ));
    // The profile is lower than what was remembered: refused, by name.
    let remembered_higher = Head {
        kdf: Some(higher(kdf)),
        ..head
    };
    match Identity::attach(&root, APP, &keystore, Some(remembered_higher)) {
        Err(Error::KdfLowered { found, remembered }) => {
            assert_eq!(found, kdf);
            assert_eq!(remembered, higher(kdf));
        }
        other => panic!("expected KdfLowered, got {other:?}"),
    }
    assert!(
        Error::KdfLowered {
            found: kdf,
            remembered: higher(kdf)
        }
        .to_string()
        .contains("only ever rise")
    );
}

/// Builds a store by hand with `kdf`, the way a test needs when it must
/// re-sign the profile later. Returns the root key.
fn hand_built(root: &std::path::Path, keystore: &dyn DeviceKeystore, kdf: Argon2Params) -> Irk {
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
        extra: Default::default(),
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
    let mut wrap = keys::wrap(
        irk.expose(),
        &keystore.unlock().unwrap(),
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
    irk
}

/// Rewrites the profile with `kdf`, signed, as a hostile or careless writer
/// with the signing key could.
fn rewrite_kdf(root: &std::path::Path, irk: &Irk, kdf: Argon2Params, by: Id) {
    let isk = signing_key(irk).unwrap();
    let store = Store::at(root);
    let mut contents = store.load().unwrap().contents;
    let mut profile = contents.profile().unwrap().clone();
    profile.kdf = kdf;
    profile.sign(&isk).unwrap();
    contents.profile = Some(profile);
    store.write(&contents, &isk, by).unwrap();
}

#[test]
fn a_raise_is_accepted_and_a_later_drop_is_refused_on_refresh_and_attach() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("identity");
    let keystore = FileKeystore::open_or_create(&dir.path().join("device-key.cbor")).unwrap();
    let start = higher(FLOOR_TEST);
    let irk = hand_built(&root, &keystore, start);

    let Attach::Attached(mut id) = Identity::attach(&root, APP, &keystore, None).unwrap() else {
        panic!("attach")
    };
    assert_eq!(id.head().kdf, Some(start));

    // Raise: accepted on refresh, and the head moves up with it.
    let raised = higher(start);
    rewrite_kdf(&root, &irk, raised, keystore.device_id());
    id.refresh().unwrap();
    assert_eq!(id.head().kdf, Some(raised));
    assert_eq!(id.profile().kdf, raised);

    // Equal: accepted.
    rewrite_kdf(&root, &irk, raised, keystore.device_id());
    id.refresh().unwrap();

    // Drop back to where it started (still above the floor): refused on
    // refresh by the open identity, and on attach by a device that
    // remembered the raised head. The floor check alone would have let it
    // through.
    rewrite_kdf(&root, &irk, start, keystore.device_id());
    assert!(start.check_floor().is_ok());
    let remembered = id.head();
    assert!(matches!(
        id.refresh(),
        Err(Error::KdfLowered { found, remembered: r }) if found == start && r == raised
    ));
    assert!(matches!(
        Identity::attach(&root, APP, &keystore, Some(remembered)),
        Err(Error::KdfLowered { .. })
    ));
    // Without memory it still opens: the memory is what makes the rule bite.
    assert!(matches!(
        Identity::attach(&root, APP, &keystore, None).unwrap(),
        Attach::Attached(_)
    ));
}

#[test]
fn calibration_only_raises() {
    assert_eq!(floor(), FLOOR_TEST, "tests run at the test floor");
    let quick = calibrate(Duration::ZERO).unwrap();
    assert_eq!(quick, FLOOR_TEST, "no time budget: the floor itself");

    let previous = Argon2Params {
        m_cost_kib: FLOOR_TEST.m_cost_kib * 4,
        t_cost: FLOOR_TEST.t_cost + 2,
        p_cost: FLOOR_TEST.p_cost,
    };
    let next = calibrate_at_least(&previous, Duration::ZERO).unwrap();
    assert!(next.meets(&previous), "{next} is below {previous}");
    assert_eq!(next, previous, "no time budget: exactly the previous set");

    let slower = calibrate_at_least(&previous, Duration::from_millis(1)).unwrap();
    assert!(slower.meets(&previous));
    assert!(slower.t_cost >= previous.t_cost);

    // A previous set below the floor is lifted to the floor, never kept.
    let weak = Argon2Params {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    assert!(
        calibrate_at_least(&weak, Duration::ZERO)
            .unwrap()
            .meets(&FLOOR_TEST)
    );
    assert_eq!(weak.max(&FLOOR_TEST), FLOOR_TEST);
}
