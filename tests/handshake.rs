//! The local handshake (spec §6 step 3) end to end: create on app A,
//! hand over to app B on the same device over the in-memory transport and
//! over a Unix socket, and the refusals (untrusted peer, declined, replay).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ecosystem_identity::ed25519_dalek::VerifyingKey;
use ecosystem_identity::handshake::wire::{HANDSHAKE_V, Message, RefusalReason, Request};
use ecosystem_identity::handshake::{
    AllowAll, AutoConfirm, ChannelTransport, Decline, HandshakeOptions, PeerChannel, PeerTransport,
    Requester, Responder, Sas, Scripted, proof_of_possession,
};
use ecosystem_identity::keystore::DeviceKeystore;
use ecosystem_identity::records::{EnrolledBy, RECORD_V};
use ecosystem_identity::{
    AppDataKey, Attach, Device, Error, FileKeystore, Identity, KeyRefKind, Purpose, Record,
    SymmetricKey, Timestamp,
};
use tempfile::TempDir;

const APP_A: &str = "mailbird";
const APP_B: &str = "lockdown";

struct Bench {
    _dir: TempDir,
    root: PathBuf,
    a: FileKeystore,
    b: FileKeystore,
}

fn new_bench() -> Bench {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("identity");
    let a = FileKeystore::open_or_create(&dir.path().join("a.device-key.cbor")).unwrap();
    let b = FileKeystore::open_or_create(&dir.path().join("b.device-key.cbor")).unwrap();
    Bench {
        _dir: dir,
        root,
        a,
        b,
    }
}

fn options() -> HandshakeOptions {
    HandshakeOptions {
        timeout: Duration::from_secs(10),
        confirm_timeout: Duration::from_secs(10),
    }
}

fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else if path.extension().is_some_and(|e| e == "cbor") || path.ends_with("FORMAT") {
                out.insert(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Runs one handshake with the responder on another thread and the
/// requester on this one. Returns both outcomes.
fn run_handshake<T: PeerTransport + Sync>(
    bench: &Bench,
    a_id: &mut Identity,
    transport: &T,
    responder_verifier: &(dyn ecosystem_identity::PeerVerifier + Sync),
    requester_verifier: &(dyn ecosystem_identity::PeerVerifier + Sync),
    confirm: &(dyn ecosystem_identity::ConfirmNewDevice + Sync),
) -> (
    ecosystem_identity::Result<ecosystem_identity::Enrolled>,
    ecosystem_identity::Result<Identity>,
    Option<Sas>,
) {
    let mut shown = None;
    let (served, requested) = std::thread::scope(|s| {
        let server = s.spawn(move || {
            Responder::new(responder_verifier, confirm, options()).serve_one(a_id, transport)
        });
        let requested = Requester::new(
            APP_B,
            "Laptop (Lockdown)",
            &bench.b,
            requester_verifier,
            options(),
        )
        .run(&bench.root, transport, &mut |sas| shown = Some(sas));
        (server.join().unwrap(), requested)
    });
    (served, requested, shown)
}

#[allow(clippy::too_many_arguments)]
fn assert_enrolled(
    bench: &Bench,
    a_id: &mut Identity,
    head_before: ecosystem_identity::Head,
    served: ecosystem_identity::Result<ecosystem_identity::Enrolled>,
    requested: ecosystem_identity::Result<Identity>,
    shown: Option<Sas>,
    confirm: &AutoConfirm,
    personal: ecosystem_identity::Id,
    key_id: ecosystem_identity::Id,
    adk: &AppDataKey,
) {
    let enrolled = served.unwrap();
    let b_id = requested.unwrap();

    // The code was the same on both sides and is six digits.
    let sas = shown.expect("the requester showed a code");
    assert_eq!(sas, enrolled.sas);
    assert_eq!(Some(sas), confirm.last_sas());
    assert_eq!(sas.digits().len(), 6);
    assert!(sas.value() < 1_000_000);

    // B opens the same persona key and the same app key, without the kit.
    assert_eq!(b_id.app(), APP_B);
    assert_eq!(b_id.device_id(), bench.b.device_id());
    assert_eq!(
        b_id.persona_key(personal).unwrap().expose(),
        a_id.persona_key(personal).unwrap().expose()
    );
    assert_eq!(
        b_id.unwrap_app_key(personal, APP_A, key_id)
            .unwrap()
            .expose(),
        adk.expose()
    );

    // B's record is in the store, signed by the ISK, enrolled by A.
    let b_device = b_id
        .devices()
        .find(|d| d.device_id == bench.b.device_id())
        .expect("B's device record")
        .clone();
    assert_eq!(b_device.name, "Laptop (Lockdown)");
    assert_eq!(
        b_device.enrolled_by,
        EnrolledBy::Device {
            id: bench.a.device_id()
        }
    );
    assert_eq!(b_device.kem_pub, bench.b.kem_pub());
    b_device
        .verify(&VerifyingKey::from_bytes(&b_id.profile().isk_pub).unwrap())
        .unwrap();
    assert_eq!(enrolled.device_id, b_device.device_id);
    assert_eq!(enrolled.app, "allow-all");

    // The manifest chain advanced: A wrote the device, B wrote its wrap.
    assert_eq!(enrolled.head.seq, head_before.seq + 1);
    assert_eq!(a_id.head(), enrolled.head);
    assert_eq!(b_id.head().seq, head_before.seq + 2);
    assert!(b_id.head().kdf.is_some());
    a_id.refresh().unwrap();
    assert_eq!(a_id.head(), b_id.head());

    // Only B's own device wrap of the IRK was stored; the peer envelope
    // travelled and was not kept.
    let irk_wraps: Vec<_> = b_id
        .envelopes()
        .filter(|e| e.purpose == Purpose::Irk)
        .collect();
    assert_eq!(irk_wraps.len(), 2);
    assert!(
        irk_wraps
            .iter()
            .all(|e| e.wrapped_by.kind == KeyRefKind::Device)
    );
    assert!(
        irk_wraps
            .iter()
            .any(|e| e.wrapped_by.id == bench.b.device_id())
    );

    // From now on B attaches the ordinary way.
    let head = b_id.head();
    drop(b_id);
    let Attach::Attached(again) =
        Identity::attach(&bench.root, APP_B, &bench.b, Some(head)).unwrap()
    else {
        panic!("B should attach after the handshake")
    };
    assert_eq!(
        again
            .unwrap_app_key(personal, APP_A, key_id)
            .unwrap()
            .expose(),
        adk.expose()
    );
}

#[test]
fn in_memory_handshake_enrols_the_second_app() {
    let bench = new_bench();
    let mut a_id = Identity::create(&bench.root, APP_A, "Laptop (Mailbird)", &bench.a).unwrap();
    let personal = a_id.personas().next().unwrap().persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = a_id.wrap_app_key(personal, APP_A, &adk).unwrap();
    let head_before = a_id.head();
    assert!(matches!(
        Identity::attach(&bench.root, APP_B, &bench.b, None).unwrap(),
        Attach::NotEnrolled { .. }
    ));

    let transport = ChannelTransport::new();
    let confirm = AutoConfirm::new();
    let (served, requested, shown) = run_handshake(
        &bench, &mut a_id, &transport, &AllowAll, &AllowAll, &confirm,
    );
    assert_enrolled(
        &bench,
        &mut a_id,
        head_before,
        served,
        requested,
        shown,
        &confirm,
        personal,
        key_id,
        &adk,
    );
}

#[test]
fn an_untrusted_peer_is_refused_on_either_side() {
    let bench = new_bench();
    let mut a_id = Identity::create(&bench.root, APP_A, "Laptop (Mailbird)", &bench.a).unwrap();
    let before = files(&bench.root);

    // The running app does not trust the newcomer.
    let transport = ChannelTransport::new();
    let confirm = AutoConfirm::new();
    let (served, requested, shown) = run_handshake(
        &bench,
        &mut a_id,
        &transport,
        &Scripted::refusing("the binary isn't signed by the ecosystem", 1),
        &AllowAll,
        &confirm,
    );
    assert!(matches!(served, Err(Error::PeerUntrusted(_))), "{served:?}");
    assert!(
        matches!(requested, Err(Error::PeerUntrusted(ref r)) if r.contains("isn't signed")),
        "{requested:?}"
    );
    assert!(shown.is_none(), "no code before trust");
    assert!(confirm.last_sas().is_none(), "the person was never asked");

    // The newcomer does not trust the running app.
    let transport = ChannelTransport::new();
    let (served, requested, shown) = run_handshake(
        &bench,
        &mut a_id,
        &transport,
        &AllowAll,
        &Scripted::refusing("unknown process", 1),
        &confirm,
    );
    assert!(
        matches!(requested, Err(Error::PeerUntrusted(_))),
        "{requested:?}"
    );
    assert!(served.is_err());
    assert!(shown.is_none());

    assert_eq!(files(&bench.root), before, "nothing was written");
    assert!(matches!(
        Identity::attach(&bench.root, APP_B, &bench.b, None).unwrap(),
        Attach::NotEnrolled { .. }
    ));
}

#[test]
fn the_person_declines_and_nothing_is_written() {
    let bench = new_bench();
    let mut a_id = Identity::create(&bench.root, APP_A, "Laptop (Mailbird)", &bench.a).unwrap();
    let head_before = a_id.head();
    let before = files(&bench.root);

    let transport = ChannelTransport::new();
    let (served, requested, shown) = run_handshake(
        &bench, &mut a_id, &transport, &AllowAll, &AllowAll, &Decline,
    );
    assert!(matches!(served, Err(Error::Declined)), "{served:?}");
    assert!(matches!(requested, Err(Error::Declined)), "{requested:?}");
    assert!(
        shown.is_some(),
        "the code was shown before the person decided"
    );

    assert_eq!(files(&bench.root), before, "nothing was written");
    assert_eq!(a_id.head(), head_before);
    assert_eq!(a_id.devices().count(), 1);
    assert!(matches!(
        Identity::attach(&bench.root, APP_B, &bench.b, None).unwrap(),
        Attach::NotEnrolled { .. }
    ));
}

/// Drives the requester's side by hand: reads the hello, sends `request`
/// (built by `build`, or replayed as given), and returns what came back.
fn drive_requester<T: PeerTransport>(
    transport: &T,
    request: &mut Option<Request>,
    build: impl FnOnce(&ecosystem_identity::handshake::wire::Hello) -> Request,
) -> Vec<Message> {
    let mut chan = transport.connect(Duration::from_secs(10)).unwrap();
    let Message::Hello(hello) =
        Message::from_bytes(&chan.recv(Duration::from_secs(10)).unwrap()).unwrap()
    else {
        panic!("expected hello")
    };
    let req = request.get_or_insert_with(|| build(&hello)).clone();
    chan.send(&Message::Request(req).to_bytes().unwrap())
        .unwrap();
    let mut got = Vec::new();
    while let Ok(bytes) = chan.recv(Duration::from_secs(10)) {
        let message = Message::from_bytes(&bytes).unwrap();
        let last = matches!(message, Message::Granted(_) | Message::Refused(_));
        got.push(message);
        if last {
            break;
        }
    }
    got
}

#[test]
fn a_replayed_request_is_refused() {
    let bench = new_bench();
    let mut a_id = Identity::create(&bench.root, APP_A, "Laptop (Mailbird)", &bench.a).unwrap();
    let profile_id = a_id.profile().profile_id;
    let transport = ChannelTransport::new();
    let confirm = AutoConfirm::new();
    // One responder across both connections: it is what remembers nonces.
    let mut responder = Responder::new(&AllowAll, &confirm, options());
    let mut request: Option<Request> = None;
    let mut head_after_first = None;

    for round in 0..2 {
        let (served, got) = std::thread::scope(|s| {
            let server = s.spawn(|| responder.serve_one(&mut a_id, &transport));
            let got = drive_requester(&transport, &mut request, |hello| {
                let device = Device {
                    v: RECORD_V,
                    device_id: bench.b.device_id(),
                    name: "Laptop (Lockdown)".into(),
                    platform: bench.b.platform(),
                    attestation: None,
                    device_pub: bench.b.device_pub(),
                    kem_pub: bench.b.kem_pub(),
                    enrolled_at: Timestamp::now(),
                    enrolled_by: EnrolledBy::Device {
                        id: hello.device_id,
                    },
                    revoked_at: None,
                    extra: Default::default(),
                    sig: Vec::new(),
                };
                let nonce = [9u8; 32];
                let pop = proof_of_possession(&bench.b, profile_id, &hello.commit, &nonce, &device)
                    .unwrap();
                Request {
                    v: HANDSHAKE_V,
                    device,
                    nonce,
                    pop,
                }
            });
            (server.join().unwrap(), got)
        });
        if round == 0 {
            // Fresh: the device is enrolled.
            served.unwrap();
            assert!(matches!(
                got.as_slice(),
                [Message::Reveal(_), Message::Granted(_)]
            ));
            head_after_first = Some(a_id.head());
        } else {
            // The very same request on a new connection: refused as a
            // replay before anything else is looked at, and nothing changes.
            assert!(matches!(served, Err(Error::Replayed)), "{served:?}");
            assert!(
                matches!(
                    got.as_slice(),
                    [Message::Refused(r)] if r.reason == RefusalReason::Replayed
                ),
                "{got:?}"
            );
        }
    }
    assert_eq!(
        a_id.devices().count(),
        2,
        "the replay enrolled nothing more"
    );
    assert_eq!(Some(a_id.head()), head_after_first, "nothing was written");
}

#[cfg(unix)]
#[test]
fn unix_socket_handshake_end_to_end() {
    use ecosystem_identity::handshake::unix::UnixSocketTransport;
    use ecosystem_identity::handshake::verify::{AllowedBinary, ProcessIdentityVerifier};
    use std::os::unix::fs::PermissionsExt;

    let bench = new_bench();
    let mut a_id = Identity::create(&bench.root, APP_A, "Laptop (Mailbird)", &bench.a).unwrap();
    let personal = a_id.personas().next().unwrap().persona_id;
    let adk = AppDataKey::generate().unwrap();
    let key_id = a_id.wrap_app_key(personal, APP_A, &adk).unwrap();
    let head_before = a_id.head();

    // Both sides check the peer by process identity: same user, this very
    // binary, by path and hash.
    let exe = std::env::current_exe().unwrap();
    let verifier = ProcessIdentityVerifier::new(vec![AllowedBinary {
        app: "allow-all".into(),
        path: exe.clone(),
        sha256: Some(ProcessIdentityVerifier::hash_of(&exe).unwrap()),
    }]);

    let transport = UnixSocketTransport::for_root(&bench.root);
    assert_eq!(transport.path(), bench.root.join("handshake.sock"));
    transport.listen().unwrap();
    let mode = std::fs::metadata(transport.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the socket is private to the user");

    let confirm = AutoConfirm::new();
    let (served, requested, shown) = run_handshake(
        &bench, &mut a_id, &transport, &verifier, &verifier, &confirm,
    );
    assert_enrolled(
        &bench,
        &mut a_id,
        head_before,
        served,
        requested,
        shown,
        &confirm,
        personal,
        key_id,
        &adk,
    );

    // A peer that is not an installed binary is refused over the socket too.
    let strict = ProcessIdentityVerifier::new(vec![AllowedBinary {
        app: "other".into(),
        path: PathBuf::from("/nonexistent/other-app"),
        sha256: None,
    }]);
    let bench_c = new_bench();
    let mut c_id = Identity::create(&bench_c.root, APP_A, "Laptop", &bench_c.a).unwrap();
    let transport_c = UnixSocketTransport::for_root(&bench_c.root);
    transport_c.listen().unwrap();
    let (served, requested, _) = run_handshake(
        &bench_c,
        &mut c_id,
        &transport_c,
        &strict,
        &verifier,
        &confirm,
    );
    assert!(matches!(served, Err(Error::PeerUntrusted(_))), "{served:?}");
    assert!(
        matches!(requested, Err(Error::PeerUntrusted(_))),
        "{requested:?}"
    );

    // Nobody listening is a clear error, and the socket file goes with the
    // listener.
    let path = transport.path().to_path_buf();
    drop(transport);
    assert!(!path.exists(), "the socket file is removed on drop");
    let gone = UnixSocketTransport::at(&path);
    assert!(matches!(
        gone.connect(Duration::from_secs(1)),
        Err(Error::Handshake(_))
    ));

    // A second listener on the same root is refused while the first lives.
    let second = UnixSocketTransport::for_root(&bench_c.root);
    assert!(matches!(second.listen(), Err(Error::Io(_))));
    drop(second);
    assert!(
        transport_c.path().exists(),
        "the first listener's socket stays"
    );
    drop(transport_c);

    // A requester that never comes times out the responder.
    let quiet = UnixSocketTransport::for_root(&bench_c.root);
    let mut responder = Responder::new(
        &AllowAll,
        &confirm,
        HandshakeOptions {
            timeout: Duration::from_millis(200),
            confirm_timeout: Duration::from_millis(200),
        },
    );
    assert!(matches!(
        responder.serve_one(&mut c_id, &quiet),
        Err(Error::Timeout)
    ));
}
