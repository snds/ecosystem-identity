//! The named pipe on a real Windows kernel (the Windows CI runner): both
//! ends in this test process, so the peer each side sees is this test
//! binary, by process id, user, image path and hash.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ecosystem_identity::Error;
use ecosystem_identity::handshake::verify::{AllowedBinary, ProcessIdentityVerifier};
use ecosystem_identity::handshake::windows::{NamedPipeTransport, PIPE_PREFIX, pipe_name_for};
use ecosystem_identity::handshake::wire::MAX_FRAME;
use ecosystem_identity::handshake::{PeerChannel, PeerIdentity, PeerTransport, PeerVerifier};

fn fresh() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let name = pipe_name_for(&dir.path().join("identity"));
    (dir, name)
}

fn me(sha256: Option<[u8; 32]>) -> AllowedBinary {
    let exe = std::env::current_exe().unwrap();
    AllowedBinary {
        app: "mailbird".into(),
        sha256,
        path: exe,
    }
}

fn this_binary() -> ProcessIdentityVerifier {
    let exe = std::env::current_exe().unwrap();
    ProcessIdentityVerifier::new(vec![me(Some(
        ProcessIdentityVerifier::hash_of(&exe).unwrap(),
    ))])
}

fn same_file(a: &Path, b: &Path) -> bool {
    let a = a.canonicalize().unwrap_or_else(|_| a.to_path_buf());
    let b = b.canonicalize().unwrap_or_else(|_| b.to_path_buf());
    a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
}

/// What the pipe says about the process on the other end.
fn peer_of(ch: &impl PeerChannel) -> (u32, Option<String>, Option<PathBuf>) {
    match ch.peer() {
        PeerIdentity::Windows { pid, sid, exe } => (pid, sid, exe),
        other => panic!("a pipe peer is a Windows peer, got {other:?}"),
    }
}

#[test]
fn the_server_reads_the_clients_pid_and_image_and_both_sides_trust_this_binary() {
    let (_dir, name) = fresh();
    assert!(name.starts_with(PIPE_PREFIX));
    let server = NamedPipeTransport::at(&name);
    server.listen().unwrap();
    let verifier = this_binary();
    let client_name = name.clone();
    let client = std::thread::spawn(move || {
        let mut ch = NamedPipeTransport::at(&client_name)
            .connect(Duration::from_secs(5))
            .unwrap();
        // The client sees the server: this process.
        let seen = peer_of(&ch);
        assert_eq!(this_binary().verify(&ch.peer()).unwrap().app, "mailbird");
        ch.send(b"hello").unwrap();
        let answer = ch.recv(Duration::from_secs(5)).unwrap();
        ch.send(&vec![7u8; MAX_FRAME]).unwrap();
        assert_eq!(ch.recv(Duration::from_secs(5)).unwrap(), b"got it");
        (answer, seen)
    });
    let mut ch = server.accept(Duration::from_secs(5)).unwrap();
    let (pid, sid, exe) = peer_of(&ch);
    assert_eq!(pid, std::process::id(), "the client's process id");
    assert!(
        sid.as_deref().is_some_and(|s| s.starts_with("S-1-")),
        "{sid:?}"
    );
    let exe = exe.expect("the client's image path");
    assert!(
        same_file(&exe, &std::env::current_exe().unwrap()),
        "{exe:?} is this test binary"
    );
    assert_eq!(verifier.verify(&ch.peer()).unwrap().app, "mailbird");
    assert_eq!(ch.recv(Duration::from_secs(5)).unwrap(), b"hello");
    ch.send(b"ready").unwrap();
    // The largest frame the channel allows arrives whole.
    assert_eq!(ch.recv(Duration::from_secs(5)).unwrap().len(), MAX_FRAME);
    ch.send(b"got it").unwrap();
    let (answer, (server_pid, server_sid, _)) = client.join().unwrap();
    assert_eq!(answer, b"ready");
    assert_eq!(server_pid, std::process::id(), "the server's process id");
    assert_eq!(server_sid, sid, "both ends run as the same user");
}

#[test]
fn the_wrong_image_the_wrong_hash_or_another_user_is_refused_on_a_real_pipe() {
    let (_dir, name) = fresh();
    let server = NamedPipeTransport::at(&name);
    server.listen().unwrap();
    let n = name.clone();
    let client = std::thread::spawn(move || {
        let ch = NamedPipeTransport::at(&n)
            .connect(Duration::from_secs(5))
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(ch);
    });
    let ch = server.accept(Duration::from_secs(5)).unwrap();
    let mut wrong_path = me(None);
    wrong_path.path = wrong_path.path.with_file_name("mailbird.exe");
    for (allowed, why) in [
        (me(Some([0; 32])), "isn't the binary"),
        (wrong_path, "isn't an installed"),
    ] {
        match ProcessIdentityVerifier::new(vec![allowed]).verify(&ch.peer()) {
            Err(Error::PeerUntrusted(m)) => assert!(m.contains(why), "{m}"),
            other => panic!("not refused: {other:?}"),
        }
    }
    // The same process as another user would be: refused by user first.
    let (pid, _, exe) = peer_of(&ch);
    let other_user = PeerIdentity::Windows {
        pid,
        sid: Some("S-1-5-18".into()),
        exe,
    };
    assert!(matches!(
        this_binary().verify(&other_user),
        Err(Error::PeerUntrusted(m)) if m.contains("another user")
    ));
    client.join().unwrap();
}

#[test]
fn a_second_listener_on_a_held_name_is_refused() {
    let (_dir, name) = fresh();
    let first = NamedPipeTransport::at(&name);
    first.listen().unwrap();
    let second = NamedPipeTransport::at(&name);
    let err = second.listen().unwrap_err();
    assert!(err.to_string().contains("already holds"), "{err}");
    // Once the first goes, the name is free again.
    drop(first);
    NamedPipeTransport::at(&name).listen().unwrap();
}

#[test]
fn accept_times_out_and_a_later_client_still_gets_through() {
    let (_dir, name) = fresh();
    let server = NamedPipeTransport::at(&name);
    let started = Instant::now();
    assert!(matches!(
        server.accept(Duration::from_millis(100)),
        Err(Error::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
    let n = name.clone();
    let client = std::thread::spawn(move || {
        let mut ch = NamedPipeTransport::at(&n)
            .connect(Duration::from_secs(5))
            .unwrap();
        ch.send(b"late").unwrap();
        // Stays until the server has read it.
        let _ = ch.recv(Duration::from_secs(5));
    });
    let mut got = None;
    for _ in 0..50 {
        match server.accept(Duration::from_millis(100)) {
            Ok(mut ch) => {
                got = Some(ch.recv(Duration::from_secs(5)).unwrap());
                ch.send(b"ok").unwrap();
                break;
            }
            Err(Error::Timeout) => {}
            Err(e) => panic!("{e}"),
        }
    }
    client.join().unwrap();
    assert_eq!(got.as_deref(), Some(&b"late"[..]));
}

#[test]
fn two_clients_one_after_another_are_both_served() {
    let (_dir, name) = fresh();
    let server = NamedPipeTransport::at(&name);
    server.listen().unwrap();
    let n = name.clone();
    let clients = std::thread::spawn(move || {
        for i in 0u8..2 {
            let mut ch = NamedPipeTransport::at(&n)
                .connect(Duration::from_secs(5))
                .unwrap();
            ch.send(&[i]).unwrap();
            assert_eq!(ch.recv(Duration::from_secs(5)).unwrap(), [i + 10]);
        }
    });
    for _ in 0..2 {
        let mut ch = server.accept(Duration::from_secs(5)).unwrap();
        let got = ch.recv(Duration::from_secs(5)).unwrap();
        ch.send(&[got[0] + 10]).unwrap();
    }
    clients.join().unwrap();
}

#[test]
fn nobody_listening_fails_fast_and_a_gone_peer_or_silence_is_reported() {
    let (_dir, name) = fresh();
    let started = Instant::now();
    assert!(matches!(
        NamedPipeTransport::at(&name).connect(Duration::from_secs(10)),
        Err(Error::Handshake(m)) if m.contains("no ecosystem app is listening")
    ));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "a missing app is reported at once, not after the timeout"
    );

    let server = NamedPipeTransport::at(&name);
    server.listen().unwrap();
    let n = name.clone();
    let client = std::thread::spawn(move || {
        let mut ch = NamedPipeTransport::at(&n)
            .connect(Duration::from_secs(5))
            .unwrap();
        // Silence first: the server's recv times out.
        std::thread::sleep(Duration::from_millis(400));
        // A frame over the limit cannot be sent.
        assert!(ch.send(&vec![0u8; MAX_FRAME + 1]).is_err());
        drop(ch);
    });
    let mut ch = server.accept(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        ch.recv(Duration::from_millis(100)),
        Err(Error::Timeout)
    ));
    client.join().unwrap();
    assert!(matches!(
        ch.recv(Duration::from_secs(5)),
        Err(Error::Handshake(_))
    ));
}
