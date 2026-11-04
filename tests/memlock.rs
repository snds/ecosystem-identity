//! The crate's secret key types on locked pages, through the public API:
//! each one is locked or counted as refused, and each one is still wiped
//! when it is dropped.
//!
//! The wipe is proven by this binary's allocator: while a check is armed,
//! every block handed back to the allocator is searched for the secret's
//! bytes before it is freed, which is the last moment those bytes are
//! readable without undefined behaviour. One test function runs every
//! check, so no other test allocates while one is armed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use ecosystem_identity::ed25519_dalek::SigningKey;
use ecosystem_identity::kem::{self, KemAlg, KemSecretKey};
use ecosystem_identity::keys::{DeviceUnlockKey, KitKey};
use ecosystem_identity::keystore::DeviceKeystore;
use ecosystem_identity::memlock::{self, Locked, PageLock};
use ecosystem_identity::{
    AppDataKey, CrownJewelKey, FileKeystore, Id, Identity, Irk, PersonaKey, RecoveryKit,
    SymmetricKey,
};

const MAX_NEEDLE: usize = 32;

static ARMED: AtomicBool = AtomicBool::new(false);
static NEEDLE: [AtomicU8; MAX_NEEDLE] = [const { AtomicU8::new(0) }; MAX_NEEDLE];
static NEEDLE_LEN: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);
static FOUND: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, searching freed blocks for the armed needle.
struct Watching;

// SAFETY: every call is passed to the system allocator unchanged; the only
// addition reads a block in `dealloc` before it is freed, while it is still
// allocated and `layout.size()` bytes long.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            let len = NEEDLE_LEN.load(Ordering::SeqCst);
            let mut needle = [0u8; MAX_NEEDLE];
            for (n, a) in needle.iter_mut().zip(NEEDLE.iter()).take(len) {
                *n = a.load(Ordering::SeqCst);
            }
            // SAFETY: the block is still allocated and `layout.size()` long.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            FREED.fetch_add(1, Ordering::SeqCst);
            if len > 0 && block.windows(len).any(|w| w == &needle[..len]) {
                FOUND.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: forwarded as is.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// Drops `value` with the allocator searching every freed block for
/// `secret`. Answers (blocks freed, blocks that still held the secret).
fn drop_watching<T>(value: T, secret: &[u8]) -> (usize, usize) {
    assert!(!secret.is_empty() && secret.len() <= MAX_NEEDLE);
    assert!(
        secret.iter().any(|b| *b != 0),
        "a needle of zeros finds nothing"
    );
    for (a, b) in NEEDLE.iter().zip(secret) {
        a.store(*b, Ordering::SeqCst);
    }
    NEEDLE_LEN.store(secret.len(), Ordering::SeqCst);
    FREED.store(0, Ordering::SeqCst);
    FOUND.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    drop(value);
    ARMED.store(false, Ordering::SeqCst);
    (FREED.load(Ordering::SeqCst), FOUND.load(Ordering::SeqCst))
}

fn assert_wiped<T>(what: &str, value: T, secret: &[u8]) {
    let (freed, found) = drop_watching(value, secret);
    assert!(freed > 0, "{what}: dropping it freed its memory");
    assert_eq!(found, 0, "{what}: a freed block still held the secret");
}

#[test]
fn every_secret_type_is_locked_or_counted_and_wiped_on_drop() {
    let before = memlock::report();
    assert!(before.supported, "Linux, macOS and Windows can lock pages");
    assert!(before.page_size >= 4096);

    // The detector works: a plain box is freed with its secret still in it.
    let plain = Box::new([0x5au8; 32]);
    let (freed, found) = drop_watching(plain, &[0x5a; 32]);
    assert!(freed > 0 && found > 0, "the allocator check sees a secret");

    // The typed 256-bit keys.
    let mut unlocked = 0u64;
    macro_rules! check_key {
        ($t:ty) => {{
            let key = <$t>::generate().unwrap();
            unlocked += u64::from(!key.is_locked());
            let secret = *key.expose();
            assert_wiped(stringify!($t), key, &secret);
        }};
    }
    check_key!(Irk);
    check_key!(PersonaKey);
    check_key!(AppDataKey);
    check_key!(CrownJewelKey);
    check_key!(DeviceUnlockKey);
    check_key!(KitKey);

    // A receiving key's seed, both schemes.
    for alg in [KemAlg::X25519, KemAlg::X25519MlKem768] {
        let seed = [0xc3u8; 32];
        let sk = KemSecretKey::from_seed(alg, seed);
        unlocked += u64::from(!sk.is_locked());
        let (_, pk) = kem::kem(alg).keypair(seed).unwrap();
        let (_, shared) = kem::kem(alg).encapsulate(&pk).unwrap();
        unlocked += u64::from(!shared.is_locked());
        let ss = *shared.expose();
        assert_wiped("KemSecretKey", sk, &seed);
        assert_wiped("SharedSecret", shared, &ss);
    }

    // The recovery kit's Secret Key and recovery code.
    let kit = RecoveryKit::generate(Id::new()).unwrap();
    unlocked += u64::from(!kit.is_locked());
    let sk = *kit.secret_key().expose();
    assert_wiped("RecoveryKit", kit, &sk);

    // The Identity Signing Key as an open identity holds it.
    let isk = SigningKey::from_bytes(&[0x77; 32]);
    let held = Locked::new(isk);
    unlocked += u64::from(!held.is_locked());
    assert_eq!(held.to_bytes(), [0x77; 32]);
    assert_wiped("Locked<SigningKey>", held, &[0x77; 32]);

    // The file keystore's seeds.
    let dir = tempfile::tempdir().unwrap();
    let ks = FileKeystore::open_or_create(&dir.path().join("device-key.cbor")).unwrap();
    unlocked += u64::from(!ks.is_locked());
    let unlock = {
        let key = ks.unlock().unwrap();
        *key.expose()
    };
    assert_wiped("FileKeystore", ks, &unlock);

    // An open identity: root key and signing key on locked pages.
    let root = dir.path().join("identity");
    let ks = FileKeystore::open_or_create(&dir.path().join("a.device-key.cbor")).unwrap();
    let identity = Identity::create(&root, "mailbird", "Laptop", &ks).unwrap();
    unlocked += u64::from(!identity.keys_locked());
    drop(identity);

    let after = memlock::report();
    assert!(
        after.refused >= before.refused + unlocked,
        "every secret that isn't locked was counted: {before:?} → {after:?}"
    );
    assert!(
        after.pages_locked_ever > before.pages_locked_ever || after.refused > before.refused,
        "something was locked, or the refusals were counted: {after:?}"
    );
    assert!(
        after.pages_unlocked_ever > before.pages_unlocked_ever || after.refused > before.refused,
        "pages are unlocked again when their last secret goes: {after:?}"
    );

    // A lock the caller holds on its own value, the way an app would lock
    // a secret type of its own beside this crate's.
    let own = Box::new([1u8; 100]);
    let lock = PageLock::of_value(&*own);
    if let Some(lock) = &lock {
        assert!(lock.pages() >= 1);
        assert!(memlock::report().pages_locked >= 1);
    }
    drop(lock);
    assert!(PageLock::of(&[]).is_none());
}
