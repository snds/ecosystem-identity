//! Keeping the crate's secret keys out of swap (03-architecture §8 "stay
//! out of swap", 04-security §14; Lockdown D314, asked for here by D378).
//!
//! Every secret key type this crate holds asks for the memory pages it sits
//! on to be locked into RAM while it lives: `mlock` on Linux and macOS,
//! `VirtualLock` on Windows. That covers the typed 256-bit keys in
//! [`crate::keys`] (the root key, Persona Keys, App Data Keys, the
//! crown-jewel key, the unlock keys, the kit key, the one-time peer-wrap
//! key), the receiving key's seed and the KEM shared secret in
//! [`crate::kem`], the Secret Key and recovery code in [`crate::kit`], the
//! Identity Signing Key an open [`crate::Identity`] holds, and the seeds a
//! [`crate::FileKeystore`] holds.
//!
//! Pages are shared with whatever else the allocator put beside a secret,
//! so a page is locked once and unlocked only when the last secret on it is
//! dropped: a count per page, since the kernel does not count `mlock` calls
//! on one page. A lock the system refuses (`RLIMIT_MEMLOCK` on Linux and
//! macOS, the minimum working set on Windows) is counted in [`report`] and
//! the secret works as before: it is still wiped on drop, it may just reach
//! swap. A refusal is never an error and never a panic.
//!
//! On drop a secret is wiped first and its pages are unlocked after, so the
//! bytes are never on an unlocked page while they still hold the secret.
//!
//! What this does not reach:
//!
//! - Values that live for one call on the stack: the 32-byte outputs of
//!   [`crate::kdf::stretch`] and [`crate::kdf::subkey`] before they become a
//!   typed key, the expanded hybrid decapsulation key inside one
//!   decapsulation, and the Ed25519 key a [`crate::FileKeystore`] rebuilds
//!   for one signature. Each is wiped by its own type on drop.
//! - Argon2id's working memory (64 MiB at the desktop floor), which is far
//!   above the usual lock limit; the `argon2` crate wipes it.
//! - Copies the allocator or a move made before a value became one of these
//!   types.
//!
//! One page table per process: a page this module locked can be unlocked
//! by any other code in the process that calls `munlock` or `VirtualUnlock`
//! on it, because the kernel keeps one lock bit per page. An app that locks
//! its own secrets should do it through [`PageLock`] so both share this
//! table.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Pages locked now, with how many secrets sit on each.
static PAGES: Mutex<BTreeMap<usize, u32>> = Mutex::new(BTreeMap::new());
static LOCKED_EVER: AtomicU64 = AtomicU64::new(0);
static UNLOCKED_EVER: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// What the process has kept out of swap through this module, for a
/// settings or diagnostics screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryReport {
    /// Whether this build can lock pages at all.
    pub supported: bool,
    /// The page size, in bytes.
    pub page_size: u64,
    /// Pages locked now.
    pub pages_locked: u64,
    /// Pages ever locked.
    pub pages_locked_ever: u64,
    /// Pages ever unlocked again, after the last secret on them was dropped.
    pub pages_unlocked_ever: u64,
    /// Locks the system refused. Each refused secret still works and is
    /// still wiped on drop; it may reach swap.
    pub refused: u64,
}

/// What is locked now, what was, and what the system refused.
pub fn report() -> MemoryReport {
    MemoryReport {
        supported: supported(),
        page_size: page_size() as u64,
        pages_locked: PAGES.lock().map(|p| p.len() as u64).unwrap_or(0),
        pages_locked_ever: LOCKED_EVER.load(Ordering::Relaxed),
        pages_unlocked_ever: UNLOCKED_EVER.load(Ordering::Relaxed),
        refused: REFUSED.load(Ordering::Relaxed),
    }
}

/// Whether this build can lock pages (Unix and Windows).
pub fn supported() -> bool {
    cfg!(any(unix, windows))
}

/// The system's page size.
pub fn page_size() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| os::page_size().max(1))
}

/// The pages under one secret, locked while this value lives.
#[derive(Debug)]
pub struct PageLock {
    first: usize,
    count: usize,
}

impl PageLock {
    /// Locks the pages under `bytes`. `None` when `bytes` is empty, when
    /// this build cannot lock, or when the system refused (counted in
    /// [`report`]).
    pub fn of(bytes: &[u8]) -> Option<Self> {
        Self::range(bytes.as_ptr() as usize, bytes.len())
    }

    /// Locks the pages under `value`, wherever it lives. Use it on a value
    /// that does not move while the lock is held: one behind a `Box`, say.
    pub fn of_value<T: ?Sized>(value: &T) -> Option<Self> {
        Self::range(
            std::ptr::from_ref(value).cast::<u8>() as usize,
            std::mem::size_of_val(value),
        )
    }

    fn range(start: usize, len: usize) -> Option<Self> {
        if len == 0 || !supported() {
            return None;
        }
        #[cfg(test)]
        if refuse::now() {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let size = page_size();
        let first = start / size;
        let last = (start + len - 1) / size;
        let mut pages = PAGES.lock().ok()?;
        let mut taken = Vec::with_capacity(last - first + 1);
        for page in first..=last {
            let n = pages.get(&page).copied().unwrap_or(0);
            if n == 0 {
                if !os::lock(page * size, size) {
                    // Undo what this call took, so no page is counted twice.
                    for p in taken {
                        release(&mut pages, p, size);
                    }
                    REFUSED.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                LOCKED_EVER.fetch_add(1, Ordering::Relaxed);
            }
            pages.insert(page, n + 1);
            taken.push(page);
        }
        Some(Self {
            first,
            count: last - first + 1,
        })
    }

    /// How many pages this lock holds.
    pub fn pages(&self) -> usize {
        self.count
    }
}

fn release(pages: &mut BTreeMap<usize, u32>, page: usize, size: usize) {
    if let Some(n) = pages.get_mut(&page) {
        *n -= 1;
        if *n == 0 {
            pages.remove(&page);
            os::unlock(page * size, size);
            UNLOCKED_EVER.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for PageLock {
    fn drop(&mut self) {
        let size = page_size();
        if let Ok(mut pages) = PAGES.lock() {
            for page in self.first..self.first + self.count {
                release(&mut pages, page, size);
            }
        }
    }
}

/// A value on the heap whose pages are locked while it lives. Dropping it
/// drops the value first (its own `Drop` wipes it, for a type that wipes
/// itself, such as `ed25519_dalek::SigningKey`) and unlocks the pages after.
///
/// Moving a value into the box copies it from wherever it was built; that
/// earlier copy is not wiped by this type. Build the value as late as
/// possible and from material that is itself wiped.
pub struct Locked<T> {
    // Field order is drop order: the value is dropped (and wiped) while its
    // pages are still locked.
    value: Box<T>,
    lock: Option<PageLock>,
}

impl<T> Locked<T> {
    /// Moves `value` to the heap and locks the pages under it.
    pub fn new(value: T) -> Self {
        let value = Box::new(value);
        let lock = PageLock::of_value(&*value);
        Self { value, lock }
    }

    /// Whether the pages under the value are locked now (`false` when the
    /// system refused or this build cannot lock).
    pub fn is_locked(&self) -> bool {
        self.lock.is_some()
    }
}

impl<T> Deref for Locked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> fmt::Debug for Locked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Locked(…, locked: {})", self.lock.is_some())
    }
}

/// In the crate's own tests, a thread can have its locks refused as the
/// system would refuse them, whether or not the page is already locked by
/// another secret, so the refusal path is tested without changing process
/// limits other tests share.
#[cfg(test)]
pub(crate) mod refuse {
    use std::cell::Cell;

    thread_local! {
        static REFUSING: Cell<bool> = const { Cell::new(false) };
    }

    /// Runs `f` with every lock this thread asks for refused.
    pub(crate) fn on_this_thread<R>(f: impl FnOnce() -> R) -> R {
        REFUSING.with(|r| r.set(true));
        let out = f();
        REFUSING.with(|r| r.set(false));
        out
    }

    pub(super) fn now() -> bool {
        REFUSING.with(Cell::get)
    }
}

#[cfg(unix)]
mod os {
    pub fn page_size() -> usize {
        // SAFETY: sysconf reads a constant of the system; no memory is touched.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if n > 0 { n as usize } else { 4096 }
    }

    pub fn lock(addr: usize, len: usize) -> bool {
        // SAFETY: mlock only changes how the kernel pages this range; the
        // range is a whole page a live allocation of the caller sits on.
        unsafe { libc::mlock(addr as *const libc::c_void, len) == 0 }
    }

    pub fn unlock(addr: usize, len: usize) {
        // SAFETY: as `lock`. Unlocking a page that is no longer mapped
        // fails harmlessly with ENOMEM.
        unsafe {
            libc::munlock(addr as *const libc::c_void, len);
        }
    }
}

#[cfg(windows)]
mod os {
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    pub fn page_size() -> usize {
        // SAFETY: GetSystemInfo fills the struct it is given and reads nothing.
        unsafe {
            let mut info: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut info);
            info.dwPageSize as usize
        }
    }

    pub fn lock(addr: usize, len: usize) -> bool {
        // SAFETY: VirtualLock only pins into the working set the committed
        // page a live allocation of the caller sits on.
        unsafe { VirtualLock(addr as *const core::ffi::c_void, len) != 0 }
    }

    pub fn unlock(addr: usize, len: usize) {
        // SAFETY: as `lock`.
        unsafe {
            VirtualUnlock(addr as *const core::ffi::c_void, len);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod os {
    pub fn page_size() -> usize {
        65_536
    }

    pub fn lock(_addr: usize, _len: usize) -> bool {
        false
    }

    pub fn unlock(_addr: usize, _len: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(page: usize) -> Option<u32> {
        PAGES.lock().unwrap().get(&page).copied()
    }

    /// This process's locked memory as the kernel counts it.
    #[cfg(target_os = "linux")]
    fn vm_locked_kb() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("VmLck:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap()
    }

    #[test]
    fn pages_are_counted_once_and_released_with_the_last_secret() {
        let size = page_size();
        // Two secrets on one page, a third across that page and the next.
        let buf = vec![7u8; size * 3];
        let at = (size - (buf.as_ptr() as usize % size)) % size;
        let first = (buf.as_ptr() as usize + at) / size;
        let before = report();
        let a = PageLock::of(&buf[at..at + 16]);
        let Some(a) = a else {
            // The system refused here: counted, and nothing held.
            assert!(report().refused > before.refused);
            assert_eq!(held(first), None);
            return;
        };
        // The same page again: no new lock is asked of the system.
        let b = PageLock::of(&buf[at + 32..at + 48]).unwrap();
        let Some(c) = PageLock::of(&buf[at + size - 8..at + size + 8]) else {
            // The next page was refused (a tight limit): counted, and the
            // page this call had already taken was given back.
            assert!(report().refused > before.refused);
            assert_eq!(held(first), Some(2));
            assert_eq!(held(first + 1), None);
            return;
        };
        assert_eq!((a.pages(), b.pages(), c.pages()), (1, 1, 2));
        assert_eq!(held(first), Some(3));
        assert_eq!(held(first + 1), Some(1));
        let mid = report();
        assert!(mid.pages_locked_ever >= before.pages_locked_ever + 2);
        assert!(mid.pages_locked >= 2);
        #[cfg(target_os = "linux")]
        assert!(vm_locked_kb() >= (2 * size / 1024) as u64);
        drop((a, b));
        assert_eq!(held(first), Some(1), "the third secret still holds it");
        drop(c);
        assert_eq!(held(first), None);
        assert_eq!(held(first + 1), None);
        assert!(report().pages_unlocked_ever >= mid.pages_unlocked_ever + 2);
        assert!(PageLock::of(&[]).is_none());
    }

    #[test]
    fn a_refused_lock_is_counted_and_nothing_is_held() {
        let size = page_size();
        let buf = vec![1u8; size * 2];
        let at = (size - (buf.as_ptr() as usize % size)) % size;
        let page = (buf.as_ptr() as usize + at) / size;
        let before = report().refused;
        let lock = refuse::on_this_thread(|| PageLock::of(&buf[at..at + 64]));
        assert!(lock.is_none());
        assert_eq!(held(page), None);
        assert!(report().refused > before);
        // The next ask, not refused, locks as usual (or the system refuses
        // for real, which is counted too).
        let again_before = report().refused;
        match PageLock::of(&buf[at..at + 64]) {
            Some(l) => assert_eq!(held(page), Some(1), "{l:?}"),
            None => assert!(report().refused > again_before),
        }
    }

    #[test]
    fn a_locked_value_is_dropped_while_its_pages_are_still_locked() {
        use std::sync::atomic::AtomicBool;
        static STILL_LOCKED: AtomicBool = AtomicBool::new(false);
        // Aligned to and as large as the biggest page size in use, so the
        // probe has its pages to itself.
        #[repr(C, align(65536))]
        struct Probe([u8; 64]);
        impl Drop for Probe {
            fn drop(&mut self) {
                let page = self.0.as_ptr() as usize / page_size();
                STILL_LOCKED.store(held(page).is_some(), Ordering::SeqCst);
            }
        }
        let boxed = Locked::new(Probe([9; 64]));
        assert_eq!(boxed.0[0], 9);
        let locked = boxed.is_locked();
        assert!(format!("{boxed:?}").starts_with("Locked(…"));
        drop(boxed);
        assert_eq!(
            STILL_LOCKED.load(Ordering::SeqCst),
            locked,
            "the value saw its page locked when it was dropped"
        );
        let refused = refuse::on_this_thread(|| Locked::new(Probe([3; 64])));
        assert!(!refused.is_locked());
        assert_eq!(refused.0[63], 3, "a refused lock leaves the value usable");
    }
}
