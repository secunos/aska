//! `LockedBuf`: a fixed-capacity byte buffer for secrets held by the `Session`.
//! Pages are pinned in RAM with `mlock`, excluded from crash dumps, and zeroised before release
//! (Client Design §3.1). The only `unsafe` in `aska-core` is the page-aligned allocation and
//! the libc calls in this file.
#![allow(unsafe_code)]

use std::alloc::{alloc_zeroed, dealloc, Layout};
use zeroize::Zeroize;

const PAGE: usize = 4096;

/// Whether the buffer's pages could be pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Locked,
    /// `mlock` failed (usually `RLIMIT_MEMLOCK`); the buffer still zeroises on drop.
    Unlocked,
}

/// `mlock` refused a buffer of this many bytes (usually `RLIMIT_MEMLOCK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockError {
    pub bytes: usize,
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot lock {} bytes of memory", self.bytes)
    }
}

impl std::error::Error for LockError {}

pub struct LockedBuf {
    ptr: *mut u8,
    cap: usize,
    len: usize,
    layout: Layout,
    state: LockState,
}

// The buffer owns its allocation exclusively; moving it between threads is fine.
unsafe impl Send for LockedBuf {}

impl std::fmt::Debug for LockedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LockedBuf(len={}, cap={}, {:?})",
            self.len, self.cap, self.state
        )
    }
}

impl LockedBuf {
    /// Allocate `capacity` bytes (rounded up to whole pages), zero-filled and pinned when the
    /// system allows it.
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1).div_ceil(PAGE) * PAGE;
        let layout = Layout::from_size_align(cap, PAGE).expect("valid layout");
        // SAFETY: layout has non-zero size and page alignment.
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "allocation failed");
        // SAFETY: ptr/cap describe exactly the allocation above.
        let state = unsafe {
            libc::madvise(ptr.cast(), cap, libc::MADV_DONTDUMP);
            if libc::mlock(ptr.cast(), cap) == 0 {
                LockState::Locked
            } else {
                LockState::Unlocked
            }
        };
        LockedBuf {
            ptr,
            cap,
            len: 0,
            layout,
            state,
        }
    }

    /// Allocate and copy `data` in.
    pub fn from_slice(data: &[u8]) -> Self {
        let mut b = Self::with_capacity(data.len());
        b.set(data);
        b
    }

    /// Like `with_capacity`, but refuses (freeing the zeroed pages) when the buffer could not
    /// be pinned and `require_lock` is set. The Session uses this for every secret so that a
    /// large buffer failing `mlock` (memlock limit exhausted) is never silently unlocked.
    pub fn try_with_capacity(capacity: usize, require_lock: bool) -> Result<Self, LockError> {
        let b = Self::with_capacity(capacity);
        if require_lock && b.state == LockState::Unlocked {
            return Err(LockError { bytes: b.cap });
        }
        Ok(b)
    }

    /// `try_with_capacity` + copy.
    pub fn try_from_slice(data: &[u8], require_lock: bool) -> Result<Self, LockError> {
        let mut b = Self::try_with_capacity(data.len(), require_lock)?;
        b.set(data);
        Ok(b)
    }

    pub fn lock_state(&self) -> LockState {
        self.state
    }
    pub fn capacity(&self) -> usize {
        self.cap
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: len <= cap and the memory is initialised (zeroed at allocation).
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above; &mut self guarantees exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Replace the contents (zeroising what was there). Panics if `data` exceeds capacity.
    pub fn set(&mut self, data: &[u8]) {
        assert!(data.len() <= self.cap, "LockedBuf capacity exceeded");
        self.clear();
        // SAFETY: data.len() <= cap; regions cannot overlap (distinct allocations).
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr, data.len()) };
        self.len = data.len();
    }

    /// Append bytes. Panics if capacity would be exceeded.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        assert!(
            self.len + data.len() <= self.cap,
            "LockedBuf capacity exceeded"
        );
        // SAFETY: bounds checked above.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(self.len), data.len()) };
        self.len += data.len();
    }

    /// Shorten to `len` bytes, zeroising the bytes dropped. No-op if `len >= self.len()`.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.as_mut_slice()[len..].zeroize();
            self.len = len;
        }
    }

    /// Zeroise the whole capacity and set the length to zero.
    pub fn clear(&mut self) {
        // SAFETY: the whole capacity is one initialised allocation.
        let all = unsafe { std::slice::from_raw_parts_mut(self.ptr, self.cap) };
        all.zeroize();
        self.len = 0;
    }
}

/// Overwrite the stack below the caller's frame. Derivations leave copies of key material in
/// frames that have already returned (moved arrays, hash block buffers); the Session calls
/// this at the end of `seal`, `open`, `add_key_material` and `close`, so it runs on the thread
/// that did the work. 128 KiB is far more than the deepest call chain uses; threads that call
/// into the Session must have at least 512 KiB of stack (every default is 2 MiB or more).
#[inline(never)]
pub fn scrub_stack() {
    const N: usize = 128 * 1024 / 8;
    let mut buf = [0u64; N];
    for w in buf.iter_mut() {
        // SAFETY: writing an initialised u64 through a valid, aligned pointer.
        unsafe { std::ptr::write_volatile(w, 0) };
    }
    std::hint::black_box(&buf);
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        self.clear();
        // SAFETY: ptr/cap/layout describe the live allocation; freed exactly once here.
        unsafe {
            if self.state == LockState::Locked {
                libc::munlock(self.ptr.cast(), self.cap);
            }
            dealloc(self.ptr, self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_clear() {
        let mut b = LockedBuf::with_capacity(10);
        assert_eq!(b.capacity(), PAGE);
        assert!(b.is_empty());
        b.set(b"hello");
        assert_eq!(b.as_slice(), b"hello");
        b.extend_from_slice(b" world");
        assert_eq!(b.as_slice(), b"hello world");
        b.as_mut_slice()[0] = b'H';
        assert_eq!(&b.as_slice()[..1], b"H");
        b.clear();
        assert!(b.is_empty());
        let raw = unsafe { std::slice::from_raw_parts(b.ptr, b.cap) };
        assert!(raw.iter().all(|&x| x == 0));
        let c = LockedBuf::from_slice(&[7u8; 5000]);
        assert_eq!(c.capacity(), 2 * PAGE);
        assert_eq!(c.len(), 5000);
    }

    #[test]
    #[should_panic]
    fn overflow_panics() {
        let mut b = LockedBuf::with_capacity(8);
        b.set(&[0u8; PAGE + 1]);
    }
}
