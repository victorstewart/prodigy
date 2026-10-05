use core::ptr;
use snow::{Builder, Error, HandshakeState};
use snow::error::StateProblem;
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize;

const PSK_BYTES: usize = 32;
const HANDSHAKE_BYTES: usize = 48;
const HASH_BYTES: usize = 32;
const MAX_PROLOGUE_BYTES: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProdigyNoiseStatus {
    Ok = 0,
    InvalidArgument = 1,
    AllocationFailure = 2,
    CryptoFailure = 3,
    OrderFailure = 4,
    AuthFailure = 5,
    NotFinished = 6,
    AlreadyExported = 7,
}

enum State {
    Active(HandshakeState),
    Exported,
}

pub struct ProdigyNoiseHandshake {
    state: State,
}

impl ProdigyNoiseHandshake {
    fn wipe(&mut self) {
        if let State::Active(handshake) = &mut self.state {
            handshake.wipe();
        }
        self.state = State::Exported;
    }
}

impl Drop for ProdigyNoiseHandshake {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn map_error(error: Error) -> ProdigyNoiseStatus {
    match error {
        Error::Decrypt => ProdigyNoiseStatus::AuthFailure,
        Error::State(StateProblem::NotTurnToRead)
        | Error::State(StateProblem::NotTurnToWrite)
        | Error::State(StateProblem::HandshakeAlreadyFinished) => ProdigyNoiseStatus::OrderFailure,
        _ => ProdigyNoiseStatus::CryptoFailure,
    }
}

unsafe fn clear_output(output: *mut u8, size: usize) {
    if !output.is_null() {
        // SAFETY: Callers provide C ABI output ranges of the stated size.
        unsafe { ptr::write_bytes(output, 0, size) };
    }
}

unsafe fn copy_input<const N: usize>(input: *const u8) -> Option<[u8; N]> {
    if input.is_null() {
        return None;
    }
    let mut value = [0u8; N];
    // SAFETY: N is the documented fixed width for the supplied C ABI pointer.
    unsafe { ptr::copy_nonoverlapping(input, value.as_mut_ptr(), N) };
    Some(value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prodigy_noise_new(
    psk: *const u8,
    prologue: *const u8,
    prologue_size: usize,
    initiator: core::ffi::c_int,
) -> *mut ProdigyNoiseHandshake {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if prologue_size > MAX_PROLOGUE_BYTES || (prologue_size != 0 && prologue.is_null()) {
            return ptr::null_mut();
        }
        let mut psk = match unsafe { copy_input::<PSK_BYTES>(psk) } {
            Some(value) => value,
            None => return ptr::null_mut(),
        };
        let prologue = if prologue_size == 0 {
            &[][..]
        } else {
            // SAFETY: validated non-null and bounded above before creating the slice.
            unsafe { core::slice::from_raw_parts(prologue, prologue_size) }
        };
        let params = match "Noise_NNpsk0_25519_ChaChaPoly_SHA256".parse() {
            Ok(value) => value,
            Err(_) => {
                psk.zeroize();
                return ptr::null_mut();
            },
        };
        let builder = match Builder::new(params).prologue(prologue).and_then(|b| b.psk(0, &psk)) {
            Ok(value) => value,
            Err(_) => {
                psk.zeroize();
                return ptr::null_mut();
            },
        };
        let state = if initiator == 1 {
            builder.build_initiator()
        } else if initiator == 0 {
            builder.build_responder()
        } else {
            psk.zeroize();
            return ptr::null_mut();
        };
        psk.zeroize();
        match state {
            Ok(state) => Box::into_raw(Box::new(ProdigyNoiseHandshake { state: State::Active(state) })),
            Err(_) => ptr::null_mut(),
        }
    }));
    result.unwrap_or(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prodigy_noise_write(
    handshake: *mut ProdigyNoiseHandshake,
    output: *mut u8,
) -> ProdigyNoiseStatus {
    unsafe { clear_output(output, HANDSHAKE_BYTES) };
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handshake.is_null() || output.is_null() {
            return ProdigyNoiseStatus::InvalidArgument;
        }
        // SAFETY: non-null was checked above and ownership remains with the caller.
        let handshake = unsafe { &mut *handshake };
        let State::Active(state) = &mut handshake.state else { return ProdigyNoiseStatus::AlreadyExported };
        let mut message = [0u8; HANDSHAKE_BYTES];
        let status = match state.write_message(&[], &mut message) {
            Ok(HANDSHAKE_BYTES) => {
                // SAFETY: output points to the documented 48-byte output range.
                unsafe { ptr::copy_nonoverlapping(message.as_ptr(), output, HANDSHAKE_BYTES) };
                ProdigyNoiseStatus::Ok
            },
            Ok(_) => ProdigyNoiseStatus::CryptoFailure,
            Err(error) => map_error(error),
        };
        message.zeroize();
        if status != ProdigyNoiseStatus::Ok {
            handshake.wipe();
        }
        status
    }));
    match result {
        Ok(status) => status,
        Err(_) => {
            if !handshake.is_null() {
                // SAFETY: this is the caller-owned opaque allocation checked above.
                unsafe { (&mut *handshake).wipe() };
            }
            ProdigyNoiseStatus::CryptoFailure
        },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prodigy_noise_read(
    handshake: *mut ProdigyNoiseHandshake,
    input: *const u8,
) -> ProdigyNoiseStatus {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handshake.is_null() || input.is_null() {
            return ProdigyNoiseStatus::InvalidArgument;
        }
        let mut message = match unsafe { copy_input::<HANDSHAKE_BYTES>(input) } {
            Some(value) => value,
            None => return ProdigyNoiseStatus::InvalidArgument,
        };
        // SAFETY: non-null was checked above and ownership remains with the caller.
        let handshake = unsafe { &mut *handshake };
        let State::Active(state) = &mut handshake.state else { message.zeroize(); return ProdigyNoiseStatus::AlreadyExported };
        let mut payload = [0u8; 0];
        let status = match state.read_message(&message, &mut payload) {
            Ok(0) => ProdigyNoiseStatus::Ok,
            Ok(_) => ProdigyNoiseStatus::CryptoFailure,
            Err(error) => map_error(error),
        };
        message.zeroize();
        if status != ProdigyNoiseStatus::Ok {
            handshake.wipe();
        }
        status
    }));
    match result {
        Ok(status) => status,
        Err(_) => {
            if !handshake.is_null() {
                // SAFETY: this is the caller-owned opaque allocation checked above.
                unsafe { (&mut *handshake).wipe() };
            }
            ProdigyNoiseStatus::CryptoFailure
        },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prodigy_noise_finished(handshake: *const ProdigyNoiseHandshake) -> core::ffi::c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handshake.is_null() {
            return 0;
        }
        // SAFETY: non-null was checked above and the immutable query does not mutate state.
        let handshake = unsafe { &*handshake };
        matches!(&handshake.state, State::Active(state) if state.is_handshake_finished()) as core::ffi::c_int
    }));
    result.unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prodigy_noise_export(
    handshake: *mut ProdigyNoiseHandshake,
    first: *mut u8,
    second: *mut u8,
    handshake_hash: *mut u8,
) -> ProdigyNoiseStatus {
    unsafe {
        clear_output(first, PSK_BYTES);
        clear_output(second, PSK_BYTES);
        clear_output(handshake_hash, HASH_BYTES);
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handshake.is_null() || first.is_null() || second.is_null() || handshake_hash.is_null() {
            return ProdigyNoiseStatus::InvalidArgument;
        }
        // SAFETY: non-null was checked above and ownership remains with the caller.
        let handshake = unsafe { &mut *handshake };
        let State::Active(state) = &mut handshake.state else { return ProdigyNoiseStatus::AlreadyExported };
        if !state.is_handshake_finished() {
            return ProdigyNoiseStatus::NotFinished;
        }
        let mut public_hash = [0u8; HASH_BYTES];
        public_hash.copy_from_slice(state.get_handshake_hash());
        let (mut k1, mut k2) = state.dangerously_get_raw_split();
        // SAFETY: each output points to its documented fixed-size C ABI range.
        unsafe {
            ptr::copy_nonoverlapping(k1.as_ptr(), first, PSK_BYTES);
            ptr::copy_nonoverlapping(k2.as_ptr(), second, PSK_BYTES);
            ptr::copy_nonoverlapping(public_hash.as_ptr(), handshake_hash, HASH_BYTES);
        }
        k1.zeroize();
        k2.zeroize();
        public_hash.zeroize();
        handshake.wipe();
        ProdigyNoiseStatus::Ok
    }));
    match result {
        Ok(status) => status,
        Err(_) => {
            if !handshake.is_null() {
                // SAFETY: this is the caller-owned opaque allocation checked above.
                unsafe { (&mut *handshake).wipe() };
            }
            ProdigyNoiseStatus::CryptoFailure
        },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prodigy_noise_free(handshake: *mut ProdigyNoiseHandshake) {
    if handshake.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: C ABI requires each successful allocation be freed exactly once.
        unsafe { drop(Box::from_raw(handshake)) };
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn new(psk: [u8; PSK_BYTES], prologue: &[u8], initiator: bool) -> *mut ProdigyNoiseHandshake {
        unsafe { prodigy_noise_new(psk.as_ptr(), prologue.as_ptr(), prologue.len(), if initiator { 1 } else { 0 }) }
    }

    unsafe fn complete(
        psk: [u8; PSK_BYTES],
        prologue: &[u8],
    ) -> (*mut ProdigyNoiseHandshake, *mut ProdigyNoiseHandshake) {
        let initiator = unsafe { new(psk, prologue, true) };
        let responder = unsafe { new(psk, prologue, false) };
        assert!(!initiator.is_null() && !responder.is_null());
        let mut first = [0u8; HANDSHAKE_BYTES];
        let mut second = [0u8; HANDSHAKE_BYTES];
        assert_eq!(unsafe { prodigy_noise_write(initiator, first.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_read(responder, first.as_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_write(responder, second.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_read(initiator, second.as_ptr()) }, ProdigyNoiseStatus::Ok);
        (initiator, responder)
    }

    unsafe fn export(handshake: *mut ProdigyNoiseHandshake) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        let mut h = [0u8; 32];
        assert_eq!(unsafe { prodigy_noise_export(handshake, k1.as_mut_ptr(), k2.as_mut_ptr(), h.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        (k1, k2, h)
    }

    #[test]
    fn successful_handshake_exports_directional_split_once() {
        let psk = [7u8; 32];
        let (initiator, responder) = unsafe { complete(psk, b"cluster pair scope") };
        assert_eq!(unsafe { prodigy_noise_finished(initiator) }, 1);
        assert_eq!(unsafe { prodigy_noise_finished(responder) }, 1);
        let initiator_keys = unsafe { export(initiator) };
        let responder_keys = unsafe { export(responder) };
        assert_eq!(initiator_keys, responder_keys);
        let mut zero = [0u8; 32];
        assert_eq!(unsafe { prodigy_noise_export(initiator, zero.as_mut_ptr(), zero.as_mut_ptr(), zero.as_mut_ptr()) }, ProdigyNoiseStatus::AlreadyExported);
        unsafe { prodigy_noise_free(initiator) };
        unsafe { prodigy_noise_free(responder) };
    }

    #[test]
    fn wrong_psk_prologue_and_tamper_fail_authentication() {
        let psk = [1u8; 32];
        let wrong = [2u8; 32];
        let initiator = unsafe { new(psk, b"route A", true) };
        let responder = unsafe { new(wrong, b"route A", false) };
        let mut first = [0u8; HANDSHAKE_BYTES];
        assert_eq!(unsafe { prodigy_noise_write(initiator, first.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_read(responder, first.as_ptr()) }, ProdigyNoiseStatus::AuthFailure);
        unsafe { prodigy_noise_free(initiator) };
        unsafe { prodigy_noise_free(responder) };

        let initiator = unsafe { new(psk, b"route A", true) };
        let responder = unsafe { new(psk, b"route B", false) };
        assert_eq!(unsafe { prodigy_noise_write(initiator, first.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_read(responder, first.as_ptr()) }, ProdigyNoiseStatus::AuthFailure);
        unsafe { prodigy_noise_free(initiator) };
        unsafe { prodigy_noise_free(responder) };

        let initiator = unsafe { new(psk, b"route A", true) };
        let responder = unsafe { new(psk, b"route A", false) };
        assert_eq!(unsafe { prodigy_noise_write(initiator, first.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        first[0] ^= 1;
        assert_eq!(unsafe { prodigy_noise_read(responder, first.as_ptr()) }, ProdigyNoiseStatus::AuthFailure);
        unsafe { prodigy_noise_free(initiator) };
        unsafe { prodigy_noise_free(responder) };
    }

    #[test]
    fn ordering_replay_and_sessions_are_bounded() {
        let psk = [3u8; 32];
        let initiator = unsafe { new(psk, b"scope", true) };
        let responder = unsafe { new(psk, b"scope", false) };
        let mut first = [0u8; HANDSHAKE_BYTES];
        assert_eq!(unsafe { prodigy_noise_write(responder, first.as_mut_ptr()) }, ProdigyNoiseStatus::OrderFailure);
        unsafe { prodigy_noise_free(responder) };
        let responder = unsafe { new(psk, b"scope", false) };
        assert_eq!(unsafe { prodigy_noise_write(initiator, first.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_write(initiator, first.as_mut_ptr()) }, ProdigyNoiseStatus::OrderFailure);
        unsafe { prodigy_noise_free(initiator) };
        let initiator = unsafe { new(psk, b"scope", true) };
        assert_eq!(unsafe { prodigy_noise_write(initiator, first.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_read(responder, first.as_ptr()) }, ProdigyNoiseStatus::Ok);
        let replay_target = unsafe { new(psk, b"scope", false) };
        assert_eq!(unsafe { prodigy_noise_read(replay_target, first.as_ptr()) }, ProdigyNoiseStatus::Ok);
        let mut original_second = [0u8; HANDSHAKE_BYTES];
        let mut replay_second = [0u8; HANDSHAKE_BYTES];
        assert_eq!(unsafe { prodigy_noise_write(responder, original_second.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_eq!(unsafe { prodigy_noise_write(replay_target, replay_second.as_mut_ptr()) }, ProdigyNoiseStatus::Ok);
        assert_ne!(original_second, replay_second);
        unsafe { prodigy_noise_free(initiator) };
        unsafe { prodigy_noise_free(responder) };
        unsafe { prodigy_noise_free(replay_target) };
    }

    #[test]
    fn export_before_completion_clears_outputs_and_free_is_terminal() {
        let psk = [4u8; 32];
        let initiator = unsafe { new(psk, b"scope", true) };
        let mut k1 = [0xffu8; 32];
        let mut k2 = [0xffu8; 32];
        let mut h = [0xffu8; 32];
        assert_eq!(unsafe { prodigy_noise_export(initiator, k1.as_mut_ptr(), k2.as_mut_ptr(), h.as_mut_ptr()) }, ProdigyNoiseStatus::NotFinished);
        assert_eq!(k1, [0; 32]);
        assert_eq!(k2, [0; 32]);
        assert_eq!(h, [0; 32]);
        unsafe { prodigy_noise_free(initiator) };
    }
}
