#![no_std]

use core::panic::PanicInfo;
use core::ptr;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_ml_kem::{KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE};

const PUBLIC_KEY_BYTES: usize = 1184;
const SECRET_KEY_BYTES: usize = 2400;
const CIPHERTEXT_BYTES: usize = 1088;
const KEYPAIR_COINS_BYTES: usize = 64;
const ENCAPS_COINS_BYTES: usize = 32;

const _: [(); PUBLIC_KEY_BYTES] = [(); MlKem768PublicKey::len()];
const _: [(); SECRET_KEY_BYTES] = [(); MlKem768PrivateKey::len()];
const _: [(); CIPHERTEXT_BYTES] = [(); MlKem768Ciphertext::len()];
const _: [(); KEYPAIR_COINS_BYTES] = [(); KEY_GENERATION_SEED_SIZE];
const _: [(); ENCAPS_COINS_BYTES] = [(); SHARED_SECRET_SIZE];

extern "C" {
    fn abort() -> !;
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { abort() }
}

unsafe fn read_array<const N: usize>(input: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    ptr::copy_nonoverlapping(input, out.as_mut_ptr(), N);
    out
}

#[no_mangle]
pub unsafe extern "C" fn goal_mlkem768_keypair_derand(
    ek: *mut u8,
    dk: *mut u8,
    coins: *const u8,
) -> i32 {
    let key_pair = mlkem768::avx2::generate_key_pair(read_array::<KEYPAIR_COINS_BYTES>(coins));
    ptr::copy_nonoverlapping(key_pair.pk().as_ptr(), ek, PUBLIC_KEY_BYTES);
    ptr::copy_nonoverlapping(key_pair.sk().as_ptr(), dk, SECRET_KEY_BYTES);
    0
}

#[no_mangle]
pub unsafe extern "C" fn goal_mlkem768_encaps_derand(
    ct: *mut u8,
    ss: *mut u8,
    ek: *const u8,
    coins: *const u8,
) -> i32 {
    let public_key = MlKem768PublicKey::from(read_array::<PUBLIC_KEY_BYTES>(ek));
    let (ciphertext, shared_secret) =
        mlkem768::avx2::encapsulate(&public_key, read_array::<ENCAPS_COINS_BYTES>(coins));
    ptr::copy_nonoverlapping(ciphertext.as_slice().as_ptr(), ct, CIPHERTEXT_BYTES);
    ptr::copy_nonoverlapping(shared_secret.as_slice().as_ptr(), ss, SHARED_SECRET_SIZE);
    0
}

#[no_mangle]
pub unsafe extern "C" fn goal_mlkem768_decaps(ss: *mut u8, ct: *const u8, dk: *const u8) -> i32 {
    let private_key = MlKem768PrivateKey::from(read_array::<SECRET_KEY_BYTES>(dk));
    let ciphertext = MlKem768Ciphertext::from(read_array::<CIPHERTEXT_BYTES>(ct));
    let shared_secret = mlkem768::avx2::decapsulate(&private_key, &ciphertext);
    ptr::copy_nonoverlapping(shared_secret.as_slice().as_ptr(), ss, SHARED_SECRET_SIZE);
    0
}
