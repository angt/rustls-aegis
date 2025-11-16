pub use rustls;

use rustls::SupportedCipherSuite;
use rustls::crypto::{self, CipherSuiteCommon, CryptoProvider};
use rustls::enums::CipherSuite;

mod aead;
mod hash;
mod hmac;

pub static TLS_AEGIS_128L_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::Unknown(0x1306),
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        protocol_version: rustls::version::TLS13_VERSION,
        hkdf_provider: &crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aegis128L,
        quic: None,
    });

pub static TLS_AEGIS_128X2_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::Unknown(0xff01), // test value
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        protocol_version: rustls::version::TLS13_VERSION,
        hkdf_provider: &crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aegis128X2,
        quic: None,
    });

pub static TLS_AEGIS_128X4_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::Unknown(0xff03), // test value
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        protocol_version: rustls::version::TLS13_VERSION,
        hkdf_provider: &crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aegis128X4,
        quic: None,
    });

pub fn provider(default: CryptoProvider) -> CryptoProvider {
    use std::borrow::Cow;

    // Extract the Tls13CipherSuite references from our SupportedCipherSuite wrappers
    let aegis_suites: Vec<&'static rustls::Tls13CipherSuite> = vec![
        match TLS_AEGIS_128X4_SHA256 {
            SupportedCipherSuite::Tls13(suite) => suite,
            _ => unreachable!(),
        },
        match TLS_AEGIS_128X2_SHA256 {
            SupportedCipherSuite::Tls13(suite) => suite,
            _ => unreachable!(),
        },
        match TLS_AEGIS_128L_SHA256 {
            SupportedCipherSuite::Tls13(suite) => suite,
            _ => unreachable!(),
        },
    ];

    let mut tls13_cipher_suites = aegis_suites;
    tls13_cipher_suites.extend(default.tls13_cipher_suites.iter().copied());

    CryptoProvider {
        tls13_cipher_suites: Cow::Owned(tls13_cipher_suites),
        ..default
    }
}
