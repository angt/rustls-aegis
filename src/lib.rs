pub use rustls;

use rustls::SupportedCipherSuite;
use rustls::crypto::{self, CryptoProvider, CipherSuiteCommon};

mod hash;
mod hmac;
mod aead;

pub static TLS_AEGIS_128L_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: rustls::CipherSuite::Unknown(0x1307),
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aegis128L,
        quic: None,
    });

pub static TLS_AEGIS_128X2_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: rustls::CipherSuite::Unknown(0xff02), //fake
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aegis128X2,
        quic: None,
    });

pub static TLS_AEGIS_128X4_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: rustls::CipherSuite::Unknown(0xff04), //fake
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aegis128X4,
        quic: None,
    });

pub fn provider(default: CryptoProvider) -> CryptoProvider {
    let mut cipher_suites: Vec<SupportedCipherSuite> = vec![
        TLS_AEGIS_128X4_SHA256,
        TLS_AEGIS_128X2_SHA256,
        TLS_AEGIS_128L_SHA256,
    ];
    cipher_suites.extend(default.cipher_suites);

    CryptoProvider {
        cipher_suites,
        ..default
    }
}
