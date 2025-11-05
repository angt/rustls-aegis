use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    MessageDecrypter, MessageEncrypter, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

macro_rules! aegis_mod {
    (
        $internal_mod_name:ident,
        $public_name:ident,
        $aegis_module:path,
        $aegis_cipher:ty
    ) => {
        mod $internal_mod_name {
            use super::*;
            use $aegis_module::{Key, Nonce, Tag};

            pub(crate) struct $public_name;

            impl Tls13AeadAlgorithm for $public_name {
                fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
                    let mut aegis_key = [0u8; KEY_LEN];
                    aegis_key.copy_from_slice(key.as_ref());
                    Box::new(Tls13AegisCipher {
                        key: Key::from(aegis_key),
                        iv,
                    })
                }

                fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
                    let mut aegis_key = [0u8; KEY_LEN];
                    aegis_key.copy_from_slice(key.as_ref());
                    Box::new(Tls13AegisCipher {
                        key: Key::from(aegis_key),
                        iv,
                    })
                }

                fn key_len(&self) -> usize {
                    KEY_LEN
                }

                fn extract_keys(
                    &self,
                    _key: AeadKey,
                    _iv: Iv,
                ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
                    Err(UnsupportedOperationError)
                }
            }

            struct Tls13AegisCipher {
                key: Key,
                iv: Iv,
            }

            impl Tls13AegisCipher {
                #[inline(always)]
                fn make_nonce(&self, seq: u64) -> Nonce {
                    let mut nonce = [0u8; NONCE_LEN];
                    nonce[NONCE_LEN - IV_LEN..].copy_from_slice(self.iv.as_ref());
                    let tail = seq ^ u64::from_be_bytes(nonce[8..].try_into().unwrap());
                    nonce[8..].copy_from_slice(&tail.to_be_bytes());
                    Nonce::from(nonce)
                }
            }

            impl MessageEncrypter for Tls13AegisCipher {
                fn encrypt(
                    &mut self,
                    m: OutboundPlainMessage<'_>,
                    seq: u64,
                ) -> Result<OutboundOpaqueMessage, Error> {
                    let payload_len = m.payload.len();
                    let inner_len = payload_len + 1;
                    let total_len = inner_len + TAG_LEN;

                    let mut payload = PrefixedPayload::with_capacity(total_len);
                    payload.extend_from_chunks(&m.payload);
                    payload.extend_from_slice(&[u8::from(m.typ)]);

                    let nonce = self.make_nonce(seq);
                    let ad = make_tls13_aad(total_len);
                    let cipher = <$aegis_cipher>::new(&self.key, &nonce);
                    let tag = cipher.encrypt_in_place(payload.as_mut(), &ad);

                    payload.extend_from_slice(&tag);

                    Ok(OutboundOpaqueMessage::new(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_2,
                            payload,
                    ))
                }

                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + 1 + TAG_LEN
                }
            }

            impl MessageDecrypter for Tls13AegisCipher {
                fn decrypt<'a>(
                    &mut self,
                    mut m: InboundOpaqueMessage<'a>,
                    seq: u64,
                ) -> Result<InboundPlainMessage<'a>, Error> {
                    let total_len = m.payload.len();
                    if total_len < TAG_LEN + 1 {
                        return Err(Error::DecryptError);
                    }
                    let payload_len = total_len - TAG_LEN;
                    let (ct, tag) = m.payload.split_at_mut(payload_len);
                    let tag = Tag::try_from(tag).unwrap();
                    let nonce = self.make_nonce(seq);
                    let ad = make_tls13_aad(total_len);
                    let cipher = <$aegis_cipher>::new(&self.key, &nonce);

                    cipher
                        .decrypt_in_place(ct, &tag, &ad)
                        .map_err(|_| Error::DecryptError)?;

                    m.payload.truncate(payload_len);
                    m.into_tls13_unpadded_message()
                }
            }
        }
        pub(crate) use $internal_mod_name::$public_name;
    };
}

aegis_mod!(
    internal_aegis128l,
    Aegis128L,
    aegis::aegis128l,
    aegis::aegis128l::Aegis128L<TAG_LEN>
);

aegis_mod!(
    internal_aegis128x2,
    Aegis128X2,
    aegis::aegis128x2,
    aegis::aegis128x2::Aegis128X2<TAG_LEN>
);

aegis_mod!(
    internal_aegis128x4,
    Aegis128X4,
    aegis::aegis128x4,
    aegis::aegis128x4::Aegis128X4<TAG_LEN>
);
