use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    MessageDecrypter, MessageEncrypter, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};
use aegis::aegis128x4::{self, Key, Nonce, Tag};

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

pub(crate) struct Aegis128X4;

impl Tls13AeadAlgorithm for Aegis128X4 {
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
        let mut nonce16 = [0u8; NONCE_LEN];
        nonce16[4..4 + IV_LEN].copy_from_slice(self.iv.as_ref());

        let mut tail = u64::from_be_bytes(nonce16[8..16].try_into().unwrap());
        tail ^= seq;

        nonce16[8..16].copy_from_slice(&tail.to_be_bytes());

        Nonce::from(nonce16)
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

        let mut payload = PrefixedPayload::with_capacity(total_len + TAG_LEN);
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&[u8::from(m.typ)]);

        let nonce = self.make_nonce(seq);
        let ad = make_tls13_aad(total_len);

        let cipher = aegis128x4::Aegis128X4::<TAG_LEN>::new(&self.key, &nonce);
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
        let buf: &mut [u8] = &mut *m.payload;
        let total_len = buf.len();

        if total_len < TAG_LEN + 1 {
            return Err(Error::DecryptError);
        }

        let payload_len = total_len - TAG_LEN;
        let tag_start = payload_len;
        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(&buf[tag_start..tag_start + TAG_LEN]);
        let tag = Tag::from(tag_arr);

        let nonce = self.make_nonce(seq);
        let ad = make_tls13_aad(total_len);

        let cipher = aegis128x4::Aegis128X4::<TAG_LEN>::new(&self.key, &nonce);

        let ct = &mut buf[..payload_len];
        cipher
            .decrypt_in_place(ct, &tag, &ad)
            .map_err(|_| Error::DecryptError)?;

        m.payload.truncate(payload_len);

        m.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use aegis::aegis128x4::{self, Key, Nonce, Tag};
    use hex_literal::hex;

    fn run_aegis128x4_vector(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
        expected_tag: &[u8],
        ad: &[u8],
    ) {
        let key: Key = key.try_into().expect("bad key");
        let nonce: Nonce = nonce.try_into().expect("bad nonce");

        let cipher = aegis128x4::Aegis128X4::<16>::new(&key, &nonce);
        let mut ciphertext = plaintext.to_vec();

        let tag: Tag<16> = cipher.encrypt_in_place(&mut ciphertext, ad).into();
        let expected_tag: Tag<16> = expected_tag.try_into().expect("bad tag");

        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let cipher = aegis128x4::Aegis128X4::<16>::new(&key, &nonce);
        cipher.decrypt_in_place(&mut ciphertext, &tag, ad).unwrap();

        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn test_vectors() {
        run_aegis128x4_vector(
            &hex!("000102030405060708090a0b0c0d0e0f"),
            &hex!("101112131415161718191a1b1c1d1e1f"),
            &hex!(""),
            &hex!(""),
            &hex!("5bef762d0947c00455b97bb3af30dfa3"),
            &hex!(""),
        );
        run_aegis128x4_vector(
            &hex!("000102030405060708090a0b0c0d0e0f"),
            &hex!("101112131415161718191a1b1c1d1e1f"),
            &hex!("040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607"),
            &hex!("e836118562f4479c9d35c17356a833114c21f9aa39e4dda5e5c87f4152a00fce9a7c38f832eafe8b1c12f8a7cf12a81a1ad8a9c24ba9dedfbdaa586ffea67ddc801ea97d9ab4a872f42d0e352e2713dacd609f9442c17517c5a29daf3e2a3fac4ff6b1380c4e46df7b086af6ce6bc1ed594b8dd64aed2a7e"),
            &hex!("0e56ab94e2e85db80f9d54010caabfb4"),
            &hex!("0102030401020304"),
        );
    }
}
