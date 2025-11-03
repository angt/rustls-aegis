use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    MessageDecrypter, MessageEncrypter, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};
use aegis::aegis128l::{self, Key, Nonce, Tag};

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

pub(crate) struct Aegis128L;

impl Tls13AeadAlgorithm for Aegis128L {
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

        let cipher = aegis128l::Aegis128L::<TAG_LEN>::new(&self.key, &nonce);
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

        let cipher = aegis128l::Aegis128L::<TAG_LEN>::new(&self.key, &nonce);

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
    use aegis::aegis128l::{self, Key, Nonce, Tag};
    use hex_literal::hex;

    fn run_aegis128l_vector(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
        expected_tag: &[u8],
        ad: &[u8],
    ) {
        let key: Key = key.try_into().expect("bad key");
        let nonce: Nonce = nonce.try_into().expect("bad nonce");

        let cipher = aegis128l::Aegis128L::<16>::new(&key, &nonce);
        let mut ciphertext = plaintext.to_vec();

        let tag: Tag<16> = cipher.encrypt_in_place(&mut ciphertext, ad).into();
        let expected_tag: Tag<16> = expected_tag.try_into().expect("bad tag");

        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let cipher = aegis128l::Aegis128L::<16>::new(&key, &nonce);
        cipher.decrypt_in_place(&mut ciphertext, &tag, ad).unwrap();

        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn test_vectors() {
        run_aegis128l_vector(
            &hex!("10010000000000000000000000000000"),
            &hex!("10000200000000000000000000000000"),
            &hex!("00000000000000000000000000000000"),
            &hex!("c1c0e58bd913006feba00f4b3cc3594e"),
            &hex!("abe0ece80c24868a226a35d16bdae37a"),
            &[],
        );

        run_aegis128l_vector(
            &hex!("10010000000000000000000000000000"),
            &hex!("10000200000000000000000000000000"),
            &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            &hex!("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84"),
            &hex!("cc6f3372f6aa1bb82388d695c3962d9a"),
            &hex!("0001020304050607"),
        );

        run_aegis128l_vector(
            &hex!("10010000000000000000000000000000"),
            &hex!("10000200000000000000000000000000"),
            &hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"),
            &hex!("b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10"),
            &hex!("7542a745733014f9474417b337399507"),
            &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"),
        );
    }
}
