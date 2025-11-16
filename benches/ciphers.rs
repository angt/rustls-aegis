use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rustls::client::ClientConnection;
use rustls::crypto::{CryptoProvider, Identity};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;
use rustls::{ClientConfig, ConnectionCommon, RootCertStore, ServerConfig, SideData};
use rustls_aegis;
use std::io::{Read, Write};
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;

// Ensure at least one crypto provider feature is enabled
#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("At least one of 'aws-lc-rs' or 'ring' features must be enabled");

const CHUNK_SIZE: usize = 16384;
const BUFFER_SIZE: usize = 64 * 1024;
const DATA_SIZE: usize = 10 * 1024 * 1024;

fn get_default_provider() -> CryptoProvider {
    #[cfg(feature = "aws-lc-rs")]
    {
        rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER.clone()
    }
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        rustls::crypto::ring::DEFAULT_PROVIDER.clone()
    }
}

fn make_configs(
    provider: Arc<CryptoProvider>,
    root_store: RootCertStore,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let client_config = ClientConfig::builder(provider.clone())
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .unwrap();

    let identity = Arc::new(Identity::from_cert_chain(vec![cert]).unwrap());

    let server_config = ServerConfig::builder(provider)
        .with_no_client_auth()
        .with_single_cert(identity, key)
        .unwrap();
    (Arc::new(client_config), Arc::new(server_config))
}

struct BenchSetup {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    root_store: RootCertStore,
    data_buf: Vec<u8>,
}

impl BenchSetup {
    fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let cert = CertificateDer::from(cert.cert);

        let mut root_store = RootCertStore::empty();
        root_store.add(cert.clone()).unwrap();

        let data_buf = vec![0x42u8; DATA_SIZE];

        Self {
            cert,
            key,
            root_store,
            data_buf,
        }
    }
}

fn transfer(
    left: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    right: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
) -> usize {
    let mut buf = [0u8; BUFFER_SIZE];
    let mut total = 0;
    while left.wants_write() {
        let sz = left.write_tls(&mut &mut buf[..]).unwrap();
        if sz == 0 {
            break;
        }
        let mut offset = 0;
        while offset < sz {
            offset += right.read_tls(&mut &buf[offset..sz]).unwrap();
        }
        total += sz;
    }
    total
}

fn handshake(
    client_cfg: Arc<ClientConfig>,
    server_cfg: Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    let mut client = ClientConnection::new(client_cfg, "localhost".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(server_cfg).unwrap();
    while server.is_handshaking()
        || client.is_handshaking()
        || client.wants_write()
        || server.wants_write()
    {
        if client.wants_write() {
            transfer(&mut client, &mut server);
            server.process_new_packets().unwrap();
        }
        if server.wants_write() {
            transfer(&mut server, &mut client);
            client.process_new_packets().unwrap();
        }
    }
    (client, server)
}

fn bench_encryption(c: &mut Criterion) {
    let setup = BenchSetup::new();
    let tls13_suites = rustls_aegis::provider(get_default_provider())
        .tls13_cipher_suites
        .iter()
        .copied()
        .collect::<Vec<_>>();

    let mut group = c.benchmark_group("Encryption throughput");
    group.throughput(Throughput::Bytes(DATA_SIZE as u64));

    for &suite in &tls13_suites {
        let provider = Arc::new(CryptoProvider {
            tls13_cipher_suites: vec![suite].into(),
            ..rustls_aegis::provider(get_default_provider())
        });
        let (client_cfg, server_cfg) = make_configs(
            provider,
            setup.root_store.clone(),
            setup.cert.clone(),
            setup.key.clone_key(),
        );

        group.bench_function(format!("{:?}", suite.common.suite), |b| {
            b.iter_batched(
                || {
                    // Setup: handshake only (NOT measured)
                    let (_client, server) = handshake(client_cfg.clone(), server_cfg.clone());
                    (server, setup.data_buf.clone())
                },
                |(mut server, data_buf)| {
                    let mut total_written = 0;
                    let mut tls_output_buf = vec![0u8; BUFFER_SIZE];

                    while total_written < data_buf.len() {
                        let end = (total_written + CHUNK_SIZE).min(data_buf.len());
                        server
                            .writer()
                            .write_all(&data_buf[total_written..end])
                            .unwrap();
                        total_written = end;

                        while server.wants_write() {
                            let sz = server.write_tls(&mut &mut tls_output_buf[..]).unwrap();
                            if sz == 0 {
                                break;
                            }
                        }
                    }
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let setup = BenchSetup::new();
    let tls13_suites = rustls_aegis::provider(get_default_provider())
        .tls13_cipher_suites
        .iter()
        .copied()
        .collect::<Vec<_>>();

    let mut group = c.benchmark_group("Decryption throughput");
    group.throughput(Throughput::Bytes(DATA_SIZE as u64));

    for &suite in &tls13_suites {
        let provider = Arc::new(CryptoProvider {
            tls13_cipher_suites: vec![suite].into(),
            ..rustls_aegis::provider(get_default_provider())
        });
        let (client_cfg, server_cfg) = make_configs(
            provider,
            setup.root_store.clone(),
            setup.cert.clone(),
            setup.key.clone_key(),
        );

        group.bench_function(format!("{:?}", suite.common.suite), |b| {
            b.iter_batched(
                || {
                    // Setup: create encrypted data (NOT measured)
                    let (client, mut server) = handshake(client_cfg.clone(), server_cfg.clone());
                    let mut encrypted_data = Vec::new();

                    let mut total_written = 0;
                    while total_written < setup.data_buf.len() {
                        let end = (total_written + CHUNK_SIZE).min(setup.data_buf.len());
                        server
                            .writer()
                            .write_all(&setup.data_buf[total_written..end])
                            .unwrap();
                        total_written = end;

                        while server.wants_write() {
                            let mut buf = vec![0u8; BUFFER_SIZE];
                            let sz = server.write_tls(&mut &mut buf[..]).unwrap();
                            if sz == 0 {
                                break;
                            }
                            encrypted_data.extend_from_slice(&buf[..sz]);
                        }
                    }

                    (client, encrypted_data)
                },
                |(mut client, encrypted_data)| {
                    let mut offset = 0;
                    let mut plaintext_buf = vec![0u8; BUFFER_SIZE];
                    while offset < encrypted_data.len() {
                        let chunk_size = (encrypted_data.len() - offset).min(BUFFER_SIZE);
                        let n = client
                            .read_tls(&mut &encrypted_data[offset..offset + chunk_size])
                            .unwrap();
                        offset += n;

                        client.process_new_packets().unwrap();

                        loop {
                            match client.reader().read(&mut plaintext_buf) {
                                Ok(0) => break,
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(e) => panic!("BENCH ERROR {:?}: {}", suite.common.suite, e),
                            }
                        }
                    }
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(40)
        .measurement_time(Duration::from_secs(60))
        .warm_up_time(Duration::from_millis(500));
    targets = bench_encryption, bench_decryption
}
criterion_main!(benches);
