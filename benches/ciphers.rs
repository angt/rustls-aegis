use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rustls::client::ClientConnection;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;
use rustls::{ClientConfig, ConnectionCommon, RootCertStore, ServerConfig, SideData};
use rustls_aegis;
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;

fn make_configs(
    provider: Arc<CryptoProvider>,
    root_store: RootCertStore,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone_key())
        .unwrap();
    (Arc::new(client_config), Arc::new(server_config))
}

fn transfer(
    left: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    right: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
) -> usize {
    let mut buf = [0u8; 64 * 1024];
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

fn bench_ciphers(c: &mut Criterion) {
    let tls13_suites = rustls_aegis::provider(default_provider())
        .cipher_suites
        .iter()
        .filter(|cs| cs.tls13().is_some())
        .copied()
        .collect::<Vec<_>>();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = CertificateDer::from(cert.cert);

    let mut root_store = RootCertStore::empty();
    root_store.add(cert.clone()).unwrap();

    let size = 10 * 1024 * 1024;
    let mut group = c.benchmark_group(format!("Transfer of a {} bytes file", size));
    let data_buf = vec![0x42u8; size];

    for suite in &tls13_suites {
        let provider = Arc::new(CryptoProvider {
            cipher_suites: vec![*suite],
            ..rustls_aegis::provider(default_provider())
        });
        let (client_cfg, server_cfg) =
            make_configs(provider, root_store.clone(), cert.clone(), key.clone_key());
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{:?}", suite.suite()), |b| {
            b.iter_batched(
                || {
                    let (client, server) = handshake(client_cfg.clone(), server_cfg.clone());
                    (client, server, data_buf.clone())
                },
                |(mut client, mut server, data_buf)| {
                    const CHUNK_SIZE: usize = 16384;
                    let mut read_buf = [0u8; CHUNK_SIZE];
                    let mut total_sent = 0;
                    let mut total_received = 0;
                    while total_sent < data_buf.len() || total_received < data_buf.len() {
                        if total_sent < data_buf.len() {
                            let end = (total_sent + CHUNK_SIZE).min(data_buf.len());
                            if let Err(e) = server.writer().write_all(&data_buf[total_sent..end]) {
                                panic!("BENCH ERROR {:?}: {}", suite.suite(), e);
                            }
                            total_sent = end;
                        }
                        if server.wants_write() {
                            transfer(&mut server, &mut client);
                        }
                        if let Err(e) = client.process_new_packets() {
                            panic!("BENCH ERROR {:?}: {}", suite.suite(), e);
                        }
                        loop {
                            let n = match client.reader().read(&mut read_buf) {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(e) => panic!("BENCH ERROR {:?}: {}", suite.suite(), e),
                            };
                            total_received += n;
                        }
                        if client.wants_write() {
                            transfer(&mut client, &mut server);
                            if let Err(e) = server.process_new_packets() {
                                panic!("BENCH ERROR {:?}: {}", suite.suite(), e);
                            }
                        }
                    }
                    if total_received != data_buf.len() {
                        panic!("BENCH ERROR {:?}: received != sent", suite.suite());
                    }
                },
                BatchSize::SmallInput,
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
    targets = bench_ciphers
}
criterion_main!(benches);
