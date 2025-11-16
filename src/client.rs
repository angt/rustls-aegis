use clap::Parser;
use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use url::Url;

#[derive(Parser, Debug)]
#[command(name = "client")]
#[command(about = "TLS 1.3 client with AEGIS cipher suite support", long_about = None)]
struct Args {
    #[arg(default_value = "https://aegis.libsodium.org")]
    url: String,

    #[arg(short, long)]
    cipher_suite: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let url = Url::parse(&args.url)?;
    let hostname = url
        .host_str()
        .ok_or("Invalid URL: missing hostname")?
        .to_string();
    let port = url.port().unwrap_or(443);

    if url.scheme() != "https" {
        return Err("Only HTTPS URLs are supported".into());
    }
    #[cfg(feature = "aws-lc-rs")]
    let default_provider = rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER.clone();
    #[cfg(feature = "ring")]
    let default_provider = rustls::crypto::ring::DEFAULT_PROVIDER.clone();
    let mut provider = rustls_aegis::provider(default_provider);

    println!("Available TLS 1.3 Cipher suites:");
    for (i, suite) in provider.tls13_cipher_suites.iter().enumerate() {
        println!("  {}: {:?}", i, suite.common.suite);
    }

    if let Some(ref suite_selection) = args.cipher_suite {
        if let Ok(index) = suite_selection.parse::<usize>() {
            if index < provider.tls13_cipher_suites.len() {
                let selected = provider.tls13_cipher_suites[index];
                provider.tls13_cipher_suites = Cow::Owned(vec![selected]);
                println!(
                    "\nUsing cipher suite {}: {:?}",
                    index, selected.common.suite
                );
            } else {
                return Err(format!(
                    "Invalid cipher suite index: {}. Must be 0-{}",
                    index,
                    provider.tls13_cipher_suites.len() - 1
                )
                .into());
            }
        } else {
            let suite_name = suite_selection.to_uppercase();
            let filtered: Vec<_> = provider
                .tls13_cipher_suites
                .iter()
                .filter(|s| format!("{:?}", s.common.suite).contains(&suite_name))
                .copied()
                .collect();

            if filtered.is_empty() {
                return Err(format!("No cipher suite matching '{}' found", suite_selection).into());
            }
            println!("\nFiltered to {} matching cipher suite(s)", filtered.len());
            provider.tls13_cipher_suites = Cow::Owned(filtered);
        }
    }

    let _ = rustls::crypto::CryptoProvider::install_default(provider.clone());

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = rustls::ClientConfig::builder(Arc::new(provider))
        .with_root_certificates(root_store)
        .with_no_client_auth()?;

    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_owned())?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let address = format!("{}:{}", hostname, port);
    let mut sock = TcpStream::connect(&address)?;
    println!("Connected to {}", address);

    loop {
        if conn.is_handshaking() {
            conn.complete_io(&mut sock)?;
        } else {
            break;
        }
    }

    println!("TLS handshake completed!");
    println!(
        "Negotiated cipher suite: {:?}",
        conn.negotiated_cipher_suite()
    );
    println!("Protocol version: {:?}", conn.protocol_version());

    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, hostname
    );
    conn.writer().write_all(request.as_bytes())?;
    conn.complete_io(&mut sock)?;

    let mut response = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        match conn.reader().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                conn.complete_io(&mut sock)?;
                continue;
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.to_string()
                        .contains("closed connection without sending TLS close_notify")
                {
                    break;
                }
                return Err(e.into());
            }
        }
        match conn.complete_io(&mut sock) {
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.to_string()
                        .contains("closed connection without sending TLS close_notify") =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    println!("\nResponse:\n{}", String::from_utf8_lossy(&response));

    Ok(())
}
