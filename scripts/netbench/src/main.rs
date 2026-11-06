//! `netbench` CLI. The shell driver `scripts/netbench/run.sh` builds the
//! network namespaces and calls these subcommands:
//!
//! ```text
//! netbench profile-env FILE            print NB_* shell variables for the link
//! netbench check FILE...               parse and validate profile files
//! netbench serve  --profile F --bind IP --ready F --cert F
//! netbench client --profile F --bind IP --ready F --cert F   (prints one JSON line)
//! ```

use anyhow::{Context, Result, bail};
use qsh_netbench::net::{self, Identity};
use qsh_netbench::profile::{Isolation, Kind, Path, Profile};
use qsh_netbench::result::{BenchResult, Metrics, round3};
use qsh_netbench::{nested, scenario};
use std::net::SocketAddr;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("netbench: {e:#}");
        std::process::exit(1);
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .with_context(|| format!("missing {name}"))
}

fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("profile-env") => {
            let f = args.get(1).context("usage: profile-env FILE")?;
            print!("{}", Profile::load(std::path::Path::new(f))?.shell_env());
            Ok(())
        }
        Some("check") => {
            for f in &args[1..] {
                Profile::load(std::path::Path::new(f))?;
            }
            Ok(())
        }
        Some(cmd @ ("serve" | "client")) => {
            let p = Profile::load(std::path::Path::new(flag(args, "--profile")?))?;
            let bind: std::net::IpAddr = flag(args, "--bind")?.parse()?;
            let ready = flag(args, "--ready")?.to_string();
            let cert = flag(args, "--cert")?.to_string();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            rt.block_on(async move {
                if cmd == "serve" {
                    serve(&p, bind, &ready, &cert).await
                } else {
                    client(&p, bind, &ready, &cert).await
                }
            })
        }
        _ => {
            bail!("usage: netbench profile-env|check|serve|client (see scripts/netbench/README.md)")
        }
    }
}

fn write_atomic(path: &str, bytes: &[u8]) -> Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn serve(p: &Profile, bind: std::net::IpAddr, ready: &str, cert_path: &str) -> Result<()> {
    let w = &p.workload;
    let id = Identity::generate()?;
    let keep = net::keep_alive_for(p);
    let ep = net::udp_endpoint(
        SocketAddr::new(bind, 0),
        Some(net::server_config(
            &id,
            w.cc,
            keep,
            w.datagram_send_buffer_kib,
        )?),
    )?;
    write_atomic(cert_path, &id.cert)?;
    write_atomic(ready, ep.local_addr()?.to_string().as_bytes())?;

    let outer = ep.accept().await.context("endpoint closed")?.await?;
    let (inner_ep, conn) = if w.path == Path::Direct {
        (None, outer.clone())
    } else {
        let (e, c) = nested::accept_inner(outer.clone(), w.path, &id, w.cc).await?;
        (Some(e), c)
    };
    let bulk_conn = if w.kind == Kind::BulkEcho && w.isolation == Isolation::SeparateConn {
        ep.accept().await.context("endpoint closed")?.await?
    } else {
        conn.clone()
    };
    match w.kind {
        Kind::Screen => scenario::screen_server(&conn, p).await?,
        Kind::Echo => scenario::echo_server(&conn, p, None).await?,
        Kind::BulkEcho => {
            let yielder = (w.isolation == Isolation::Yield)
                .then(|| qsh_netbench::yielder::Yielder::new(bulk_conn.clone()));
            let (a, b) = tokio::join!(
                scenario::echo_server(&conn, p, yielder.as_ref()),
                scenario::bulk_server(&bulk_conn, p, yielder.as_ref())
            );
            a?;
            b?;
        }
    }
    // Stay up until the client is done reading.
    let _ = tokio::time::timeout(
        Duration::from_secs(u64::from(w.duration_s) + 20),
        conn.closed(),
    )
    .await;
    drop(inner_ep);
    Ok(())
}

async fn client(p: &Profile, bind: std::net::IpAddr, ready: &str, cert_path: &str) -> Result<()> {
    let w = &p.workload;
    let server: SocketAddr = std::fs::read_to_string(ready)?.trim().parse()?;
    let cert = rustls::pki_types::CertificateDer::from(std::fs::read(cert_path)?);
    let keep = net::keep_alive_for(p);
    let mut ep = net::udp_endpoint(SocketAddr::new(bind, 0), None)?;
    ep.set_default_client_config(net::client_config(
        &cert,
        w.cc,
        keep,
        w.datagram_send_buffer_kib,
    )?);

    let outer = ep
        .connect(server, net::SERVER_NAME)?
        .await
        .context("handshake")?;
    let (inner_ep, conn) = if w.path == Path::Direct {
        (None, outer.clone())
    } else {
        let (e, c) = nested::connect_inner(outer.clone(), w.path, &cert, w.cc).await?;
        (Some(e), c)
    };
    let mut m = Metrics::default();
    match w.kind {
        Kind::Screen => scenario::screen_client(&conn, p, &mut m).await?,
        Kind::Echo => scenario::echo_client(&conn, p, &mut m).await?,
        Kind::BulkEcho => {
            let bulk_conn = if w.isolation == Isolation::SeparateConn {
                ep.connect(server, net::SERVER_NAME)?
                    .await
                    .context("bulk handshake")?
            } else {
                conn.clone()
            };
            let pb = p.clone();
            let bulk = tokio::spawn(async move { scenario::bulk_client(&bulk_conn, &pb).await });
            scenario::echo_client(&conn, p, &mut m).await?;
            let bytes = bulk.await??;
            m.bulk_mb_s = Some(scenario::goodput_mb_s(bytes, w.duration_s));
        }
    }
    m.max_datagram_bytes = outer.max_datagram_size().map(|x| x as u64);
    let st = conn.stats();
    m.conn_rtt_ms = Some(round3(st.path.rtt.as_secs_f64() * 1000.0));
    m.lost_packets = Some(st.path.lost_packets);
    println!("{}", BenchResult::new(p, m).to_line());

    conn.close(0u32.into(), b"done");
    outer.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(2), ep.wait_idle()).await;
    drop(inner_ep);
    Ok(())
}
