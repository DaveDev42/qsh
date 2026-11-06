//! A loopback HTTP server for release assets: the stand-in for GitHub in the
//! remote install tests (ADR-0051 decision 3). It serves bytes registered
//! with [`AssetServer::put`] under `GET /<path>`, answers anything else with
//! 404, and records the path of every request. Plain HTTP on `127.0.0.1`
//! only; nothing leaves the machine.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use sha2::{Digest as _, Sha256};

/// The server. Dropping it stops the thread.
pub struct AssetServer {
    addr: SocketAddr,
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    hits: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AssetServer {
    /// Start on a free loopback port.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the asset server");
        let addr = listener.local_addr().expect("local addr");
        let files: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::default();
        let hits: Arc<Mutex<Vec<String>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (files, hits, stop) = (files.clone(), hits.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(stream) = stream {
                        let _ = serve_one(stream, &files, &hits);
                    }
                }
            })
        };
        Self {
            addr,
            files,
            hits,
            stop,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`: what `QSH_RELEASE_BASE_URL` takes.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Serve `bytes` at `path` (no leading slash), replacing what was there.
    pub fn put(&self, path: &str, bytes: &[u8]) {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), bytes.to_vec());
    }

    /// Publish a release under `tag`: the archive `asset` and a
    /// `SHA256SUMS` that lists it with `digest` (the real sha256 of `bytes`
    /// when `None`). Returns the digest listed.
    pub fn put_release(
        &self,
        tag: &str,
        asset: &str,
        bytes: &[u8],
        digest: Option<&str>,
    ) -> String {
        let digest = digest.map_or_else(|| sha256_hex(bytes), str::to_string);
        self.put(&format!("{tag}/{asset}"), bytes);
        self.put(
            &format!("{tag}/SHA256SUMS"),
            format!("{digest}  {asset}\n").as_bytes(),
        );
        digest
    }

    /// The request paths seen so far, oldest first, without the leading `/`.
    pub fn requests(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }
}

impl Drop for AssetServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn serve_one(
    stream: TcpStream,
    files: &Mutex<BTreeMap<String, Vec<u8>>>,
    hits: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    // Drain the headers.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
    }
    let path = request
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    let body = files.lock().unwrap().get(&path).cloned();
    hits.lock().unwrap().push(path);
    let mut out = stream;
    match body {
        Some(body) => {
            write!(
                out,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            out.write_all(&body)?;
        }
        None => out.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?,
    }
    out.flush()
}
