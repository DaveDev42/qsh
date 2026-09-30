use super::*;
use proptest::prelude::*;

/// Test-only key generated once in a throwaway HOME; the file holds the
/// key file bytes as hex so no PEM header line lives in the repository.
const GOLDEN_HEX: &str = include_str!("../../testdata/openssh/ed25519_golden.hex");
const GOLDEN_SEED_HEX: &str = "e0a3d490ac207b6a613ef0d9ece980a23fc4fae80a11d6e8bb87836df909f6f0";
const GOLDEN_PUBLIC_HEX: &str = "c5823db0474406fc8765512b49112913f128b2418dfbaddee18ae88c7f54b23f";
/// `ssh-keygen -lf` output for the golden key (fingerprint checked by the
/// consumers that have a hash; here it documents the fixture).
#[allow(dead_code)]
const GOLDEN_SSH_FINGERPRINT: &str = "SHA256:XxSbKVKvD1gyArwLk6oM3TZnt9rZogny7tQgxWR2bek";
const GOLDEN_PUB_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMWCPbBHRAb8h2VRK0kRKRPxKLJBjfut3uGK6Ix/VLI/ qsh-test-only";

fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.bytes())
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    assert_eq!(digits.len() % 2, 0);
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn golden_file() -> Vec<u8> {
    unhex(GOLDEN_HEX)
}

fn golden_body() -> Vec<u8> {
    decode_pem_envelope(&golden_file()).unwrap().to_vec()
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Every field of the binary layout, defaulting to the golden key, so a
/// test can bend exactly one thing.
struct Spec {
    cipher: Vec<u8>,
    kdf: Vec<u8>,
    kdf_options: Vec<u8>,
    nkeys: u32,
    pub_type: Vec<u8>,
    public: Vec<u8>,
    check: (u32, u32),
    priv_type: Vec<u8>,
    priv_public: Vec<u8>,
    secret: Vec<u8>,
    comment: Vec<u8>,
}

impl Spec {
    fn golden() -> Self {
        let seed = unhex(GOLDEN_SEED_HEX);
        let public = unhex(GOLDEN_PUBLIC_HEX);
        let mut secret = seed;
        secret.extend_from_slice(&public);
        Spec {
            cipher: b"none".to_vec(),
            kdf: b"none".to_vec(),
            kdf_options: Vec::new(),
            nkeys: 1,
            pub_type: b"ssh-ed25519".to_vec(),
            public: public.clone(),
            check: (0x1234_5678, 0x1234_5678),
            priv_type: b"ssh-ed25519".to_vec(),
            priv_public: public,
            secret,
            comment: b"qsh-test-only".to_vec(),
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut public_section = Vec::new();
        put_string(&mut public_section, &self.pub_type);
        put_string(&mut public_section, &self.public);

        let mut private = Vec::new();
        private.extend_from_slice(&self.check.0.to_be_bytes());
        private.extend_from_slice(&self.check.1.to_be_bytes());
        put_string(&mut private, &self.priv_type);
        put_string(&mut private, &self.priv_public);
        put_string(&mut private, &self.secret);
        put_string(&mut private, &self.comment);
        let mut pad = 1u8;
        while private.len() % NONE_BLOCK != 0 {
            private.push(pad);
            pad += 1;
        }

        let mut out = MAGIC.to_vec();
        put_string(&mut out, &self.cipher);
        put_string(&mut out, &self.kdf);
        put_string(&mut out, &self.kdf_options);
        out.extend_from_slice(&self.nkeys.to_be_bytes());
        put_string(&mut out, &public_section);
        put_string(&mut out, &private);
        out
    }
}

#[test]
fn parse_openssh_private_key_reads_an_unencrypted_ed25519_golden_vector() {
    let key = parse_openssh_private_key(&golden_file()).unwrap();
    assert_eq!(key.seed().as_slice(), unhex(GOLDEN_SEED_HEX));
    assert_eq!(key.public_key().as_slice(), unhex(GOLDEN_PUBLIC_HEX));

    // The wire blob is what `ssh-keygen` prints in the .pub line.
    let b64 = GOLDEN_PUB_LINE.split(' ').nth(1).unwrap();
    assert_eq!(STANDARD.decode(b64).unwrap(), key.public_wire_blob());

    // The two layers agree with the combined entry point.
    let via_layers = parse_openssh_key_body(&golden_body()).unwrap();
    assert_eq!(via_layers.seed(), key.seed());
}

#[test]
fn parse_openssh_private_key_accepts_crlf_and_surrounding_whitespace() {
    let text = String::from_utf8(golden_file()).unwrap();
    let crlf = format!("\n  {}\r\n\r\n", text.trim().replace('\n', "\r\n"));
    assert!(parse_openssh_private_key(crlf.as_bytes()).is_ok());
}

#[test]
fn parse_openssh_private_key_rejects_an_encrypted_key_as_encrypted() {
    let mut spec = Spec::golden();
    spec.cipher = b"aes256-ctr".to_vec();
    spec.kdf = b"bcrypt".to_vec();
    spec.kdf_options = vec![0u8; 24];
    assert_eq!(
        parse_openssh_key_body(&spec.build()).err(),
        Some(OpensshKeyError::Encrypted)
    );
}

#[test]
fn parse_openssh_private_key_rejects_rsa_and_ecdsa_as_unsupported_key_type() {
    for key_type in [&b"ssh-rsa"[..], b"ecdsa-sha2-nistp256"] {
        let mut spec = Spec::golden();
        spec.pub_type = key_type.to_vec();
        spec.public = vec![7u8; 65];
        spec.priv_type = key_type.to_vec();
        assert_eq!(
            parse_openssh_key_body(&spec.build()).err(),
            Some(OpensshKeyError::UnsupportedKeyType),
            "{}",
            String::from_utf8_lossy(key_type)
        );
    }
}

#[test]
fn parse_openssh_private_key_rejects_every_truncation_of_the_golden_vector() {
    let body = golden_body();
    for len in 0..body.len() {
        assert!(
            parse_openssh_key_body(&body[..len]).is_err(),
            "body truncated to {len} bytes was accepted"
        );
    }
    // Armored form: any cut that loses part of the closing line fails. (A
    // cut that only drops the final newline is still a valid file.)
    let file = golden_file();
    let armored_len = file.trim_ascii().len();
    for len in 0..armored_len {
        assert!(
            parse_openssh_private_key(&file[..len]).is_err(),
            "file truncated to {len} bytes was accepted"
        );
    }
}

#[test]
fn parse_openssh_private_key_rejects_a_length_prefix_larger_than_the_input_before_allocating() {
    // A 4 GiB - 1 prefix on the cipher name, and again on later strings.
    let mut body = MAGIC.to_vec();
    body.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        parse_openssh_key_body(&body).err(),
        Some(OpensshKeyError::Malformed)
    );

    let mut spec = Spec::golden().build();
    // Overwrite the length of the public-key section (after the 15-byte
    // magic, cipher "none", kdf "none", empty options, and the key count).
    let at = MAGIC.len() + (4 + 4) + (4 + 4) + 4 + 4;
    spec[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        parse_openssh_key_body(&spec).err(),
        Some(OpensshKeyError::Malformed)
    );
}

#[test]
fn parse_openssh_private_key_rejects_mismatched_check_ints() {
    let mut spec = Spec::golden();
    spec.check = (1, 2);
    assert_eq!(
        parse_openssh_key_body(&spec.build()).err(),
        Some(OpensshKeyError::CheckIntMismatch)
    );
}

#[test]
fn parse_openssh_private_key_rejects_a_public_key_that_differs_between_sections() {
    let mut spec = Spec::golden();
    spec.priv_public[0] ^= 1;
    assert_eq!(
        parse_openssh_key_body(&spec.build()).err(),
        Some(OpensshKeyError::PublicKeyMismatch)
    );

    let mut spec = Spec::golden();
    let last = spec.secret.len() - 1;
    spec.secret[last] ^= 1;
    assert_eq!(
        parse_openssh_key_body(&spec.build()).err(),
        Some(OpensshKeyError::PublicKeyMismatch)
    );
}

#[test]
fn parse_openssh_private_key_rejection_table() {
    type Bend = fn(&mut Spec);
    let cases: [(&str, Bend, OpensshKeyError); 7] = [
        ("two keys", |s| s.nkeys = 2, OpensshKeyError::Malformed),
        ("zero keys", |s| s.nkeys = 0, OpensshKeyError::Malformed),
        (
            "cipher none with a bcrypt kdf",
            |s| s.kdf = b"bcrypt".to_vec(),
            OpensshKeyError::Malformed,
        ),
        (
            "cipher none with kdf options",
            |s| s.kdf_options = vec![1],
            OpensshKeyError::Malformed,
        ),
        (
            "security-key ed25519",
            |s| {
                s.pub_type = b"sk-ssh-ed25519@openssh.com".to_vec();
                s.priv_type = b"sk-ssh-ed25519@openssh.com".to_vec();
            },
            OpensshKeyError::UnsupportedKeyType,
        ),
        (
            "ed25519 certificate",
            |s| {
                s.pub_type = b"ssh-ed25519-cert-v01@openssh.com".to_vec();
                s.priv_type = b"ssh-ed25519-cert-v01@openssh.com".to_vec();
            },
            OpensshKeyError::UnsupportedKeyType,
        ),
        (
            "secret of the wrong length",
            |s| s.secret.truncate(40),
            OpensshKeyError::Malformed,
        ),
    ];
    for (name, bend, want) in cases {
        let mut spec = Spec::golden();
        bend(&mut spec);
        assert_eq!(
            parse_openssh_key_body(&spec.build()).err(),
            Some(want),
            "{name}"
        );
    }
}

#[test]
fn parse_openssh_private_key_rejects_bad_padding_and_trailing_bytes() {
    // A two-byte comment leaves seven padding bytes.
    let mut spec = Spec::golden();
    spec.comment = b"xx".to_vec();
    let good = spec.build();
    assert!(parse_openssh_key_body(&good).is_ok());
    // Trailing garbage after the private section.
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        parse_openssh_key_body(&trailing).err(),
        Some(OpensshKeyError::Malformed)
    );
    // Break the last padding byte.
    let mut bad_pad = good;
    let last = bad_pad.len() - 1;
    bad_pad[last] = 0xff;
    assert_eq!(
        parse_openssh_key_body(&bad_pad).err(),
        Some(OpensshKeyError::Malformed)
    );
}

#[test]
fn parse_openssh_private_key_rejects_missing_or_garbled_armor() {
    let file = String::from_utf8(golden_file()).unwrap();
    for bad in [
        String::new(),
        "not a key".to_owned(),
        file.replace("-----END", "-----FIN"),
        {
            // Join the armor line to the body so the header has no newline.
            let begin = std::str::from_utf8(PEM_BEGIN).unwrap();
            file.replacen(&format!("{begin}\n"), begin, 1)
        },
        file.replacen("b3Blbn", "!3Blbn", 1),
    ] {
        assert!(parse_openssh_private_key(bad.as_bytes()).is_err());
    }
    let big = vec![b'A'; OPENSSH_KEY_INPUT_MAX + 1];
    assert_eq!(
        parse_openssh_private_key(&big).err(),
        Some(OpensshKeyError::TooLarge)
    );
    assert_eq!(
        parse_openssh_key_body(&big).err(),
        Some(OpensshKeyError::TooLarge)
    );
}

#[test]
fn openssh_seed_debug_output_never_contains_key_bytes() {
    let key = parse_openssh_private_key(&golden_file()).unwrap();
    let rendered = format!("{key:?} {key:#?}");
    let seed = unhex(GOLDEN_SEED_HEX);
    assert!(!rendered.contains(GOLDEN_SEED_HEX));
    assert!(!rendered.contains(&format!("{seed:?}")));
    assert!(!rendered.contains(&format!("{:?}", key.seed())));
    for err in [
        OpensshKeyError::Encrypted,
        OpensshKeyError::UnsupportedKeyType,
        OpensshKeyError::Malformed,
        OpensshKeyError::CheckIntMismatch,
        OpensshKeyError::PublicKeyMismatch,
        OpensshKeyError::TooLarge,
    ] {
        assert!(!format!("{err} {err:?}").contains(GOLDEN_SEED_HEX));
    }
}

fn ed25519_line_blob() -> String {
    GOLDEN_PUB_LINE.split(' ').nth(1).unwrap().to_owned()
}

#[test]
fn parse_authorized_keys_classifies_each_line_independently() {
    let blob = ed25519_line_blob();
    let public: [u8; 32] = unhex(GOLDEN_PUBLIC_HEX).try_into().unwrap();
    let rsa_blob = STANDARD.encode({
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-rsa");
        put_string(&mut b, &[1, 2, 3]);
        b
    });
    let input = format!(
        "# a comment\r\n\
         \r\n\
         ssh-ed25519 {blob} laptop key\r\n\
         command=\"echo a b\",no-pty ssh-ed25519 {blob}\n\
         from=\"10.0.0.1, 10.0.0.2\" ssh-rsa {rsa_blob} old\n\
         ssh-ed25519 !!!notbase64\n\
         ssh-ed25519 {rsa_blob}\n\
         command=\"unterminated ssh-ed25519 {blob}\n\
         \n\
         ssh-ed25519\n\
         ssh-ed25519 {blob}"
    );
    let got = parse_authorized_keys(input.as_bytes());
    let lines: Vec<usize> = got.iter().map(|l| l.line).collect();
    assert_eq!(lines, [3, 4, 5, 6, 7, 8, 10, 11]);
    assert_eq!(
        got[0].entry,
        AuthorizedKeysEntry::Ed25519 {
            public_key: public,
            restricted: false,
            comment: "laptop key",
        }
    );
    assert_eq!(
        got[1].entry,
        AuthorizedKeysEntry::Ed25519 {
            public_key: public,
            restricted: true,
            comment: "",
        }
    );
    assert_eq!(
        got[2].entry,
        AuthorizedKeysEntry::OtherKeyType {
            key_type: "ssh-rsa",
            restricted: true,
        }
    );
    for (i, name) in [
        (3, "bad base64"),
        (4, "blob type disagrees with key type"),
        (5, "unterminated quote"),
        (6, "missing blob"),
    ] {
        assert_eq!(got[i].entry, AuthorizedKeysEntry::Malformed, "{name}");
    }
    assert_eq!(
        got[7].entry,
        AuthorizedKeysEntry::Ed25519 {
            public_key: public,
            restricted: false,
            comment: "",
        }
    );
}

#[test]
fn parse_authorized_keys_marks_invalid_utf8_lines_malformed() {
    let got = parse_authorized_keys(b"ssh-ed25519 \xff\xfe\n");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].entry, AuthorizedKeysEntry::Malformed);
}

proptest! {
    #[test]
    fn parse_openssh_private_key_never_panics_on_a_bitflipped_golden_vector(
        flips in proptest::collection::vec((0usize..400, 0u8..8), 1..6),
        cut in proptest::option::of(0usize..420),
    ) {
        let mut file = golden_file();
        for (at, bit) in flips {
            let i = at % file.len();
            file[i] ^= 1 << bit;
        }
        if let Some(cut) = cut {
            file.truncate(cut);
        }
        let _ = parse_openssh_private_key(&file);
        let _ = parse_authorized_keys(&file);
    }

    #[test]
    fn parse_openssh_key_body_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _ = parse_openssh_key_body(&bytes);
        let _ = decode_pem_envelope(&bytes);
        let _ = parse_authorized_keys(&bytes);
    }
}
