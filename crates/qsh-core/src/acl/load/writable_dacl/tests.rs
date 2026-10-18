use super::*;

const OWNER: &str = "S-1-5-21-1-2-3-1001";
const USER_OTHER: &str = "S-1-5-21-1-2-3-1002";
const EVERYONE: &str = "S-1-1-0";
const USERS: &str = "S-1-5-32-545";

/// `FILE_GENERIC_READ`: read data, read attributes, read EA, read control,
/// synchronize.
const READ_ONLY: u32 = 0x0012_0089;
/// `FILE_ALL_ACCESS`.
const FULL: u32 = 0x001F_01FF;

fn trusted() -> Vec<String> {
    vec![
        OWNER.to_string(),
        SID_SYSTEM.to_string(),
        SID_ADMINISTRATORS.to_string(),
    ]
}

fn allow(sid: &str, mask: u32) -> Ace {
    Ace {
        allows: true,
        inherit_only: false,
        sid: sid.to_string(),
        mask,
    }
}

fn aces(list: Vec<Ace>) -> Dacl {
    Dacl::Aces(list)
}

#[test]
fn acl_dacl_warns_for_a_write_ace_to_another_sid() {
    let found = exposure(
        &aces(vec![allow(OWNER, FULL), allow(EVERYONE, 0x0012_0116)]),
        &trusted(),
    )
    .expect("an Everyone write ACE exposes the file");
    assert_eq!(found.reason, Reason::WriteAce);
    assert_eq!(found.sid, EVERYONE);
    assert_eq!(found.sid_count, 1);
    assert_eq!(found.reason.code(), "write_ace");
}

#[test]
fn acl_dacl_warns_for_each_write_right_alone() {
    for (name, mask) in [
        ("FILE_WRITE_DATA", 0x0002),
        ("FILE_APPEND_DATA", 0x0004),
        ("WRITE_DAC", 0x0004_0000),
        ("WRITE_OWNER", 0x0008_0000),
        ("GENERIC_WRITE", 0x4000_0000),
        ("GENERIC_ALL", 0x1000_0000),
    ] {
        let dacl = aces(vec![allow(USER_OTHER, READ_ONLY | mask)]);
        assert!(
            exposure(&dacl, &trusted()).is_some(),
            "{name} given to another SID must warn"
        );
    }
}

#[test]
fn acl_dacl_is_silent_for_owner_system_and_administrators() {
    let dacl = aces(vec![
        allow(OWNER, FULL),
        allow(SID_SYSTEM, FULL),
        allow(SID_ADMINISTRATORS, FULL),
    ]);
    assert_eq!(exposure(&dacl, &trusted()), None);
    // The trusted set is compared without regard to case, since SID text is
    // not canonicalised by every producer.
    let lower = aces(vec![allow(&SID_ADMINISTRATORS.to_lowercase(), FULL)]);
    assert_eq!(exposure(&lower, &trusted()), None);
}

#[test]
fn acl_dacl_warns_for_a_null_dacl() {
    let found = exposure(&Dacl::Null, &trusted()).expect("a missing DACL is full access to all");
    assert_eq!(found.reason, Reason::NullDacl);
    assert_eq!(found.sid, EVERYONE);
    assert_eq!(found.sid_count, 1);
    assert_eq!(found.reason.code(), "null_dacl");
}

#[test]
fn acl_dacl_ignores_read_only_aces() {
    let dacl = aces(vec![
        allow(OWNER, FULL),
        allow(EVERYONE, READ_ONLY),
        allow(USERS, READ_ONLY),
    ]);
    assert_eq!(exposure(&dacl, &trusted()), None);
}

#[test]
fn acl_dacl_ignores_deny_and_inherit_only_aces() {
    let deny = Ace {
        allows: false,
        ..allow(EVERYONE, FULL)
    };
    let inherit_only = Ace {
        inherit_only: true,
        ..allow(USERS, FULL)
    };
    assert_eq!(exposure(&aces(vec![deny, inherit_only]), &trusted()), None);
}

#[test]
fn acl_dacl_reports_the_first_offender_and_the_count_of_distinct_sids() {
    let dacl = aces(vec![
        allow(OWNER, FULL),
        allow(USERS, 0x0004),
        allow(EVERYONE, FULL),
        // The same SID twice is one offender.
        allow(USERS, 0x0002),
    ]);
    let found = exposure(&dacl, &trusted()).unwrap();
    assert_eq!(found.sid, USERS);
    assert_eq!(found.sid_count, 2);
}

#[test]
fn an_empty_dacl_is_not_exposed() {
    // An empty (not null) DACL denies everyone; there is nothing to warn about.
    assert_eq!(exposure(&aces(vec![]), &trusted()), None);
}
