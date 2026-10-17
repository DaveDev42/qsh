//! Readers and setters the DACL tests share: what a path's DACL actually is
//! on disk, read back with `GetNamedSecurityInfoW` (or, for an object that
//! must not be opened by name such as a pipe instance, `GetSecurityInfo` on
//! a handle the test already holds), and a deny-everything DACL for the
//! unreadable-log row.

use std::ffi::c_void;
use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT,
    SE_KERNEL_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    InitializeAcl, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use super::{DaclSource, ObjectKind, OwnerOnly, to_wide, token_user_sid};

/// One ACE of a DACL as read back.
#[derive(Debug)]
pub(crate) struct Ace {
    pub(crate) ace_type: u8,
    pub(crate) flags: u8,
    pub(crate) mask: u32,
    pub(crate) sid: String,
    pub(crate) is_current_user: bool,
}

/// A path's DACL as read back.
#[derive(Debug)]
pub(crate) struct DaclReport {
    /// `SE_DACL_PROTECTED`: nothing is inherited from the parent.
    pub(crate) protected: bool,
    /// The DACL is absent (everyone has full access).
    pub(crate) null_dacl: bool,
    pub(crate) aces: Vec<Ace>,
}

pub(crate) fn read_dacl(path: &Path) -> DaclReport {
    let wide = to_wide(path).unwrap();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; the out-pointers are locals.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(
        rc,
        0,
        "GetNamedSecurityInfoW({}) failed: {rc}",
        path.display()
    );
    report_and_free(dacl, descriptor)
}

/// [`read_dacl`] for an object the caller already holds a handle to. A named
/// pipe instance is read this way: opening it by name would connect to it.
pub(crate) fn read_dacl_of_handle(handle: HANDLE) -> DaclReport {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: `handle` is a live handle with `READ_CONTROL`; the out-pointers
    // are locals.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(rc, 0, "GetSecurityInfo failed: {rc}");
    report_and_free(dacl, descriptor)
}

/// [`read_dacl_of_handle`] for a kernel object that is not a file, such as a
/// named event. The handle needs `READ_CONTROL`.
pub(crate) fn read_dacl_of_kernel_handle(handle: HANDLE) -> DaclReport {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: `handle` is a live handle with `READ_CONTROL`; the out-pointers
    // are locals.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(rc, 0, "GetSecurityInfo (kernel object) failed: {rc}");
    report_and_free(dacl, descriptor)
}

/// Turn the `dacl` and `descriptor` an `Get*SecurityInfo` call returned into
/// a [`DaclReport`], then free the descriptor.
fn report_and_free(dacl: *mut ACL, descriptor: *mut c_void) -> DaclReport {
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` was just returned by the call above.
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        0
    );
    let user = token_user_sid().unwrap();

    let mut aces = Vec::new();
    if !dacl.is_null() {
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` points into `descriptor`, which is alive until the
        // `LocalFree` below.
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        for index in 0..info.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the ACE count; the ACE lives in `dacl`.
            assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0);
            // SAFETY: every ACE starts with an `ACE_HEADER`; allow and deny
            // ACEs continue with the mask and the SID, which is all read.
            let (header, mask, sid) = unsafe {
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                (
                    *ace.cast::<ACE_HEADER>(),
                    (*allowed).Mask,
                    (&raw mut (*allowed).SidStart).cast::<c_void>(),
                )
            };
            aces.push(Ace {
                ace_type: header.AceType,
                flags: header.AceFlags,
                mask,
                sid: sid_string(sid),
                // SAFETY: both are valid SIDs.
                is_current_user: unsafe { EqualSid(sid, user.as_ptr() as *mut c_void) } != 0,
            });
        }
    }
    // SAFETY: allocated by `Get*SecurityInfo` with `LocalAlloc`.
    unsafe { LocalFree(descriptor) };
    DaclReport {
        protected: control & SE_DACL_PROTECTED != 0,
        null_dacl: dacl.is_null(),
        aces,
    }
}

fn sid_string(sid: *mut c_void) -> String {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID; the result is freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return "<unprintable SID>".to_string();
    }
    // SAFETY: `text` is a NUL-terminated wide string from the call above.
    let out = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    };
    // SAFETY: allocated by `ConvertSidToStringSidW` with `LocalAlloc`.
    unsafe { LocalFree(text.cast()) };
    out
}

/// The pin of ADR-0035 decision 9: a protected DACL holding exactly one
/// allow ACE, for the token user, with `FILE_ALL_ACCESS`, inheriting into
/// children for a directory and not for a file.
pub(crate) fn assert_owner_only(path: &Path, kind: ObjectKind) {
    assert_owner_only_report(&path.display().to_string(), read_dacl(path), kind);
}

/// [`assert_owner_only`] over a report that is already read.
pub(crate) fn assert_owner_only_report(what: &str, report: DaclReport, kind: ObjectKind) {
    let shown = format!("{what}: {report:?}");
    assert!(!report.null_dacl, "no DACL on {shown}");
    assert!(report.protected, "DACL is not protected on {shown}");
    assert_eq!(report.aces.len(), 1, "expected one ACE on {shown}");
    let ace = &report.aces[0];
    assert_eq!(ace.ace_type, ACCESS_ALLOWED_ACE_TYPE as u8, "{shown}");
    assert!(
        ace.is_current_user,
        "ACE is for {}, not the token user, on {shown}",
        ace.sid
    );
    assert_eq!(ace.mask, kind.access(), "{shown}");
    let inherit = match kind {
        ObjectKind::File | ObjectKind::Pipe | ObjectKind::Event => 0,
        // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, and nothing else.
        ObjectKind::Dir => 0x1 | 0x2,
    };
    assert_eq!(ace.flags, inherit, "ACE flags on {shown}");
}

/// Replace the DACL of `path` with an empty, protected one: every access
/// except the owner's implicit `READ_CONTROL` and `WRITE_DAC` is denied.
pub(crate) fn deny_all_access(path: &Path) {
    let mut acl = vec![0u32; size_of::<ACL>().div_ceil(4)];
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    // SAFETY: a zeroed, DWORD-aligned buffer of exactly the header size.
    assert_ne!(
        unsafe { InitializeAcl(acl_ptr, (acl.len() * 4) as u32, ACL_REVISION) },
        0
    );
    let wide = to_wide(path).unwrap();
    // SAFETY: `wide` is NUL-terminated and `acl` is a valid, empty ACL.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl_ptr,
            std::ptr::null(),
        )
    };
    assert_eq!(
        rc,
        0,
        "SetNamedSecurityInfoW({}) failed: {rc}",
        path.display()
    );
}

/// A source whose token-user lookup fails.
pub(crate) struct NoSid;

impl DaclSource for NoSid {
    fn owner_only(&self, _kind: ObjectKind) -> io::Result<OwnerOnly> {
        Err(io::Error::other(
            "injected: the token user SID is unavailable",
        ))
    }
    fn volume_keeps_acls(&self, _path: &Path) -> io::Result<bool> {
        Ok(true)
    }
}

/// A source for a volume that stores no ACLs.
pub(crate) struct NoAcls;

impl DaclSource for NoAcls {
    fn owner_only(&self, kind: ObjectKind) -> io::Result<OwnerOnly> {
        OwnerOnly::for_sid(&token_user_sid()?, kind)
    }
    fn volume_keeps_acls(&self, _path: &Path) -> io::Result<bool> {
        Ok(false)
    }
}
