//! The Windows counterpart of the group-/world-writable `acl.toml` warning
//! (ADR-0035 decision 24, `docs/design/threat-model.md` §4 E): a file whose
//! DACL lets a principal other than its owner, `SYSTEM` and `Administrators`
//! write to it, or has no DACL at all, is a policy any such principal can
//! rewrite. Like the unix check this warns and never denies (see the call
//! site in [`super::PolicySource`]), and qsh does not write `acl.toml`
//! itself (ADR-0017), so it never repairs the DACL either.
//!
//! The decision is a pure function over the ACEs as values, so it runs on
//! every platform; only reading the ACEs out of the file is Windows code.

/// `FILE_WRITE_DATA`.
const FILE_WRITE_DATA: u32 = 0x0002;
/// `FILE_APPEND_DATA`.
const FILE_APPEND_DATA: u32 = 0x0004;
/// `WRITE_DAC`.
const WRITE_DAC: u32 = 0x0004_0000;
/// `WRITE_OWNER`.
const WRITE_OWNER: u32 = 0x0008_0000;
/// `GENERIC_WRITE`.
const GENERIC_WRITE: u32 = 0x4000_0000;
/// `GENERIC_ALL`.
const GENERIC_ALL: u32 = 0x1000_0000;

/// The access bits that let a principal change the file or its access
/// control.
const WRITE_RIGHTS: u32 =
    FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;

/// `SYSTEM`.
pub(super) const SID_SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub(super) const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// `Everyone`, the principal a missing DACL grants everything to.
const SID_EVERYONE: &str = "S-1-1-0";

/// One ACE of a file's DACL, as far as this check reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ace {
    /// The ACE allows (`true`) or denies or audits (`false`). Only allowing
    /// ACEs can expose the file, and a deny is not weighed against them: a
    /// DACL that both grants and denies write to the same SID is rare, and
    /// the warning is a diagnostic that errs toward speaking.
    pub allows: bool,
    /// `INHERIT_ONLY_ACE`: the ACE is for the children of a container and
    /// does not apply to this object.
    pub inherit_only: bool,
    /// The trustee, in `S-1-...` text.
    pub sid: String,
    pub mask: u32,
}

/// A file's DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Dacl {
    /// No DACL: the system gives everyone full access.
    Null,
    Aces(Vec<Ace>),
}

/// Why a file is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reason {
    /// An allowing ACE grants a write right to a principal outside the
    /// trusted ones.
    WriteAce,
    /// The file has no DACL.
    NullDacl,
}

impl Reason {
    /// The machine-stable word the warning carries.
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::WriteAce => "write_ace",
            Self::NullDacl => "null_dacl",
        }
    }
}

/// What the check found, structurally: no ACE masks, no names, nothing from
/// the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Exposure {
    pub reason: Reason,
    /// The first offending SID (`Everyone` for a missing DACL).
    pub sid: String,
    /// How many distinct SIDs are offending.
    pub sid_count: usize,
}

/// Whether `dacl` lets someone outside `trusted` write to the file.
/// `trusted` holds the SIDs that may: the file's owner and the account qsh
/// runs as (they differ when the file's owner is the `Administrators` group),
/// plus [`SID_SYSTEM`] and [`SID_ADMINISTRATORS`].
pub(super) fn exposure(dacl: &Dacl, trusted: &[String]) -> Option<Exposure> {
    let aces = match dacl {
        Dacl::Null => {
            return Some(Exposure {
                reason: Reason::NullDacl,
                sid: SID_EVERYONE.to_string(),
                sid_count: 1,
            });
        }
        Dacl::Aces(aces) => aces,
    };
    let mut offending: Vec<&str> = Vec::new();
    for ace in aces {
        if ace.allows
            && !ace.inherit_only
            && ace.mask & WRITE_RIGHTS != 0
            && !trusted.iter().any(|sid| sid.eq_ignore_ascii_case(&ace.sid))
            && !offending.contains(&ace.sid.as_str())
        {
            offending.push(&ace.sid);
        }
    }
    let first = offending.first()?;
    Some(Exposure {
        reason: Reason::WriteAce,
        sid: (*first).to_string(),
        sid_count: offending.len(),
    })
}

#[cfg(windows)]
pub(super) use read::warn_if_writable_by_others;

#[cfg(windows)]
mod read {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::io::AsRawHandle as _;
    use std::path::Path;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, OWNER_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    };

    use super::{Ace, Dacl, SID_ADMINISTRATORS, SID_SYSTEM, exposure};
    use crate::fsutil::dacl::{sid_ptr_to_string, sid_to_string, token_user_sid};

    /// `INHERIT_ONLY_ACE`.
    const INHERIT_ONLY_ACE: u8 = 0x08;

    /// Windows half of the writable-file warning installed in the policy
    /// loader (`acl/load.rs`). `tracing::warn!`, same target
    /// and structural-fields-only discipline as the unix check: the path,
    /// the first offending SID and how many SIDs offend, never an ACE mask,
    /// an account name or a byte of the file. A file whose security cannot be
    /// read is left silent, as the unix check is when it cannot stat.
    pub(in super::super) fn warn_if_writable_by_others(path: &Path, file: &File) {
        let Ok((owner, dacl)) = read_owner_and_dacl(file) else {
            return;
        };
        let mut trusted = vec![
            owner,
            SID_SYSTEM.to_string(),
            SID_ADMINISTRATORS.to_string(),
        ];
        if let Ok(user) = token_user_sid().and_then(|sid| sid_to_string(&sid)) {
            trusted.push(user);
        }
        if let Some(found) = exposure(&dacl, &trusted) {
            tracing::warn!(
                target: "qsh::acl",
                path = %path.display(),
                reason = found.reason.code(),
                sid = %found.sid,
                sid_count = found.sid_count,
                "acl.toml's DACL lets a principal other than its owner, SYSTEM and \
                 Administrators write to it; that principal can grant itself anything \
                 this policy is capable of granting"
            );
        }
    }

    /// The owner SID text and the DACL of the file `file` is open on.
    fn read_owner_and_dacl(file: &File) -> io::Result<(String, Dacl)> {
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        // SAFETY: the handle is open for the call (a `File::open` handle has
        // `READ_CONTROL`) and the out-pointers are locals.
        let rc = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        // The owner SID and the ACL point into `descriptor`, which is freed
        // once both are turned into values.
        let result = (|| {
            // SAFETY: `owner` points at a SID inside `descriptor`, or is
            // null, which is checked.
            let owner = if owner.is_null() {
                String::new()
            } else {
                unsafe { sid_ptr_to_string(owner) }?
            };
            Ok((owner, read_aces(dacl)?))
        })();
        // SAFETY: allocated by `GetSecurityInfo` with `LocalAlloc`.
        unsafe { LocalFree(descriptor) };
        result
    }

    fn read_aces(dacl: *mut ACL) -> io::Result<Dacl> {
        if dacl.is_null() {
            return Ok(Dacl::Null);
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` is a valid ACL inside the caller's descriptor.
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut aces = Vec::new();
        for index in 0..info.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the ACE count and the ACE lives in `dacl`.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: every ACE starts with an `ACE_HEADER`.
            let header = unsafe { *ace.cast::<ACE_HEADER>() };
            let allows = header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8
                || header.AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE as u8;
            // An allow ACE and its callback form continue with the mask and
            // the SID; any other kind (deny, audit, object ACEs) grants
            // nothing to this object and is not read further.
            if !allows {
                continue;
            }
            // SAFETY: an allowing ACE is laid out as an `ACCESS_ALLOWED_ACE`.
            let (mask, sid) = unsafe {
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                (
                    (*allowed).Mask,
                    (&raw mut (*allowed).SidStart).cast::<c_void>(),
                )
            };
            aces.push(Ace {
                allows,
                inherit_only: header.AceFlags & INHERIT_ONLY_ACE != 0,
                // SAFETY: the SID follows the mask inside the ACE.
                sid: unsafe { sid_ptr_to_string(sid) }?,
                mask,
            });
        }
        Ok(Dacl::Aces(aces))
    }
}

#[cfg(test)]
mod tests;
