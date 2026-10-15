//! Owner-only DACLs for the files and directories qsh keeps private on
//! Windows (ADR-0035 decisions 9 and 10), the counterpart of the 0600/0700
//! modes unix gives the same paths.
//!
//! A descriptor is built from the user SID of the process token and passed
//! to `CreateFileW` / `CreateDirectoryW` as `SECURITY_ATTRIBUTES`, so the
//! object has its final DACL from the moment it exists. There is no
//! "create, then fix the ACL" window in which an inherited ACL would let
//! another local user read a key, and nothing here runs `icacls`.
//!
//! - A file gets one `FILE_ALL_ACCESS` allow ACE for that SID.
//! - A directory gets one such ACE with `OBJECT_INHERIT | CONTAINER_INHERIT`,
//!   so what is created inside it by a process that passes no descriptor of
//!   its own is owner-only too.
//! - Both descriptors are protected (`SE_DACL_PROTECTED`): nothing is
//!   inherited from the parent.
//!
//! Failure is closed (decision 10). A SID that cannot be read, or a volume
//! that keeps no ACLs (FAT/exFAT, some network shares), is an error returned
//! before the object is created, never a file with a weaker DACL.
//!
//! The pieces that can fail for environmental reasons sit behind
//! [`DaclSource`], so a test can make them fail and check that nothing was
//! created. Production code uses the process-token implementation through
//! [`open_private_file`] and [`create_private_dir`]; the `_with` forms take
//! the source explicitly.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::FromRawHandle as _;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, CopySid,
    GetLengthSid, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    OBJECT_INHERIT_ACE, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_DATA, GetVolumeInformationW, GetVolumePathNameW, OPEN_ALWAYS,
};
use windows_sys::Win32::System::SystemServices::{
    FILE_PERSISTENT_ACLS, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::PrivateOpen;

/// What a descriptor is for: a file, or a directory that passes its ACE on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectKind {
    File,
    Dir,
}

/// The two environmental inputs of an owner-only object: the descriptor and
/// whether the volume can hold one.
pub(crate) trait DaclSource: Send + Sync {
    /// A protected descriptor with one `FILE_ALL_ACCESS` ACE for the
    /// current user. `Err` when the user SID cannot be determined.
    fn owner_only(&self, kind: ObjectKind) -> io::Result<OwnerOnly>;

    /// Whether the volume that holds `path` (or the nearest existing
    /// ancestor of it) stores ACLs at all.
    fn volume_keeps_acls(&self, path: &Path) -> io::Result<bool>;
}

/// The real source: the user SID of the process token, and the volume flags
/// Windows reports.
pub(crate) struct CurrentUser;

impl DaclSource for CurrentUser {
    fn owner_only(&self, kind: ObjectKind) -> io::Result<OwnerOnly> {
        #[cfg(test)]
        if let Some(source) = injected() {
            return source.owner_only(kind);
        }
        OwnerOnly::for_sid(&token_user_sid()?, kind)
    }

    fn volume_keeps_acls(&self, path: &Path) -> io::Result<bool> {
        #[cfg(test)]
        if let Some(source) = injected() {
            return source.volume_keeps_acls(path);
        }
        volume_keeps_acls(path)
    }
}

/// A security descriptor and the buffers it points into. The
/// `SECURITY_ATTRIBUTES` it hands out are valid while this value lives.
pub(crate) struct OwnerOnly {
    attributes: SECURITY_ATTRIBUTES,
    // Boxed so the address in `attributes` survives a move of `self`; the
    // ACL buffer is a heap allocation that does not move either.
    _descriptor: Box<SECURITY_DESCRIPTOR>,
    _acl: Vec<u32>,
}

impl OwnerOnly {
    /// Build the descriptor for `sid` (a SID in a `u32`-aligned buffer, as
    /// [`token_user_sid`] returns it).
    pub(crate) fn for_sid(sid: &[u32], kind: ObjectKind) -> io::Result<Self> {
        let sid_ptr = sid.as_ptr() as *mut c_void;
        // SAFETY: `sid` holds a SID copied out of the token (or built by a
        // test the same way), which stays borrowed for the call.
        let sid_len = unsafe { GetLengthSid(sid_ptr) } as usize;
        // `ACL` header, then one ACE whose trailing SID is `sid_len` bytes
        // (`ACCESS_ALLOWED_ACE::SidStart` is the first four bytes of it),
        // rounded up to the DWORD alignment ACLs require.
        let acl_len = (size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>()
            + sid_len)
            .next_multiple_of(4);
        let mut acl = vec![0u32; acl_len / 4];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        let flags = match kind {
            ObjectKind::File => 0,
            ObjectKind::Dir => OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        };
        // SAFETY: `acl` is a zeroed, DWORD-aligned buffer of `acl_len` bytes;
        // the SID is valid; each call reports failure through its return value.
        unsafe {
            check(
                InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION),
                "InitializeAcl",
            )?;
            check(
                AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, flags, FILE_ALL_ACCESS, sid_ptr),
                "AddAccessAllowedAceEx",
            )?;
        }
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let descriptor_ptr = (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>();
        // SAFETY: `descriptor` is a boxed `SECURITY_DESCRIPTOR`, the size
        // `InitializeSecurityDescriptor` expects; the ACL outlives it (both
        // are owned by the returned value).
        unsafe {
            check(
                InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION),
                "InitializeSecurityDescriptor",
            )?;
            check(
                SetSecurityDescriptorDacl(descriptor_ptr, 1, acl_ptr, 0),
                "SetSecurityDescriptorDacl",
            )?;
            check(
                SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED),
                "SetSecurityDescriptorControl",
            )?;
        }
        Ok(Self {
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor_ptr,
                bInheritHandle: 0,
            },
            _descriptor: descriptor,
            _acl: acl,
        })
    }

    fn attributes_ptr(&self) -> *mut c_void {
        std::ptr::from_ref(&self.attributes).cast_mut().cast()
    }
}

/// Open `path` as `how`; a file this call creates has the owner-only DACL
/// from the start. An existing file is opened as it is.
pub(crate) fn open_private_file(how: PrivateOpen, path: &Path) -> io::Result<File> {
    open_private_file_with(how, path, &CurrentUser)
}

/// [`open_private_file`] with an explicit [`DaclSource`]. Nothing is
/// created when the source fails.
///
/// The access, sharing and disposition are what `std::fs::OpenOptions`
/// passes to `CreateFileW` for the same combination; `std` offers no way to
/// add the `SECURITY_ATTRIBUTES` that make the DACL part of the creation.
pub(crate) fn open_private_file_with(
    how: PrivateOpen,
    path: &Path,
    source: &dyn DaclSource,
) -> io::Result<File> {
    require_acls(source, path)?;
    let descriptor = source.owner_only(ObjectKind::File)?;
    let (access, disposition) = match how {
        PrivateOpen::CreateTruncate => (GENERIC_WRITE, CREATE_ALWAYS),
        PrivateOpen::CreateNew => (GENERIC_WRITE, CREATE_NEW),
        // Append is write access without `FILE_WRITE_DATA`, so every write
        // lands at the end of the file.
        PrivateOpen::Append => (FILE_GENERIC_WRITE & !FILE_WRITE_DATA, OPEN_ALWAYS),
        PrivateOpen::Lock => (GENERIC_WRITE, OPEN_ALWAYS),
    };
    let wide = to_wide(path)?;
    // SAFETY: `wide` is NUL-terminated; the attributes point at a live
    // descriptor owned by `descriptor`; no template handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            descriptor.attributes_ptr().cast(),
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle that nothing else owns.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Create `dir` and every missing parent with the owner-only, inheriting
/// DACL. An existing directory is left as it is.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    create_private_dir_with(dir, &CurrentUser)
}

/// [`create_private_dir`] with an explicit [`DaclSource`].
pub(crate) fn create_private_dir_with(dir: &Path, source: &dyn DaclSource) -> io::Result<()> {
    // An empty path is the current directory (the parent of a bare file name).
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    require_acls(source, dir)?;
    create_missing(dir, source)
}

fn create_missing(dir: &Path, source: &dyn DaclSource) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        create_missing(parent, source)?;
    }
    let descriptor = source.owner_only(ObjectKind::Dir)?;
    let wide = to_wide(dir)?;
    // SAFETY: `wide` is NUL-terminated and the attributes point at a live
    // descriptor owned by `descriptor`.
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), descriptor.attributes_ptr().cast()) };
    if created != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    // Another process made it between the check and the call.
    if err.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) && dir.is_dir() {
        return Ok(());
    }
    Err(err)
}

fn require_acls(source: &dyn DaclSource, path: &Path) -> io::Result<()> {
    if source.volume_keeps_acls(path)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the volume does not store access control lists (FAT/exFAT or a network share), \
             so an owner-only DACL cannot be applied",
        ))
    }
}

/// The user SID of the process token, in a `u32`-aligned buffer.
pub(crate) fn token_user_sid() -> io::Result<Vec<u32>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the out-pointer is a local; failure is reported by the return.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(context(io::Error::last_os_error(), "OpenProcessToken"));
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: the handle came from `OpenProcessToken` and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = Token(token);

    let mut needed = 0u32;
    // SAFETY: a zero-length query only reports the size needed.
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(context(
            io::Error::last_os_error(),
            "GetTokenInformation (size)",
        ));
    }
    // `TOKEN_USER` wants pointer alignment; `u64` words give it.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` is at least `needed` bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(context(io::Error::last_os_error(), "GetTokenInformation"));
    }
    // SAFETY: the call above filled `buf` with a `TOKEN_USER` whose SID
    // points into the same buffer.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` is that valid SID.
    let len = unsafe { GetLengthSid(sid) };
    let mut out = vec![0u32; (len as usize).div_ceil(4)];
    // SAFETY: `out` holds at least `len` bytes.
    check(
        unsafe { CopySid(len, out.as_mut_ptr().cast(), sid) },
        "CopySid",
    )?;
    Ok(out)
}

/// `FILE_PERSISTENT_ACLS` of the volume holding `path`, taken from the
/// nearest ancestor that exists (the path itself usually does not yet).
fn volume_keeps_acls(path: &Path) -> io::Result<bool> {
    let absolute = std::path::absolute(path)?;
    let existing: PathBuf = absolute
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or(&absolute)
        .to_path_buf();
    let wide = to_wide(&existing)?;
    let mut root = vec![0u16; 32_768];
    // SAFETY: `wide` is NUL-terminated and `root` has the length passed.
    check(
        unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) },
        "GetVolumePathNameW",
    )?;
    let mut flags = 0u32;
    // SAFETY: `root` is NUL-terminated by the call above; every optional
    // out-parameter is null.
    check(
        unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut flags,
                std::ptr::null_mut(),
                0,
            )
        },
        "GetVolumeInformationW",
    )?;
    Ok(flags & FILE_PERSISTENT_ACLS != 0)
}

pub(crate) fn to_wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn check(result: i32, what: &str) -> io::Result<()> {
    if result == 0 {
        Err(context(io::Error::last_os_error(), what))
    } else {
        Ok(())
    }
}

fn context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{what} failed: {err}"))
}

#[cfg(test)]
static INJECTED: std::sync::Mutex<Option<std::sync::Arc<dyn DaclSource>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn injected() -> Option<std::sync::Arc<dyn DaclSource>> {
    INJECTED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Make [`CurrentUser`] answer from `source` until the guard drops, so a
/// test can reach the call sites that take no source (the audit sink, the
/// reset key). Process-wide, hence sound only under the process-isolated
/// runner the repo requires (`cargo nextest`).
#[cfg(test)]
pub(crate) fn inject_for_test(source: std::sync::Arc<dyn DaclSource>) -> InjectGuard {
    *INJECTED.lock().unwrap_or_else(|e| e.into_inner()) = Some(source);
    InjectGuard
}

#[cfg(test)]
pub(crate) struct InjectGuard;

#[cfg(test)]
impl Drop for InjectGuard {
    fn drop(&mut self) {
        *INJECTED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests;
