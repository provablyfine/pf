use libc::{c_char, c_int, c_long, gid_t, group, passwd, size_t, uid_t, ENOENT, ERANGE};
use sha2::{Digest, Sha256};
use std::fs;

const NSS_STATUS_TRYAGAIN: c_int = -2;
const NSS_STATUS_UNAVAIL: c_int = -1;
const NSS_STATUS_NOTFOUND: c_int = 0;
const NSS_STATUS_SUCCESS: c_int = 1;

const CONFIG_PATH: &str = "/etc/pf-nss.conf";
const DEFAULT_UID_MIN: u32 = 100000;
const DEFAULT_UID_MAX: u32 = 999999;

struct Config {
    uid_range_min: u32,
    uid_range_max: u32,
}

fn load_config() -> Config {
    let mut min = DEFAULT_UID_MIN;
    let mut max = DEFAULT_UID_MAX;
    if let Ok(contents) = fs::read_to_string(CONFIG_PATH) {
        for line in contents.lines() {
            let line = line.trim();
            if let Some((key, val)) = line.split_once('=') {
                match key.trim() {
                    "uid_range_min" => {
                        if let Ok(v) = val.trim().parse::<u32>() {
                            min = v;
                        }
                    }
                    "uid_range_max" => {
                        if let Ok(v) = val.trim().parse::<u32>() {
                            max = v;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Config {
        uid_range_min: min,
        uid_range_max: max,
    }
}

// Must match Python's _uid_from_username exactly:
//   digest = SHA256(name.encode())
//   value = int.from_bytes(digest[:8], "big")
//   return range_min + (value % (range_max - range_min))
fn uid_from_username(name: &str, cfg: &Config) -> u32 {
    let digest = Sha256::digest(name.as_bytes());
    let raw = u64::from_be_bytes(digest[..8].try_into().unwrap());
    cfg.uid_range_min + (raw % (cfg.uid_range_max - cfg.uid_range_min) as u64) as u32
}

// Write a C string into buf at *offset. Returns a pointer to the start of the
// written string, or null if there is not enough space.
unsafe fn write_str(s: &str, buf: *mut c_char, buflen: size_t, offset: &mut usize) -> *mut c_char {
    let bytes = s.as_bytes();
    let needed = bytes.len() + 1;
    if *offset + needed > buflen {
        return std::ptr::null_mut();
    }
    let ptr = buf.add(*offset);
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, ptr, bytes.len());
    *ptr.add(bytes.len()) = 0;
    *offset += needed;
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getpwnam_r(
    name: *const c_char,
    result: *mut passwd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let name_str = match std::ffi::CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => {
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }
    };

    let cfg = load_config();
    let uid = uid_from_username(name_str, &cfg);
    let home = format!("/home/{name_str}");

    let mut offset: usize = 0;
    macro_rules! ws {
        ($s:expr) => {{
            let p = write_str($s, buf, buflen, &mut offset);
            if p.is_null() {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
            }
            p
        }};
    }

    let pw_name = ws!(name_str);
    let pw_passwd = ws!("x");
    let pw_gecos = ws!("");
    let pw_dir = ws!(&home);
    let pw_shell = ws!("/bin/bash");

    (*result).pw_name = pw_name;
    (*result).pw_passwd = pw_passwd;
    (*result).pw_uid = uid as uid_t;
    (*result).pw_gid = uid as gid_t;
    (*result).pw_gecos = pw_gecos;
    (*result).pw_dir = pw_dir;
    (*result).pw_shell = pw_shell;

    NSS_STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getpwuid_r(
    _uid: uid_t,
    _result: *mut passwd,
    _buf: *mut c_char,
    _buflen: size_t,
    _errnop: *mut c_int,
) -> c_int {
    NSS_STATUS_UNAVAIL
}

#[no_mangle]
pub extern "C" fn _nss_provablyfine_setpwent() {}

#[no_mangle]
pub extern "C" fn _nss_provablyfine_endpwent() {}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getpwent_r(
    _result: *mut passwd,
    _buf: *mut c_char,
    _buflen: size_t,
    _errnop: *mut c_int,
) -> c_int {
    NSS_STATUS_UNAVAIL
}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getgrnam_r(
    name: *const c_char,
    result: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let name_str = match std::ffi::CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => {
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }
    };

    let cfg = load_config();
    let gid = uid_from_username(name_str, &cfg);

    let mut offset: usize = 0;
    macro_rules! ws {
        ($s:expr) => {{
            let p = write_str($s, buf, buflen, &mut offset);
            if p.is_null() {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
            }
            p
        }};
    }

    let gr_name = ws!(name_str);
    let gr_passwd = ws!("x");
    let member_str = ws!(name_str);

    // Align offset to pointer boundary for the gr_mem array.
    let align = std::mem::align_of::<*mut c_char>();
    let aligned = (offset + align - 1) & !(align - 1);
    let array_size = 2 * std::mem::size_of::<*mut c_char>();
    if aligned + array_size > buflen {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    // Write the two-element gr_mem array: [ptr-to-member, NULL]
    let gr_mem_ptr = buf.add(aligned) as *mut *mut c_char;
    *gr_mem_ptr = member_str;
    *gr_mem_ptr.add(1) = std::ptr::null_mut();

    (*result).gr_name = gr_name;
    (*result).gr_passwd = gr_passwd;
    (*result).gr_gid = gid as gid_t;
    (*result).gr_mem = gr_mem_ptr;

    NSS_STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getgrgid_r(
    _gid: gid_t,
    _result: *mut group,
    _buf: *mut c_char,
    _buflen: size_t,
    _errnop: *mut c_int,
) -> c_int {
    NSS_STATUS_UNAVAIL
}

// Called by glibc's getgrouplist to collect supplementary groups for a user.
// We have no supplementary groups — the primary group comes from the passwd entry.
// NOTFOUND (rather than SUCCESS) so the module never terminates the lookup chain:
// under the default `SUCCESS=return` action, claiming success here would truncate
// the supplementary groups contributed by any source listed after us.
#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_initgroups_dyn(
    _user: *const c_char,
    _group: libc::gid_t,
    _start: *mut libc::c_long,
    _size: *mut libc::c_long,
    _groups: *mut *mut libc::gid_t,
    _limit: libc::c_long,
    errnop: *mut c_int,
) -> c_int {
    *errnop = ENOENT;
    NSS_STATUS_NOTFOUND
}

#[no_mangle]
pub extern "C" fn _nss_provablyfine_setgrent() {}

#[no_mangle]
pub extern "C" fn _nss_provablyfine_endgrent() {}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getgrent_r(
    _result: *mut group,
    _buf: *mut c_char,
    _buflen: size_t,
    _errnop: *mut c_int,
) -> c_int {
    NSS_STATUS_UNAVAIL
}

// Shadow password database — needed so pam_unix.so finds a valid account entry.
// The synthesized shadow record marks the account as locked for password login ("!!")
// but otherwise valid (no expiry). SSH key auth is unaffected by the locked password.
#[repr(C)]
pub struct Spwd {
    sp_namp: *mut c_char,
    sp_pwdp: *mut c_char,
    sp_lstchg: c_long,
    sp_min: c_long,
    sp_max: c_long,
    sp_warn: c_long,
    sp_inact: c_long,
    sp_expire: c_long,
    sp_flag: c_long,
}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getspnam_r(
    name: *const c_char,
    result: *mut Spwd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let name_str = match std::ffi::CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => {
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }
    };

    let mut offset: usize = 0;
    macro_rules! ws {
        ($s:expr) => {{
            let p = write_str($s, buf, buflen, &mut offset);
            if p.is_null() {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
            }
            p
        }};
    }

    let sp_namp = ws!(name_str);
    let sp_pwdp = ws!("!!");

    (*result).sp_namp = sp_namp;
    (*result).sp_pwdp = sp_pwdp;
    (*result).sp_lstchg = -1;
    (*result).sp_min = -1;
    (*result).sp_max = -1;
    (*result).sp_warn = -1;
    (*result).sp_inact = -1;
    (*result).sp_expire = -1;
    (*result).sp_flag = 0;

    NSS_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn _nss_provablyfine_setspent() {}

#[no_mangle]
pub extern "C" fn _nss_provablyfine_endspent() {}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getspent_r(
    _result: *mut Spwd,
    _buf: *mut c_char,
    _buflen: size_t,
    _errnop: *mut c_int,
) -> c_int {
    NSS_STATUS_UNAVAIL
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid_from_name(name: &str) -> u32 {
        uid_from_username(name, &Config { uid_range_min: 100000, uid_range_max: 999999 })
    }

    // Verify hash matches Python: hashlib.sha256(b"alice").digest()[:8] big-endian u64
    // % (999999 - 100000) + 100000
    #[test]
    fn test_hash_matches_python() {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(b"alice");
        let raw = u64::from_be_bytes(digest[..8].try_into().unwrap());
        let expected = 100000 + (raw % (999999 - 100000)) as u32;
        assert_eq!(uid_from_name("alice"), expected);
    }

    #[test]
    fn test_hash_deterministic() {
        assert_eq!(uid_from_name("alice"), uid_from_name("alice"));
        assert_ne!(uid_from_name("alice"), uid_from_name("bob"));
    }

    #[test]
    fn test_hash_in_range() {
        for name in &["alice", "bob", "charlie", "root", "deploy"] {
            let uid = uid_from_name(name);
            assert!(uid >= 100000, "uid {uid} for {name} below range_min");
            assert!(uid < 999999, "uid {uid} for {name} at or above range_max");
        }
    }

    #[test]
    fn test_getpwnam_r() {
        let name = std::ffi::CString::new("alice").unwrap();
        let mut result = unsafe { std::mem::zeroed::<passwd>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getpwnam_r(
                name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errno_val,
            )
        };
        assert_eq!(status, NSS_STATUS_SUCCESS);
        let uid = uid_from_name("alice");
        assert_eq!(result.pw_uid, uid);
        assert_eq!(result.pw_gid, uid);
        let name_back = unsafe { std::ffi::CStr::from_ptr(result.pw_name).to_str().unwrap() };
        assert_eq!(name_back, "alice");
        let dir = unsafe { std::ffi::CStr::from_ptr(result.pw_dir).to_str().unwrap() };
        assert_eq!(dir, "/home/alice");
    }

    #[test]
    fn test_getpwnam_r_buffer_too_small() {
        let name = std::ffi::CString::new("alice").unwrap();
        let mut result = unsafe { std::mem::zeroed::<passwd>() };
        let mut buf = vec![0i8; 4]; // too small
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getpwnam_r(
                name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errno_val,
            )
        };
        assert_eq!(status, NSS_STATUS_TRYAGAIN);
        assert_eq!(errno_val, ERANGE);
    }

    #[test]
    fn test_getgrnam_r() {
        let name = std::ffi::CString::new("alice").unwrap();
        let mut result = unsafe { std::mem::zeroed::<group>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getgrnam_r(
                name.as_ptr(),
                &mut result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errno_val,
            )
        };
        assert_eq!(status, NSS_STATUS_SUCCESS);
        let gid = uid_from_name("alice");
        assert_eq!(result.gr_gid, gid);
        let name_back = unsafe { std::ffi::CStr::from_ptr(result.gr_name).to_str().unwrap() };
        assert_eq!(name_back, "alice");
        // gr_mem[0] is "alice", gr_mem[1] is null
        let member = unsafe { std::ffi::CStr::from_ptr(*result.gr_mem).to_str().unwrap() };
        assert_eq!(member, "alice");
        assert!(unsafe { (*result.gr_mem.add(1)).is_null() });
    }
}
