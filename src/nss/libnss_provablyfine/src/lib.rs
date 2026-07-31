use libc::{c_char, c_int, c_long, gid_t, group, passwd, size_t, uid_t, ENOENT, ERANGE};
use std::fs;

const NSS_STATUS_TRYAGAIN: c_int = -2;
const NSS_STATUS_UNAVAIL: c_int = -1;
const NSS_STATUS_NOTFOUND: c_int = 0;
const NSS_STATUS_SUCCESS: c_int = 1;

const CONFIG_PATH: &str = "/etc/pf-nss.conf";
const DEFAULT_MIN_UID: u32 = 100000;
const DEFAULT_MIN_GID: u32 = 100000;

struct Config {
    min_uid: u32,
    min_gid: u32,
}

fn load_config() -> Config {
    let mut min_uid = DEFAULT_MIN_UID;
    let mut min_gid = DEFAULT_MIN_GID;
    if let Ok(contents) = fs::read_to_string(CONFIG_PATH) {
        for line in contents.lines() {
            let line = line.trim();
            if let Some((key, val)) = line.split_once('=') {
                match key.trim() {
                    "unix_min_uid" => {
                        if let Ok(v) = val.trim().parse::<u32>() {
                            min_uid = v;
                        }
                    }
                    "unix_min_gid" => {
                        if let Ok(v) = val.trim().parse::<u32>() {
                            min_gid = v;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Config { min_uid, min_gid }
}

// Standalone-mode usernames are "u" followed by the hex-encoded sequential id
// (e.g. "u1", "ua", "u10"). Anything else is not ours to resolve: we return
// None so the caller falls through to the next nsswitch source instead of
// synthesizing an account for it.
fn offset_from_username(name: &str) -> Option<u32> {
    let hex = name.strip_prefix('u')?;
    if hex.is_empty() {
        return None;
    }
    u32::from_str_radix(hex, 16).ok()
}

fn username_from_offset(offset: u32) -> String {
    format!("u{offset:x}")
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

unsafe fn build_passwd(
    name: &str,
    uid: u32,
    gid: u32,
    result: *mut passwd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let home = format!("/home/{name}");

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

    let pw_name = ws!(name);
    let pw_passwd = ws!("x");
    let pw_gecos = ws!("");
    let pw_dir = ws!(&home);
    let pw_shell = ws!("/bin/bash");

    (*result).pw_name = pw_name;
    (*result).pw_passwd = pw_passwd;
    (*result).pw_uid = uid as uid_t;
    (*result).pw_gid = gid as gid_t;
    (*result).pw_gecos = pw_gecos;
    (*result).pw_dir = pw_dir;
    (*result).pw_shell = pw_shell;

    NSS_STATUS_SUCCESS
}

unsafe fn build_group(
    name: &str,
    gid: u32,
    result: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
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

    let gr_name = ws!(name);
    let gr_passwd = ws!("x");
    let member_str = ws!(name);

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

    let offset = match offset_from_username(name_str) {
        Some(o) => o,
        None => {
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }
    };

    let cfg = load_config();
    build_passwd(name_str, cfg.min_uid + offset, cfg.min_gid + offset, result, buf, buflen, errnop)
}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getpwuid_r(
    uid: uid_t,
    result: *mut passwd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let cfg = load_config();
    let uid = uid as u32;
    if uid < cfg.min_uid {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    let offset = uid - cfg.min_uid;
    let name = username_from_offset(offset);
    build_passwd(&name, uid, cfg.min_gid + offset, result, buf, buflen, errnop)
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

    let offset = match offset_from_username(name_str) {
        Some(o) => o,
        None => {
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }
    };

    let cfg = load_config();
    build_group(name_str, cfg.min_gid + offset, result, buf, buflen, errnop)
}

#[no_mangle]
pub unsafe extern "C" fn _nss_provablyfine_getgrgid_r(
    gid: gid_t,
    result: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let cfg = load_config();
    let gid = gid as u32;
    if gid < cfg.min_gid {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    let offset = gid - cfg.min_gid;
    let name = username_from_offset(offset);
    build_group(&name, gid, result, buf, buflen, errnop)
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

    if offset_from_username(name_str).is_none() {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

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

    // Tests exercise the real _nss_provablyfine_* entry points, which call
    // load_config() and read CONFIG_PATH (/etc/pf-nss.conf) directly. There's
    // no config file in the test environment, so DEFAULT_MIN_UID/DEFAULT_MIN_GID
    // apply — both 100000.

    #[test]
    fn test_offset_parsing() {
        assert_eq!(offset_from_username("u1"), Some(1));
        assert_eq!(offset_from_username("ua"), Some(10));
        assert_eq!(offset_from_username("u10"), Some(16));
        assert_eq!(offset_from_username("u0"), Some(0));
    }

    #[test]
    fn test_offset_parsing_rejects_non_matching() {
        assert_eq!(offset_from_username("alice"), None);
        assert_eq!(offset_from_username("root"), None);
        assert_eq!(offset_from_username("u"), None);
        assert_eq!(offset_from_username("uzzz"), None);
        assert_eq!(offset_from_username(""), None);
    }

    #[test]
    fn test_username_from_offset_roundtrip() {
        for offset in [0u32, 1, 10, 255, 4096] {
            let name = username_from_offset(offset);
            assert_eq!(offset_from_username(&name), Some(offset));
        }
    }

    #[test]
    fn test_getpwnam_r_matching() {
        let name = std::ffi::CString::new("u1").unwrap();
        let mut result = unsafe { std::mem::zeroed::<passwd>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getpwnam_r(name.as_ptr(), &mut result, buf.as_mut_ptr(), buf.len(), &mut errno_val)
        };
        assert_eq!(status, NSS_STATUS_SUCCESS);
        assert_eq!(result.pw_uid, 100001);
        assert_eq!(result.pw_gid, 100001);
        let name_back = unsafe { std::ffi::CStr::from_ptr(result.pw_name).to_str().unwrap() };
        assert_eq!(name_back, "u1");
        let dir = unsafe { std::ffi::CStr::from_ptr(result.pw_dir).to_str().unwrap() };
        assert_eq!(dir, "/home/u1");
    }

    #[test]
    fn test_getpwnam_r_non_matching_falls_through() {
        let name = std::ffi::CString::new("alice").unwrap();
        let mut result = unsafe { std::mem::zeroed::<passwd>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getpwnam_r(name.as_ptr(), &mut result, buf.as_mut_ptr(), buf.len(), &mut errno_val)
        };
        assert_eq!(status, NSS_STATUS_NOTFOUND);
    }

    #[test]
    fn test_getpwnam_r_buffer_too_small() {
        let name = std::ffi::CString::new("u1").unwrap();
        let mut result = unsafe { std::mem::zeroed::<passwd>() };
        let mut buf = vec![0i8; 4]; // too small
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getpwnam_r(name.as_ptr(), &mut result, buf.as_mut_ptr(), buf.len(), &mut errno_val)
        };
        assert_eq!(status, NSS_STATUS_TRYAGAIN);
        assert_eq!(errno_val, ERANGE);
    }

    #[test]
    fn test_getgrnam_r_matching() {
        let name = std::ffi::CString::new("ua").unwrap();
        let mut result = unsafe { std::mem::zeroed::<group>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getgrnam_r(name.as_ptr(), &mut result, buf.as_mut_ptr(), buf.len(), &mut errno_val)
        };
        assert_eq!(status, NSS_STATUS_SUCCESS);
        assert_eq!(result.gr_gid, 100010);
        let name_back = unsafe { std::ffi::CStr::from_ptr(result.gr_name).to_str().unwrap() };
        assert_eq!(name_back, "ua");
        // gr_mem[0] is "ua", gr_mem[1] is null
        let member = unsafe { std::ffi::CStr::from_ptr(*result.gr_mem).to_str().unwrap() };
        assert_eq!(member, "ua");
        assert!(unsafe { (*result.gr_mem.add(1)).is_null() });
    }

    #[test]
    fn test_getgrnam_r_non_matching_falls_through() {
        let name = std::ffi::CString::new("wheel").unwrap();
        let mut result = unsafe { std::mem::zeroed::<group>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getgrnam_r(name.as_ptr(), &mut result, buf.as_mut_ptr(), buf.len(), &mut errno_val)
        };
        assert_eq!(status, NSS_STATUS_NOTFOUND);
    }

    #[test]
    fn test_reverse_lookup_below_min_falls_through() {
        let mut result = unsafe { std::mem::zeroed::<passwd>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status =
            unsafe { _nss_provablyfine_getpwuid_r(1000, &mut result, buf.as_mut_ptr(), buf.len(), &mut errno_val) };
        assert_eq!(status, NSS_STATUS_NOTFOUND);
    }

    #[test]
    fn test_reverse_lookup_matches_forward() {
        // getpwuid_r(min_uid + offset) should synthesize the same account as
        // getpwnam_r(u<offset in hex>).
        let uid_name = std::ffi::CString::new("u2a").unwrap();
        let mut fwd = unsafe { std::mem::zeroed::<passwd>() };
        let mut fwd_buf = vec![0i8; 512];
        let mut fwd_errno: c_int = 0;
        let fwd_status = unsafe {
            _nss_provablyfine_getpwnam_r(
                uid_name.as_ptr(),
                &mut fwd,
                fwd_buf.as_mut_ptr(),
                fwd_buf.len(),
                &mut fwd_errno,
            )
        };
        assert_eq!(fwd_status, NSS_STATUS_SUCCESS);

        let mut rev = unsafe { std::mem::zeroed::<passwd>() };
        let mut rev_buf = vec![0i8; 512];
        let mut rev_errno: c_int = 0;
        let rev_status = unsafe {
            _nss_provablyfine_getpwuid_r(fwd.pw_uid, &mut rev, rev_buf.as_mut_ptr(), rev_buf.len(), &mut rev_errno)
        };
        assert_eq!(rev_status, NSS_STATUS_SUCCESS);
        assert_eq!(rev.pw_uid, fwd.pw_uid);
        assert_eq!(rev.pw_gid, fwd.pw_gid);
        let rev_name = unsafe { std::ffi::CStr::from_ptr(rev.pw_name).to_str().unwrap() };
        assert_eq!(rev_name, "u2a");
    }

    #[test]
    fn test_getspnam_r_matching_and_non_matching() {
        let name = std::ffi::CString::new("u5").unwrap();
        let mut result = unsafe { std::mem::zeroed::<Spwd>() };
        let mut buf = vec![0i8; 512];
        let mut errno_val: c_int = 0;
        let status = unsafe {
            _nss_provablyfine_getspnam_r(name.as_ptr(), &mut result, buf.as_mut_ptr(), buf.len(), &mut errno_val)
        };
        assert_eq!(status, NSS_STATUS_SUCCESS);
        let pwdp = unsafe { std::ffi::CStr::from_ptr(result.sp_pwdp).to_str().unwrap() };
        assert_eq!(pwdp, "!!");

        let other_name = std::ffi::CString::new("bob").unwrap();
        let mut other_result = unsafe { std::mem::zeroed::<Spwd>() };
        let status = unsafe {
            _nss_provablyfine_getspnam_r(
                other_name.as_ptr(),
                &mut other_result,
                buf.as_mut_ptr(),
                buf.len(),
                &mut errno_val,
            )
        };
        assert_eq!(status, NSS_STATUS_NOTFOUND);
    }
}
