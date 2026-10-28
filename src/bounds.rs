//! Dependency-free security primitives; also runnable with `rustc --test src/bounds.rs`.
use std::net::IpAddr;

pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with(['/', '\\'])
        && !path.contains(['\0', ':', '\\'])
        && !path.split('/').any(|p| p == "..")
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 192 && b == 0 && (c == 0 || c == 2))
                && !(a == 192 && b == 88 && c == 99)
                && !(a == 198 && b == 51 && c == 100)
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|v| public_ip(IpAddr::V4(v)))
            .unwrap_or_else(|| {
                let s = ip.segments();
                (s[0] & 0xe000) == 0x2000
                    && s[0] != 0x2002
                    && !(s[0] == 0x2001 && s[1] < 0x0200)
                    && !(s[0] == 0x2001 && s[1] == 0x0db8)
            }),
    }
}

pub fn parse_range(value: &str, len: usize) -> Option<(usize, usize)> {
    if len == 0 {
        return None;
    }
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    if start.is_empty() {
        let suffix: usize = end.parse().ok()?;
        return (suffix > 0).then_some((len.saturating_sub(suffix), len - 1));
    }
    let start: usize = start.parse().ok()?;
    let end = if end.is_empty() {
        len - 1
    } else {
        end.parse::<usize>().ok()?.min(len - 1)
    };
    (start <= end && start < len).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_archive_traversal_on_both_platforms() {
        for path in [
            "",
            "../x",
            "a/../x",
            "/etc/passwd",
            "C:/Windows/x",
            "a\\..\\b",
            "\\server\\share",
            "a\0b",
        ] {
            assert!(!safe_path(path), "accepted {path:?}");
        }
        for path in [
            "package/src/main.rs",
            "./package.json",
            "wheel.data/lib/libexample.so",
            "a..b",
        ] {
            assert!(safe_path(path));
        }
    }
    #[test]
    fn reject_private_and_special_ipv4() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "accepted {ip}");
        }
    }
    #[test]
    fn reject_ipv6_bypasses() {
        for ip in [
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "2002:7f00:1::",
            "2001:db8::1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "accepted {ip}");
        }
    }
    #[test]
    fn allow_global_addresses() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(public_ip(ip.parse().unwrap()), "rejected {ip}");
        }
    }
    #[test]
    fn range_bounds_and_suffixes() {
        assert_eq!(parse_range("bytes=2-5", 10), Some((2, 5)));
        assert_eq!(parse_range("bytes=2-", 10), Some((2, 9)));
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(parse_range("bytes=-20", 10), Some((0, 9)));
        assert_eq!(parse_range("bytes=5-200", 10), Some((5, 9)));
    }
    #[test]
    fn malformed_ranges_cannot_panic_or_overflow() {
        for value in [
            "bytes=0-1,2-3",
            "bytes=-0",
            "bytes=10-20",
            "bytes=5-2",
            "bytes=184467440737095516159-",
            "items=0-1",
            "bytes=--1",
        ] {
            assert_eq!(parse_range(value, 10), None, "accepted {value}");
        }
        assert_eq!(parse_range("bytes=0-", 0), None);
    }
}
