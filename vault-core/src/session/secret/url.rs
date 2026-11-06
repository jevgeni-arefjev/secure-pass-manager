//! The forms a secret's URL may take (ADR-0013): an absolute `http` or `https` URL with
//! a non-empty host, or a bare host such as `github.com` (optionally with a port and a
//! path). The URL is stored exactly as typed; this only decides whether it is accepted.
//!
//! Security: refusing `javascript:`, `data:`, `file:` and every other scheme is a
//! second defence behind the web client's link allowlist, which only ever links
//! `http:` and `https:`. Other identifiers (`ssh://`, app IDs) belong in notes or a
//! custom field.

/// Whether `url` is an accepted URL form. Expects the trimmed text, already checked
/// for unsafe characters.
///
/// ```ignore
/// assert!(is_supported("https://github.com/login"));
/// assert!(is_supported("github.com"));
/// assert!(!is_supported("javascript:alert(1)"));
/// assert!(!is_supported("https://"));
/// ```
pub(super) fn is_supported(url: &str) -> bool {
    if url.chars().any(char::is_whitespace) || url.contains('\\') {
        return false;
    }
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let web = scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
            web && has_host(authority(rest))
        }
        None => is_host_port(authority(url)),
    }
}

/// The part of `rest` before its path, query or fragment.
///
/// ```ignore
/// assert_eq!(authority("alice@github.com:443/x?y"), "alice@github.com:443");
/// ```
fn authority(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or_default()
}

/// Whether an absolute URL's `authority` (`[userinfo@]host[:port]`) has a usable host.
///
/// ```ignore
/// assert!(has_host("alice@[::1]:8443"));
/// assert!(!has_host("alice@"));
/// ```
fn has_host(authority: &str) -> bool {
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_userinfo, host_port)| host_port);
    is_host_port(host_port)
}

/// Whether `text` is `host[:port]`, the host a name or IPv4 address made of non-empty
/// dot-separated labels, or an IPv6 address in brackets.
///
/// ```ignore
/// assert!(is_host_port("localhost:8080"));
/// assert!(is_host_port("[::1]"));
/// assert!(!is_host_port("javascript:alert(1)"));
/// ```
fn is_host_port(text: &str) -> bool {
    let (host_ok, port) = match text.strip_prefix('[') {
        Some(bracketed) => {
            let Some((address, tail)) = bracketed.split_once(']') else {
                return false;
            };
            // Only a port may follow the closing bracket.
            let port = match tail.strip_prefix(':') {
                Some(port) => Some(port),
                None if tail.is_empty() => None,
                None => return false,
            };
            (is_ipv6(address), port)
        }
        None => match text.split_once(':') {
            Some((host, port)) => (is_host_name(host), Some(port)),
            None => (is_host_name(text), None),
        },
    };
    host_ok && port.is_none_or(is_port)
}

/// Whether `host` is non-empty dot-separated labels of letters, digits, `-` and `_`.
///
/// ```ignore
/// assert!(is_host_name("github.com"));
/// assert!(!is_host_name("github..com"));
/// ```
fn is_host_name(host: &str) -> bool {
    host.split('.').all(|label| {
        !label.is_empty()
            && label
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_'))
    })
}

/// Whether `address` (inside brackets) looks like an IPv6 address: hex digits, colons
/// and dots (for an embedded IPv4 address), at least one colon.
///
/// ```ignore
/// assert!(is_ipv6("::1"));
/// assert!(!is_ipv6(""));
/// ```
fn is_ipv6(address: &str) -> bool {
    address.contains(':')
        && address
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'))
}

/// Whether `port` is 1 to 5 ASCII digits.
///
/// ```ignore
/// assert!(is_port("8080"));
/// assert!(!is_port("ssh"));
/// ```
fn is_port(port: &str) -> bool {
    (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit())
}
