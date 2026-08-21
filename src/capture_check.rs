//! Answering "can this machine capture at all?" from inside the binary that
//! would have to do it.
//!
//! A consumer cannot work this out for itself. Whether a capture handle opens
//! depends on *this* executable's file capabilities, the ambient set it
//! inherited, and — on Windows — whether the `wpcap.dll` it links resolved at
//! load time. Every outside heuristic (group membership, parsing `getcap`,
//! reading an xattr) reimplements kernel policy and is wrong somewhere: a home
//! on NFS carries no xattrs, a `nosuid` mount drops file capabilities, and a
//! binary run under `sudo` needs none of them.
//!
//! So the check is a real attempt, and the verdict says which of the distinct
//! failures happened, because they have different fixes.

use std::io::ErrorKind;

/// Errno values used to tell the failures apart. Same numbers on Linux and
/// macOS, and the only ones this needs; `std` maps `EACCES`/`EPERM` to
/// [`ErrorKind::PermissionDenied`], but has no stable mapping for the other two
/// across the versions this builds on.
const EBUSY: i32 = 16;
const ENOENT: i32 = 2;

/// How many `/dev/bpf*` nodes to try before concluding there are no more.
///
/// macOS creates them on demand, so a gap means "that is all there is". The
/// scan stops at the first `ENOENT` anyway; this is only the backstop.
const BPF_SCAN_LIMIT: u32 = 256;

/// What a capture attempt found. Distinct variants because the fixes differ:
/// a driver to install, a permission to grant, a program to close, a name to
/// correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// A handle opened. Nothing to do.
    Ready,
    /// The kernel refused for lack of privilege.
    NoPermission,
    /// Privilege is fine; every capture device is in use by something else.
    Busy,
    /// The named interface does not exist on this machine.
    NoSuchInterface,
    /// libpcap lists no interfaces at all — on Windows this is what a missing
    /// capture driver looks like from here.
    NoDevices,
    /// It failed for a reason this does not recognise. The text is passed
    /// through rather than guessed at.
    Unknown(String),
}

impl Readiness {
    /// The wire word, and the only thing a consumer should match on.
    pub fn as_str(&self) -> &'static str {
        match self {
            Readiness::Ready => "ready",
            Readiness::NoPermission => "no_permission",
            Readiness::Busy => "busy",
            Readiness::NoSuchInterface => "no_such_interface",
            Readiness::NoDevices => "no_devices",
            Readiness::Unknown(_) => "unknown",
        }
    }
}

/// Classify a libpcap failure message.
///
/// libpcap composes its errors as text and does not hand back an errno, so this
/// reads the message. Kept pure and separate so the mapping is testable on a
/// host where none of these conditions can be produced.
pub fn classify_pcap_error(msg: &str) -> Readiness {
    let m = msg.to_ascii_lowercase();
    if m.contains("permission denied") || m.contains("operation not permitted") {
        Readiness::NoPermission
    } else if m.contains("busy") {
        Readiness::Busy
    } else if m.contains("no such device")
        || m.contains("no such interface")
        || m.contains("not found")
        || m.contains("syntax error in filter")
    {
        Readiness::NoSuchInterface
    } else {
        Readiness::Unknown(msg.to_string())
    }
}

/// Fold a `/dev/bpf*` scan into a verdict.
///
/// `denied` outranks `busy`: a machine where some nodes are readable and others
/// are not has a half-applied permission fix, and calling that "busy" would
/// send the operator to close programs that are not the problem. Only when
/// nothing could be opened *and* nothing was refused is the answer "busy".
pub fn fold_bpf_scan(opened_any: bool, denied: bool, busy: bool) -> Option<Readiness> {
    if denied {
        Some(Readiness::NoPermission)
    } else if opened_any {
        None // permission is fine; the interface itself still has to be tried
    } else if busy {
        Some(Readiness::Busy)
    } else {
        None // nothing conclusive — let the pcap attempt speak
    }
}

/// Try to open `/dev/bpf*` directly, for the raw errno libpcap hides.
///
/// Only macOS and the BSDs have these; elsewhere this reports nothing and the
/// pcap attempt is the whole answer.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn scan_bpf() -> Option<Readiness> {
    let (mut opened_any, mut denied, mut busy) = (false, false, false);
    for n in 0..BPF_SCAN_LIMIT {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/bpf{n}"))
        {
            Ok(_) => {
                opened_any = true;
                break;
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => denied = true,
            Err(e) if e.raw_os_error() == Some(EBUSY) => busy = true,
            // Past the last node that exists: nothing more to learn.
            Err(e) if e.raw_os_error() == Some(ENOENT) => break,
            Err(_) => break,
        }
    }
    fold_bpf_scan(opened_any, denied, busy)
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
fn scan_bpf() -> Option<Readiness> {
    None
}

/// Attempt a capture on `iface`, or on the first non-loopback interface libpcap
/// lists when none is named.
///
/// Returns the verdict and the interface it actually tried, so a consumer can
/// report which one the answer is about.
pub fn check(iface: Option<&str>) -> (Readiness, Option<String>) {
    // Asked first: on macOS a permission problem is global, and the raw errno
    // separates "refused" from "in use", which libpcap's text does not.
    if let Some(verdict) = scan_bpf() {
        return (verdict, iface.map(str::to_string));
    }

    let target = match iface {
        Some(name) => name.to_string(),
        None => match pcap::Device::list() {
            // Loopback carries no PROFINET, so it is a poor thing to answer
            // about; anything else will do, since privilege is not per
            // interface.
            Ok(devices) => match devices.into_iter().find(|d| !d.name.starts_with("lo")) {
                Some(d) => d.name,
                None => return (Readiness::NoDevices, None),
            },
            Err(e) => return (classify_pcap_error(&e.to_string()), None),
        },
    };

    let verdict = match pcap::Capture::from_device(target.as_str()) {
        Ok(builder) => match builder
            .immediate_mode(true)
            .snaplen(65535)
            .timeout(1)
            .open()
        {
            Ok(_) => Readiness::Ready,
            Err(e) => classify_pcap_error(&e.to_string()),
        },
        Err(e) => classify_pcap_error(&e.to_string()),
    };
    (verdict, Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_messages_map_to_the_fix_they_need() {
        assert_eq!(
            classify_pcap_error("(cannot open BPF device) /dev/bpf0: Permission denied"),
            Readiness::NoPermission
        );
        assert_eq!(
            classify_pcap_error("socket: Operation not permitted"),
            Readiness::NoPermission
        );
        assert_eq!(
            classify_pcap_error("(cannot open BPF device) /dev/bpf0: Device busy"),
            Readiness::Busy
        );
        assert_eq!(
            classify_pcap_error("en99: No such device exists"),
            Readiness::NoSuchInterface
        );
        // Unrecognised text is passed through, not guessed at: a wrong guess
        // sends the operator to fix something that is not broken.
        let odd = classify_pcap_error("the kernel is on fire");
        assert_eq!(odd, Readiness::Unknown("the kernel is on fire".into()));
        assert_eq!(odd.as_str(), "unknown");
    }

    /// A half-applied ChmodBPF — some nodes readable, some refused — is a
    /// permission problem. Reporting "busy" would send someone to close
    /// Wireshark, which is not what is wrong.
    #[test]
    fn a_refusal_outranks_a_busy_device() {
        assert_eq!(
            fold_bpf_scan(false, true, true),
            Some(Readiness::NoPermission)
        );
        assert_eq!(
            fold_bpf_scan(false, true, false),
            Some(Readiness::NoPermission)
        );
        // Every node in use, none refused: privilege is proven fine.
        assert_eq!(fold_bpf_scan(false, false, true), Some(Readiness::Busy));
        // Opened one: say nothing, the interface itself is still untested.
        assert_eq!(fold_bpf_scan(true, false, true), None);
        assert_eq!(fold_bpf_scan(false, false, false), None);
    }

    #[test]
    fn the_wire_words_are_stable() {
        for (r, w) in [
            (Readiness::Ready, "ready"),
            (Readiness::NoPermission, "no_permission"),
            (Readiness::Busy, "busy"),
            (Readiness::NoSuchInterface, "no_such_interface"),
            (Readiness::NoDevices, "no_devices"),
        ] {
            assert_eq!(r.as_str(), w);
        }
    }
}
