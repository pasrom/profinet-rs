//! Raw Layer-2 Ethernet backend over libpcap, ported from the pcap branches
//! of `profinet-py/profinet/util.py` (ethernet_socket, get_mac) and
//! `_pcap.py` (PcapSocket), plus DCP discovery over it (dcp.py send_discover
//! + read_response).
//!
//! Uses the `pcap` crate (libpcap), which works on macOS BPF and Linux.
//! Opening a capture requires privileges (root, or Wireshark's ChmodBPF
//! helper on macOS). The socket and discovery loop are bench-validated; the
//! pure helpers ([`bpf_filter`], [`aggregate_responses`]) are unit-tested.

use std::fmt;
use std::time::{Duration, Instant};

use crate::dcp::{
    identify_all_request, parse_dcp_xid, parse_identify_response, DcpDevice, PROFINET_ETHERTYPE,
};

/// VLAN-aware BPF filter for one EtherType, as installed by `_pcap.py`
/// PcapSocket: PROFINET frames are often 802.1Q tagged and libpcap/BPF
/// (unlike Linux AF_PACKET) delivers the tag in-band, so match both the
/// plain and the tagged EtherType.
pub fn bpf_filter(ethertype: u16) -> String {
    format!("ether proto 0x{ethertype:04x} or (vlan and ether proto 0x{ethertype:04x})")
}

/// Raw Ethernet socket backed by libpcap, the port of `_pcap.py` PcapSocket:
/// immediate mode (so RT/DCP frames are delivered per-packet instead of being
/// held in the BPF store buffer), promiscuous, 65535 snaplen, 1 ms read
/// timeout with the wall-clock deadline enforced in [`RawSocket::recv`].
pub struct RawSocket {
    cap: pcap::Capture<pcap::Active>,
}

impl fmt::Debug for RawSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawSocket").finish_non_exhaustive()
    }
}

impl RawSocket {
    /// Open a live capture on `iface`. If `ethertype` is set, install the
    /// VLAN-aware BPF filter for it (see [`bpf_filter`]); otherwise all
    /// frames are captured (the reference's ETH_P_ALL behaviour, needed for
    /// VLAN-tagged responses when no filter is wanted).
    pub fn open(iface: &str, ethertype: Option<u16>) -> Result<Self, String> {
        let cap = pcap::Capture::from_device(iface)
            .map_err(|e| format!("pcap open of {iface:?} failed: {e}"))?
            .immediate_mode(true)
            .snaplen(65535)
            .promisc(true)
            .timeout(1)
            .open()
            .map_err(|e| format!("pcap activate on {iface:?} failed: {e}"))?;
        let mut sock = RawSocket { cap };
        if let Some(et) = ethertype {
            sock.cap
                .filter(&bpf_filter(et), true)
                .map_err(|e| format!("BPF filter failed on {iface:?}: {e}"))?;
        }
        Ok(sock)
    }

    /// Send a complete raw Ethernet frame (pcap_sendpacket).
    pub fn send(&mut self, frame: &[u8]) -> Result<(), String> {
        self.cap
            .sendpacket(frame)
            .map_err(|e| format!("pcap sendpacket failed: {e}"))
    }

    /// Receive one raw Ethernet frame, waiting up to `timeout` wall-clock
    /// time. Returns `Ok(None)` on timeout. The packet data is copied out of
    /// pcap's buffer (which is only valid until the next capture call).
    pub fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.cap.next_packet() {
                Ok(packet) => return Ok(Some(packet.data.to_vec())),
                Err(pcap::Error::TimeoutExpired) => {
                    // The 1 ms pcap read timeout elapsed with no packet;
                    // keep polling until the wall-clock deadline.
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                }
                Err(e) => return Err(format!("pcap next_packet failed: {e}")),
            }
        }
    }
}

/// MAC address of a network interface, the port of util.py get_mac
/// (getifaddrs/AF_LINK on macOS, SIOCGIFHWADDR on Linux — the mac_address
/// crate wraps both).
pub fn get_mac(iface: &str) -> Result<[u8; 6], String> {
    let mut last_err = None;
    for candidate in mac_lookup_names(iface) {
        match mac_address::mac_address_by_name(&candidate) {
            Ok(Some(mac)) => return Ok(mac.bytes()),
            Ok(None) => {}
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) => Err(format!("failed to get MAC address for {iface:?}: {e}")),
        None => Err(format!("no MAC address found for interface {iface:?}")),
    }
}

/// Names to try when asking the OS for an interface's MAC, in order.
///
/// On Unix the pcap device name *is* the OS interface name (`en10`, `eth0`),
/// so the first candidate answers. Windows names its capture devices
/// `\Device\NPF_{GUID}` while the OS knows the adapter by the bare GUID, so
/// the prefix has to come off or the lookup finds nothing.
fn mac_lookup_names(iface: &str) -> Vec<String> {
    let mut names = vec![iface.to_string()];
    if let Some(guid) = iface.strip_prefix(r"\Device\NPF_") {
        names.push(guid.to_string());
    }
    names
}

/// First IPv4 address of a network interface, from libpcap's device list
/// (pcap_findalldevs); needed as the source address for the UDP-over-raw-L2
/// RPC transport ([`crate::rawudp`]).
pub fn get_ipv4(iface: &str) -> Result<[u8; 4], String> {
    let devices = pcap::Device::list().map_err(|e| format!("pcap device list failed: {e}"))?;
    let dev = devices
        .into_iter()
        .find(|d| d.name == iface)
        .ok_or_else(|| format!("interface {iface:?} not found by pcap"))?;
    dev.addresses
        .iter()
        .find_map(|a| match a.addr {
            std::net::IpAddr::V4(ip) => Some(ip.octets()),
            std::net::IpAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("no IPv4 address on interface {iface:?}"))
}

/// Aggregate captured frames into discovered devices, mirroring dcp.py
/// read_response: keep only frames addressed to us that echo our request's
/// `expected_xid`, parse each as a DCP Identify response (parse failures are
/// skipped, like the reference's per-frame `continue`), and dedup by source
/// MAC with later responses replacing earlier ones (`result[eth.src] = parsed`).
///
/// Matching the xid keeps a concurrent controller's Identify-All responses on
/// the same segment out of our result set.
pub fn aggregate_responses(
    frames: &[Vec<u8>],
    my_mac: &[u8; 6],
    expected_xid: u32,
) -> Vec<DcpDevice> {
    let mut devices: Vec<DcpDevice> = Vec::new();
    for frame in frames {
        if frame.len() < 14 || frame[0..6] != my_mac[..] {
            continue;
        }
        if parse_dcp_xid(frame) != Some(expected_xid) {
            continue;
        }
        let Ok(device) = parse_identify_response(frame) else {
            continue;
        };
        match devices.iter_mut().find(|d| d.mac == device.mac) {
            Some(existing) => *existing = device,
            None => devices.push(device),
        }
    }
    devices
}

/// DCP device discovery on a raw interface: open a PROFINET-filtered
/// [`RawSocket`], multicast an Identify-All request (dcp.py send_discover)
/// with a fresh random xid, then collect responses until `timeout` elapses
/// and aggregate them (dcp.py read_response).
pub fn discover(iface: &str, timeout: Duration) -> Result<Vec<DcpDevice>, String> {
    // Enumerating everything genuinely needs the whole window: devices spread
    // their Identify responses over the response-delay window to avoid
    // collisions, so leaving early would silently truncate the device list.
    discover_until(iface, timeout, |_| false)
}

/// DCP discovery that can stop early: after every newly parsed response the
/// aggregated device list is handed to `done`, and the first `true` returns
/// immediately instead of sitting out the rest of `timeout`.
///
/// This is what makes resolving ONE known station fast. The device answers
/// within milliseconds, so waiting out the default 10 s window (as
/// [`discover`] must, to enumerate everything) added ~10 s of dead time to
/// every connect — dwarfing the actual AR setup, which takes ~2 s.
pub fn discover_until(
    iface: &str,
    timeout: Duration,
    mut done: impl FnMut(&[DcpDevice]) -> bool,
) -> Result<Vec<DcpDevice>, String> {
    let mut sock = RawSocket::open(iface, Some(PROFINET_ETHERTYPE))?;
    let my_mac = get_mac(iface)?;

    let mut xid_bytes = [0u8; 4];
    getrandom::fill(&mut xid_bytes).map_err(|e| format!("getrandom failed: {e}"))?;
    let xid = u32::from_be_bytes(xid_bytes);

    sock.send(&identify_all_request(&my_mac, xid))?;

    let deadline = Instant::now() + timeout;
    let mut frames = Vec::new();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match sock.recv(deadline - now)? {
            Some(frame) => {
                frames.push(frame);
                let devices = aggregate_responses(&frames, &my_mac, xid);
                if done(&devices) {
                    return Ok(devices);
                }
            }
            None => break,
        }
    }
    Ok(aggregate_responses(&frames, &my_mac, xid))
}

#[cfg(test)]
mod tests {
    use super::mac_lookup_names;

    #[test]
    fn unix_device_names_are_looked_up_as_given() {
        assert_eq!(mac_lookup_names("en10"), vec!["en10".to_string()]);
        assert_eq!(mac_lookup_names("eth0"), vec!["eth0".to_string()]);
    }

    #[test]
    fn windows_capture_names_also_try_the_bare_guid() {
        // Bench-found on Windows 11: pcap hands out this form, while the OS
        // knows the adapter by the GUID alone, so looking up the pcap name
        // verbatim finds no MAC and discovery dies before sending anything.
        let names = mac_lookup_names(r"\Device\NPF_{00000000-1111-2222-3333-444444444444}");
        assert_eq!(
            names,
            vec![
                r"\Device\NPF_{00000000-1111-2222-3333-444444444444}".to_string(),
                "{00000000-1111-2222-3333-444444444444}".to_string(),
            ]
        );
    }

    #[test]
    fn a_name_that_merely_looks_similar_is_not_stripped() {
        // Only the exact pcap prefix means a GUID follows; anything else is
        // passed through untouched rather than mangled into a second lookup.
        assert_eq!(
            mac_lookup_names(r"\Device\OtherThing"),
            vec![r"\Device\OtherThing".to_string()]
        );
    }
}
