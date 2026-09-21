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

/// The source address chosen for a destination, and whether it can be
/// expected to reach it.
///
/// `reaches_target` false is not a refusal. The RPC transport addresses the
/// device by MAC and only carries the IP in the UDP header, so a device whose
/// address sits in another network — a factory default, which this tool
/// exists to change — still answers. It is worth saying out loud, though: it
/// is also exactly what a wrong source address looks like, and without it the
/// two are told apart only by a packet capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAddress {
    /// The address to put in the UDP header.
    pub ip: [u8; 4],
    /// Whether its network contains the destination.
    pub reaches_target: bool,
}

/// Pick the source address for talking to `dst` from an interface's addresses.
///
/// A host can carry several addresses on one interface, and the first one the
/// operating system reports is not necessarily the one the device can answer.
/// So prefer an address whose network contains the destination, and fall back
/// to the first when none does.
///
/// Split from [`get_ipv4_toward`] so the choice can be tested without an
/// interface: the interesting case is several addresses on one card, which is
/// what a test machine does not have.
pub fn pick_source_ipv4(addresses: &[pcap::Address], dst: [u8; 4]) -> Option<SourceAddress> {
    let v4: Vec<([u8; 4], Option<[u8; 4]>)> = addresses
        .iter()
        .filter_map(|a| match a.addr {
            std::net::IpAddr::V4(ip) => Some((
                ip.octets(),
                match a.netmask {
                    Some(std::net::IpAddr::V4(m)) => Some(m.octets()),
                    _ => None,
                },
            )),
            std::net::IpAddr::V6(_) => None,
        })
        .collect();

    // An address whose network is unknown cannot be shown to contain the
    // destination, so it only ever serves as the fallback. A netmask of
    // 0.0.0.0 counts as unknown rather than as a network holding everything:
    // libpcap reports one for interfaces that have no network of their own,
    // and taking it as a match would claim every device is reachable from it
    // — silencing the note on exactly the address that cannot explain itself.
    if let Some((ip, _)) = v4
        .iter()
        .find(|(ip, mask)| mask.is_some_and(|m| m != [0, 0, 0, 0] && same_network(*ip, dst, m)))
    {
        return Some(SourceAddress {
            ip: *ip,
            reaches_target: true,
        });
    }
    v4.first().map(|(ip, _)| SourceAddress {
        ip: *ip,
        reaches_target: false,
    })
}

/// Whether two IPv4 addresses share a network under `mask`.
fn same_network(a: [u8; 4], b: [u8; 4], mask: [u8; 4]) -> bool {
    (0..4).all(|i| a[i] & mask[i] == b[i] & mask[i])
}

/// Source address of `iface` for talking to `dst`, from libpcap's device list
/// (pcap_findalldevs); needed for the UDP-over-raw-L2 RPC transport
/// ([`crate::rawudp`]). See [`pick_source_ipv4`] for how the choice is made.
pub fn get_ipv4_toward(iface: &str, dst: [u8; 4]) -> Result<SourceAddress, String> {
    let devices = pcap::Device::list().map_err(|e| format!("pcap device list failed: {e}"))?;
    let dev = devices
        .into_iter()
        .find(|d| d.name == iface)
        .ok_or_else(|| format!("interface {iface:?} not found by pcap"))?;
    pick_source_ipv4(&dev.addresses, dst)
        .ok_or_else(|| format!("no IPv4 address on interface {iface:?}"))
}

/// First IPv4 address of a network interface, from libpcap's device list
/// (pcap_findalldevs). Prefer [`get_ipv4_toward`] wherever the destination is
/// known: this one cannot tell which of several addresses reaches it.
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
    use super::{mac_lookup_names, pick_source_ipv4};
    use std::net::{IpAddr, Ipv4Addr};

    /// One entry of an interface's address list.
    fn addr(ip: [u8; 4], mask: Option<[u8; 4]>) -> pcap::Address {
        pcap::Address {
            addr: IpAddr::V4(Ipv4Addr::from(ip)),
            netmask: mask.map(|m| IpAddr::V4(Ipv4Addr::from(m))),
            broadcast_addr: None,
            dst_addr: None,
        }
    }

    const MASK24: [u8; 4] = [255, 255, 255, 0];

    #[test]
    fn the_address_whose_network_holds_the_target_wins() {
        // The first address is not the one that reaches the device. Taking it
        // anyway is the failure this exists to prevent: the frames go out, the
        // device cannot answer the source, and the session dies in a timeout
        // that says nothing about why.
        let addresses = [
            addr([10, 0, 0, 5], Some(MASK24)),
            addr([192, 168, 0, 7], Some(MASK24)),
        ];
        let chosen = pick_source_ipv4(&addresses, [192, 168, 0, 2]).expect("an address");
        assert_eq!(chosen.ip, [192, 168, 0, 7]);
        assert!(chosen.reaches_target);
    }

    #[test]
    fn the_first_address_is_the_fallback_when_none_matches() {
        // A device on a factory default address is in nobody's network, and
        // this tool exists partly to change that — so this is reported, not
        // refused.
        let addresses = [
            addr([10, 0, 0, 5], Some(MASK24)),
            addr([172, 16, 0, 9], Some(MASK24)),
        ];
        let chosen = pick_source_ipv4(&addresses, [192, 168, 0, 2]).expect("an address");
        assert_eq!(chosen.ip, [10, 0, 0, 5]);
        assert!(!chosen.reaches_target);
    }

    #[test]
    fn an_address_without_a_netmask_can_only_be_the_fallback() {
        // Nothing can be concluded from an address whose network is unknown,
        // so it must not win over one that demonstrably matches.
        let addresses = [
            addr([192, 168, 0, 9], None),
            addr([192, 168, 0, 7], Some(MASK24)),
        ];
        let chosen = pick_source_ipv4(&addresses, [192, 168, 0, 2]).expect("an address");
        assert_eq!(chosen.ip, [192, 168, 0, 7]);

        // On its own it is still better than nothing.
        let only = [addr([192, 168, 0, 9], None)];
        let chosen = pick_source_ipv4(&only, [192, 168, 0, 2]).expect("an address");
        assert_eq!(chosen.ip, [192, 168, 0, 9]);
        assert!(!chosen.reaches_target);
    }

    #[test]
    fn an_all_zero_netmask_is_not_a_network_holding_everything() {
        // Every address is "in" 0.0.0.0/0, so treating it as a match would
        // make the first such entry win for any device — and report it as
        // reaching the target, which suppresses the note.
        let addresses = [
            addr([10, 0, 0, 5], Some([0, 0, 0, 0])),
            addr([192, 168, 0, 7], Some(MASK24)),
        ];
        let chosen = pick_source_ipv4(&addresses, [192, 168, 0, 2]).expect("an address");
        assert_eq!(chosen.ip, [192, 168, 0, 7]);
        assert!(chosen.reaches_target);

        // Alone it is still the fallback, and says so.
        let only = [addr([10, 0, 0, 5], Some([0, 0, 0, 0]))];
        let chosen = pick_source_ipv4(&only, [192, 168, 0, 2]).expect("an address");
        assert_eq!(chosen.ip, [10, 0, 0, 5]);
        assert!(!chosen.reaches_target);
    }

    #[test]
    fn a_wider_mask_still_matches() {
        let addresses = [addr([10, 1, 0, 5], Some([255, 0, 0, 0]))];
        let chosen = pick_source_ipv4(&addresses, [10, 9, 9, 9]).expect("an address");
        assert!(chosen.reaches_target);
    }

    #[test]
    fn an_interface_with_no_ipv4_address_yields_nothing() {
        let addresses = [pcap::Address {
            addr: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            netmask: None,
            broadcast_addr: None,
            dst_addr: None,
        }];
        assert_eq!(pick_source_ipv4(&addresses, [192, 168, 0, 2]), None);
    }

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
