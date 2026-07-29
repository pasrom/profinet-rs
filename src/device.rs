//! High-level device API, ported from `profinet-py/profinet/device.py`
//! (`ProfinetDevice`, `DeviceInfo`, `WriteItem`, `scan`): discovery by
//! name/MAC/IP, an AR-managed RPC connection with lazy connect, record
//! read/write, the I&M convenience accessors and writers, diagnosis and
//! topology reads, all composed from the lower crate modules.
//!
//! Deviations from the reference, forced by the raw-L2 transport (macOS
//! Local Network privacy drops inbound LAN UDP through the IP stack, so the
//! RPC connection runs UDP-over-raw-L2 like the bench does):
//! - Construction needs the interface plus the controller MAC and IPv4
//!   (looked up from the interface) and the device MAC (from DCP discovery);
//!   `device.py`'s UDP-socket `RPCCon` only needed the device IP.
//! - `connect()` establishes a Device-Access AR (IOSAR) exactly like the
//!   reference's plain `connect()`; `with_alarm_cr`/`iocr_setup` and the
//!   alarm-listener/cyclic lifecycles are driven via [`crate::transport`],
//!   [`crate::alarm_listener`] and [`crate::cyclic`] directly instead.
//! - `read_all_im` covers I&M0..3 (the parsers ported so far); the reference
//!   also probes I&M4/5.
//! - `api` is fixed to 0 for all record operations (the reference's default).
//! - The CMInitiatorStationName is the reference's hardcoded `"tp"`, the
//!   only value proven to be accepted by the devices tested against.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::alarms::{parse_alarm_notification, AlarmNotification};
use crate::blocks::{block_header, WriteMultipleResult};
use crate::dcp::DcpDevice;
use crate::diagnosis::DiagnosisData;
use crate::epm;
use crate::gsdml::DeviceSlot;
use crate::im;
use crate::pcap;
use crate::transport::{RpcConn, READ_LENGTH};
use crate::util::{mac2s, s2ip, s2mac};
use crate::vendors::get_vendor_name;

/// CMInitiatorStationName sent in the ARBlockReq. `connect()` hardcodes "tp",
/// the value profinet-py uses, because that is the one this port has been
/// proven interoperable with; nothing here depends on its content.
const CM_STATION_NAME: &[u8] = b"tp";

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested without a device)
// ---------------------------------------------------------------------------

/// Parse a MAC address string to bytes, `None` if invalid (`_parse_mac`):
/// tolerates `-` and `.` separators and mixed case.
pub fn parse_mac_flexible(s: &str) -> Option<[u8; 6]> {
    let normalized = s.trim().to_ascii_lowercase().replace(['-', '.'], ":");
    s2mac(&normalized).ok()
}

/// Select a discovered device by station name or MAC address, the filter
/// `ProfinetDevice.discover` applies to the Identify-All responses. The
/// identifier is treated as a MAC when it parses as one (`_is_mac_address`),
/// otherwise as a station name.
pub fn find_by_identifier(devices: &[DcpDevice], identifier: &str) -> Option<DcpDevice> {
    match parse_mac_flexible(identifier) {
        Some(mac) => devices.iter().find(|d| d.mac == mac).cloned(),
        None => devices.iter().find(|d| d.name == identifier).cloned(),
    }
}

/// Select a discovered device by IP address string, the filter `from_ip`
/// applies to the Identify-All responses.
pub fn find_by_ip(devices: &[DcpDevice], ip: &str) -> Option<DcpDevice> {
    devices
        .iter()
        .find(|d| s2ip(&d.ip).ok().as_deref() == Some(ip))
        .cloned()
}

/// Encode a string field as Latin-1 padded with spaces to `width`
/// (`write_im1..3`: `.encode("latin-1")[:width].ljust(width, b"\x20")` after
/// the length check, which errors like the reference's ValueError).
fn latin1_field(s: &str, width: usize, what: &str) -> Result<Vec<u8>, String> {
    if s.chars().count() > width {
        return Err(format!("{what} exceeds {width} character limit"));
    }
    let mut out = Vec::with_capacity(width);
    for c in s.chars() {
        let code = u32::from(c);
        if code > 0xFF {
            return Err(format!("{what} contains non-Latin-1 character {c:?}"));
        }
        out.push(code as u8);
    }
    out.resize(width, 0x20);
    Ok(out)
}

/// Build the I&M1 record `write_im1` writes: BlockHeader(6, type 0x0021,
/// length 58, version 1.0) ++ padding(2) ++ TagFunction(32) ++
/// TagLocation(22) = 62 bytes.
pub fn im1_record(tag_function: &str, tag_location: &str) -> Result<Vec<u8>, String> {
    let mut data = block_header(im::BLOCK_IM1, 58, 1, 0);
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&latin1_field(tag_function, 32, "tag_function")?);
    data.extend_from_slice(&latin1_field(tag_location, 22, "tag_location")?);
    Ok(data)
}

/// Build the I&M2 record `write_im2` writes: BlockHeader(6, type 0x0022,
/// length 20, version 1.0) ++ padding(2) ++ InstallationDate(16) = 24 bytes.
/// The date format is "YYYY-MM-DD HH:MM".
pub fn im2_record(date: &str) -> Result<Vec<u8>, String> {
    let mut data = block_header(im::BLOCK_IM2, 20, 1, 0);
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&latin1_field(date, 16, "date")?);
    Ok(data)
}

/// Build the I&M3 record `write_im3` writes: BlockHeader(6, type 0x0023,
/// length 58, version 1.0) ++ padding(2) ++ Descriptor(54) = 62 bytes.
pub fn im3_record(descriptor: &str) -> Result<Vec<u8>, String> {
    let mut data = block_header(im::BLOCK_IM3, 58, 1, 0);
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&latin1_field(descriptor, 54, "descriptor")?);
    Ok(data)
}

/// Interpret a record payload as an alarm notification (`read_alarm`'s
/// post-read logic): payloads shorter than the 28-byte minimum or that fail
/// to parse yield `None` (the reference lets parse errors propagate; folding
/// them into `None` keeps the no-alarm probe non-fatal).
pub fn alarm_from_record(data: &[u8]) -> Option<AlarmNotification> {
    if data.len() < 28 {
        return None;
    }
    parse_alarm_notification(data).ok()
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Single write operation for [`ProfinetDevice::write_multiple`]
/// (`WriteItem`; api is fixed to 0 like the reference's default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteItem {
    pub slot: u16,
    pub subslot: u16,
    pub index: u16,
    pub data: Vec<u8>,
}

/// All I&M records a device turned out to support (`read_all_im`; the Rust
/// port parses I&M0..3, so only those are probed).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllIm {
    pub im0: Option<im::InM0>,
    pub im1: Option<im::InM1>,
    pub im2: Option<im::InM2>,
    pub im3: Option<im::InM3>,
}

/// Complete device information summary (`DeviceInfo`): DCP discovery data
/// combined with I&M0 identification, the EPM annotation and optionally the
/// physical topology.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceInfo {
    // From DCP.
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub vendor_id: u16,
    pub device_id: u16,
    pub device_type: String,
    pub netmask: String,
    pub gateway: String,
    /// Raw DCP role byte (the reference decodes it into a role-name list).
    pub role: u8,
    pub vendor_name: String,

    // From I&M0 (optional).
    pub im0: Option<im::InM0>,

    // From PDRealData (optional).
    pub topology: Option<im::PdRealData>,

    // From EPM (optional): device model annotation.
    pub annotation: String,
}

impl DeviceInfo {
    /// The DCP-derived part of the summary, before the optional reads.
    pub fn from_dcp(d: &DcpDevice) -> DeviceInfo {
        DeviceInfo {
            name: d.name.clone(),
            ip: s2ip(&d.ip).unwrap_or_default(),
            mac: mac2s(&d.mac),
            vendor_id: d.vendor_id,
            device_id: d.device_id,
            device_type: d.device_type.clone(),
            netmask: s2ip(&d.netmask).unwrap_or_default(),
            gateway: s2ip(&d.gateway).unwrap_or_default(),
            role: d.role,
            vendor_name: get_vendor_name(d.vendor_id),
            ..DeviceInfo::default()
        }
    }

    /// Serial number from I&M0 if available (`serial_number` property).
    pub fn serial_number(&self) -> String {
        self.im0
            .as_ref()
            .map(|im0| im0.serial_number_str().trim().to_string())
            .unwrap_or_default()
    }

    /// Order ID from I&M0 if available (`order_id` property).
    pub fn order_id(&self) -> String {
        self.im0
            .as_ref()
            .map(|im0| im0.order_id_str().trim().to_string())
            .unwrap_or_default()
    }

    /// Hardware revision from I&M0 if available (`hardware_revision`).
    pub fn hardware_revision(&self) -> u16 {
        self.im0.as_ref().map_or(0, |im0| im0.im_hardware_revision)
    }

    /// Software revision string from I&M0 if available
    /// (`software_revision`, e.g. "V1.2.3").
    pub fn software_revision(&self) -> String {
        self.im0
            .as_ref()
            .map(im::InM0::software_revision)
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// ProfinetDevice
// ---------------------------------------------------------------------------

/// High-level PROFINET device interface (`ProfinetDevice`): wraps a DCP
/// discovery result and manages the RPC connection lifecycle, connecting
/// lazily on the first operation. Dropping the device releases the AR.
///
/// ```no_run
/// use std::time::Duration;
/// use profinet_rs::device::ProfinetDevice;
///
/// let mut dev =
///     ProfinetDevice::discover("my-device", "en8", Duration::from_secs(5))?;
/// let im0 = dev.read_im0()?;
/// println!("Order: {}", im0.order_id_str());
/// # Ok::<(), String>(())
/// ```
#[derive(Debug)]
pub struct ProfinetDevice {
    info: DcpDevice,
    interface: String,
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    timeout: Duration,
    rpc: Option<RpcConn>,
}

impl ProfinetDevice {
    /// Wrap a DCP discovery result with explicit controller addressing.
    /// Use [`ProfinetDevice::discover`] / [`ProfinetDevice::from_ip`] /
    /// [`ProfinetDevice::from_dcp_info`] instead of calling this directly
    /// (they look the controller MAC/IP up from the interface).
    pub fn new(
        info: DcpDevice,
        interface: &str,
        src_mac: [u8; 6],
        src_ip: [u8; 4],
        timeout: Duration,
    ) -> ProfinetDevice {
        ProfinetDevice {
            info,
            interface: interface.to_string(),
            src_mac,
            src_ip,
            timeout,
            rpc: None,
        }
    }

    /// Create a device from an existing DCP discovery result
    /// (`from_dcp_info`), looking up the controller MAC and IPv4 from the
    /// interface.
    pub fn from_dcp_info(
        info: DcpDevice,
        interface: &str,
        timeout: Duration,
    ) -> Result<ProfinetDevice, String> {
        let src_mac = pcap::get_mac(interface)?;
        let src_ip = pcap::get_ipv4(interface)?;
        Ok(ProfinetDevice::new(
            info, interface, src_mac, src_ip, timeout,
        ))
    }

    /// Discover a device by station name or MAC address (`discover`). The
    /// timeout is used for both the DCP discovery and later RPC operations,
    /// like the reference. Deviation: the reference resolves names via a
    /// name-filtered DCP Identify; this port filters the Identify-All
    /// responses instead.
    pub fn discover(
        identifier: &str,
        interface: &str,
        timeout: Duration,
    ) -> Result<ProfinetDevice, String> {
        let devices = pcap::discover(interface, timeout)?;
        let info = find_by_identifier(&devices, identifier)
            .ok_or_else(|| format!("Device {identifier:?} not found"))?;
        ProfinetDevice::from_dcp_info(info, interface, timeout)
    }

    /// Discover a device by station name; `discover` restricted to names.
    pub fn from_name(
        name: &str,
        interface: &str,
        timeout: Duration,
    ) -> Result<ProfinetDevice, String> {
        let devices = pcap::discover(interface, timeout)?;
        let info = devices
            .iter()
            .find(|d| d.name == name)
            .cloned()
            .ok_or_else(|| format!("Device {name:?} not found"))?;
        ProfinetDevice::from_dcp_info(info, interface, timeout)
    }

    /// Discover a device by IP address (`from_ip`): DCP Identify-All
    /// filtered by IP.
    pub fn from_ip(ip: &str, interface: &str, timeout: Duration) -> Result<ProfinetDevice, String> {
        let devices = pcap::discover(interface, timeout)?;
        let info = find_by_ip(&devices, ip).ok_or_else(|| format!("No device found at IP {ip}"))?;
        ProfinetDevice::from_dcp_info(info, interface, timeout)
    }

    /// Scan the network for PROFINET devices (`scan`), one wrapper per
    /// Identify-All response.
    pub fn scan(interface: &str, timeout: Duration) -> Result<Vec<ProfinetDevice>, String> {
        let src_mac = pcap::get_mac(interface)?;
        let src_ip = pcap::get_ipv4(interface)?;
        Ok(pcap::discover(interface, timeout)?
            .into_iter()
            .map(|info| ProfinetDevice::new(info, interface, src_mac, src_ip, timeout))
            .collect())
    }

    // -----------------------------------------------------------------------
    // Connection management
    // -----------------------------------------------------------------------

    /// Establish the AR with the device (`connect`): a Device-Access AR for
    /// acyclic read/write, over the raw-L2 UDP transport. Called
    /// automatically by the first operation; explicit calls are idempotent.
    pub fn connect(&mut self) -> Result<(), String> {
        if self.rpc.is_some() {
            return Ok(());
        }
        let mut conn = RpcConn::new_raw(
            &self.interface,
            self.src_mac,
            self.src_ip,
            self.info.mac,
            self.info.ip,
            self.info.device_id,
            self.info.vendor_id,
            self.timeout,
        )?;
        conn.connect_device_access(&self.src_mac, CM_STATION_NAME)
            .map_err(|e| format!("Failed to connect to {}: {e}", self.info.name))?;
        self.rpc = Some(conn);
        Ok(())
    }

    /// Gracefully disconnect (`disconnect`): send the Release terminating
    /// the AR and drop the connection; the next operation reconnects fresh,
    /// like the reference's `_ensure_connected` after a disconnect.
    pub fn disconnect(&mut self) {
        if let Some(mut rpc) = self.rpc.take() {
            rpc.release();
        }
    }

    /// Close the connection and release resources (`close`; also sends the
    /// best-effort Release, which the reference's raw socket close skips).
    pub fn close(&mut self) {
        self.disconnect();
    }

    fn ensure_connected(&mut self) -> Result<&mut RpcConn, String> {
        if self.rpc.is_none() {
            self.connect()?;
        }
        Ok(self.rpc.as_mut().expect("connected above"))
    }

    // -----------------------------------------------------------------------
    // Device info
    // -----------------------------------------------------------------------

    /// Device station name (`name` property).
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// Device IP address as a string (`ip` property).
    pub fn ip(&self) -> String {
        s2ip(&self.info.ip).unwrap_or_default()
    }

    /// Device MAC address as a string (`mac` property).
    pub fn mac(&self) -> String {
        mac2s(&self.info.mac)
    }

    /// The underlying DCP discovery result (`_info`).
    pub fn dcp_info(&self) -> &DcpDevice {
        &self.info
    }

    /// True while an AR is established.
    pub fn is_connected(&self) -> bool {
        self.rpc.is_some()
    }

    /// Complete device information (`get_info`): DCP data plus best-effort
    /// I&M0, EPM annotation and (if requested) topology — read failures
    /// leave the optional fields empty, like the reference's debug-logged
    /// swallows. Connecting itself may fail, hence the `Result`.
    pub fn get_info(&mut self, include_topology: bool) -> Result<DeviceInfo, String> {
        let mut info = DeviceInfo::from_dcp(&self.info);
        let rpc = self.ensure_connected()?;
        info.im0 = rpc.read_im0(0, 1).ok();
        if include_topology {
            info.topology = rpc.read_pd_real_data().ok();
        }
        if let Ok(endpoints) = epm::epm_lookup(
            &self.interface,
            self.src_mac,
            self.src_ip,
            self.info.mac,
            self.info.ip,
            self.timeout,
            None,
        ) {
            if let Some(ep) = endpoints.iter().find(|ep| !ep.annotation.is_empty()) {
                info.annotation = ep.annotation.clone();
            }
        }
        Ok(info)
    }

    // -----------------------------------------------------------------------
    // Read/write operations
    // -----------------------------------------------------------------------

    /// Read a record from the device (`read`), returning the raw record
    /// payload. Uses the default 4096-byte requested length; see
    /// [`ProfinetDevice::read_record_len`] for devices that require the
    /// exact record size.
    pub fn read_record(&mut self, slot: u16, subslot: u16, index: u16) -> Result<Vec<u8>, String> {
        self.read_record_len(slot, subslot, index, READ_LENGTH)
    }

    /// Read a record with an explicit requested length (rpc.py `read()`'s
    /// `length` parameter; some devices mandate the exact record size).
    pub fn read_record_len(
        &mut self,
        slot: u16,
        subslot: u16,
        index: u16,
        length: u32,
    ) -> Result<Vec<u8>, String> {
        self.ensure_connected()?
            .read_raw(index, slot, subslot, length)
    }

    /// Write a record to the device (`write`).
    pub fn write_record(
        &mut self,
        slot: u16,
        subslot: u16,
        index: u16,
        data: &[u8],
    ) -> Result<(), String> {
        self.ensure_connected()?.write(index, slot, subslot, data)
    }

    /// Write multiple records atomically (`write_multiple`), one result per
    /// write.
    pub fn write_multiple(
        &mut self,
        writes: &[WriteItem],
    ) -> Result<Vec<WriteMultipleResult>, String> {
        let entries: Vec<(u16, u16, u16, &[u8])> = writes
            .iter()
            .map(|w| (w.index, w.slot, w.subslot, w.data.as_slice()))
            .collect();
        self.ensure_connected()?.write_multiple(&entries)
    }

    // -----------------------------------------------------------------------
    // I&M convenience methods (reference defaults: slot 0, subslot 1)
    // -----------------------------------------------------------------------

    /// Read I&M0 identification data (`read_im0`, slot 0 / subslot 1).
    pub fn read_im0(&mut self) -> Result<im::InM0, String> {
        self.read_im0_at(0, 1)
    }

    /// Read I&M0 from an explicit slot/subslot.
    pub fn read_im0_at(&mut self, slot: u16, subslot: u16) -> Result<im::InM0, String> {
        self.ensure_connected()?.read_im0(slot, subslot)
    }

    /// Read I&M1 tag function/location (`read_im1`, slot 0 / subslot 1).
    pub fn read_im1(&mut self) -> Result<im::InM1, String> {
        self.read_im1_at(0, 1)
    }

    /// Read I&M1 from an explicit slot/subslot.
    pub fn read_im1_at(&mut self, slot: u16, subslot: u16) -> Result<im::InM1, String> {
        self.ensure_connected()?.read_im1(slot, subslot)
    }

    /// Read I&M2 installation date (`read_im2`, slot 0 / subslot 1).
    pub fn read_im2(&mut self) -> Result<im::InM2, String> {
        self.read_im2_at(0, 1)
    }

    /// Read I&M2 from an explicit slot/subslot.
    pub fn read_im2_at(&mut self, slot: u16, subslot: u16) -> Result<im::InM2, String> {
        self.ensure_connected()?.read_im2(slot, subslot)
    }

    /// Read I&M3 descriptor (`read_im3`, slot 0 / subslot 1).
    pub fn read_im3(&mut self) -> Result<im::InM3, String> {
        self.read_im3_at(0, 1)
    }

    /// Read I&M3 from an explicit slot/subslot.
    pub fn read_im3_at(&mut self, slot: u16, subslot: u16) -> Result<im::InM3, String> {
        self.ensure_connected()?.read_im3(slot, subslot)
    }

    /// Read all available I&M records (`read_all_im`): probe I&M0..3 at the
    /// given slot/subslot, keeping only the ones the device supports.
    pub fn read_all_im(&mut self, slot: u16, subslot: u16) -> Result<AllIm, String> {
        let rpc = self.ensure_connected()?;
        Ok(AllIm {
            im0: rpc.read_im0(slot, subslot).ok(),
            im1: rpc.read_im1(slot, subslot).ok(),
            im2: rpc.read_im2(slot, subslot).ok(),
            im3: rpc.read_im3(slot, subslot).ok(),
        })
    }

    /// Write I&M1 tag function (max 32 chars) and location (max 22 chars)
    /// (`write_im1`, slot 0 / subslot 1).
    pub fn write_im1(&mut self, tag_function: &str, tag_location: &str) -> Result<(), String> {
        let data = im1_record(tag_function, tag_location)?;
        self.write_record(0, 1, im::IM1, &data)
    }

    /// Write the I&M2 installation date, format "YYYY-MM-DD HH:MM", max 16
    /// chars (`write_im2`, slot 0 / subslot 1).
    pub fn write_im2(&mut self, date: &str) -> Result<(), String> {
        let data = im2_record(date)?;
        self.write_record(0, 1, im::IM2, &data)
    }

    /// Write the I&M3 descriptor, max 54 chars (`write_im3`, slot 0 /
    /// subslot 1).
    pub fn write_im3(&mut self, descriptor: &str) -> Result<(), String> {
        let data = im3_record(descriptor)?;
        self.write_record(0, 1, im::IM3, &data)
    }

    // -----------------------------------------------------------------------
    // Configuration & diagnosis
    // -----------------------------------------------------------------------

    /// Read diagnosis data (`read_diagnosis`; reference defaults slot 0,
    /// subslot 0, index 0xF000 for all diagnosis). Read errors yield an
    /// empty [`DiagnosisData`], like the reference's swallow.
    pub fn read_diagnosis(
        &mut self,
        slot: u16,
        subslot: u16,
        index: u16,
    ) -> Result<DiagnosisData, String> {
        Ok(self
            .ensure_connected()?
            .read_diagnosis(slot, subslot, index))
    }

    /// Read diagnosis from all standard indices (`read_all_diagnosis`),
    /// keeping only the ones with entries.
    pub fn read_all_diagnosis(&mut self) -> Result<BTreeMap<u16, DiagnosisData>, String> {
        Ok(self.ensure_connected()?.read_all_diagnosis())
    }

    /// Discover all slots/subslots from RealIdentificationData
    /// (`discover_slots`).
    pub fn discover_slots(&mut self) -> Result<Vec<DeviceSlot>, String> {
        self.ensure_connected()?.discover_slots()
    }

    /// Read the physical topology (`read_topology`: PDRealData 0xF841).
    pub fn read_topology(&mut self) -> Result<im::PdRealData, String> {
        self.ensure_connected()?.read_pd_real_data()
    }

    /// Read alarm data (`read_alarm`; reference defaults slot 0, subslot 0,
    /// index 0x800C): `None` when no alarm is present or the read fails.
    pub fn read_alarm(&mut self, slot: u16, subslot: u16, index: u16) -> Option<AlarmNotification> {
        let data = self.read_record(slot, subslot, index).ok()?;
        alarm_from_record(&data)
    }
}

/// `__repr__`: `ProfinetDevice('name', ip, connected|disconnected)`.
impl fmt::Display for ProfinetDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProfinetDevice({:?}, {}, {})",
            self.info.name,
            self.ip(),
            if self.rpc.is_some() {
                "connected"
            } else {
                "disconnected"
            }
        )
    }
}

/// Dropping the device releases the AR (the context-manager `__exit__`).
impl Drop for ProfinetDevice {
    fn drop(&mut self) {
        self.close();
    }
}
