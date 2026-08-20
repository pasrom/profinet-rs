//! PROFINET RT_CLASS_1 real-time framing, ported from
//! `profinet-py/profinet/rt.py` (RTFrame, IOCRConfig, IODataObject,
//! CyclicDataBuilder, build_iocr_configs and the frame-id / data-status
//! constants).
//!
//! `RtFrame` bytes cover only the RT payload (frame_id .. APDU status
//! trailer), exactly like the reference: the Ethernet header is prepended
//! separately by [`build_ethernet_frame`].

use crate::util::skip_vlan_tags;

/// EtherType for PROFINET RT frames.
pub const ETHERTYPE_PROFINET: u16 = 0x8892;

/// Frame ID ranges.
pub const FRAME_ID_RT_CLASS_1_MIN: u16 = 0x8000;
pub const FRAME_ID_RT_CLASS_1_MAX: u16 = 0xFBFF;

/// Whether a frame ID can carry RT_CLASS_1 cyclic data. The controller now
/// lets the device assign the output CR's frame ID, so the answer has to be
/// checked before transmitting: a device that omits the IOCRBlockRes leaves it
/// 0x0000, and one that echoes the request leaves it 0xFFFF. Both are
/// reserved, and frames sent with them are discarded without a word.
pub fn is_rt_class_1_frame_id(frame_id: u16) -> bool {
    (FRAME_ID_RT_CLASS_1_MIN..=FRAME_ID_RT_CLASS_1_MAX).contains(&frame_id)
}
pub const FRAME_ID_ALARM_HIGH: u16 = 0xFC01;
pub const FRAME_ID_ALARM_LOW: u16 = 0xFE01;

/// IOCR types.
pub const IOCR_TYPE_INPUT: u16 = 1; // Device -> Controller
pub const IOCR_TYPE_OUTPUT: u16 = 2; // Controller -> Device

/// RT Class values.
pub const RT_CLASS_1: u8 = 0x01; // Software scheduled (250us - 512ms)
pub const RT_CLASS_2: u8 = 0x02; // Hardware scheduled (reserved)
pub const RT_CLASS_3: u8 = 0x03; // IRT (isochronous, hardware only)

/// DataStatus bit definitions.
pub const DATA_STATUS_STATE: u8 = 0x01; // 0=Backup, 1=Primary
pub const DATA_STATUS_REDUNDANCY: u8 = 0x02; // Redundancy state
pub const DATA_STATUS_VALID: u8 = 0x04; // 0=Invalid, 1=Valid
pub const DATA_STATUS_RESERVED: u8 = 0x08;
pub const DATA_STATUS_PROVIDER_RUN: u8 = 0x10; // 0=Stop, 1=Run
pub const DATA_STATUS_STATION_OK: u8 = 0x20; // 0=Problem, 1=OK
pub const DATA_STATUS_IGNORE: u8 = 0x80; // 1=Ignore frame

/// IOxS (Provider/Consumer Status) values.
pub const IOXS_GOOD: u8 = 0x80; // Good data, subslot level
/// DataState is bit 7 of an IOxS byte; the lower bits carry Instance and
/// Extension, so a *received* IOxS must be masked with this rather than
/// compared against [`IOXS_GOOD`].
pub const IOXS_DATA_STATE_GOOD: u8 = 0x80;
pub const IOXS_BAD: u8 = 0x00; // Bad data
pub const IOXS_EXTENSION: u8 = 0x01; // More IOxS follows

/// PROFINET Real-Time cyclic frame (RTFrame): frame_id ++ C_SDU payload ++
/// APDU status trailer (cycle_counter, data_status, transfer_status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtFrame {
    /// Frame ID identifying the IOCR (0x8000-0xFBFF for RT_CLASS_1).
    pub frame_id: u16,
    /// 16-bit cycle counter, increments each cycle.
    pub cycle_counter: u16,
    /// DataStatus byte with validity and state flags.
    pub data_status: u8,
    /// TransferStatus byte (usually 0).
    pub transfer_status: u8,
    /// C_SDU payload containing process data and IOxS.
    pub payload: Vec<u8>,
}

impl RtFrame {
    /// Parse an RT frame from raw bytes (after the Ethernet header), as
    /// `RTFrame.from_bytes`: frame_id (u16 BE), payload, then the 4-byte
    /// trailer cycle_counter (u16 BE) ++ data_status ++ transfer_status.
    pub fn from_bytes(data: &[u8]) -> Result<RtFrame, String> {
        if data.len() < 6 {
            return Err(format!("RT frame too short: {} bytes", data.len()));
        }
        let trailer = &data[data.len() - 4..];
        Ok(RtFrame {
            frame_id: u16::from_be_bytes([data[0], data[1]]),
            cycle_counter: u16::from_be_bytes([trailer[0], trailer[1]]),
            data_status: trailer[2],
            transfer_status: trailer[3],
            payload: data[2..data.len() - 4].to_vec(),
        })
    }

    /// Serialize to bytes (frame_id ++ payload ++ trailer), as
    /// `RTFrame.to_bytes`. Does NOT include the Ethernet header.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.payload.len() + 4);
        out.extend_from_slice(&self.frame_id.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.cycle_counter.to_be_bytes());
        out.push(self.data_status);
        out.push(self.transfer_status);
        out
    }

    /// True if data is valid (DataStatus bit 2).
    pub fn is_valid(&self) -> bool {
        self.data_status & DATA_STATUS_VALID != 0
    }

    /// True if provider is running (DataStatus bit 4).
    pub fn is_running(&self) -> bool {
        self.data_status & DATA_STATUS_PROVIDER_RUN != 0
    }

    /// True if station is OK (DataStatus bit 5).
    pub fn is_ok(&self) -> bool {
        self.data_status & DATA_STATUS_STATION_OK != 0
    }

    /// True if this is primary data (DataStatus bit 0).
    pub fn is_primary(&self) -> bool {
        self.data_status & DATA_STATUS_STATE != 0
    }
}

/// Single IO data object within C_SDU (IODataObject): one piece of process
/// data mapped to a slot/subslot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoDataObject {
    /// Slot number.
    pub slot: u16,
    /// Subslot number.
    pub subslot: u16,
    /// Offset within C_SDU payload for data.
    pub frame_offset: usize,
    /// Length of process data in bytes.
    pub data_length: usize,
    /// Offset for IOPS (Provider Status) byte.
    pub iops_offset: usize,
    /// Offset of the IOCS (Consumer Status) byte, for the objects that carry
    /// one. `None` rather than a sentinel: offset 0 is a real position — an
    /// input-only device puts the first IOCS byte there — and a `> 0` guard
    /// silently excluded it, so its consumer status stayed BAD for the whole
    /// session.
    pub iocs_offset: Option<usize>,
}

/// IOCR configuration from AR setup (IOCRConfig): timing parameters and IO
/// object mappings for cyclic data exchange. Plain data, no wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocrConfig {
    /// IOCR type: 1=Input (device->controller), 2=Output (controller->device).
    pub iocr_type: u16,
    /// Local IOCR reference number.
    pub iocr_reference: u16,
    /// Assigned Frame ID (0x8000-0xFBFF for RT_CLASS_1).
    pub frame_id: u16,
    /// Base clock multiplier (32 = 1ms base).
    pub send_clock_factor: u16,
    /// Update rate reduction (1 = every cycle).
    pub reduction_ratio: u16,
    /// Phase offset within cycle.
    pub phase: u16,
    /// Watchdog multiplier (timeout = watchdog_factor * cycle_time).
    pub watchdog_factor: u16,
    /// Total C_SDU length (minimum 40 bytes).
    pub data_length: usize,
    /// IO data objects within this IOCR.
    pub objects: Vec<IoDataObject>,
}

impl IocrConfig {
    /// New config with the reference dataclass defaults (send_clock_factor 32,
    /// reduction_ratio 32, phase 0, watchdog_factor 3, data_length 40).
    pub fn new(iocr_type: u16, iocr_reference: u16, frame_id: u16) -> IocrConfig {
        IocrConfig {
            iocr_type,
            iocr_reference,
            frame_id,
            send_clock_factor: 32,
            reduction_ratio: 32,
            phase: 0,
            watchdog_factor: 3,
            data_length: 40,
            objects: Vec::new(),
        }
    }

    /// Cycle time in microseconds: reduction_ratio * send_clock_factor *
    /// 31.25us, computed with integer math (31.25 = 125/4) as the reference.
    pub fn cycle_time_us(&self) -> u64 {
        (self.reduction_ratio as u64 * self.send_clock_factor as u64 * 125) / 4
    }

    /// Cycle time in milliseconds.
    pub fn cycle_time_ms(&self) -> f64 {
        self.cycle_time_us() as f64 / 1000.0
    }

    /// Watchdog timeout in microseconds.
    pub fn watchdog_time_us(&self) -> u64 {
        self.watchdog_factor as u64 * self.cycle_time_us()
    }

    /// True if this is an Input IOCR (device->controller).
    pub fn is_input(&self) -> bool {
        self.iocr_type == IOCR_TYPE_INPUT
    }

    /// True if this is an Output IOCR (controller->device).
    pub fn is_output(&self) -> bool {
        self.iocr_type == IOCR_TYPE_OUTPUT
    }
}

/// Builds the C_SDU payload from IO data objects with double-buffering
/// (CyclicDataBuilder): the application writes into the write buffer via
/// [`CyclicDataBuilder::set_data`], the TX path promotes it with
/// [`CyclicDataBuilder::swap`] and reads it with [`CyclicDataBuilder::build`].
///
/// Unlike the reference (which locks internally), the Rust builder is a plain
/// `&mut self` struct; `cyclic::CyclicController` wraps it in one `Mutex`,
/// which preserves the swap/build semantics with equivalent synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CyclicDataBuilder {
    /// IOCR configuration with data length and object mappings.
    pub config: IocrConfig,
    write_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
    dirty: bool,
}

impl CyclicDataBuilder {
    /// New builder with zeroed buffers of `config.data_length` bytes.
    pub fn new(config: IocrConfig) -> CyclicDataBuilder {
        let len = config.data_length;
        CyclicDataBuilder {
            config,
            write_buffer: vec![0; len],
            send_buffer: vec![0; len],
            dirty: false,
        }
    }

    /// Set process data for a slot/subslot in the write buffer. Data longer
    /// than the object is truncated, shorter data writes a prefix (the
    /// reference's `data[: obj.data_length]` slice semantics).
    pub fn set_data(&mut self, slot: u16, subslot: u16, data: &[u8]) -> Result<(), String> {
        for obj in &self.config.objects {
            if obj.slot == slot && obj.subslot == subslot {
                let n = data.len().min(obj.data_length);
                self.write_buffer[obj.frame_offset..obj.frame_offset + n]
                    .copy_from_slice(&data[..n]);
                self.dirty = true;
                return Ok(());
            }
        }
        Err(format!("Unknown slot/subslot: {slot}/{subslot}"))
    }

    /// Get process data for a slot/subslot from the write buffer.
    pub fn get_data(&self, slot: u16, subslot: u16) -> Result<Vec<u8>, String> {
        for obj in &self.config.objects {
            if obj.slot == slot && obj.subslot == subslot {
                return Ok(
                    self.write_buffer[obj.frame_offset..obj.frame_offset + obj.data_length]
                        .to_vec(),
                );
            }
        }
        Err(format!("Unknown slot/subslot: {slot}/{subslot}"))
    }

    /// Set Provider Status (IOPS) for a slot/subslot. Skips IOCS-only
    /// objects (data_length == 0) which have no IOPS byte; unknown
    /// slot/subslot is silently ignored, as the reference.
    pub fn set_iops(&mut self, slot: u16, subslot: u16, status: u8) {
        for obj in &self.config.objects {
            if obj.slot == slot && obj.subslot == subslot {
                if obj.data_length > 0 {
                    self.write_buffer[obj.iops_offset] = status;
                    self.dirty = true;
                }
                return;
            }
        }
    }

    /// Set Consumer Status (IOCS) for a slot/subslot (objects that carry one);
    /// unknown slot/subslot is silently ignored.
    pub fn set_iocs(&mut self, slot: u16, subslot: u16, status: u8) {
        for obj in &self.config.objects {
            if obj.slot == slot && obj.subslot == subslot {
                if let Some(off) = obj.iocs_offset {
                    self.write_buffer[off] = status;
                    self.dirty = true;
                }
                return;
            }
        }
    }

    /// Set IOPS for all objects that carry process data (data_length > 0).
    pub fn set_all_iops(&mut self, status: u8) {
        for obj in &self.config.objects {
            if obj.data_length > 0 {
                self.write_buffer[obj.iops_offset] = status;
            }
        }
        self.dirty = true;
    }

    /// Set IOCS for all objects that have an iocs_offset.
    pub fn set_all_iocs(&mut self, status: u8) {
        for obj in &self.config.objects {
            if let Some(off) = obj.iocs_offset {
                if self.write_buffer[off] != status {
                    self.write_buffer[off] = status;
                    self.dirty = true;
                }
            }
        }
    }

    /// Clear all data to zeros.
    pub fn clear(&mut self) {
        self.write_buffer.fill(0);
        self.dirty = true;
    }

    /// Swap the write buffer into the send buffer. Called by the TX path at
    /// the start of each cycle; only copies if dirty since the last swap.
    pub fn swap(&mut self) {
        if self.dirty {
            self.send_buffer.copy_from_slice(&self.write_buffer);
            self.dirty = false;
        }
    }

    /// Build and return the C_SDU payload from the send buffer.
    pub fn build(&self) -> Vec<u8> {
        self.send_buffer.clone()
    }

    /// True if the write buffer has unswapped changes (mirrors the reference's
    /// `_dirty` flag; read-only, used to observe the swap-skip optimization).
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Load payload data into the write buffer (truncating to buffer size).
    pub fn load(&mut self, payload: &[u8]) {
        let n = payload.len().min(self.write_buffer.len());
        self.write_buffer[..n].copy_from_slice(&payload[..n]);
        self.dirty = true;
    }
}

/// Build the (input, output) [`IocrConfig`] pair for the cyclic controller
/// from slot definitions, as `build_iocr_configs`: frame offsets match what
/// the connect IOCR blocks describe, including IOCS entries for submodules
/// without data in each direction. The output IOCR gets IOCS-only objects
/// (data_length 0) for input-only submodules so `set_all_iocs` can
/// acknowledge received input (PROTO-2/3).
pub fn build_iocr_configs(
    slots: &[crate::gsdml::IoSlot],
    input_frame_id: u16,
    output_frame_id: u16,
    send_clock_factor: u16,
    reduction_ratio: u16,
    watchdog_factor: u16,
) -> (IocrConfig, IocrConfig) {
    // --- Input IOCR: device -> controller ---
    let mut input_objects = Vec::new();
    let mut frame_offset = 0usize;
    for s in slots {
        if s.input_length > 0 {
            input_objects.push(IoDataObject {
                slot: s.slot,
                subslot: s.subslot,
                frame_offset,
                data_length: s.input_length,
                iops_offset: frame_offset + s.input_length,
                iocs_offset: None,
            });
            frame_offset += s.input_length + 1; // data + IOPS byte
        }
    }
    // IOCS entries for slots with no input data
    for s in slots {
        if s.input_length == 0 {
            frame_offset += 1;
        }
    }
    let input_iocr = IocrConfig {
        iocr_type: IOCR_TYPE_INPUT,
        iocr_reference: 1,
        frame_id: input_frame_id,
        send_clock_factor,
        reduction_ratio,
        phase: 0,
        watchdog_factor,
        data_length: frame_offset.max(40),
        objects: input_objects,
    };

    // --- Output IOCR: controller -> device ---
    let mut output_objects = Vec::new();
    let mut frame_offset = 0usize;
    for s in slots {
        if s.output_length > 0 {
            output_objects.push(IoDataObject {
                slot: s.slot,
                subslot: s.subslot,
                frame_offset,
                data_length: s.output_length,
                iops_offset: frame_offset + s.output_length,
                iocs_offset: None,
            });
            frame_offset += s.output_length + 1; // data + IOPS byte
        }
    }
    // IOCS entries for slots with no output data (PROTO-2/3 fix): the
    // controller sets their IOCS to GOOD to acknowledge the device's input.
    for s in slots {
        if s.output_length == 0 {
            output_objects.push(IoDataObject {
                slot: s.slot,
                subslot: s.subslot,
                frame_offset,
                data_length: 0,
                iops_offset: 0,
                iocs_offset: Some(frame_offset),
            });
            frame_offset += 1;
        }
    }
    let output_iocr = IocrConfig {
        iocr_type: IOCR_TYPE_OUTPUT,
        iocr_reference: 2,
        frame_id: output_frame_id,
        send_clock_factor,
        reduction_ratio,
        phase: 0,
        watchdog_factor,
        data_length: frame_offset.max(40),
        objects: output_objects,
    };

    (input_iocr, output_iocr)
}

/// 802.1Q priority tag for cyclic RT frames per IEC 61158-6-10: TPID 0x8100,
/// PCP 6, VID 0 (TCI 0xC000, matching the negotiated IOCRTagHeader). RT frames
/// are defined as priority-tagged: devices validate the negotiated priority,
/// and managed switches may drop untagged sub-64-byte RT frames as runts.
pub const VLAN_TAG_RT: [u8; 4] = [0x81, 0x00, 0xC0, 0x00];

/// Build a complete Ethernet frame with RT payload, as
/// `build_ethernet_frame`: dst_mac ++ src_mac ++ VLAN tag ++ ethertype 0x8892
/// ++ frame.
pub fn build_ethernet_frame(dst_mac: &[u8; 6], src_mac: &[u8; 6], rt_frame: &RtFrame) -> Vec<u8> {
    let body = rt_frame.to_bytes();
    let mut out = Vec::with_capacity(18 + body.len());
    out.extend_from_slice(dst_mac);
    out.extend_from_slice(src_mac);
    out.extend_from_slice(&VLAN_TAG_RT);
    out.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Parse an Ethernet frame and extract the RT frame, as
/// `parse_ethernet_frame`: None unless ethertype is 0x8892 and the RT part
/// parses.
pub fn parse_ethernet_frame(data: &[u8]) -> Option<RtFrame> {
    if data.len() < 18 {
        // 14 (eth) + 4 (min RT)
        return None;
    }
    // RT frames are priority-tagged, including the ones build_ethernet_frame
    // emits, so the EtherType is not at a fixed offset.
    let eth_offset = skip_vlan_tags(data);
    if data.len() < eth_offset + 2 {
        return None;
    }
    if u16::from_be_bytes([data[eth_offset], data[eth_offset + 1]]) != ETHERTYPE_PROFINET {
        return None;
    }
    RtFrame::from_bytes(&data[eth_offset + 2..]).ok()
}
