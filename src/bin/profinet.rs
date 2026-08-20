//! PROFINET IO-controller command-line interface, a 1:1 port of
//! `profinet-py/profinet/cli.py`. Mirrors its subcommands (discover,
//! get-param/set-param, read/write, read-inm0..3, read-inm0-filter, set-ip,
//! signal, reset, cyclic) using this crate's existing pieces over the raw-L2
//! (libpcap) transport so it works headless on macOS.
//!
//! Every subcommand takes the global `-i/--interface`. The DCP commands
//! address the device by MAC; the RPC/cyclic commands by station name and
//! resolve the device MAC/IP internally via DCP discovery.
//!
//! Usage:
//!   profinet -i en8 discover
//!   profinet -i en8 get-param aa:bb:cc:dd:ee:ff name
//!   profinet -i en8 read my-device --slot 0 --subslot 1 --index 0xAFF0
//!   profinet -i en8 cyclic my-device --gsdml dev.xml --cycle-ms 32

use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use serde::Serialize;

use profinet_rs::connect::IocrSetup;
use profinet_rs::cyclic::{CyclicController, CyclicState};
use profinet_rs::dcp;
use profinet_rs::gsdml::load_gsdml;
use profinet_rs::im;
use profinet_rs::pcap::{self, RawSocket};
use profinet_rs::rt::build_iocr_configs;
use profinet_rs::transport::{RpcConn, READ_LENGTH};
use profinet_rs::util::{ip2s, mac2s, s2ip, s2mac};

const RPC_TIMEOUT: Duration = Duration::from_secs(5);
/// Set by the Ctrl+C handler; the long-running loops poll it and break to
/// their clean shutdown path (STOP frames + AR release) instead of dying
/// mid-AR.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// Whether a repeat Ctrl+C may hard-exit the process. Starts false and is
/// set true only once a hard exit is provably harmless: immediately when no
/// output is ever driven, and otherwise ONLY after the safe shutdown has
/// driven the safe image, verified it via 0x8029, stopped the cyclic frames
/// and released the AR. `process::exit` runs no destructors — no
/// [`safe_shutdown`], no `Drop` — and a device may keep applying the last
/// output image it received, so an ungated hard exit could leave a commanded
/// bit set with nothing driving it back.
static SAFE_TO_HARD_EXIT: AtomicBool = AtomicBool::new(false);
const APP_READY_TIMEOUT: Duration = Duration::from_secs(15);
/// profinet-py hardcodes the CMInitiatorStationName "tp". Match it rather
/// than inventing one: that is the value this port has been proven
/// interoperable with, and no device is known to require anything else.
const CM_STATION_NAME: &[u8] = b"tp";

#[derive(Parser, Debug)]
#[command(
    name = "profinet",
    about = "PROFINET IO-Controller CLI",
    after_help = "https://github.com/f0rw4rd/profinet-py"
)]
struct Cli {
    /// Network interface to use.
    #[arg(short, long, value_name = "IFACE")]
    interface: String,

    /// Enable verbose output.
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug output.
    #[arg(long)]
    debug: bool,

    /// Discovery timeout in seconds.
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,

    #[command(subcommand)]
    command: Command,
}

/// Parameter selector for get-param/set-param (argparse `choices`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Param {
    Name,
    Ip,
}

/// Reset mode for the reset command (argparse `choices`, default factory).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ResetMode {
    Communication,
    Application,
    Engineering,
    #[value(name = "all-data")]
    AllData,
    Device,
    Factory,
}

impl ResetMode {
    fn mask(self) -> u16 {
        match self {
            ResetMode::Communication => dcp::RESET_MODE_COMMUNICATION,
            ResetMode::Application => dcp::RESET_MODE_APPLICATION,
            ResetMode::Engineering => dcp::RESET_MODE_ENGINEERING,
            ResetMode::AllData => dcp::RESET_MODE_ALL_DATA,
            ResetMode::Device => dcp::RESET_MODE_DEVICE,
            ResetMode::Factory => dcp::RESET_MODE_FACTORY,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ResetMode::Communication => "communication",
            ResetMode::Application => "application",
            ResetMode::Engineering => "engineering",
            ResetMode::AllData => "all-data",
            ResetMode::Device => "device",
            ResetMode::Factory => "factory",
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover PROFINET devices.
    Discover,

    /// Read device parameter.
    GetParam {
        /// Device MAC address (e.g. aa:bb:cc:dd:ee:ff).
        #[arg(value_name = "MAC")]
        target: String,
        /// Parameter to read.
        #[arg(value_enum)]
        param: Param,
    },

    /// Write device parameter.
    SetParam {
        /// Device MAC address (e.g. aa:bb:cc:dd:ee:ff).
        #[arg(value_name = "MAC")]
        target: String,
        /// Parameter to write.
        #[arg(value_enum)]
        param: Param,
        /// New value.
        value: String,
    },

    /// Read data record.
    Read {
        /// Station name (e.g. my-device).
        #[arg(value_name = "NAME")]
        target: String,
        /// API (default: 0).
        #[arg(long, default_value_t = 0)]
        api: u32,
        /// Slot number.
        #[arg(long)]
        slot: u16,
        /// Subslot number.
        #[arg(long)]
        subslot: u16,
        /// Record index (decimal or hex with 0x prefix).
        #[arg(long)]
        index: String,
        /// Requested record length in bytes (some devices mandate the exact
        /// record size).
        #[arg(long, default_value_t = READ_LENGTH)]
        length: u32,
        /// Use the AR-less Read Implicit service instead of connecting a
        /// Device Access AR (for stacks that reject the AR).
        #[arg(long)]
        implicit: bool,
    },

    /// Write data record.
    Write {
        /// Station name (e.g. my-device).
        #[arg(value_name = "NAME")]
        target: String,
        /// API (default: 0).
        #[arg(long, default_value_t = 0)]
        api: u32,
        /// Slot number.
        #[arg(long)]
        slot: u16,
        /// Subslot number.
        #[arg(long)]
        subslot: u16,
        /// Record index (decimal or hex with 0x prefix, e.g. 0xAFF1).
        #[arg(long)]
        index: String,
        /// Data to write as a hex string (e.g. deadbeef).
        #[arg(value_name = "HEX")]
        data: String,
    },

    /// Read device topology.
    ReadInm0Filter {
        /// Station name (e.g. my-device).
        #[arg(value_name = "NAME")]
        target: String,
    },

    /// Read IM0 identification data.
    ReadInm0(ImArgs),
    /// Read IM1 tag data.
    ReadInm1(ImArgs),
    /// Read IM2 date data.
    ReadInm2(ImArgs),
    /// Read IM3 descriptor data.
    ReadInm3(ImArgs),

    /// Set device IP configuration via DCP.
    SetIp {
        /// Device MAC address (e.g. aa:bb:cc:dd:ee:ff).
        #[arg(value_name = "MAC")]
        target: String,
        /// IP address.
        ip: String,
        /// Subnet mask.
        netmask: String,
        /// Gateway address.
        gateway: String,
        /// Save IP permanently.
        #[arg(long)]
        permanent: bool,
    },

    /// Flash device LEDs.
    Signal {
        /// Device MAC address (e.g. aa:bb:cc:dd:ee:ff).
        #[arg(value_name = "MAC")]
        target: String,
    },

    /// Reset device to factory settings.
    Reset {
        /// Device MAC address (e.g. aa:bb:cc:dd:ee:ff).
        #[arg(value_name = "MAC")]
        target: String,
        /// Reset mode.
        #[arg(long, value_enum, default_value = "factory")]
        mode: ResetMode,
    },

    /// Monitor cyclic IO using GSDML.
    Cyclic {
        /// Station name (e.g. my-device).
        #[arg(value_name = "NAME")]
        target: String,
        /// Path to GSDML XML file.
        #[arg(long)]
        gsdml: String,
        /// Cycle time in ms (default: 32).
        #[arg(long, default_value_t = 32)]
        cycle_ms: u16,
        /// Seconds to run (0 = until Ctrl+C).
        #[arg(long, default_value_t = 0)]
        duration: u64,
        /// Submodule override as slot:subslot:submodule_id (repeatable).
        #[arg(long, value_name = "SLOT:SUBSLOT:ID")]
        submodule: Vec<String>,
    },

    /// Serve acyclic record reads and writes over stdin/stdout as NDJSON, so
    /// a consuming application can drive the device without this tool knowing
    /// what any index means.
    ///
    /// Opens a Device-Access AR (acyclic only, no IOCRs), then answers one
    /// response per request. Which indices exist, how long they are and what
    /// the bytes mean is the caller's business; this side does the AR, the
    /// request pacing, the BUSY retry, and reports what the device said
    /// verbatim.
    ///
    /// `--read-only` refuses write commands at the process boundary, which is
    /// what a caller that must not be able to command anything should spawn.
    ///
    /// `--cyclic` additionally claims the full IO AR, streams the input image
    /// as `cyclic` lines at cycle rate, and (bounded by `--allow-mask`) drives
    /// the output image from `set_level` / `pulse` commands. See those flags
    /// for what taking that AR costs.
    Serve {
        /// Station name or IPv4 address.
        #[arg(value_name = "NAME")]
        target: String,
        /// Refuse every write command, whatever arrives on stdin.
        #[arg(long)]
        read_only: bool,
        /// Minimum gap between acyclic requests, in ms. Some devices throttle
        /// acyclic access and answer BUSY if asked again too soon.
        #[arg(long, default_value_t = 0)]
        gap_ms: u64,
        /// Send a keepalive read this often when the caller is idle, so the
        /// AR does not lapse. 0 disables it.
        #[arg(long, default_value_t = 2000)]
        keepalive_ms: u64,
        /// Also receive the cyclic process image, emitted as `cyclic` NDJSON
        /// lines at cycle rate.
        ///
        /// This makes us the IO-controller: it needs a full IO AR, which the
        /// device grants to only one controller at a time. Against a plant
        /// that is actually being controlled, taking that AR displaces the
        /// real controller and the outputs become ours. Bench and
        /// commissioning only. Requires --gsdml.
        #[arg(long)]
        cyclic: bool,
        /// GSDML file describing the device. Required by --cyclic, which needs
        /// the submodule layout to size the IOCRs.
        ///
        /// It must match the running firmware: a GSDML declaring a longer
        /// input image than the device sends makes every cyclic read silently
        /// return zeros. --cyclic verifies this before it starts.
        #[arg(long)]
        gsdml: Option<String>,
        /// Cyclic cycle time in ms (power of two, default 16).
        #[arg(long, default_value_t = 16)]
        cycle_ms: u16,
        /// Bits that may ever be driven on the output image, as a byte mask
        /// (decimal or 0x hex).
        ///
        /// Defaults to 0: nothing may be driven, so a session started without
        /// thinking about it refuses everything rather than commanding
        /// something. A command touching any bit outside this mask is refused
        /// whole, not masked down. The application decides which bits are safe
        /// to arm for the task at hand and passes them here.
        #[arg(long, default_value_t = 0, value_parser = parse_u8_maybe_hex)]
        allow_mask: u8,
        /// Confirm the device is on a bench with no other IO-controller
        /// attached. Required together with a non-zero --allow-mask: driving
        /// outputs means displacing whatever controller held the AR.
        #[arg(long)]
        i_am_on_the_bench: bool,
        /// Seconds to hold the AR in cyclic mode (0 = until stdin EOF, a quit
        /// command, or Ctrl+C).
        #[arg(long, default_value_t = 0)]
        seconds: u64,
    },
}

/// Shared args for the read-inm0..3 commands (argparse defaults: slot 0,
/// subslot 1).
#[derive(clap::Args, Debug)]
struct ImArgs {
    /// Station name (e.g. my-device).
    #[arg(value_name = "NAME")]
    target: String,
    /// API (default: 0).
    #[arg(long, default_value_t = 0)]
    api: u32,
    /// Slot number (default: 0).
    #[arg(long, default_value_t = 0)]
    slot: u16,
    /// Subslot number (default: 1).
    #[arg(long, default_value_t = 1)]
    subslot: u16,
}

/// Parse a record index accepting both decimal and `0x`-prefixed hex, like
/// cli.py `int(args.index, 16) if startswith("0x") else int(args.index)`.
fn parse_index(s: &str) -> Result<u16, String> {
    let value = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16)
    } else {
        s.parse::<u16>()
    };
    value.map_err(|_| format!("invalid index {s:?}"))
}

/// Decode a hex string, ignoring spaces (cli.py
/// `bytes.fromhex(data.replace(" ", ""))`).
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string {s:?}"));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| format!("invalid hex {s:?}"))
        })
        .collect()
}

/// Parse a dotted-quad into 4 bytes (cli.py `ip_to_bytes`).
fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    ip2s(s)
}

// ---------------------------------------------------------------------------
// DCP (raw-L2) commands
// ---------------------------------------------------------------------------

/// Send a DCP request and wait for a SET response, returning the block error
/// code. Mirrors dcp.py `_recv_set_response`: skip frames not addressed to us
/// and non-response frames (our own echoed request), enforce the timeout.
fn dcp_set_roundtrip(
    iface: &str,
    my_mac: &[u8; 6],
    request: &[u8],
    timeout: Duration,
) -> Result<u8, String> {
    // Match the response to THIS request's xid so a stray RTA/RT frame or a
    // foreign device cannot be mistaken for a SET success.
    let expected_xid =
        dcp::parse_dcp_xid(request).ok_or_else(|| "malformed DCP request".to_string())?;
    let mut sock = RawSocket::open(iface, Some(dcp::PROFINET_ETHERTYPE))?;
    sock.send(request)?;

    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("No DCP SET response received".to_string());
        }
        let Some(frame) = sock.recv(deadline - now)? else {
            return Err("No DCP SET response received".to_string());
        };
        if frame.len() < 14 || frame[0..6] != my_mac[..] {
            continue;
        }
        match dcp::parse_set_response(&frame, expected_xid) {
            Ok(Some(code)) => return Ok(code),
            // Not our response (echoed request, foreign/stale frame): keep waiting.
            Ok(None) => continue,
            Err(e) => return Err(e),
        }
    }
}

fn cmd_get_param(iface: &str, my_mac: &[u8; 6], target: &str, param: Param) -> Result<i32, String> {
    let dst = s2mac(target)?;
    let (option, suboption) = match param {
        Param::Name => (dcp::DCP_OPTION_DEVICE, dcp::DCP_SUBOPTION_DEVICE_NAME),
        Param::Ip => (dcp::DCP_OPTION_IP, dcp::DCP_SUBOPTION_IP_PARAMETER),
    };
    let request = dcp::get_request(my_mac, &dst, gen_xid()?, option, suboption);

    let mut sock = RawSocket::open(iface, Some(dcp::PROFINET_ETHERTYPE))?;
    sock.send(&request)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now = Instant::now();
        if now >= deadline {
            println!("Could not read parameter '{}'", param_name(param));
            return Ok(1);
        }
        let Some(frame) = sock.recv(deadline - now)? else {
            println!("Could not read parameter '{}'", param_name(param));
            return Ok(1);
        };
        if frame.len() < 14 || frame[0..6] != my_mac[..] {
            continue;
        }
        match dcp::parse_get_response(&frame, option, suboption) {
            Ok(Some(value)) => {
                match param {
                    Param::Name => {
                        println!("{}", String::from_utf8_lossy(&value));
                    }
                    Param::Ip => {
                        let ip = &value[..value.len().min(4)];
                        println!("{}", s2ip(ip).unwrap_or_else(|_| "?".to_string()));
                    }
                }
                return Ok(0);
            }
            Ok(None) | Err(_) => continue,
        }
    }
}

fn cmd_set_param(
    iface: &str,
    my_mac: &[u8; 6],
    target: &str,
    param: Param,
    value: &str,
) -> Result<i32, String> {
    let dst = s2mac(target)?;
    if param == Param::Name && value.len() > dcp::DCP_MAX_NAME_LENGTH {
        return Err(format!(
            "Station name exceeds maximum length: {} > {}",
            value.len(),
            dcp::DCP_MAX_NAME_LENGTH
        ));
    }
    let (option, suboption) = match param {
        Param::Name => (dcp::DCP_OPTION_DEVICE, dcp::DCP_SUBOPTION_DEVICE_NAME),
        Param::Ip => (dcp::DCP_OPTION_IP, dcp::DCP_SUBOPTION_IP_PARAMETER),
    };
    let request = dcp::set_param_request(
        my_mac,
        &dst,
        gen_xid()?,
        option,
        suboption,
        value.as_bytes(),
    );

    match dcp_set_roundtrip(iface, my_mac, &request, Duration::from_secs(5)) {
        Ok(dcp::DCP_BLOCK_ERROR_OK) => {
            println!("Set {} = {value}", param_name(param));
            Ok(0)
        }
        Ok(code) => Err(format!(
            "DCP SET failed for '{}': {}",
            param_name(param),
            dcp::block_error_name(code)
        )),
        Err(_) => {
            println!("Failed to set {}", param_name(param));
            Ok(1)
        }
    }
}

fn cmd_set_ip(
    iface: &str,
    my_mac: &[u8; 6],
    target: &str,
    ip: &str,
    netmask: &str,
    gateway: &str,
    permanent: bool,
) -> Result<i32, String> {
    let dst = s2mac(target)?;
    let request = dcp::set_ip_request_qualified(
        my_mac,
        &dst,
        gen_xid()?,
        &parse_ipv4(ip)?,
        &parse_ipv4(netmask)?,
        &parse_ipv4(gateway)?,
        permanent,
    );

    println!("Setting IP {ip} on {target}...");
    match dcp_set_roundtrip(iface, my_mac, &request, Duration::from_secs(5)) {
        Ok(dcp::DCP_BLOCK_ERROR_OK) => {
            println!("Set IP={ip} netmask={netmask} gateway={gateway}");
            Ok(0)
        }
        Ok(code) => Err(format!(
            "DCP SET IP failed: {}",
            dcp::block_error_name(code)
        )),
        Err(_) => {
            println!("Failed to set IP (timeout)");
            Ok(1)
        }
    }
}

fn cmd_signal(iface: &str, my_mac: &[u8; 6], target: &str) -> Result<i32, String> {
    let dst = s2mac(target)?;
    let request = dcp::signal_request(my_mac, &dst, gen_xid()?, 3000);

    println!("Signalling device {target}...");
    match dcp_set_roundtrip(iface, my_mac, &request, Duration::from_secs(5)) {
        Ok(dcp::DCP_BLOCK_ERROR_OK) => {
            println!("Device LED flash triggered");
            Ok(0)
        }
        Ok(code) => Err(format!(
            "DCP Signal failed: {}",
            dcp::block_error_name(code)
        )),
        Err(_) => {
            println!("Failed to signal device (timeout)");
            Ok(1)
        }
    }
}

fn cmd_reset(iface: &str, my_mac: &[u8; 6], target: &str, mode: ResetMode) -> Result<i32, String> {
    let dst = s2mac(target)?;
    let request = dcp::reset_request(my_mac, &dst, gen_xid()?, mode.mask());

    println!("Resetting device {target} (mode: {})...", mode.as_str());
    match dcp_set_roundtrip(iface, my_mac, &request, Duration::from_secs(5)) {
        Ok(dcp::DCP_BLOCK_ERROR_OK) => {
            println!("Reset command acknowledged");
            Ok(0)
        }
        Ok(code) => Err(format!(
            "DCP Reset to Factory failed: {}",
            dcp::block_error_name(code)
        )),
        Err(_) => {
            println!("Failed to reset device (timeout)");
            Ok(1)
        }
    }
}

fn cmd_discover(iface: &str, timeout: Duration) -> Result<i32, String> {
    println!("Discovering PROFINET devices on {iface}...");
    let devices = pcap::discover(iface, timeout)?;
    if devices.is_empty() {
        println!("No devices found");
        return Ok(0);
    }
    println!("\nFound {} device(s):\n", devices.len());
    for d in &devices {
        print_device(d);
        println!();
    }
    Ok(0)
}

/// Print a discovered device, mirroring dcp.py DCPDeviceDescription.__str__.
fn print_device(d: &dcp::DcpDevice) {
    println!("PROFINET Device: {}", d.name);
    println!("  MAC:     {}", mac2s(&d.mac));
    if !d.device_type.is_empty() {
        println!("  Type:    {}", d.device_type);
    }
    println!("  IP:      {}", s2ip(&d.ip).unwrap_or_default());
    println!("  Netmask: {}", s2ip(&d.netmask).unwrap_or_default());
    println!("  Gateway: {}", s2ip(&d.gateway).unwrap_or_default());
    println!(
        "  Vendor:  {} (0x{:04X})",
        profinet_rs::vendors::get_vendor_name(d.vendor_id),
        d.vendor_id
    );
    println!("  Device:  0x{:04X}", d.device_id);
    let roles = decode_device_role(d.role);
    if !roles.is_empty() {
        println!("  Role:    {}", roles.join(", "));
    }
}

/// Decode the device-role bitmask to names (dcp.py decode_device_role;
/// returns empty when the role byte is 0, matching cli.py's `if
/// self.device_roles`).
fn decode_device_role(role: u8) -> Vec<&'static str> {
    let mut roles = Vec::new();
    if role & 0x01 != 0 {
        roles.push("IO-Device");
    }
    if role & 0x02 != 0 {
        roles.push("IO-Controller");
    }
    if role & 0x04 != 0 {
        roles.push("IO-Multidevice");
    }
    if role & 0x08 != 0 {
        roles.push("PN-Supervisor");
    }
    roles
}

// ---------------------------------------------------------------------------
// RPC (raw-L2) commands
// ---------------------------------------------------------------------------

/// True when a discovered device is the requested station: by station name, or
/// by IPv4 when `target` parses as one ("demo" or "192.168.0.2").
fn device_matches(d: &dcp::DcpDevice, target: &str) -> bool {
    d.name == target || matches!(target.parse::<std::net::Ipv4Addr>(), Ok(a) if a.octets() == d.ip)
}

/// Find a discovered device by station name or IPv4.
fn match_device(devices: Vec<dcp::DcpDevice>, target: &str) -> Option<dcp::DcpDevice> {
    devices.into_iter().find(|d| device_matches(d, target))
}

/// Resolve ONE station, returning as soon as it answers rather than sitting
/// out the whole DCP response window. The device replies within milliseconds,
/// so the default 10 s window used to add ~10 s of dead time to every connect
/// — far more than the AR setup itself (~2 s). Only [`pcap::discover`], which
/// enumerates every device, still needs the full window.
fn resolve_device(iface: &str, target: &str, timeout: Duration) -> Result<dcp::DcpDevice, String> {
    let devices = pcap::discover_until(iface, timeout, |found| {
        found.iter().any(|d| device_matches(d, target))
    })?;
    match_device(devices, target).ok_or_else(|| format!("Device {target:?} not found"))
}

/// Transport to the device without establishing an AR: enough for the AR-less
/// Read Implicit service, which addresses the device by IP only.
fn rpc_transport(iface: &str, target: &str, timeout: Duration) -> Result<RpcConn, String> {
    let cm_mac = pcap::get_mac(iface)?;
    let cm_ip = pcap::get_ipv4(iface)?;
    let dev = resolve_device(iface, target, timeout)?;
    RpcConn::new_raw(
        iface,
        cm_mac,
        cm_ip,
        dev.mac,
        dev.ip,
        dev.device_id,
        dev.vendor_id,
        RPC_TIMEOUT,
    )
}

/// Resolve a station by name via DCP and open a Device-Access AR for acyclic
/// read/write, the equivalent of cli.py's `get_station_info` + `RPCCon.connect`.
fn rpc_connect(iface: &str, target: &str, timeout: Duration) -> Result<RpcConn, String> {
    let cm_mac = pcap::get_mac(iface)?;
    let mut conn = rpc_transport(iface, target, timeout)?;
    conn.connect_device_access(&cm_mac, CM_STATION_NAME)
        .map_err(|e| format!("Failed to connect to {target}: {e}"))?;
    Ok(conn)
}

#[allow(clippy::too_many_arguments)]
fn cmd_read(
    iface: &str,
    target: &str,
    slot: u16,
    subslot: u16,
    index: &str,
    length: u32,
    implicit: bool,
    timeout: Duration,
) -> Result<i32, String> {
    let idx = parse_index(index)?;
    if implicit {
        println!("Reading {target} without an AR (Read Implicit)...");
        let mut conn = rpc_transport(iface, target, timeout)?;
        let data = conn.read_raw_implicit(idx, slot, subslot, length)?;
        println!("Read {} bytes:", data.len());
        println!("{}", hex_encode(&data));
        return Ok(0);
    }
    println!("Connecting to {target}...");
    let mut conn = rpc_connect(iface, target, timeout)?;
    let data = conn.read_raw(idx, slot, subslot, length)?;
    conn.release();
    println!("Read {} bytes:", data.len());
    println!("{}", hex_encode(&data));
    Ok(0)
}

fn cmd_write(
    iface: &str,
    target: &str,
    slot: u16,
    subslot: u16,
    index: &str,
    data_hex: &str,
    timeout: Duration,
) -> Result<i32, String> {
    println!("Connecting to {target}...");
    let idx = parse_index(index)?;
    let data = parse_hex(data_hex)?;
    let mut conn = rpc_connect(iface, target, timeout)?;
    conn.write(idx, slot, subslot, &data)?;
    conn.release();
    println!(
        "Wrote {} bytes to slot={slot} subslot={subslot} index=0x{idx:04X}",
        data.len()
    );
    Ok(0)
}

fn cmd_read_inm0_filter(iface: &str, target: &str, timeout: Duration) -> Result<i32, String> {
    println!("Connecting to {target}...");
    let mut conn = rpc_connect(iface, target, timeout)?;
    let data = conn.read_inm0_filter()?;
    conn.release();

    println!("\nDevice Topology:");
    for (api, modules) in &data {
        println!("\nAPI {api}:");
        for (slot_number, (module_id, subslots)) in modules {
            println!("  Slot {slot_number}: Module 0x{module_id:04X}");
            for (subslot_number, submodule_id) in subslots {
                println!("    Subslot {subslot_number}: Submodule 0x{submodule_id:04X}");
            }
        }
    }
    Ok(0)
}

/// One of the read-inm0..3 commands, dispatched by index.
fn cmd_read_inm(iface: &str, args: &ImArgs, idx: u16, timeout: Duration) -> Result<i32, String> {
    println!("Connecting to {}...", args.target);
    let mut conn = rpc_connect(iface, &args.target, timeout)?;
    let out = match idx {
        im::IM0 => conn.read_im0(args.slot, args.subslot).map(print_im0),
        im::IM1 => conn.read_im1(args.slot, args.subslot).map(print_im1),
        im::IM2 => conn.read_im2(args.slot, args.subslot).map(print_im2),
        _ => conn.read_im3(args.slot, args.subslot).map(print_im3),
    };
    conn.release();
    match out {
        Ok(()) => Ok(0),
        Err(e) => {
            // Mirror cli.py's "No IMx data available" on an empty read.
            println!("No IM{} data available", idx - im::IM0);
            if std::env::var_os("PROFINET_DEBUG").is_some() {
                eprintln!("(read failed: {e})");
            }
            Ok(0)
        }
    }
}

fn print_im0(im0: im::InM0) {
    println!("IM0 (identification):");
    println!(
        "  Vendor ID:         0x{:04X} ({})",
        im0.vendor_id(),
        profinet_rs::vendors::get_vendor_name(im0.vendor_id())
    );
    println!("  Order ID:          {}", im0.order_id_str());
    println!("  Serial number:     {}", im0.serial_number_str());
    println!("  Hardware revision: {}", im0.im_hardware_revision);
    println!("  Software revision: {}", im0.software_revision());
    println!("  Revision counter:  {}", im0.im_revision_counter);
    println!("  Profile ID:        0x{:04X}", im0.im_profile_id);
    println!("  IM supported:      0x{:04X}", im0.im_supported);
}

fn print_im1(im1: im::InM1) {
    println!("IM1 (tag):");
    println!("  Tag function:      {}", im1.tag_function_str());
    println!("  Tag location:      {}", im1.tag_location_str());
}

fn print_im2(im2: im::InM2) {
    println!("IM2 (date):");
    println!("  Installation date: {}", im2.date_str());
}

fn print_im3(im3: im::InM3) {
    println!("IM3 (descriptor):");
    println!("  Descriptor:        {}", im3.descriptor_str());
}

// ---------------------------------------------------------------------------
// Cyclic command (connect + cyclic + monitor), port of cli.py cmd_cyclic
// ---------------------------------------------------------------------------

fn cmd_cyclic(
    iface: &str,
    target: &str,
    gsdml_path: &str,
    cycle_ms: u16,
    duration: u64,
    submodules: &[String],
    timeout: Duration,
) -> Result<i32, String> {
    validate_cycle_ms(cycle_ms)?;
    let cm_mac = pcap::get_mac(iface)?;
    let cm_ip = pcap::get_ipv4(iface)?;

    // Step 1: resolve device via DCP.
    let dev = resolve_device(iface, target, timeout)?;
    println!(
        "Connecting to {target} ({})...",
        s2ip(&dev.ip).unwrap_or_default()
    );

    // Step 2: acyclic connect to discover slots.
    let mut conn = RpcConn::new_raw(
        iface,
        cm_mac,
        cm_ip,
        dev.mac,
        dev.ip,
        dev.device_id,
        dev.vendor_id,
        RPC_TIMEOUT,
    )?;
    conn.connect_device_access(&cm_mac, CM_STATION_NAME)
        .map_err(|e| format!("Failed to connect to {target}: {e}"))?;

    print!("Discovering slots... ");
    let device_slots = conn.discover_slots()?;
    println!("{} entries", device_slots.len());

    // Step 3: load GSDML and match against the device slots.
    // (--submodule overrides are validated but the current
    // build_io_slots_from_device matches by discovered idents; overrides are
    // accepted for CLI parity.)
    for spec in submodules {
        if spec.split(':').count() != 3 {
            conn.release();
            return Err(format!(
                "invalid --submodule format '{spec}', expected slot:subslot:submodule_id"
            ));
        }
    }
    let gsdml_device = load_gsdml(gsdml_path)?;
    let io_slots = gsdml_device.build_io_slots_from_device(&device_slots, None)?;

    println!("Matching against GSDML...");
    let (mut total_in, mut total_out) = (0usize, 0usize);
    for s in &io_slots {
        if s.input_length > 0 || s.output_length > 0 {
            let mut parts = Vec::new();
            if s.input_length > 0 {
                parts.push(format!("{}B in", s.input_length));
            }
            if s.output_length > 0 {
                parts.push(format!("{}B out", s.output_length));
            }
            println!("  slot={} sub={}: {}", s.slot, s.subslot, parts.join(", "));
        }
        total_in += s.input_length;
        total_out += s.output_length;
    }
    println!("Total: {total_in}B input, {total_out}B output");

    // Step 4: disconnect acyclic, reconnect with IOCR. Give the device time
    // to process the Release before rebinding (cli.py sleeps 0.5s).
    conn.release();
    thread::sleep(Duration::from_millis(500));

    let send_clock_factor: u16 = 32;
    let reduction_ratio = cycle_ms;
    let setup = IocrSetup {
        io_slots: io_slots.clone(),
        send_clock_factor,
        reduction_ratio,
        watchdog_factor: 6,
        data_hold_factor: 6,
    };

    let mut conn = RpcConn::new_raw(
        iface,
        cm_mac,
        cm_ip,
        dev.mac,
        dev.ip,
        dev.device_id,
        dev.vendor_id,
        RPC_TIMEOUT,
    )?;
    let result = conn.connect(&cm_mac, CM_STATION_NAME, &setup)?;
    if !result.has_cyclic {
        conn.release();
        return Err("cyclic IO not established by device".to_string());
    }

    // Step 5: parameter phase and ApplicationReady.
    println!("\nCyclic IO ({cycle_ms}ms cycle)...");
    conn.prm_end()?;
    println!("  PrmEnd OK");
    conn.application_ready(APP_READY_TIMEOUT)?;
    println!("  ApplicationReady OK");
    println!(
        "  Input frame: 0x{:04X}, Output frame: 0x{:04X}",
        result.input_frame_id, result.output_frame_id
    );

    // Step 6: build IOCRConfigs and start the cyclic controller.
    let (input_iocr, output_iocr) = build_iocr_configs(
        &io_slots,
        result.input_frame_id,
        result.output_frame_id,
        send_clock_factor,
        reduction_ratio,
        6,
    );
    let mut cyclic = CyclicController::new(iface, cm_mac, dev.mac, input_iocr, output_iocr, 3)?;
    cyclic.start()?;

    let input_slots: Vec<(u16, u16)> = io_slots
        .iter()
        .filter(|s| s.input_length > 0)
        .map(|s| (s.slot, s.subslot))
        .collect();

    println!("\nRunning (Ctrl+C to stop)");
    let start = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(1));
        let elapsed = start.elapsed().as_secs_f64();
        if duration > 0 && elapsed >= duration as f64 {
            break;
        }
        let parts: Vec<String> = input_slots
            .iter()
            .map(
                |&(slot, subslot)| match cyclic.get_input_data(slot, subslot) {
                    Some(data) if !data.is_empty() => {
                        format!("{slot}:{subslot}={}", hex_encode(&data))
                    }
                    _ => format!("{slot}:{subslot}=--"),
                },
            )
            .collect();
        let stats = cyclic.stats();
        println!(
            "[{elapsed:5.1}s] {} | TX={} RX={}",
            parts.join(" "),
            stats.frames_sent,
            stats.frames_received
        );
    }

    cyclic.stop();
    let stats = cyclic.stats();
    println!(
        "\nStopped. TX={} RX={} missed={}",
        stats.frames_sent, stats.frames_received, stats.frames_missed
    );
    conn.release();
    Ok(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn param_name(param: Param) -> &'static str {
    match param {
        Param::Name => "name",
        Param::Ip => "ip",
    }
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn gen_xid() -> Result<u32, String> {
    let mut buf = [0u8; 4];
    getrandom::fill(&mut buf).map_err(|e| format!("getrandom failed: {e}"))?;
    Ok(u32::from_be_bytes(buf))
}

/// The spec's "resource busy" PNIO status. Devices that throttle acyclic
/// access answer it when asked again too soon. Surfaced verbatim by the
/// transport as `PNIO error status 0x...`.
const PNIO_BUSY_STATUS: &str = "DE80C200";
/// Gap before an internally-issued acyclic read. Devices commonly guard
/// acyclic access with a one-shot timer in the tens of milliseconds and
/// answer BUSY inside it; 30 ms clears the guards observed while testing,
/// which beats being refused and retrying. Callers pace their own requests
/// with `--gap-ms`.
const ACYCLIC_READ_GAP: Duration = Duration::from_millis(30);
const PACED_READ_RETRIES: usize = 4;

/// One paced acyclic read: wait out [`ACYCLIC_READ_GAP`], then read; on a BUSY
/// guard-hit back off and retry. Other errors and the response are returned
/// as-is, so a caller keeps its own exact-length check.
///
/// Used for the reads this tool issues on its own behalf (the GSDML pre-flight,
/// the output readback). Reads a caller asks for go through `serve`, which
/// paces them with the caller's own `--gap-ms`.
fn paced_read(
    conn: &mut RpcConn,
    idx: u16,
    slot: u16,
    subslot: u16,
    length: u32,
) -> Result<Vec<u8>, String> {
    let mut last = String::new();
    for attempt in 0..PACED_READ_RETRIES {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(ACYCLIC_READ_GAP);
        match conn.read_raw(idx, slot, subslot, length) {
            Ok(d) => return Ok(d),
            Err(e) if e.contains(PNIO_BUSY_STATUS) => last = e, // guard hit: retry
            Err(e) => return Err(e), // wrong length / bad index: no point retrying
        }
    }
    Err(format!(
        "index {idx}: {last} (after {PACED_READ_RETRIES} attempts)"
    ))
}

/// Second-SIGINT policy: hard-exit is allowed only when a hard exit is
/// provably harmless ([`SAFE_TO_HARD_EXIT`]). Until then a repeat Ctrl+C
/// only re-asserts [`SHUTDOWN`] — mashing Ctrl+C must not truncate a
/// running safe shutdown and abandon a possibly-unsafe output.
fn should_hard_exit(already_shutting_down: bool, safe_to_hard_exit: bool) -> bool {
    already_shutting_down && safe_to_hard_exit
}

/// Cyclic states that mean we are no longer driving the device, so the
/// commanded safe shutdown must run: `Fault` (RX watchdog escalated — comms
/// lost) and `Stopped` (threads gone). Extracted as a pure policy for the
/// same reason as [`should_hard_exit`]: the run loop is not unit-testable.
///
/// `Starting`/`Running` are healthy; `Stopping`/`Idle` cannot occur while the
/// run loop owns the controller.
fn cyclic_abort_reason(state: CyclicState) -> Option<&'static str> {
    match state {
        CyclicState::Fault => Some("cyclic_fault"),
        CyclicState::Stopped => Some("cyclic_stopped"),
        _ => None,
    }
}

/// Install the termination handler that raises [`SHUTDOWN`]. With the ctrlc
/// "termination" feature this covers SIGINT (Ctrl+C) **and** SIGTERM/SIGHUP,
/// so a plain `kill`, a supervisor or `timeout` also runs the commanded safe
/// shutdown instead of killing the process outright and stranding a
/// held output bit.
///
/// A second signal force-exits for the case where the loop is stuck before
/// its next poll — but only once [`SAFE_TO_HARD_EXIT`] says the output
/// cannot be left driven (see [`should_hard_exit`]).
fn install_shutdown_handler() -> Result<(), String> {
    ctrlc::set_handler(|| {
        let again = SHUTDOWN.swap(true, Ordering::SeqCst);
        if should_hard_exit(again, SAFE_TO_HARD_EXIT.load(Ordering::SeqCst)) {
            exit(130);
        }
    })
    .map_err(|e| format!("failed to install Ctrl+C handler: {e}"))
}

/// RT_CLASS_1 reduction ratios are powers of two up to 512; reject anything
/// else before touching the device.
fn validate_cycle_ms(cycle_ms: u16) -> Result<(), String> {
    if !(1..=512).contains(&cycle_ms) || !cycle_ms.is_power_of_two() {
        return Err(format!(
            "cycle_ms must be a power of two in 1..=512 (RT_CLASS_1 reduction ratio), got {cycle_ms}"
        ));
    }
    Ok(())
}

/// Length of the input image the device actually provides, parsed from a
/// RecordInputDataObjectElement (index 0x8028).
///
/// Layout after the 6-byte BlockHeader: LengthIOCS, IOCS[], LengthIOPS,
/// IOPS[], LengthIOData (u16 big-endian), IOData[]. Returns `None` if the
/// record is truncated or a declared length runs past its end.
///
/// This exists to catch a GSDML that does not match the running firmware.
/// The cyclic receive path drops any IO object whose declared window does not
/// fit the received frame, so a GSDML that over-declares the input image
/// yields zeros forever, with a healthy AR and `missed=0` the whole time.
/// Comparing this against the GSDML turns that into a startup error.
fn parse_input_data_length(record: &[u8]) -> Option<usize> {
    let mut pos = 6usize;
    // LengthIOCS then LengthIOPS: a one-byte count, then that many status bytes.
    for _ in 0..2 {
        let count = *record.get(pos)? as usize;
        pos = pos.checked_add(1)?.checked_add(count)?;
    }
    let len = u16::from_be_bytes([*record.get(pos)?, *record.get(pos.checked_add(1)?)?]) as usize;
    // The declared payload has to actually be present.
    if record.len() < pos.checked_add(2)?.checked_add(len)? {
        return None;
    }
    Some(len)
}

/// Extract the 1-byte output C_SDU (the control byte) from a
/// RecordOutputDataObjectElement (index 0x8029) read: BlockHeader (type
/// 0x0016, 6 B), SubstituteActiveFlag (2 B), LengthIOCS (1 B), LengthIOPS
/// (1 B), LengthDataItem (2 B), then DataItem = IOCS, data, IOPS. The control
/// byte is the first data byte, right after the leading IOCS.
///
/// This reports the byte the device is applying, whether it comes from a
/// controller or from substitute values — see [`output_substitute_active`] for
/// that distinction, which matters only to the safe-shutdown verify.
fn parse_output_control_byte(record: &[u8]) -> Option<u8> {
    if record.len() < 12 || record[0] != 0x00 || record[1] != 0x16 {
        return None;
    }
    let len_iocs = record[8] as usize;
    if be_u16(record, 10) == 0 {
        return None;
    }
    record.get(12 + len_iocs).copied()
}

/// SubstituteActiveFlag of a 0x8029 output record: the device is applying
/// substitute values instead of controller-provided output data.
///
/// Asymmetric by design:
/// * **Ownership gate** (before takeover, nobody holds the AR): substitutes
///   are the *expected* state and mean no controller is commanding anything.
///   The gate therefore judges the byte alone — rejecting substitutes there
///   would refuse every normal takeover.
/// * **Safe-shutdown verify** (we hold the AR and drive 0x00): substitutes
///   active means our data is NOT in effect, so a 0x00 read back proves
///   nothing. Accepting it would report `verified_safe`, unlock the hard exit
///   and exit 0 with the output state unproven.
fn output_substitute_active(record: &[u8]) -> bool {
    record.len() >= 8 && be_u16(record, 6) != 0
}

fn be_u16(d: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([d[off], d[off + 1]])
}

/// Write one NDJSON line and flush, so a parent process reading the pipe sees
/// it immediately.
fn emit(line: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

// ---------------------------------------------------------------------------
// The emitted line vocabulary.
//
// Every line `serve` writes to stdout is built by exactly one function here,
// and nowhere else. Two reasons for the rule. First, a line built inline in a
// 400-line loop cannot be tested, so the wire format was only ever checked by
// reading it. Second, the vocabulary is the protocol: with the builders in one
// place, the list below *is* the specification a consumer needs, instead of 30
// format strings and 4 bare literals scattered over 34 emit sites.
//
// A builder is a pure function of its arguments and returns the line without
// the newline. `emit` adds that and flushes.
//
// Each one serialises a struct rather than writing a format string. The point
// is not brevity — the structs are longer — but that the shape stops being a
// string. Field names, the tag and the nesting are checked by the compiler,
// escaping happens structurally instead of through a helper every site has to
// remember to call, and the struct list is a protocol specification that cannot
// drift from what the code emits. Field order is declaration order, which is
// how the wire format survived the change to serde: every line is byte for byte
// what the format strings produced, with one exception that
// `control_characters_use_the_short_escapes` pins.
// ---------------------------------------------------------------------------

/// The wire tag of an emitted line. Naming it here is what makes a tag a value
/// the compiler knows rather than a literal repeated at every emit site.
#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Tag {
    Ack,
    Alarm,
    ArLost,
    Bye,
    ControlActive,
    CurrentOutput,
    Cyclic,
    CyclicStarted,
    Data,
    Deadman,
    Error,
    Hello,
    Ok,
    Output,
    Pong,
    ReadError,
    Refused,
    SafeShutdown,
    Status,
    Stopped,
    TransportError,
    Warning,
}

/// Serialise one line.
///
/// The `expect` cannot fire: `serde_json` only fails on a map with non-string
/// keys, a float that is NaN or infinite, or a `Serialize` implementation that
/// returns an error itself. Every type below is a flat struct of integers,
/// booleans and string slices, so none of the three is reachable. Saying that
/// out loud is better than an `unwrap_or_default` that would silently emit an
/// empty line if the reasoning were ever wrong.
fn json_line<T: Serialize>(line: &T) -> String {
    serde_json::to_string(line).expect("a flat struct of integers, bools and strs cannot fail")
}

/// `{"type":"error","read":..,"msg":..}` — a named read failed and the session
/// continues.
#[derive(Serialize)]
struct ErrorRead<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    read: &'a str,
    msg: &'a str,
}

fn error_read_line(read: &str, err: &str) -> String {
    json_line(&ErrorRead {
        tag: Tag::Error,
        read,
        msg: err,
    })
}

/// `{"type":"error","msg":..}` — something failed that is not tied to a
/// specific read.
#[derive(Serialize)]
struct ErrorMsg<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    msg: &'a str,
}

fn error_msg_line(msg: &str) -> String {
    json_line(&ErrorMsg {
        tag: Tag::Error,
        msg,
    })
}

/// `{"type":"error","msg":"bad command: ..","line":..}` — the input line did
/// not parse. The offending line is echoed so the caller can see what arrived.
#[derive(Serialize)]
struct BadCommand<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    msg: String,
    line: &'a str,
}

fn bad_command_line(msg: &str, line: &str) -> String {
    json_line(&BadCommand {
        tag: Tag::Error,
        msg: format!("bad command: {msg}"),
        line,
    })
}

/// `{"type":"warning","code":..,"msg":..}` — the session is doing something
/// the caller should know about but that is not an error.
#[derive(Serialize)]
struct Warning<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    code: &'a str,
    msg: &'a str,
}

fn warning_line(code: &str, msg: &str) -> String {
    json_line(&Warning {
        tag: Tag::Warning,
        code,
        msg,
    })
}

/// `{"proto":N,"type":"hello",..}` — always the first line. `proto` comes
/// first so a consumer can reject an incompatible server from the first bytes
/// it sees.
#[derive(Serialize)]
struct Hello<'a> {
    proto: u32,
    #[serde(rename = "type")]
    tag: Tag,
    station: &'a str,
    read_only: bool,
    gap_ms: u64,
    cyclic: bool,
    allow_mask: u8,
}

fn hello_line(station: &str, read_only: bool, gap_ms: u64, cyclic: bool, allow_mask: u8) -> String {
    json_line(&Hello {
        proto: SERVE_PROTO,
        tag: Tag::Hello,
        station,
        read_only,
        gap_ms,
        cyclic,
        allow_mask,
    })
}

/// `{"id":N,"type":"bye"}` — answer to `quit`.
#[derive(Serialize)]
struct Bye {
    id: u64,
    #[serde(rename = "type")]
    tag: Tag,
}

fn bye_line(id: u64) -> String {
    json_line(&Bye { id, tag: Tag::Bye })
}

/// `{"id":N,"type":"pong",..}` — answer to `ping`.
#[derive(Serialize)]
struct Pong {
    id: u64,
    #[serde(rename = "type")]
    tag: Tag,
    host_us: u128,
}

fn pong_line(id: u64, host_us: u128) -> String {
    json_line(&Pong {
        id,
        tag: Tag::Pong,
        host_us,
    })
}

/// `{"id":N,"type":"data",..}` — answer to `read`.
#[derive(Serialize)]
struct Data<'a> {
    id: u64,
    #[serde(rename = "type")]
    tag: Tag,
    host_us: u128,
    len: usize,
    hex: &'a str,
}

fn data_line(id: u64, host_us: u128, len: usize, hex: &str) -> String {
    json_line(&Data {
        id,
        tag: Tag::Data,
        host_us,
        len,
        hex,
    })
}

/// `{"id":N,"type":"ok",..}` — answer to `write`.
#[derive(Serialize)]
struct WriteOk {
    id: u64,
    #[serde(rename = "type")]
    tag: Tag,
    host_us: u128,
}

fn ok_line(id: u64, host_us: u128) -> String {
    json_line(&WriteOk {
        id,
        tag: Tag::Ok,
        host_us,
    })
}

/// `{"id":N,"type":"read_error",..}` — the device answered no. `pnio` carries
/// its status word, which is what tells a caller *why*.
#[derive(Serialize)]
struct ReadError<'a> {
    id: u64,
    #[serde(rename = "type")]
    tag: Tag,
    host_us: u128,
    pnio: &'a str,
    msg: &'a str,
}

fn read_error_line(id: u64, host_us: u128, pnio: &str, msg: &str) -> String {
    json_line(&ReadError {
        id,
        tag: Tag::ReadError,
        host_us,
        pnio,
        msg,
    })
}

/// `{"id":N,"type":"transport_error",..}` — the request never got an answer.
/// Distinct from `read_error` on purpose: this one poisons the session.
#[derive(Serialize)]
struct TransportError<'a> {
    id: u64,
    #[serde(rename = "type")]
    tag: Tag,
    host_us: u128,
    msg: &'a str,
}

fn transport_error_line(id: u64, host_us: u128, msg: &str) -> String {
    json_line(&TransportError {
        id,
        tag: Tag::TransportError,
        host_us,
        msg,
    })
}

/// `{"id":N,"type":"refused","reason":"server is read-only"}` — a write
/// arrived at a `--read-only` server.
#[derive(Serialize)]
struct RefusedWithId {
    id: u64,
    #[serde(rename = "type")]
    tag: Tag,
    reason: &'static str,
}

fn refused_read_only_line(id: u64) -> String {
    json_line(&RefusedWithId {
        id,
        tag: Tag::Refused,
        reason: "server is read-only",
    })
}

/// `{"type":"refused","reason":..}` — the session will not start. Carries no
/// id because nothing was requested: these are refusals of the setup itself.
#[derive(Serialize)]
struct RefusedSetup<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    reason: &'a str,
}

fn refused_setup_line(reason: &str) -> String {
    json_line(&RefusedSetup {
        tag: Tag::Refused,
        reason,
    })
}

/// `{"type":"refused","reason":"control commands need --cyclic","line":..}` —
/// a control command arrived at an acyclic-only session.
#[derive(Serialize)]
struct RefusedNeedsCyclic<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    reason: &'static str,
    line: &'a str,
}

fn refused_needs_cyclic_line(line: &str) -> String {
    json_line(&RefusedNeedsCyclic {
        tag: Tag::Refused,
        reason: "control commands need --cyclic",
        line,
    })
}

/// `{"type":"refused","cmd":..,"mask":..,"reason":..}` — a control command was
/// understood and not carried out.
#[derive(Serialize)]
struct RefusedCmd<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    cmd: &'a str,
    mask: u8,
    reason: &'a str,
}

fn refused_cmd_line(cmd: &str, mask: u8, reason: &str) -> String {
    json_line(&RefusedCmd {
        tag: Tag::Refused,
        cmd,
        mask,
        reason,
    })
}

/// `{"type":"ack","cmd":"set_level",..}` — a level bit was set or cleared.
/// `level` is the resulting state, not the request.
#[derive(Serialize)]
struct AckSetLevel {
    #[serde(rename = "type")]
    tag: Tag,
    cmd: &'static str,
    mask: u8,
    on: bool,
    level: u8,
}

fn ack_set_level_line(mask: u8, on: bool, level: u8) -> String {
    json_line(&AckSetLevel {
        tag: Tag::Ack,
        cmd: "set_level",
        mask,
        on,
        level,
    })
}

/// `{"type":"ack","cmd":"pulse",..}` — a pulse was armed for `pulse_ticks`
/// output cycles.
#[derive(Serialize)]
struct AckPulse {
    #[serde(rename = "type")]
    tag: Tag,
    cmd: &'static str,
    mask: u8,
    pulse_ticks: u32,
}

fn ack_pulse_line(mask: u8) -> String {
    json_line(&AckPulse {
        tag: Tag::Ack,
        cmd: "pulse",
        mask,
        pulse_ticks: PULSE_TICKS,
    })
}

/// `{"type":"ack","cmd":"keepalive"}` — the dead-man timer was reset.
#[derive(Serialize)]
struct AckPlain {
    #[serde(rename = "type")]
    tag: Tag,
    cmd: &'static str,
}

fn ack_keepalive_line() -> String {
    json_line(&AckPlain {
        tag: Tag::Ack,
        cmd: "keepalive",
    })
}

/// `{"type":"current_output",..}` — the output image as found before takeover.
#[derive(Serialize)]
struct CurrentOutput<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    len: usize,
    hex: &'a str,
}

fn current_output_line(len: usize, hex: &str) -> String {
    json_line(&CurrentOutput {
        tag: Tag::CurrentOutput,
        len,
        hex,
    })
}

/// `{"type":"cyclic",..}` — one received input frame.
#[derive(Serialize)]
struct Cyclic<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    slot: u16,
    subslot: u16,
    host_us: u128,
    len: usize,
    hex: &'a str,
}

fn cyclic_line(slot: u16, subslot: u16, host_us: u128, len: usize, hex: &str) -> String {
    json_line(&Cyclic {
        tag: Tag::Cyclic,
        slot,
        subslot,
        host_us,
        len,
        hex,
    })
}

/// `{"type":"cyclic_started",..}` — the IOCRs are up. `input_len` is the
/// length the GSDML promised and the firmware confirmed.
#[derive(Serialize)]
struct CyclicStarted {
    #[serde(rename = "type")]
    tag: Tag,
    cycle_ms: u16,
    input_frame_id: u16,
    output_frame_id: u16,
    input_len: usize,
    out_slot: u16,
    out_subslot: u16,
}

fn cyclic_started_line(
    cycle_ms: u16,
    input_frame_id: u16,
    output_frame_id: u16,
    input_len: usize,
    out_slot: u16,
    out_subslot: u16,
) -> String {
    json_line(&CyclicStarted {
        tag: Tag::CyclicStarted,
        cycle_ms,
        input_frame_id,
        output_frame_id,
        input_len,
        out_slot,
        out_subslot,
    })
}

/// `{"type":"control_active",..}` — commanding is possible and this is what it
/// may drive. Goes out even with an all-zero mask: that is how a consumer
/// learns nothing has been armed.
#[derive(Serialize)]
struct ControlActive {
    #[serde(rename = "type")]
    tag: Tag,
    output_byte: u8,
    allow_mask: u8,
}

fn control_active_line(output_byte: u8, allow_mask: u8) -> String {
    json_line(&ControlActive {
        tag: Tag::ControlActive,
        output_byte,
        allow_mask,
    })
}

/// `{"type":"output",..}` — the output image was written, with the device's
/// own readback of it.
#[derive(Serialize)]
struct Output<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    control_byte: u8,
    safe: bool,
    readback_hex: &'a str,
}

fn output_line(control_byte: u8, safe: bool, readback_hex: &str) -> String {
    json_line(&Output {
        tag: Tag::Output,
        control_byte,
        safe,
        readback_hex,
    })
}

/// `{"type":"deadman",..}` — a level bit was held with no traffic, so the
/// session is stopping.
#[derive(Serialize)]
struct Deadman {
    #[serde(rename = "type")]
    tag: Tag,
    msg: &'static str,
}

fn deadman_line() -> String {
    json_line(&Deadman {
        tag: Tag::Deadman,
        msg: "no command/keepalive while a level bit is held",
    })
}

/// `{"type":"status",..}` — once a second while cyclic frames run.
#[derive(Serialize)]
struct Status {
    #[serde(rename = "type")]
    tag: Tag,
    tx: u64,
    rx: u64,
    missed: u64,
    out_byte: u8,
}

fn status_line(tx: u64, rx: u64, missed: u64, out_byte: u8) -> String {
    json_line(&Status {
        tag: Tag::Status,
        tx,
        rx,
        missed,
        out_byte,
    })
}

/// `{"type":"ar_lost",..}` — the AR died under us.
#[derive(Serialize)]
struct ArLost<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    host_us: u128,
    msg: &'a str,
}

fn ar_lost_line(host_us: u128, msg: &str) -> String {
    json_line(&ArLost {
        tag: Tag::ArLost,
        host_us,
        msg,
    })
}

/// `{"type":"safe_shutdown",..}` — the commanded shutdown ran, with the
/// device's readback of the safe image and whether it matched.
#[derive(Serialize)]
struct SafeShutdown<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    reason: &'a str,
    verified_safe: bool,
    readback_hex: &'a str,
}

fn safe_shutdown_line(reason: &str, verified_safe: bool, readback_hex: &str) -> String {
    json_line(&SafeShutdown {
        tag: Tag::SafeShutdown,
        reason,
        verified_safe,
        readback_hex,
    })
}

/// The distinct machine-readable alarm for a shutdown that could NOT verify
/// the safe image. A supervising parent must treat this as "a commanded bit
/// possibly still set"; it is paired with the non-zero exit code from
/// [`safe_shutdown_verdict`].
#[derive(Serialize)]
struct Alarm<'a> {
    #[serde(rename = "type")]
    tag: Tag,
    reason: &'static str,
    shutdown_reason: &'a str,
    readback_hex: &'a str,
}

fn alarm_line(reason: &str, readback_hex: &str) -> String {
    json_line(&Alarm {
        tag: Tag::Alarm,
        reason: "safe output NOT verified",
        shutdown_reason: reason,
        readback_hex,
    })
}

/// `{"type":"stopped","exit":N}` — an acyclic-only session ended.
#[derive(Serialize)]
struct StoppedExit {
    #[serde(rename = "type")]
    tag: Tag,
    exit: i32,
}

fn stopped_exit_line(exit: i32) -> String {
    json_line(&StoppedExit {
        tag: Tag::Stopped,
        exit,
    })
}

/// `{"type":"stopped","tx":..}` — a cyclic session ended, with frame counts.
#[derive(Serialize)]
struct StoppedStats {
    #[serde(rename = "type")]
    tag: Tag,
    tx: u64,
    rx: u64,
    missed: u64,
}

fn stopped_stats_line(tx: u64, rx: u64, missed: u64) -> String {
    json_line(&StoppedStats {
        tag: Tag::Stopped,
        tx,
        rx,
        missed,
    })
}

/// Emit an `{"type":"error",...}` line for a failed read and keep going.
fn emit_read_error(read: &str, err: &str) {
    emit(&error_read_line(read, err));
}

/// Swap the monitor's read-only Device-Access AR for a full IO AR and start
/// the cyclic controller, so the process image arrives at cycle rate instead
/// of once per acyclic poll.
///
/// `conn` is consumed: the device grants the IO AR only once the
/// Device-Access AR is released. Returns the rebound connection, which the
/// caller keeps using for the acyclic tiers, plus the running controller.
///
/// Outputs are never written here. The controller starts with the all-zero
/// output image, the conventional fail-safe, and driving anything else is the
/// command layer's job, behind its own gates.
#[allow(clippy::too_many_arguments)]
fn start_cyclic_tier(
    iface: &str,
    target: &str,
    mut conn: RpcConn,
    // `input_submodule`: the submodule whose input image is verified against
    // the GSDML. `None` picks the first submodule the device reports with
    // inputs, which is what a caller carrying no device knowledge can do.
    input_submodule: Option<(u16, u16)>,
    gsdml_path: &str,
    cycle_ms: u16,
    require_safe_output: bool,
    timeout: Duration,
) -> Result<CyclicTier, String> {
    validate_cycle_ms(cycle_ms)?;
    let cm_mac = pcap::get_mac(iface)?;
    let cm_ip = pcap::get_ipv4(iface)?;

    let device_slots = conn.discover_slots()?;
    let gsdml_device = load_gsdml(gsdml_path)?;
    let io_slots = gsdml_device.build_io_slots_from_device(&device_slots, None)?;

    // Pre-flight: the GSDML must agree with the running firmware about the
    // input image, or every cyclic frame decodes to zeros without any error.
    let (in_slot, in_subslot) = match input_submodule {
        Some(pair) => pair,
        None => io_slots
            .iter()
            .find(|s| s.input_length > 0)
            .map(|s| (s.slot, s.subslot))
            .ok_or_else(|| format!("GSDML {gsdml_path} describes no submodule with inputs"))?,
    };
    let declared = io_slots
        .iter()
        .find(|s| s.slot == in_slot && s.subslot == in_subslot)
        .map(|s| s.input_length)
        .ok_or_else(|| {
            format!(
                "GSDML {gsdml_path} describes no submodule at slot {in_slot} subslot {in_subslot}"
            )
        })?;
    let record = paced_read(&mut conn, 0x8028, in_slot, in_subslot, 128)
        .map_err(|e| format!("could not read the input image (0x8028) to verify the GSDML: {e}"))?;
    let actual = parse_input_data_length(&record)
        .ok_or_else(|| "could not parse the input image record (0x8028)".to_string())?;
    if declared != actual {
        conn.release();
        return Err(format!(
            "GSDML mismatch: {gsdml_path} declares a {declared}-byte input image \
             for slot {in_slot} subslot {in_subslot}, but the device provides {actual} bytes. \
             Cyclic reads would silently return zeros. Use the GSDML matching this firmware."
        ));
    }

    // The submodule that carries the output image, taken from the device+GSDML
    // rather than assumed: the caller drives this one, and nothing else.
    let (out_slot, out_subslot) = io_slots
        .iter()
        .find(|s| s.output_length > 0)
        .map(|s| (s.slot, s.subslot))
        .unwrap_or((in_slot, in_subslot));

    // GATE (only when this process intends to command): refuse the takeover
    // unless the device's current output image is already the safe image. A
    // failed read or unparseable record also refuses — never proceed blind.
    //
    // Requiring the whole byte, not just the level bits, is deliberate: a
    // non-zero byte means someone else is mid-command, and taking the AR from
    // under them would cut that command short at an arbitrary point.
    if require_safe_output {
        let probe = conn.read_raw(0x8029, out_slot, out_subslot, 128);
        let output_is_safe = match &probe {
            Ok(d) => {
                emit(&current_output_line(d.len(), &hex_encode(d)));
                parse_output_control_byte(d).is_some_and(|b| b == SAFE_OUTPUT_BYTE)
            }
            Err(e) => {
                emit_read_error("current_output", e);
                false
            }
        };
        if !output_is_safe {
            conn.release();
            emit(&refused_setup_line(
                "output is not at the safe image or state unknown; refusing takeover",
            ));
            return Err(
                "ownership probe failed: output is not at the safe image or state unknown; \
                 refusing to take over the cyclic AR"
                    .to_string(),
            );
        }
    }

    // Rebind as an IO controller. The device needs a moment to process the
    // Release before it accepts the new AR.
    conn.release();
    thread::sleep(Duration::from_millis(500));

    let dev = resolve_device(iface, target, timeout)?;
    let send_clock_factor: u16 = 32;
    let setup = IocrSetup {
        io_slots: io_slots.clone(),
        send_clock_factor,
        reduction_ratio: cycle_ms,
        watchdog_factor: 6,
        data_hold_factor: 6,
    };
    let mut conn = RpcConn::new_raw(
        iface,
        cm_mac,
        cm_ip,
        dev.mac,
        dev.ip,
        dev.device_id,
        dev.vendor_id,
        RPC_TIMEOUT,
    )?;
    let result = conn.connect(&cm_mac, CM_STATION_NAME, &setup)?;
    if !result.has_cyclic {
        conn.release();
        return Err("cyclic IO not established by device".to_string());
    }
    conn.prm_end()?;
    conn.application_ready(APP_READY_TIMEOUT)?;

    let (input_iocr, output_iocr) = build_iocr_configs(
        &io_slots,
        result.input_frame_id,
        result.output_frame_id,
        send_clock_factor,
        cycle_ms,
        6,
    );
    let mut cyclic = CyclicController::new(iface, cm_mac, dev.mac, input_iocr, output_iocr, 3)?;
    // Safety: register the safe image with the controller so EVERY stop
    // path — a commanded safe shutdown, but also a panic-unwind Drop — forces
    // 0x00 into the frame buffer before STOP frames go out.
    cyclic.set_safe_output(out_slot, out_subslot, &[SAFE_OUTPUT_BYTE]);
    cyclic.on_input(|slot, subslot, data| {
        emit(&cyclic_line(
            slot,
            subslot,
            host_unix_us(),
            data.len(),
            &hex_encode(data),
        ));
    });
    cyclic.start()?;
    emit(&cyclic_started_line(
        cycle_ms,
        result.input_frame_id,
        result.output_frame_id,
        actual,
        out_slot,
        out_subslot,
    ));
    Ok(CyclicTier {
        conn,
        cyclic,
        out_slot,
        out_subslot,
    })
}

/// A running cyclic tier: the rebound acyclic connection on the IO AR, the
/// controller driving the frames, and the submodule that carries the output
/// image.
struct CyclicTier {
    conn: RpcConn,
    cyclic: CyclicController,
    out_slot: u16,
    out_subslot: u16,
}

/// Host wall-clock in microseconds since the Unix epoch, for pairing an
/// emitted line with when it left this process.
fn host_unix_us() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// serve: generic acyclic read/write over stdin/stdout
// ---------------------------------------------------------------------------

/// Wire protocol version of the `serve` NDJSON contract. A consumer that
/// understands a different one must refuse rather than misread: the two
/// programs ship separately and can drift apart.
const SERVE_PROTO: u32 = 5;

/// One parsed request from the caller.
#[derive(Debug, PartialEq, Eq)]
enum ServeCmd {
    Read {
        id: u64,
        index: u16,
        slot: u16,
        subslot: u16,
        len: u32,
    },
    Write {
        id: u64,
        index: u16,
        slot: u16,
        subslot: u16,
        data: Vec<u8>,
    },
    /// Explicit liveness ping. The idle keepalive covers the AR on its own;
    /// this exists so a caller can confirm the server is answering at all.
    Ping {
        id: u64,
    },
    Quit {
        id: u64,
    },
}

impl ServeCmd {
    fn id(&self) -> u64 {
        match self {
            ServeCmd::Read { id, .. }
            | ServeCmd::Write { id, .. }
            | ServeCmd::Ping { id }
            | ServeCmd::Quit { id } => *id,
        }
    }
}

/// One stdin line, in either of the two vocabularies `serve` accepts.
///
/// They are kept apart rather than merged into one enum because they answer
/// differently: an RPC command is a request that owes exactly one response
/// carrying its `id`, while a control command drives the output image and is
/// acknowledged without one. Folding them together would force an id onto
/// commands that have never had one.
#[derive(Debug, PartialEq, Eq)]
enum ServeLine {
    /// Acyclic request/response, matched by caller-chosen `id`.
    Rpc(ServeCmd),
    /// Output-image command, only meaningful with `--cyclic`.
    Control(ControlCmd),
}

fn parse_serve_line(line: &str) -> Result<ServeLine, String> {
    match json_field_str(line, "cmd") {
        // `quit` exists in both vocabularies. The id decides which: with one,
        // the caller expects the `bye` response that carries it back.
        Some("quit") if json_field_u64(line, "id").is_none() => {
            Ok(ServeLine::Control(ControlCmd::Quit))
        }
        Some("set_level" | "pulse" | "keepalive") => {
            parse_control_cmd(line).map(ServeLine::Control)
        }
        _ => parse_serve_cmd(line).map(ServeLine::Rpc),
    }
}

/// Parse one request line.
///
/// `id` is required rather than optional: responses share stdout with
/// unsolicited lines, a retried request can answer late, and count discovery
/// asks about the same index repeatedly at different lengths. Matching on
/// anything but a caller-chosen id is ambiguous the first time those overlap.
/// Parse an unsigned integer field, decimal or `0x`-prefixed hex.
fn json_field_u64(line: &str, key: &str) -> Option<u64> {
    let rest = json_field_raw(line, key)?.trim_start();
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let token: &str = rest
        .find(|c: char| !c.is_ascii_alphanumeric())
        .map_or(rest, |end| &rest[..end]);
    match token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => token.parse().ok(),
    }
}

fn parse_serve_cmd(line: &str) -> Result<ServeCmd, String> {
    let id = json_field_u64(line, "id").ok_or_else(|| "missing \"id\" field".to_string())?;
    let cmd = json_field_str(line, "cmd").ok_or_else(|| "missing \"cmd\" field".to_string())?;
    let field_u16 = |k: &str| -> Result<u16, String> {
        json_field_u64(line, k)
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| format!("{cmd} needs \"{k}\" (0..=65535)"))
    };
    match cmd {
        "read" => Ok(ServeCmd::Read {
            id,
            index: field_u16("index")?,
            slot: field_u16("slot")?,
            subslot: field_u16("subslot")?,
            len: json_field_u64(line, "len")
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| "read needs \"len\"".to_string())?,
        }),
        "write" => {
            let hex =
                json_field_str(line, "hex").ok_or_else(|| "write needs \"hex\"".to_string())?;
            Ok(ServeCmd::Write {
                id,
                index: field_u16("index")?,
                slot: field_u16("slot")?,
                subslot: field_u16("subslot")?,
                data: parse_hex(hex)?,
            })
        }
        "ping" => Ok(ServeCmd::Ping { id }),
        "quit" => Ok(ServeCmd::Quit { id }),
        other => Err(format!("unknown cmd {other:?}")),
    }
}

/// Classify a transport error string as "the AR is gone" rather than "the
/// device answered no".
///
/// The caller needs the two apart: a device that rejects an index is a normal
/// negative answer to probe against, while a dead AR means every later request
/// is meaningless. Without the distinction a consumer cannot tell a bad index
/// from a lost connection.
fn is_transport_failure(msg: &str) -> bool {
    !msg.contains("PNIO error status")
}

/// The PNIO status hex out of a transport error string, if it carries one.
/// Returned verbatim: discovery pivots on the exact code, so any tidying here
/// would break the caller silently.
fn pnio_status_of(msg: &str) -> Option<String> {
    let at = msg.find("PNIO error status 0x")? + "PNIO error status 0x".len();
    let hex: String = msg[at..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    (hex.len() == 8).then_some(hex)
}

fn serve_emit_error(id: u64, msg: &str) {
    match pnio_status_of(msg) {
        Some(pnio) => emit(&read_error_line(id, host_unix_us(), &pnio, msg)),
        None => emit(&transport_error_line(id, host_unix_us(), msg)),
    }
}

/// Attempts per acyclic request before a BUSY is reported to the caller.
/// BUSY is the device's throttle guard tripping, a transport condition this
/// layer owns; every other PNIO status is the device's answer and goes back
/// verbatim on the first try.
const SERVE_BUSY_RETRIES: u32 = 5;

/// The cyclic tier of `serve`: claim the IO AR, stream the input image, and
/// drive the output image from control commands.
struct ServeCyclic<'a> {
    gsdml_path: &'a str,
    cycle_ms: u16,
    allow_mask: u8,
    seconds: u64,
}

/// Issue one acyclic request under the caller's pacing, retrying only BUSY.
fn serve_rpc<T>(
    last: &mut Instant,
    gap: Duration,
    mut op: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    let mut busy = String::new();
    for attempt in 0..SERVE_BUSY_RETRIES {
        if attempt > 0 {
            thread::sleep(Duration::from_millis(50));
        }
        serve_pace(last, gap);
        match op() {
            Ok(v) => return Ok(v),
            Err(e) if e.contains(PNIO_BUSY_STATUS) => busy = e,
            Err(e) => return Err(e),
        }
    }
    Err(busy)
}

/// Serve acyclic reads and writes until stdin ends or a quit arrives.
///
/// With `cyclic`, the same loop additionally owns the device's IO AR: it emits
/// the input image at cycle rate and drives the output image from `set_level`
/// / `pulse` commands bounded by `allow_mask`, with the dead-man and the
/// commanded safe shutdown that layer has always carried.
fn cmd_serve(
    iface: &str,
    target: &str,
    read_only: bool,
    gap_ms: u64,
    keepalive_ms: u64,
    cyclic: Option<ServeCyclic<'_>>,
    timeout: Duration,
) -> Result<i32, String> {
    // Writes are refused whole in read-only mode, control commands included:
    // a caller that must not be able to command anything must not reach the
    // output image either.
    let allow_mask = match &cyclic {
        Some(c) if !read_only => c.allow_mask,
        _ => 0,
    };
    let commanding = allow_mask != 0;
    install_shutdown_handler()?;
    // A hard exit is safe unless we are driving the output image: with no
    // level bit ever set, the image stays all zeros, which is the safe image.
    SAFE_TO_HARD_EXIT.store(!commanding, Ordering::SeqCst);

    let conn = rpc_connect(iface, target, timeout)?;
    emit(&hello_line(
        target,
        read_only,
        gap_ms,
        cyclic.is_some(),
        allow_mask,
    ));

    // Optional cyclic tier. The controller is bound for the life of the loop:
    // dropping it stops the frames. `conn` is rebound onto the IO AR in that
    // case, so acyclic requests keep working over the same AR.
    let mut cyclic_ctl: Option<CyclicController> = None;
    let (mut out_slot, mut out_subslot) = (0u16, 0u16);
    let mut conn = match &cyclic {
        Some(c) => {
            emit(&warning_line(
                "io_controller_mode",
                "--cyclic claims the device's single IO AR: this process is now its \
                 IO-controller and provides the outputs. Any controller that held that \
                 AR has been displaced. Bench and commissioning only.",
            ));
            let tier = start_cyclic_tier(
                iface,
                target,
                conn,
                None,
                c.gsdml_path,
                c.cycle_ms,
                commanding,
                timeout,
            )?;
            cyclic_ctl = Some(tier.cyclic);
            out_slot = tier.out_slot;
            out_subslot = tier.out_subslot;
            tier.conn
        }
        None => conn,
    };

    let (cmd_tx, cmd_rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        while let Some(line) = read_bounded_line(&mut reader, MAX_STDIN_LINE) {
            match line {
                Ok(l) => {
                    if cmd_tx.send(l).is_err() {
                        return;
                    }
                }
                Err(msg) => emit(&error_msg_line(msg)),
            }
        }
    });

    let gap = Duration::from_millis(gap_ms);
    let mut last_request = Instant::now().checked_sub(gap).unwrap_or_else(Instant::now);
    let mut last_traffic = Instant::now();

    // Cyclic-mode state. Inert while `tier` is None.
    let cycle_ms = cyclic.as_ref().map_or(0, |c| c.cycle_ms);
    let seconds = cyclic.as_ref().map_or(0, |c| c.seconds);
    let tick = match cycle_ms {
        0 => Duration::from_millis(100),
        ms => Duration::from_millis(ms as u64),
    };
    let mut state = ControlState::default();
    let mut driven_byte = SAFE_OUTPUT_BYTE;
    let mut last_activity = Instant::now();
    let mut last_status = Instant::now();
    let mut last_tick = Instant::now();
    let start = Instant::now();

    if cyclic_ctl.is_some() {
        // Tell the caller the command layer is live and what it may drive.
        // With an all-zero allow mask this still goes out: it is how a
        // consumer learns that commanding is possible in principle but that
        // nothing has been armed.
        emit(&control_active_line(SAFE_OUTPUT_BYTE, allow_mask));
    }

    let stop = 'run: loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break 'run ServeStop::Reason("signal");
        }
        if seconds > 0 && start.elapsed().as_secs() >= seconds {
            break 'run ServeStop::Reason("timer");
        }
        // The cyclic frames are the ONLY channel commanding the output. If the
        // RX watchdog escalated to Fault, or the threads stopped, we are no
        // longer driving the device: bail out to the commanded safe shutdown
        // instead of "commanding" into a dead AR. The dead-man cannot catch
        // this, it only sees caller silence.
        if let Some(c) = cyclic_ctl.as_ref() {
            if let Some(reason) = cyclic_abort_reason(c.state()) {
                break 'run ServeStop::Reason(reason);
            }
        }

        match cmd_rx.recv_timeout(tick) {
            Ok(line) => {
                last_activity = Instant::now();
                match parse_serve_line(&line) {
                    Err(msg) => emit(&bad_command_line(&msg, &line)),
                    // `quit` is the one control command that still means
                    // something without a cyclic tier: it is how a caller
                    // driving an acyclic-only session says it is done.
                    Ok(ServeLine::Control(ControlCmd::Quit)) => {
                        break 'run ServeStop::Reason("quit")
                    }
                    Ok(ServeLine::Control(cmd)) => {
                        if cyclic_ctl.is_none() {
                            emit(&refused_needs_cyclic_line(&line));
                        } else if apply_control_cmd(cmd, &mut state, allow_mask) {
                            break 'run ServeStop::Reason("quit");
                        }
                    }
                    Ok(ServeLine::Rpc(cmd)) => {
                        let id = cmd.id();
                        match cmd {
                            ServeCmd::Quit { id } => {
                                emit(&bye_line(id));
                                break 'run ServeStop::Reason("quit");
                            }
                            ServeCmd::Ping { id } => emit(&pong_line(id, host_unix_us())),
                            ServeCmd::Write { .. } if read_only => {
                                emit(&refused_read_only_line(id))
                            }
                            ServeCmd::Read {
                                index,
                                slot,
                                subslot,
                                len,
                                ..
                            } => {
                                // The device's own answer, byte for byte and
                                // length included: exact-length probing
                                // depends on seeing what actually came back.
                                let r = serve_rpc(&mut last_request, gap, || {
                                    conn.read_raw(index, slot, subslot, len)
                                });
                                match r {
                                    Ok(d) => emit(&data_line(
                                        id,
                                        host_unix_us(),
                                        d.len(),
                                        &hex_encode(&d),
                                    )),
                                    Err(e) => {
                                        serve_emit_error(id, &e);
                                        if is_transport_failure(&e) {
                                            break 'run ServeStop::ArLost(e);
                                        }
                                    }
                                }
                                last_traffic = Instant::now();
                            }
                            ServeCmd::Write {
                                index,
                                slot,
                                subslot,
                                data,
                                ..
                            } => {
                                let r = serve_rpc(&mut last_request, gap, || {
                                    conn.write(index, slot, subslot, &data)
                                });
                                match r {
                                    Ok(()) => emit(&ok_line(id, host_unix_us())),
                                    Err(e) => {
                                        serve_emit_error(id, &e);
                                        if is_transport_failure(&e) {
                                            break 'run ServeStop::ArLost(e);
                                        }
                                    }
                                }
                                last_traffic = Instant::now();
                            }
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Idle keepalive, acyclic mode only: the AR lapses if nothing
                // uses it, and a caller is allowed to go quiet (a dialog is
                // open, an import is running) without losing its connection.
                // Under --cyclic the frames themselves keep the AR up.
                if cyclic_ctl.is_none()
                    && keepalive_ms > 0
                    && last_traffic.elapsed() >= Duration::from_millis(keepalive_ms)
                {
                    let r = serve_rpc(&mut last_request, gap, || conn.read_raw(0x8028, 1, 1, 128));
                    if let Err(e) = r {
                        if is_transport_failure(&e) {
                            break 'run ServeStop::ArLost(e);
                        }
                    }
                    last_traffic = Instant::now();
                }
            }
            // stdin closed: the caller is gone, so is our reason to hold the AR.
            Err(mpsc::RecvTimeoutError::Disconnected) => break 'run ServeStop::Reason("stdin_eof"),
        }

        if let Some(ctl) = cyclic_ctl.as_mut() {
            // Drive the commanded byte immediately, so a command takes effect
            // on the next frame rather than on the next tick.
            let effective = state.effective();
            if effective != driven_byte {
                if let Err(e) = ctl.set_output_data(out_slot, out_subslot, &[effective]) {
                    emit(&error_msg_line(&format!("set_output_data failed: {e}")));
                    break 'run ServeStop::Reason("io_error");
                }
                driven_byte = effective;
                // Let at least one output frame carry the new byte before
                // confirming it via the acyclic readback.
                thread::sleep(Duration::from_millis(2 * cycle_ms as u64 + 25));
                let readback = conn
                    .read_raw(0x8029, out_slot, out_subslot, 128)
                    .map(|d| hex_encode(&d))
                    .unwrap_or_default();
                emit(&output_line(
                    effective,
                    effective == SAFE_OUTPUT_BYTE,
                    &readback,
                ));
            }

            // Advance the pulse shapers by however many output cycles have
            // actually elapsed. Counting elapsed periods rather than loop
            // passes is what lets an acyclic read block here without
            // stretching a pulse.
            let elapsed = last_tick.elapsed();
            if elapsed >= tick {
                let periods = (elapsed.as_micros() / tick.as_micros().max(1)) as u32;
                last_tick = Instant::now();
                state.tick(periods);
            }

            // Dead-man: a level bit held plus a silent caller means we are
            // commanding on behalf of something that may be gone.
            if state.level != 0 && last_activity.elapsed() >= CONTROL_DEADMAN {
                emit(&deadman_line());
                break 'run ServeStop::Reason("deadman");
            }

            if last_status.elapsed() >= Duration::from_secs(1) {
                last_status = Instant::now();
                let stats = ctl.stats();
                emit(&status_line(
                    stats.frames_sent,
                    stats.frames_received,
                    stats.frames_missed,
                    state.effective(),
                ));
            }
        }
    };

    if let ServeStop::ArLost(msg) = &stop {
        emit(&ar_lost_line(host_unix_us(), msg));
    }

    match cyclic_ctl.as_mut() {
        // Commanding or not, the AR we hold is the IO AR: every exit path goes
        // through the commanded safe shutdown, so no bit is left held.
        Some(ctl) => {
            let verified = safe_shutdown(
                &mut conn,
                ctl,
                out_slot,
                out_subslot,
                cycle_ms,
                stop.reason(),
            );
            safe_shutdown_verdict(verified).map(|_| stop.exit_code())
        }
        None => {
            conn.release();
            emit(&stopped_exit_line(stop.exit_code()));
            Ok(stop.exit_code())
        }
    }
}

/// Why the serve loop stopped. `ArLost` is kept apart from the ordinary
/// reasons because it is the one that must reach the caller as a distinct
/// line: every request after it is meaningless, which a plain non-zero exit
/// does not say.
enum ServeStop {
    Reason(&'static str),
    ArLost(String),
}

impl ServeStop {
    fn reason(&self) -> &'static str {
        match self {
            ServeStop::Reason(r) => r,
            ServeStop::ArLost(_) => "ar_lost",
        }
    }

    fn exit_code(&self) -> i32 {
        match self {
            ServeStop::ArLost(_) => 1,
            ServeStop::Reason(_) => 0,
        }
    }
}

/// Wait out the inter-request gap, then mark the request as issued.
fn serve_pace(last: &mut Instant, gap: Duration) {
    let waited = last.elapsed();
    if waited < gap {
        thread::sleep(gap - waited);
    }
    *last = Instant::now();
}

// ---------------------------------------------------------------------------
// control command layer: NDJSON stdin commands -> output control byte
// ---------------------------------------------------------------------------

/// The output image this layer treats as safe. All-zero is the conventional
/// fail-safe for a PROFINET output image and is what every exit path drives.
/// It is deliberately not configurable yet: making "safe" a parameter without
/// a way to verify the claim would weaken the one invariant this layer sells.
const SAFE_OUTPUT_BYTE: u8 = 0x00;
/// Edge-bit pulse shape: the bit is held set for PULSE_TICKS output cycles,
/// then must stay clear for PULSE_COOLDOWN_TICKS cycles before the same bit
/// may pulse again, so a consumer that reacts to a rising edge sees a clean
/// one every time.
const PULSE_TICKS: u32 = 3;
const PULSE_COOLDOWN_TICKS: u32 = 3;
/// Dead-man: with a level bit held, any silence on stdin
/// longer than this triggers the commanded safe shutdown.
const CONTROL_DEADMAN: Duration = Duration::from_secs(5);
/// Bound on one stdin command line. The fixed command vocabulary fits in
/// tens of bytes; an unbounded `lines()` would buffer a no-newline blob
/// until the allocator aborts the process — a hard exit that would skip
/// the safe shutdown.
const MAX_STDIN_LINE: u64 = 4096;

/// Read the next newline-terminated line with a hard memory bound. Returns
/// `None` at EOF (or a read/UTF-8 error, matching the previous `lines()`
/// behavior) and `Err` for an over-long line — which is dropped and the
/// stream resynced to the next newline, so one garbage blob can neither
/// abort the process nor smuggle its tail into a later command.
fn read_bounded_line<R: std::io::BufRead>(
    reader: &mut R,
    max: u64,
) -> Option<Result<String, &'static str>> {
    use std::io::{BufRead, Read};
    let mut buf = Vec::new();
    match (&mut *reader).take(max).read_until(b'\n', &mut buf) {
        Ok(0) => None,
        Ok(n) => {
            if buf.last() == Some(&b'\n') {
                buf.pop();
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
            } else if n as u64 == max {
                // Hit the cap mid-line: discard (in bounded chunks) until
                // the next newline or EOF, then report the overflow.
                loop {
                    let mut skip = Vec::new();
                    match (&mut *reader).take(max).read_until(b'\n', &mut skip) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if skip.last() == Some(&b'\n') => break,
                        Ok(_) => {}
                    }
                }
                return Some(Err("stdin line too long"));
            }
            // else: final unterminated line at EOF.
            match String::from_utf8(buf) {
                Ok(s) => Some(Ok(s)),
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

/// One parsed stdin command.
#[derive(Debug, PartialEq, Eq)]
/// A command from the application. Deliberately free of device semantics:
/// this layer transports and fail-safes an output image, it does not know
/// what any bit means. Naming the bits is the application's job,
/// the same split a PLC draws between its PROFINET controller and its program.
enum ControlCmd {
    /// Hold `mask` set (or clear it) until changed again.
    SetLevel {
        mask: u8,
        on: bool,
    },
    /// Drive a shaped rising edge on `mask`: held for [`PULSE_TICKS`] output
    /// cycles, cleared, then a cooldown before the same mask may pulse again.
    Pulse {
        mask: u8,
    },
    Keepalive,
    Quit,
}

/// Locate the raw value after `"key":` in a one-line JSON object. Minimal by
/// design: enough for the fixed command vocabulary, not a general parser.
fn json_field_raw<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\"");
    let start = line.find(&pat)? + pat.len();
    line[start..]
        .trim_start()
        .strip_prefix(':')
        .map(str::trim_start)
}

/// Extract a JSON string field value (no escape handling; the command
/// vocabulary contains none).
fn json_field_str<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = json_field_raw(line, key)?.strip_prefix('"')?;
    rest.find('"').map(|end| &rest[..end])
}

/// Extract a JSON boolean field value.
fn json_field_bool(line: &str, key: &str) -> Option<bool> {
    let rest = json_field_raw(line, key)?;
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Parse one NDJSON stdin line into a command.
/// Parse an unsigned byte field, accepting decimal or `0x`-prefixed hex.
/// Masks read far better as hex, and a control protocol should not force the
/// caller to convert.
fn json_field_u8(line: &str, key: &str) -> Option<u8> {
    // json_field_raw yields the whole remainder of the line, so take only the
    // leading token: the value ends at the first character that cannot be part
    // of a decimal or 0x-hex literal.
    let rest = json_field_raw(line, key)?.trim_start();
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let token: &str = rest
        .find(|c: char| !c.is_ascii_alphanumeric())
        .map_or(rest, |end| &rest[..end]);
    match token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        Some(hex) => u8::from_str_radix(hex, 16).ok(),
        None => token.parse().ok(),
    }
}

/// clap value parser for a byte written decimal or as `0x` hex.
fn parse_u8_maybe_hex(raw: &str) -> Result<u8, String> {
    let raw = raw.trim();
    match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u8::from_str_radix(hex, 16),
        None => raw.parse(),
    }
    .map_err(|e| format!("invalid byte {raw:?}: {e}"))
}

fn parse_control_cmd(line: &str) -> Result<ControlCmd, String> {
    let cmd = json_field_str(line, "cmd").ok_or_else(|| "missing \"cmd\" field".to_string())?;
    match cmd {
        "set_level" => {
            let mask = json_field_u8(line, "mask")
                .ok_or_else(|| "set_level needs \"mask\":<byte>".to_string())?;
            let on = json_field_bool(line, "on")
                .ok_or_else(|| "set_level needs \"on\":true|false".to_string())?;
            Ok(ControlCmd::SetLevel { mask, on })
        }
        "pulse" => {
            let mask = json_field_u8(line, "mask")
                .ok_or_else(|| "pulse needs \"mask\":<byte>".to_string())?;
            Ok(ControlCmd::Pulse { mask })
        }
        "keepalive" => Ok(ControlCmd::Keepalive),
        "quit" => Ok(ControlCmd::Quit),
        other => Err(format!("unknown cmd {other:?}")),
    }
}

/// Pulse shaper for one edge bit: at most one pulse in flight, a mandatory
/// all-clear gap before the next, and the bit can never be left set (tick()
/// always counts an active pulse down to zero).
#[derive(Default)]
struct EdgePulse {
    remaining: u32,
    cooldown: u32,
}

impl EdgePulse {
    /// Queue a pulse; refused while one is active or cooling down.
    fn trigger(&mut self) -> Result<(), &'static str> {
        if self.remaining > 0 {
            return Err("pulse already active");
        }
        if self.cooldown > 0 {
            return Err("pulse cooling down");
        }
        self.remaining = PULSE_TICKS;
        Ok(())
    }

    fn active(&self) -> bool {
        self.remaining > 0
    }

    /// Advance by `periods` output cycles.
    ///
    /// Counted in elapsed cycle periods rather than loop iterations because
    /// the wire, not the loop, is what holds the bit: the cyclic controller
    /// keeps sending the last written byte every cycle regardless of what the
    /// command loop is doing. A loop that blocks for tens of milliseconds on
    /// an acyclic read has still driven the bit for that long, so the shaper
    /// has to count that time or the pulse would be stretched to whenever the
    /// loop next came around.
    fn tick(&mut self, periods: u32) {
        for _ in 0..periods {
            if self.remaining > 0 {
                self.remaining -= 1;
                if self.remaining == 0 {
                    self.cooldown = PULSE_COOLDOWN_TICKS;
                }
            } else if self.cooldown > 0 {
                self.cooldown -= 1;
            } else {
                break;
            }
        }
    }
}

/// The driven output byte model: held LEVEL bits plus shaped edge pulses.
/// Initialized to the all-zero image — the safe commissioning default; a
/// field variant would instead seed the level from the pre-takeover 0x8029
/// state.
#[derive(Default)]
struct ControlState {
    /// Level bits currently commanded; they persist until changed.
    level: u8,
    /// One shaper per mask that has ever been pulsed. Distinct masks pulse
    /// independently, so one edge command does not block another.
    pulses: Vec<(u8, EdgePulse)>,
}

impl ControlState {
    /// The byte to drive this cycle: the level bits OR every active pulse.
    fn effective(&self) -> u8 {
        self.pulses
            .iter()
            .filter(|(_, p)| p.active())
            .fold(self.level, |acc, (mask, _)| acc | mask)
    }

    /// Queue a shaped pulse on `mask`, reusing that mask's shaper so its
    /// cooldown is honoured across repeats.
    fn trigger_pulse(&mut self, mask: u8) -> Result<(), &'static str> {
        match self.pulses.iter_mut().find(|(m, _)| *m == mask) {
            Some((_, pulse)) => pulse.trigger(),
            None => {
                let mut pulse = EdgePulse::default();
                pulse.trigger()?;
                self.pulses.push((mask, pulse));
                Ok(())
            }
        }
    }

    /// Advance every pulse shaper by `periods` output cycles.
    fn tick(&mut self, periods: u32) {
        for (_, pulse) in &mut self.pulses {
            pulse.tick(periods);
        }
    }
}

/// Apply one parsed command to the control state, emitting an ack or a
/// refusal. Returns true for `quit`.
///
/// `allow_mask` is the only authority over what may ever be driven: a command
/// touching any bit outside it is refused whole, never masked down to the
/// permitted subset. Silently driving a smaller value than asked would be a
/// worse failure than refusing, because the caller would believe it succeeded.
fn apply_control_cmd(cmd: ControlCmd, state: &mut ControlState, allow_mask: u8) -> bool {
    let requested = match &cmd {
        ControlCmd::SetLevel { mask, .. } | ControlCmd::Pulse { mask } => Some(*mask),
        ControlCmd::Keepalive | ControlCmd::Quit => None,
    };
    if let Some(mask) = requested {
        if mask & !allow_mask != 0 {
            let name = match &cmd {
                ControlCmd::Pulse { .. } => "pulse",
                _ => "set_level",
            };
            emit(&refused_cmd_line(
                name,
                mask,
                &format!("mask has bits outside --allow-mask (0x{allow_mask:02x})"),
            ));
            return false;
        }
    }
    match cmd {
        ControlCmd::SetLevel { mask, on } => {
            if on {
                state.level |= mask;
            } else {
                state.level &= !mask;
            }
            emit(&ack_set_level_line(mask, on, state.level));
        }
        ControlCmd::Pulse { mask } => match state.trigger_pulse(mask) {
            Ok(()) => emit(&ack_pulse_line(mask)),
            Err(r) => emit(&refused_cmd_line("pulse", mask, r)),
        },
        ControlCmd::Keepalive => emit(&ack_keepalive_line()),
        ControlCmd::Quit => return true,
    }
    false
}

/// Map the safe-shutdown outcome to the process result. A verified-safe
/// shutdown unlocks the second-Ctrl+C hard exit ([`SAFE_TO_HARD_EXIT`]) —
/// only past that point may a stuck teardown be force-killed — and exits 0.
/// An unverified shutdown keeps the hard exit forbidden and reports failure
/// (non-zero exit) so a supervising parent detects the unverified output.
fn safe_shutdown_verdict(verified: bool) -> Result<i32, String> {
    if verified {
        SAFE_TO_HARD_EXIT.store(true, Ordering::SeqCst);
        Ok(0)
    } else {
        Err(
            "safe shutdown could not verify the safe output (see the \"alarm\" NDJSON \
             line); the device may still hold the last commanded output"
                .to_string(),
        )
    }
}

/// Commanded safe shutdown — the only way a commanding session stops the AR.
/// Drive the safe image 0x00 (no levels, no edges), hold it on the wire for
/// well over 3 output cycles so the device definitely receives it, verify via
/// a 0x8029 read that the output image really is the safe one, THEN stop the
/// cyclic frames (forced to 0x00 via [`CyclicController::stop_safe`]) and
/// release the AR. While that is not yet verified the AR is kept up for
/// several rounds, re-commanding 0x00 each round — stopping early would
/// remove the only channel actively driving it. Returns whether it was
/// verified;
/// [`safe_shutdown_verdict`] turns that into the exit code and the
/// hard-exit unlock.
fn safe_shutdown(
    conn: &mut RpcConn,
    cyclic: &mut CyclicController,
    out_slot: u16,
    out_subslot: u16,
    cycle_ms: u16,
    reason: &str,
) -> bool {
    let mut verified = false;
    let mut readback = String::new();
    'rounds: for _round in 0..3 {
        // (Re-)command the safe image, retrying the write: the cyclic
        // frames are the only channel driving the output back to it.
        for attempt in 0..3 {
            if attempt > 0 {
                thread::sleep(Duration::from_millis(50));
            }
            match cyclic.set_output_data(out_slot, out_subslot, &[0x00]) {
                Ok(()) => break,
                Err(e) => emit(&error_msg_line(&format!(
                    "safe shutdown set_output_data failed: {e}"
                ))),
            }
        }
        // >= 3 output cycles of the safe image on the wire, with a floor
        // for tiny cycles.
        thread::sleep(Duration::from_millis((cycle_ms as u64 * 5).max(100)));
        for attempt in 0..3 {
            if attempt > 0 {
                thread::sleep(Duration::from_millis(100));
            }
            match conn.read_raw(0x8029, out_slot, out_subslot, 128) {
                Ok(d) => {
                    readback = hex_encode(&d);
                    // Only OUR commanded data counts as proof: if the device
                    // fell back to substitutes our image is not in effect, so
                    // a 0x00 read back proves nothing.
                    if !output_substitute_active(&d)
                        && parse_output_control_byte(&d).is_some_and(|b| b == SAFE_OUTPUT_BYTE)
                    {
                        verified = true;
                        break 'rounds;
                    }
                }
                Err(e) => emit_read_error("safe_shutdown_readback", &e),
            }
        }
    }
    emit(&safe_shutdown_line(reason, verified, &readback));
    if !verified {
        emit(&alarm_line(reason, &readback));
    }
    cyclic.stop_safe(out_slot, out_subslot, &[0x00]);
    let stats = cyclic.stats();
    emit(&stopped_stats_line(
        stats.frames_sent,
        stats.frames_received,
        stats.frames_missed,
    ));
    conn.release();
    verified
}

fn run(cli: &Cli) -> Result<i32, String> {
    let iface = cli.interface.as_str();
    let timeout = Duration::from_secs(cli.timeout);
    // The DCP commands need the controller MAC; look it up once up front.
    match &cli.command {
        Command::Discover => cmd_discover(iface, timeout),
        Command::GetParam { target, param } => {
            let my_mac = pcap::get_mac(iface)?;
            cmd_get_param(iface, &my_mac, target, *param)
        }
        Command::SetParam {
            target,
            param,
            value,
        } => {
            let my_mac = pcap::get_mac(iface)?;
            cmd_set_param(iface, &my_mac, target, *param, value)
        }
        Command::Read {
            target,
            api: _,
            slot,
            subslot,
            index,
            length,
            implicit,
        } => cmd_read(
            iface, target, *slot, *subslot, index, *length, *implicit, timeout,
        ),
        Command::Write {
            target,
            api: _,
            slot,
            subslot,
            index,
            data,
        } => cmd_write(iface, target, *slot, *subslot, index, data, timeout),
        Command::ReadInm0Filter { target } => cmd_read_inm0_filter(iface, target, timeout),
        Command::ReadInm0(args) => cmd_read_inm(iface, args, im::IM0, timeout),
        Command::ReadInm1(args) => cmd_read_inm(iface, args, im::IM1, timeout),
        Command::ReadInm2(args) => cmd_read_inm(iface, args, im::IM2, timeout),
        Command::ReadInm3(args) => cmd_read_inm(iface, args, im::IM3, timeout),
        Command::SetIp {
            target,
            ip,
            netmask,
            gateway,
            permanent,
        } => {
            let my_mac = pcap::get_mac(iface)?;
            cmd_set_ip(iface, &my_mac, target, ip, netmask, gateway, *permanent)
        }
        Command::Signal { target } => {
            let my_mac = pcap::get_mac(iface)?;
            cmd_signal(iface, &my_mac, target)
        }
        Command::Reset { target, mode } => {
            let my_mac = pcap::get_mac(iface)?;
            cmd_reset(iface, &my_mac, target, *mode)
        }
        Command::Cyclic {
            target,
            gsdml,
            cycle_ms,
            duration,
            submodule,
        } => cmd_cyclic(
            iface, target, gsdml, *cycle_ms, *duration, submodule, timeout,
        ),
        Command::Serve {
            target,
            read_only,
            gap_ms,
            keepalive_ms,
            cyclic,
            gsdml,
            cycle_ms,
            allow_mask,
            i_am_on_the_bench,
            seconds,
        } => {
            let cyclic_opts = match cyclic {
                // Refuse rather than ignore: a caller that passed --allow-mask
                // believes it armed those bits, and silently serving acyclic
                // only would leave that belief standing.
                false if *allow_mask != 0 => {
                    return Err(
                        "--allow-mask only applies to the output image, which needs --cyclic"
                            .to_string(),
                    )
                }
                false => None,
                true => {
                    let gsdml = gsdml.as_deref().ok_or(
                        "--cyclic needs --gsdml: the submodule layout sizes the IOCRs, and \
                         the input length is checked against the firmware before starting",
                    )?;
                    // Driving outputs displaces whatever controller held the
                    // AR, so arming any bit needs the explicit confirmation.
                    if *allow_mask != 0 && !*i_am_on_the_bench {
                        emit(&refused_setup_line("missing --i-am-on-the-bench"));
                        return Err(
                            "refusing to drive outputs: pass --i-am-on-the-bench to confirm \
                             the device is on a bench with no other IO-controller attached"
                                .to_string(),
                        );
                    }
                    Some(ServeCyclic {
                        gsdml_path: gsdml,
                        cycle_ms: *cycle_ms,
                        allow_mask: *allow_mask,
                        seconds: *seconds,
                    })
                }
            };
            cmd_serve(
                iface,
                target,
                *read_only,
                *gap_ms,
                *keepalive_ms,
                cyclic_opts,
                timeout,
            )
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => exit(code),
        Err(e) => {
            eprintln!("Error: {e}");
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid args")
    }

    #[test]
    fn match_device_accepts_name_or_ip() {
        let dev = dcp::DcpDevice {
            name: "demo".to_string(),
            ip: [192, 168, 0, 2],
            ..Default::default()
        };
        assert!(match_device(vec![dev.clone()], "demo").is_some());
        assert!(match_device(vec![dev.clone()], "192.168.0.2").is_some());
        // Wrong name, wrong IP, and non-IP junk all miss.
        assert!(match_device(vec![dev.clone()], "other-device").is_none());
        assert!(match_device(vec![dev.clone()], "192.168.0.9").is_none());
        assert!(match_device(vec![dev], "not-an-ip-or-name").is_none());
    }

    #[test]
    fn interface_is_required() {
        assert!(Cli::try_parse_from(["profinet", "discover"]).is_err());
    }

    #[test]
    fn discover_defaults() {
        let cli = parse(&["profinet", "-i", "en0", "discover"]);
        assert_eq!(cli.interface, "en0");
        assert_eq!(cli.timeout, 10);
        assert!(matches!(cli.command, Command::Discover));
    }

    #[test]
    fn global_timeout_flag() {
        let cli = parse(&["profinet", "-i", "en0", "-t", "3", "discover"]);
        assert_eq!(cli.timeout, 3);
    }

    #[test]
    fn get_param_enum() {
        let cli = parse(&[
            "profinet",
            "-i",
            "en0",
            "get-param",
            "aa:bb:cc:dd:ee:ff",
            "name",
        ]);
        match cli.command {
            Command::GetParam { target, param } => {
                assert_eq!(target, "aa:bb:cc:dd:ee:ff");
                assert_eq!(param, Param::Name);
            }
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn get_param_rejects_unknown_param() {
        assert!(
            Cli::try_parse_from(["profinet", "-i", "en0", "get-param", "aa:bb", "serial"]).is_err()
        );
    }

    #[test]
    fn read_requires_slot_subslot_index() {
        assert!(Cli::try_parse_from(["profinet", "-i", "en0", "read", "dev"]).is_err());
        let cli = parse(&[
            "profinet",
            "-i",
            "en0",
            "read",
            "dev",
            "--slot",
            "0",
            "--subslot",
            "1",
            "--index",
            "0xAFF0",
        ]);
        match cli.command {
            Command::Read {
                target,
                slot,
                subslot,
                index,
                length,
                ..
            } => {
                assert_eq!(target, "dev");
                assert_eq!(slot, 0);
                assert_eq!(subslot, 1);
                assert_eq!(index, "0xAFF0");
                assert_eq!(length, READ_LENGTH);
            }
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn read_length_override() {
        let cli = parse(&[
            "profinet",
            "-i",
            "en0",
            "read",
            "dev",
            "--slot",
            "2",
            "--subslot",
            "1",
            "--index",
            "6000",
            "--length",
            "12",
        ]);
        match cli.command {
            Command::Read { length, .. } => assert_eq!(length, 12),
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn write_positional_hex() {
        let cli = parse(&[
            "profinet",
            "-i",
            "en0",
            "write",
            "dev",
            "--slot",
            "0",
            "--subslot",
            "1",
            "--index",
            "0xAFF1",
            "deadbeef",
        ]);
        match cli.command {
            Command::Write { data, index, .. } => {
                assert_eq!(data, "deadbeef");
                assert_eq!(index, "0xAFF1");
            }
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn read_inm_defaults() {
        let cli = parse(&["profinet", "-i", "en0", "read-inm0", "dev"]);
        match cli.command {
            Command::ReadInm0(args) => {
                assert_eq!(args.slot, 0);
                assert_eq!(args.subslot, 1);
            }
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn set_ip_positionals_and_flag() {
        let cli = parse(&[
            "profinet",
            "-i",
            "en0",
            "set-ip",
            "aa:bb:cc:dd:ee:ff",
            "192.168.0.5",
            "255.255.255.0",
            "192.168.0.1",
            "--permanent",
        ]);
        match cli.command {
            Command::SetIp {
                ip,
                netmask,
                gateway,
                permanent,
                ..
            } => {
                assert_eq!(ip, "192.168.0.5");
                assert_eq!(netmask, "255.255.255.0");
                assert_eq!(gateway, "192.168.0.1");
                assert!(permanent);
            }
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn reset_default_and_enum() {
        let cli = parse(&["profinet", "-i", "en0", "reset", "aa:bb"]);
        match cli.command {
            Command::Reset { mode, .. } => assert_eq!(mode, ResetMode::Factory),
            other => panic!("wrong command: {other:?}"),
        }
        let cli = parse(&[
            "profinet", "-i", "en0", "reset", "aa:bb", "--mode", "all-data",
        ]);
        match cli.command {
            Command::Reset { mode, .. } => assert_eq!(mode, ResetMode::AllData),
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn cyclic_repeatable_submodule() {
        let cli = parse(&[
            "profinet",
            "-i",
            "en0",
            "cyclic",
            "dev",
            "--gsdml",
            "d.xml",
            "--submodule",
            "1:1:0x1",
            "--submodule",
            "2:1:0x2",
        ]);
        match cli.command {
            Command::Cyclic {
                gsdml,
                cycle_ms,
                submodule,
                ..
            } => {
                assert_eq!(gsdml, "d.xml");
                assert_eq!(cycle_ms, 32);
                assert_eq!(submodule, vec!["1:1:0x1", "2:1:0x2"]);
            }
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn parse_index_hex_and_decimal() {
        assert_eq!(parse_index("0xAFF0").unwrap(), 0xAFF0);
        assert_eq!(parse_index("0Xaff1").unwrap(), 0xAFF1);
        assert_eq!(parse_index("6000").unwrap(), 6000);
        assert!(parse_index("nope").is_err());
    }

    #[test]
    fn parse_hex_ignores_spaces() {
        assert_eq!(
            parse_hex("de ad be ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(parse_hex("").unwrap(), Vec::<u8>::new());
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn parse_ipv4_dotted_quad() {
        assert_eq!(parse_ipv4("192.168.0.2").unwrap(), [192, 168, 0, 2]);
        assert!(parse_ipv4("999.1.1.1").is_err());
    }

    #[test]
    fn reset_mode_masks() {
        assert_eq!(ResetMode::Factory.mask(), dcp::RESET_MODE_FACTORY);
        assert_eq!(
            ResetMode::Communication.mask(),
            dcp::RESET_MODE_COMMUNICATION
        );
        assert_eq!(ResetMode::AllData.as_str(), "all-data");
    }

    #[test]
    fn device_role_decoding() {
        assert_eq!(decode_device_role(0x01), vec!["IO-Device"]);
        assert_eq!(decode_device_role(0x03), vec!["IO-Device", "IO-Controller"]);
        assert!(decode_device_role(0).is_empty());
    }

    #[test]
    fn hex_encode_lowercase() {
        assert_eq!(hex_encode(&[0x00, 0xAB, 0xff]), "00abff");
    }

    /// A 0x8028 RecordInputDataObjectElement, framed as the specification
    /// says: BlockHeader (type 0x0015), then LengthIOCS + IOCS, LengthIOPS +
    /// IOPS (0x80 = GOOD), LengthIOData, and the process image.
    ///
    /// Synthesised rather than captured. The framing is what the parser walks
    /// and it is identical on every device; the payload of a real capture is
    /// one device's live telemetry, which has no business being a fixture in
    /// a general-purpose tool.
    const INPUT_RECORD: &str = "001500180100010001800010000102030405060708090a0b0c0d0e0f";

    #[test]
    fn parse_input_data_length_walks_the_status_arrays() {
        let record = parse_hex(INPUT_RECORD).unwrap();
        assert_eq!(parse_input_data_length(&record), Some(16));
    }

    #[test]
    fn parse_input_data_length_skips_variable_status_arrays() {
        // Same record with 3-byte IOCS and 2-byte IOPS arrays: the declared
        // length still has to be found by walking, not by a fixed offset.
        let mut record = parse_hex("001500360100").unwrap();
        record.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // LengthIOCS + IOCS
        record.extend_from_slice(&[0x02, 0x80, 0x80]); // LengthIOPS + IOPS
        record.extend_from_slice(&[0x00, 0x04]); // LengthIOData
        record.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_input_data_length(&record), Some(4));
    }

    #[test]
    fn parse_input_data_length_rejects_truncated_payload() {
        // Declares 16 bytes of IOData but carries only 15: refusing beats
        // reporting a length the frame cannot satisfy.
        let mut record = parse_hex(INPUT_RECORD).unwrap();
        record.pop();
        assert_eq!(parse_input_data_length(&record), None);
    }

    #[test]
    fn parse_input_data_length_rejects_short_record() {
        assert_eq!(parse_input_data_length(&[]), None);
        assert_eq!(parse_input_data_length(&[0u8; 6]), None);
        // Header plus a LengthIOCS that runs off the end.
        assert_eq!(
            parse_input_data_length(&[0x00, 0x15, 0x00, 0x30, 0x01, 0x00, 0xff]),
            None
        );
    }

    /// A 0x8029 RecordOutputDataObjectElement carrying the all-zero control
    /// byte: BlockHeader (type 0x0016), SubstituteActiveFlag, LengthIOCS,
    /// LengthIOPS, LengthDataItem, then IOCS + data + IOPS.
    ///
    /// Same reasoning as [`INPUT_RECORD`]: the framing is the specification's,
    /// the trailing bytes are filler rather than one device's readback.
    const OUTPUT_RECORD: &str = "0016001601000000010100018000800000010203040506070809";

    #[test]
    fn parse_output_control_byte_reads_the_data_item() {
        let record = parse_hex(OUTPUT_RECORD).unwrap();
        assert_eq!(parse_output_control_byte(&record), Some(0x00));
    }

    #[test]
    fn parse_output_control_byte_walks_a_multi_byte_iocs() {
        // The DataItem begins after however many IOCS bytes the record
        // declares, so the control byte is at 12 + LengthIOCS, not at a fixed
        // offset. Every other fixture here declares one IOCS byte, where the
        // two happen to coincide: without this record a parser that ignored
        // LengthIOCS would pass the whole suite.
        //
        // 3-byte IOCS (0x808080), then the data byte 0xa5, then IOPS.
        let record = parse_hex("0016000d0100000003010001808080a580").unwrap();
        assert_eq!(parse_output_control_byte(&record), Some(0xa5));
    }

    #[test]
    fn parse_output_control_byte_non_safe_image() {
        // The same record with the control byte (after the leading IOCS) set
        // to something other than the safe image.
        let mut record = parse_hex(OUTPUT_RECORD).unwrap();
        record[13] = 0x01;
        assert_eq!(parse_output_control_byte(&record), Some(0x01));
    }

    #[test]
    fn substitute_flag_is_separate_from_the_control_byte() {
        // The shape a device sends with NO controller attached: it applies
        // substitute values (flag set) and the data byte is 0x00. That is the
        // normal pre-takeover state, so the ownership gate must still judge
        // the byte — an earlier blanket rejection here refused every takeover.
        let no_controller =
            parse_hex("0016001601000001010100018000000000010203040506070809").unwrap();
        assert!(
            output_substitute_active(&no_controller),
            "no controller attached => device applies substitutes"
        );
        assert_eq!(parse_output_control_byte(&no_controller), Some(0x00));

        // With a controller holding the AR the flag is clear, so this byte
        // IS our commanded data — the only thing
        // the safe-shutdown verify may accept as proof of the safe image.
        let ours = parse_hex(OUTPUT_RECORD).unwrap();
        assert!(!output_substitute_active(&ours));
        assert_eq!(parse_output_control_byte(&ours), Some(0x00));

        assert!(!output_substitute_active(&[]));
    }

    #[test]
    fn parse_output_control_byte_rejects_bad_records() {
        assert_eq!(parse_output_control_byte(&[]), None);
        assert_eq!(parse_output_control_byte(&[0u8; 11]), None);
        // Wrong block type.
        let mut record = parse_hex(OUTPUT_RECORD).unwrap();
        record[1] = 0x15;
        assert_eq!(parse_output_control_byte(&record), None);
        // Empty DataItem.
        let mut record = parse_hex(OUTPUT_RECORD).unwrap();
        record[10] = 0;
        record[11] = 0;
        assert_eq!(parse_output_control_byte(&record), None);
        // Truncated before the control byte.
        let record = parse_hex(OUTPUT_RECORD).unwrap();
        assert_eq!(parse_output_control_byte(&record[..13]), None);
    }

    #[test]
    fn cycle_ms_power_of_two_validation() {
        for ok in [1u16, 2, 8, 16, 32, 128, 512] {
            assert!(validate_cycle_ms(ok).is_ok(), "{ok} should be accepted");
        }
        for bad in [0u16, 3, 12, 24, 100, 513, 1024] {
            assert!(validate_cycle_ms(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn parse_control_cmd_vocabulary() {
        assert_eq!(
            parse_control_cmd("{\"cmd\":\"set_level\",\"mask\":1,\"on\":true}").unwrap(),
            ControlCmd::SetLevel { mask: 1, on: true }
        );
        assert_eq!(
            parse_control_cmd("{\"cmd\":\"set_level\",\"mask\":1,\"on\":false}").unwrap(),
            ControlCmd::SetLevel { mask: 1, on: false }
        );
        // Masks may be written as hex, which is how anyone thinks about bits.
        assert_eq!(
            parse_control_cmd("{\"cmd\":\"pulse\",\"mask\":\"0x04\"}").unwrap(),
            ControlCmd::Pulse { mask: 4 }
        );
        // Field order is not significant.
        assert_eq!(
            parse_control_cmd("{ \"on\" : true , \"mask\":2, \"cmd\" : \"set_level\" }").unwrap(),
            ControlCmd::SetLevel { mask: 2, on: true }
        );
        assert_eq!(
            parse_control_cmd("{\"cmd\":\"pulse\",\"mask\":2}").unwrap(),
            ControlCmd::Pulse { mask: 2 }
        );
        assert_eq!(
            parse_control_cmd("{\"cmd\":\"keepalive\"}").unwrap(),
            ControlCmd::Keepalive
        );
        assert_eq!(
            parse_control_cmd("{\"cmd\":\"quit\"}").unwrap(),
            ControlCmd::Quit
        );
    }

    #[test]
    fn parse_control_cmd_rejects_bad_lines() {
        assert!(parse_control_cmd("{\"cmd\":\"set_level\",\"mask\":1}").is_err());
        assert!(parse_control_cmd("{\"cmd\":\"set_level\",\"on\":true}").is_err());
        assert!(parse_control_cmd("{\"cmd\":\"set_level\",\"mask\":1,\"on\":1}").is_err());
        assert!(parse_control_cmd("{\"cmd\":\"pulse\"}").is_err());
        assert!(parse_control_cmd("{\"cmd\":\"open_sesame\"}").is_err());
        assert!(parse_control_cmd("not json").is_err());
        assert!(parse_control_cmd("").is_err());
    }

    #[test]
    fn edge_pulse_shape_and_cooldown() {
        let mut p = EdgePulse::default();
        assert!(!p.active());
        p.trigger().unwrap();
        // Exactly PULSE_TICKS active cycles...
        for _ in 0..PULSE_TICKS {
            assert!(p.active());
            assert!(p.trigger().is_err(), "no second pulse while active");
            p.tick(1);
        }
        // ...then the mandatory all-clear gap: the bit is never left set.
        for _ in 0..PULSE_COOLDOWN_TICKS {
            assert!(!p.active());
            assert!(p.trigger().is_err(), "no re-trigger during cooldown");
            p.tick(1);
        }
        // After the cooldown a fresh pulse is allowed again.
        p.trigger().unwrap();
        assert!(p.active());
    }

    #[test]
    fn control_state_effective_byte() {
        // Bit meanings are the application's; here they are just masks.
        const LEVEL: u8 = 0x01;
        const EDGE_A: u8 = 0x02;
        const EDGE_B: u8 = 0x04;

        let mut s = ControlState::default();
        assert_eq!(s.effective(), 0x00, "safe commissioning default is 0x00");
        s.level = LEVEL;
        assert_eq!(s.effective(), LEVEL);
        s.trigger_pulse(EDGE_A).unwrap();
        assert_eq!(s.effective(), LEVEL | EDGE_A);
        // Distinct masks pulse independently.
        s.trigger_pulse(EDGE_B).unwrap();
        assert_eq!(s.effective(), LEVEL | EDGE_A | EDGE_B);
        // Pulses decay on their own; the level bits stay.
        for _ in 0..PULSE_TICKS {
            s.tick(1);
        }
        assert_eq!(s.effective(), LEVEL);
        s.level = 0;
        assert_eq!(s.effective(), 0x00);
    }

    #[test]
    fn apply_control_cmd_refuses_masks_outside_allow_mask() {
        // Nothing is drivable by default, so an unconfigured session commands
        // nothing rather than something.
        let mut s = ControlState::default();
        assert!(!apply_control_cmd(
            ControlCmd::SetLevel {
                mask: 0x01,
                on: true
            },
            &mut s,
            0x00
        ));
        assert_eq!(
            s.effective(),
            0x00,
            "refused level must not reach the image"
        );

        // A mask straddling the allow mask is refused WHOLE, never masked down
        // to the permitted subset: a partial command the caller believes
        // succeeded is worse than a refusal.
        let mut s = ControlState::default();
        assert!(!apply_control_cmd(
            ControlCmd::SetLevel {
                mask: 0x06,
                on: true
            },
            &mut s,
            0x02
        ));
        assert_eq!(s.effective(), 0x00, "no partial application");

        // Clearing is gated too: the mask, not the direction, is the authority.
        let mut s = ControlState {
            level: 0x01,
            ..Default::default()
        };
        assert!(!apply_control_cmd(
            ControlCmd::SetLevel {
                mask: 0x01,
                on: false
            },
            &mut s,
            0x00
        ));
        assert_eq!(s.effective(), 0x01);

        // Within the allow mask the command applies.
        let mut s = ControlState::default();
        assert!(!apply_control_cmd(
            ControlCmd::SetLevel {
                mask: 0x01,
                on: true
            },
            &mut s,
            0x01
        ));
        assert_eq!(s.effective(), 0x01);
        // quit reports true and changes nothing.
        assert!(apply_control_cmd(ControlCmd::Quit, &mut s, 0x01));
        assert_eq!(s.effective(), 0x01);
    }

    #[test]
    fn apply_control_cmd_single_pulse_per_mask() {
        let mut s = ControlState::default();
        assert!(!apply_control_cmd(
            ControlCmd::Pulse { mask: 0x02 },
            &mut s,
            0xFF
        ));
        assert_eq!(s.effective(), 0x02);
        // A second pulse on the same mask while one is in flight is dropped;
        // the refusal is emitted and the shaper is not restarted.
        assert!(!apply_control_cmd(
            ControlCmd::Pulse { mask: 0x02 },
            &mut s,
            0xFF
        ));
        let remaining = s
            .pulses
            .iter()
            .find(|(m, _)| *m == 0x02)
            .map(|(_, p)| p.remaining)
            .unwrap();
        assert_eq!(remaining, PULSE_TICKS);
        // A different mask is independent.
        assert!(!apply_control_cmd(
            ControlCmd::Pulse { mask: 0x04 },
            &mut s,
            0xFF
        ));
        assert_eq!(s.effective(), 0x06);
    }

    #[test]
    fn second_sigint_hard_exit_gated_on_proven_safe_image() {
        // The only combination that may hard-exit (destructor-free) is a
        // repeat SIGINT AFTER the safe shutdown proved the safe image.
        assert!(!should_hard_exit(false, false));
        assert!(
            !should_hard_exit(true, false),
            "a repeat Ctrl+C must NOT hard-exit before open is proven"
        );
        assert!(!should_hard_exit(false, true));
        assert!(should_hard_exit(true, true));
    }

    #[test]
    fn lost_cyclic_link_aborts_to_safe_shutdown() {
        // Losing the cyclic link means we are no longer driving the output
        // at all, so the run loop must bail out to the commanded safe
        // shutdown instead of driving a dead AR. The dead-man cannot catch
        // this (keepalives into a dead link keep it satisfied).
        assert_eq!(
            cyclic_abort_reason(CyclicState::Fault),
            Some("cyclic_fault"),
            "a watchdog-escalated FAULT must abort to safe shutdown"
        );
        assert_eq!(
            cyclic_abort_reason(CyclicState::Stopped),
            Some("cyclic_stopped")
        );
        // Healthy / transient states keep the loop running.
        for ok in [
            CyclicState::Starting,
            CyclicState::Running,
            CyclicState::Idle,
            CyclicState::Stopping,
        ] {
            assert_eq!(cyclic_abort_reason(ok), None, "{ok:?} must not abort");
        }
    }

    #[test]
    fn safe_shutdown_verdict_gates_hard_exit_and_exit_code() {
        SAFE_TO_HARD_EXIT.store(false, Ordering::SeqCst);
        // Unverified: non-zero result for the supervising parent, and the
        // hard-exit escape hatch stays locked.
        assert!(safe_shutdown_verdict(false).is_err());
        assert!(
            !SAFE_TO_HARD_EXIT.load(Ordering::SeqCst),
            "an unverified shutdown must keep the hard exit forbidden"
        );
        // Verified: exit 0 and the hard exit unlocks.
        assert_eq!(safe_shutdown_verdict(true), Ok(0));
        assert!(SAFE_TO_HARD_EXIT.load(Ordering::SeqCst));
        SAFE_TO_HARD_EXIT.store(false, Ordering::SeqCst);
    }

    #[test]
    fn alarm_line_is_distinct_and_machine_readable() {
        let line = alarm_line("signal", "0016");
        assert!(line.starts_with("{\"type\":\"alarm\",\"reason\":\"safe output NOT verified\""));
        assert!(line.contains("\"shutdown_reason\":\"signal\""));
        assert!(line.contains("\"readback_hex\":\"0016\""));
    }

    #[test]
    fn read_bounded_line_normal_lines_and_eof() {
        let mut r = std::io::Cursor::new(b"{\"cmd\":\"keepalive\"}\r\nquit".to_vec());
        assert_eq!(
            read_bounded_line(&mut r, 64),
            Some(Ok("{\"cmd\":\"keepalive\"}".to_string()))
        );
        // Final unterminated line at EOF is still delivered.
        assert_eq!(read_bounded_line(&mut r, 64), Some(Ok("quit".to_string())));
        assert_eq!(read_bounded_line(&mut r, 64), None);
    }

    #[test]
    fn read_bounded_line_rejects_overlong_and_resyncs() {
        // A 10 KB no-newline blob followed by a valid command: the blob is
        // dropped without unbounded buffering, the command still parses.
        let mut input = vec![b'x'; 10_000];
        input.push(b'\n');
        input.extend_from_slice(b"{\"cmd\":\"quit\"}\n");
        let mut r = std::io::Cursor::new(input);
        assert_eq!(
            read_bounded_line(&mut r, 64),
            Some(Err("stdin line too long"))
        );
        assert_eq!(
            read_bounded_line(&mut r, 64),
            Some(Ok("{\"cmd\":\"quit\"}".to_string()))
        );
        assert_eq!(read_bounded_line(&mut r, 64), None);
        // Over-long final line with no newline at all: rejected, then EOF.
        let mut r = std::io::Cursor::new(vec![b'y'; 10_000]);
        assert_eq!(
            read_bounded_line(&mut r, 64),
            Some(Err("stdin line too long"))
        );
        assert_eq!(read_bounded_line(&mut r, 64), None);
        // A line exactly at the cap (newline included) is NOT an overflow.
        let mut exact = vec![b'z'; 63];
        exact.push(b'\n');
        let mut r = std::io::Cursor::new(exact);
        assert_eq!(read_bounded_line(&mut r, 64), Some(Ok("z".repeat(63))));
        assert_eq!(read_bounded_line(&mut r, 64), None);
    }

    #[test]
    fn serve_parses_the_request_vocabulary() {
        assert_eq!(
            parse_serve_cmd(r#"{"id":1,"cmd":"read","index":1234,"slot":2,"subslot":1,"len":24}"#)
                .unwrap(),
            ServeCmd::Read {
                id: 1,
                index: 1234,
                slot: 2,
                subslot: 1,
                len: 24
            }
        );
        // Indices read far better as hex, so both forms are accepted.
        assert_eq!(
            parse_serve_cmd(
                r#"{"id":2,"cmd":"read","index":"0x8028","slot":1,"subslot":1,"len":128}"#
            )
            .unwrap(),
            ServeCmd::Read {
                id: 2,
                index: 0x8028,
                slot: 1,
                subslot: 1,
                len: 128
            }
        );
        assert_eq!(
            parse_serve_cmd(
                r#"{"id":3,"cmd":"write","index":5000,"slot":2,"subslot":1,"hex":"01ff"}"#
            )
            .unwrap(),
            ServeCmd::Write {
                id: 3,
                index: 5000,
                slot: 2,
                subslot: 1,
                data: vec![0x01, 0xff]
            }
        );
        assert_eq!(
            parse_serve_cmd(r#"{"id":4,"cmd":"ping"}"#).unwrap(),
            ServeCmd::Ping { id: 4 }
        );
        assert_eq!(
            parse_serve_cmd(r#"{"id":5,"cmd":"quit"}"#).unwrap(),
            ServeCmd::Quit { id: 5 }
        );
    }

    #[test]
    fn serve_requires_an_id_on_every_request() {
        // Responses share stdout with unsolicited lines and a retried request
        // can answer late, so a request without an id could not be matched to
        // its answer. Refusing beats guessing.
        assert!(
            parse_serve_cmd(r#"{"cmd":"read","index":1,"slot":1,"subslot":1,"len":4}"#).is_err()
        );
        assert!(parse_serve_cmd(r#"{"cmd":"ping"}"#).is_err());
    }

    /// The wire format, pinned byte for byte.
    ///
    /// One assertion per line shape, 30 of them, and it is the whole
    /// vocabulary: `no_json_is_assembled_outside_the_line_builders` proves
    /// nothing else emits, and `the_pinned_shapes_cover_every_builder` proves
    /// nothing here is missing. Written against the format-string
    /// implementation and deliberately never edited afterwards, so any later
    /// rewrite of the builders has to reproduce these bytes exactly rather
    /// than being blessed by a golden adjusted to fit it.
    ///
    /// Values are distinct per field on purpose: swapping two same-typed
    /// arguments inside a builder changes the output here.
    #[test]
    fn emitted_lines_are_pinned() {
        // Answers to a request, all id-first.
        assert_eq!(bye_line(7), r#"{"id":7,"type":"bye"}"#);
        assert_eq!(
            pong_line(7, 1234),
            r#"{"id":7,"type":"pong","host_us":1234}"#
        );
        assert_eq!(
            data_line(7, 1234, 3, "a1b2c3"),
            r#"{"id":7,"type":"data","host_us":1234,"len":3,"hex":"a1b2c3"}"#
        );
        assert_eq!(ok_line(7, 1234), r#"{"id":7,"type":"ok","host_us":1234}"#);
        assert_eq!(
            read_error_line(7, 1234, "DE80B900", "wrong length"),
            r#"{"id":7,"type":"read_error","host_us":1234,"pnio":"DE80B900","msg":"wrong length"}"#
        );
        assert_eq!(
            transport_error_line(7, 1234, "no answer"),
            r#"{"id":7,"type":"transport_error","host_us":1234,"msg":"no answer"}"#
        );
        assert_eq!(
            refused_read_only_line(7),
            r#"{"id":7,"type":"refused","reason":"server is read-only"}"#
        );

        // Session framing.
        assert_eq!(
            hello_line("demo", true, 30, false, 6),
            r#"{"proto":5,"type":"hello","station":"demo","read_only":true,"gap_ms":30,"cyclic":false,"allow_mask":6}"#
        );
        assert_eq!(stopped_exit_line(0), r#"{"type":"stopped","exit":0}"#);
        assert_eq!(
            stopped_stats_line(11, 12, 13),
            r#"{"type":"stopped","tx":11,"rx":12,"missed":13}"#
        );

        // Diagnostics.
        assert_eq!(
            error_read_line("uptime", "timeout"),
            r#"{"type":"error","read":"uptime","msg":"timeout"}"#
        );
        assert_eq!(error_msg_line("nope"), r#"{"type":"error","msg":"nope"}"#);
        assert_eq!(
            bad_command_line("no id", "{}"),
            r#"{"type":"error","msg":"bad command: no id","line":"{}"}"#
        );
        assert_eq!(
            warning_line("io_controller_mode", "displaced"),
            r#"{"type":"warning","code":"io_controller_mode","msg":"displaced"}"#
        );
        assert_eq!(
            ar_lost_line(1234, "cable"),
            r#"{"type":"ar_lost","host_us":1234,"msg":"cable"}"#
        );

        // Refusals that carry no id.
        assert_eq!(
            refused_setup_line("missing --i-am-on-the-bench"),
            r#"{"type":"refused","reason":"missing --i-am-on-the-bench"}"#
        );
        assert_eq!(
            refused_needs_cyclic_line("{\"cmd\":\"pulse\"}"),
            r#"{"type":"refused","reason":"control commands need --cyclic","line":"{\"cmd\":\"pulse\"}"}"#
        );
        assert_eq!(
            refused_cmd_line("pulse", 6, "a pulse is already running"),
            r#"{"type":"refused","cmd":"pulse","mask":6,"reason":"a pulse is already running"}"#
        );

        // The command layer.
        assert_eq!(
            ack_set_level_line(4, true, 6),
            r#"{"type":"ack","cmd":"set_level","mask":4,"on":true,"level":6}"#
        );
        assert_eq!(
            ack_pulse_line(2),
            r#"{"type":"ack","cmd":"pulse","mask":2,"pulse_ticks":3}"#
        );
        assert_eq!(ack_keepalive_line(), r#"{"type":"ack","cmd":"keepalive"}"#);
        assert_eq!(
            control_active_line(0, 6),
            r#"{"type":"control_active","output_byte":0,"allow_mask":6}"#
        );
        assert_eq!(
            output_line(4, false, "0004"),
            r#"{"type":"output","control_byte":4,"safe":false,"readback_hex":"0004"}"#
        );
        assert_eq!(
            deadman_line(),
            r#"{"type":"deadman","msg":"no command/keepalive while a level bit is held"}"#
        );

        // The cyclic tier.
        assert_eq!(
            current_output_line(2, "0000"),
            r#"{"type":"current_output","len":2,"hex":"0000"}"#
        );
        assert_eq!(
            cyclic_line(1, 2, 1234, 3, "aabbcc"),
            r#"{"type":"cyclic","slot":1,"subslot":2,"host_us":1234,"len":3,"hex":"aabbcc"}"#
        );
        assert_eq!(
            cyclic_started_line(16, 0x8001, 0x8002, 40, 1, 2),
            r#"{"type":"cyclic_started","cycle_ms":16,"input_frame_id":32769,"output_frame_id":32770,"input_len":40,"out_slot":1,"out_subslot":2}"#
        );
        assert_eq!(
            status_line(11, 12, 13, 4),
            r#"{"type":"status","tx":11,"rx":12,"missed":13,"out_byte":4}"#
        );

        // Shutdown.
        assert_eq!(
            safe_shutdown_line("quit", true, "0000"),
            r#"{"type":"safe_shutdown","reason":"quit","verified_safe":true,"readback_hex":"0000"}"#
        );
        assert_eq!(
            alarm_line("signal", "0004"),
            r#"{"type":"alarm","reason":"safe output NOT verified","shutdown_reason":"signal","readback_hex":"0004"}"#
        );
    }

    /// Where the pinned region ends. Named so the test that depends on it
    /// fails loudly if this comment is reworded.
    const END_OF_PIN_TEST: &str = "\n    /// Where the pinned region ends.";

    /// Does `haystack` call `name` as a whole identifier? A bare substring
    /// search matches a longer builder name ending in the same word.
    fn calls_by_name(haystack: &str, name: &str) -> bool {
        let needle = format!("{name}(");
        haystack.match_indices(&needle).any(|(i, _)| {
            i == 0
                || !haystack[..i]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    }

    /// Collect the line builders straight from the source: a function whose
    /// name ends in `_line` and that returns a `String`. The naming rule is
    /// what makes the two tests below decidable without a hand-kept list that
    /// could go stale.
    fn line_builders(production: &str) -> Vec<&str> {
        production
            .split("\nfn ")
            .skip(1)
            .filter_map(|f| {
                let (signature, _) = f.split_once('{')?;
                let name = signature.split('(').next()?;
                // The signature may span several lines, so split at the brace
                // rather than at the newline.
                (name.ends_with("_line") && signature.contains("-> String")).then_some(name)
            })
            .collect()
    }

    fn production_source() -> &'static str {
        let src = include_str!("profinet.rs");
        &src[..src.find("\n#[cfg(test)]").expect("test module")]
    }

    /// The rule the vocabulary rests on: JSON is assembled in the line
    /// builders and nowhere else.
    ///
    /// Without this, the pinned shapes above prove only that the builders are
    /// right — an emit site that keeps building its own line, or a new one
    /// added later, would pass every assertion while emitting something no
    /// test has ever seen. Checking the source is the only way to check a
    /// negative like this.
    ///
    /// Three ways to build a line are looked for: an escaped literal
    /// (`\"type\"`), a raw one (`r#"{"type":…`), and reaching for the
    /// serialiser directly (`json!`, `serde_json::to_string`). Comments are
    /// stripped first, because the builders' own documentation quotes the wire
    /// format. What is left uncovered is a literal split across pieces so no
    /// single one spells a key — text matching cannot see that, and it is not
    /// something anybody does by accident.
    #[test]
    fn no_json_is_assembled_outside_the_line_builders() {
        let production = production_source();
        let builders = line_builders(production);
        assert!(
            builders.len() > 20,
            "the builder scan found almost nothing, so this test would pass vacuously: {builders:?}"
        );

        let mut current = "";
        let mut offenders = Vec::new();
        for (n, line) in production.lines().enumerate() {
            if let Some(rest) = line.strip_prefix("fn ") {
                // Split on `<` too, so a generic function is recognised by its
                // bare name.
                current = rest.split(['(', '<']).next().unwrap_or("");
            }
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            let assembles_json = code.contains("\\\"type\\\"")
                || code.contains("\\\"proto\\\"")
                || code.contains("{\"type\"")
                || code.contains("json!(");
            // `serde_json::to_string` belongs to `json_line` alone; anywhere
            // else it is a line being serialised outside the vocabulary.
            let serialises = code.contains("serde_json::to_string") && current != "json_line";
            if (assembles_json || serialises) && !builders.contains(&current) {
                offenders.push(format!("{}: {} (in {current})", n + 1, code));
            }
        }
        assert!(
            offenders.is_empty(),
            "JSON assembled outside a line builder:\n{}",
            offenders.join("\n")
        );
    }

    /// Every builder is pinned. Guards the other direction: a builder added
    /// without a pinned shape would otherwise never be checked against the
    /// wire format at all.
    #[test]
    fn the_pinned_shapes_cover_every_builder() {
        let src = include_str!("profinet.rs");
        let pinned = {
            let start = src.find("fn emitted_lines_are_pinned").expect("pin test");
            let rest = &src[start..];
            // `expect`, not `unwrap_or(rest.len())`: rewording the marker must
            // fail loudly. Falling back to the end of the file would silently
            // stretch the region over the hostile-content test, which calls
            // nearly every builder, and this check would pass forever.
            let end = rest
                .find(END_OF_PIN_TEST)
                .expect("the pin test's end marker moved, so the region is wrong");
            &rest[..end]
        };
        let missing: Vec<&str> = line_builders(production_source())
            .into_iter()
            // A plain `contains("{name}(")` would let a new builder named
            // `cmd_line` ride on the pinned `refused_cmd_line(`, so require
            // that the match does not continue an identifier to the left.
            .filter(|name| !calls_by_name(pinned, name))
            .collect();
        assert!(
            missing.is_empty(),
            "builders with no pinned shape: {missing:?}"
        );
    }

    /// The one thing the port to `serde` did change, pinned so it is a
    /// documented fact rather than a surprise.
    ///
    /// The hand-written escaper wrote every control character below 0x20
    /// except `\n` as `\u00xx`. `serde_json` uses the short forms for four of
    /// them. Both are valid JSON for the same string, so no parser can tell —
    /// only a consumer comparing raw bytes or matching a regex against a line
    /// could, which is why it is stated here instead of buried in a commit
    /// message. Everything else escapes identically: quote, backslash, `\n`,
    /// the remaining control characters, and anything non-ASCII.
    #[test]
    fn control_characters_use_the_short_escapes() {
        let raw = "a\u{8}b\u{9}c\u{c}d\u{d}e";
        assert_eq!(
            error_msg_line(raw),
            r#"{"type":"error","msg":"a\bb\tc\fd\re"}"#
        );

        // The four that changed form still decode to exactly what went in.
        let line = error_msg_line(raw);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["msg"].as_str(), Some(raw));

        // The ones that did not change: quote, backslash, newline, and a
        // control character that has no short form.
        assert_eq!(
            error_msg_line("q\"b\\x\u{a}c\u{1}"),
            r#"{"type":"error","msg":"q\"b\\x\nc\u0001"}"#
        );
    }

    /// Every string that goes into an emitted line has to survive being
    /// hostile.
    ///
    /// This used to be the check on a hand-written escaper that each emit site
    /// had to remember to call. It is kept now that `serde` escapes
    /// structurally, because the property is what matters and not the
    /// mechanism: a future field holding device text must still produce a line
    /// the consumer can parse. A `#[serde(skip_serializing)]`, a raw-string
    /// shortcut or a hand-built `String` field would break it again.
    #[test]
    fn every_emitted_string_survives_hostile_content() {
        let nasty = "he said \"stop\"\n\tand \\ left\u{1}";
        // Every builder that carries text this process did not author: device
        // messages, PNIO status words, the station name off the command line,
        // an echoed input line. Calling the builders rather than restating
        // their format strings is deliberate — a hand-copied literal here
        // would drift away from the real one without any test noticing.
        for (label, line) in [
            ("error_read", error_read_line(nasty, nasty)),
            ("error_msg", error_msg_line(nasty)),
            ("bad_command", bad_command_line(nasty, nasty)),
            ("warning", warning_line(nasty, nasty)),
            ("hello", hello_line(nasty, true, 30, false, 6)),
            ("read_error", read_error_line(1, 2, nasty, nasty)),
            ("transport_error", transport_error_line(1, 2, nasty)),
            ("refused_setup", refused_setup_line(nasty)),
            ("refused_needs_cyclic", refused_needs_cyclic_line(nasty)),
            ("refused_cmd", refused_cmd_line(nasty, 6, nasty)),
            ("ar_lost", ar_lost_line(2, nasty)),
            ("data", data_line(1, 2, 3, nasty)),
            ("cyclic", cyclic_line(1, 2, 3, 4, nasty)),
            ("current_output", current_output_line(2, nasty)),
            ("output", output_line(4, false, nasty)),
            ("safe_shutdown", safe_shutdown_line(nasty, true, nasty)),
            ("alarm", alarm_line(nasty, nasty)),
        ] {
            // The consumer parses these with serde_json, so valid JSON is the
            // contract, not merely "looks about right".
            let v: serde_json::Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("{label} is not valid JSON: {e}\n{line}"));
            assert!(v.get("type").is_some(), "{label} lost its type field");
        }

        // And the escaping round-trips: what goes in comes back out.
        let v: serde_json::Value = serde_json::from_str(&alarm_line(nasty, "00ff")).unwrap();
        assert_eq!(v["shutdown_reason"].as_str(), Some(nasty));
        assert_eq!(v["readback_hex"].as_str(), Some("00ff"));
    }

    #[test]
    fn serve_routes_the_two_vocabularies_apart() {
        // Control commands never carried an id and must not start needing one.
        assert_eq!(
            parse_serve_line(r#"{"cmd":"set_level","mask":1,"on":true}"#).unwrap(),
            ServeLine::Control(ControlCmd::SetLevel { mask: 1, on: true })
        );
        assert_eq!(
            parse_serve_line(r#"{"cmd":"pulse","mask":"0x02"}"#).unwrap(),
            ServeLine::Control(ControlCmd::Pulse { mask: 2 })
        );
        assert_eq!(
            parse_serve_line(r#"{"cmd":"keepalive"}"#).unwrap(),
            ServeLine::Control(ControlCmd::Keepalive)
        );
        // RPC requests keep their mandatory id.
        assert_eq!(
            parse_serve_line(r#"{"id":7,"cmd":"ping"}"#).unwrap(),
            ServeLine::Rpc(ServeCmd::Ping { id: 7 })
        );
        assert!(
            parse_serve_line(r#"{"cmd":"read","index":1,"slot":1,"subslot":1,"len":4}"#).is_err()
        );
    }

    #[test]
    fn serve_quit_belongs_to_whichever_vocabulary_sent_it() {
        // `quit` exists in both. Only the id-carrying form owes a `bye` that
        // carries it back, so routing has to split on the id, not the verb.
        assert_eq!(
            parse_serve_line(r#"{"id":9,"cmd":"quit"}"#).unwrap(),
            ServeLine::Rpc(ServeCmd::Quit { id: 9 })
        );
        assert_eq!(
            parse_serve_line(r#"{"cmd":"quit"}"#).unwrap(),
            ServeLine::Control(ControlCmd::Quit)
        );
    }

    #[test]
    fn edge_pulse_counts_elapsed_periods_not_loop_passes() {
        // A blocking acyclic read stalls the command loop, but the controller
        // keeps sending the last written byte every cycle: the bit is on the
        // wire for that whole time. Advancing by the elapsed period count is
        // what keeps a pulse the length it was asked to be.
        let mut p = EdgePulse::default();
        p.trigger().unwrap();
        p.tick(PULSE_TICKS);
        assert!(
            !p.active(),
            "the pulse ends after its ticks, however few loop passes"
        );
        assert!(p.trigger().is_err(), "cooldown still owed");
        p.tick(PULSE_COOLDOWN_TICKS);
        p.trigger().unwrap();

        // A single huge jump must not consume the next pulse's cooldown or
        // wrap the counters.
        let mut q = EdgePulse::default();
        q.trigger().unwrap();
        q.tick(u32::MAX);
        assert!(!q.active());
        q.trigger().expect("cooldown elapsed within the same jump");
        assert!(q.active());
    }

    #[test]
    fn serve_rejects_incomplete_and_malformed_requests() {
        assert!(
            parse_serve_cmd(r#"{"id":1,"cmd":"read","index":1,"slot":1,"subslot":1}"#).is_err()
        );
        assert!(
            parse_serve_cmd(r#"{"id":1,"cmd":"write","index":1,"slot":1,"subslot":1}"#).is_err()
        );
        // An index outside u16 is not a valid record index.
        assert!(parse_serve_cmd(
            r#"{"id":1,"cmd":"read","index":70000,"slot":1,"subslot":1,"len":4}"#
        )
        .is_err());
        assert!(parse_serve_cmd(r#"{"id":1,"cmd":"open_sesame"}"#).is_err());
        assert!(parse_serve_cmd("not json").is_err());
    }

    #[test]
    fn a_device_saying_no_is_not_a_lost_connection() {
        // The caller probes lengths and indices on purpose, so a PNIO status
        // is a normal negative answer; anything else means the AR is gone and
        // every later request is meaningless.
        let refused = "read failed: PNIO error status 0xDE80B900 (...)";
        assert!(!is_transport_failure(refused));
        assert_eq!(pnio_status_of(refused).as_deref(), Some("DE80B900"));

        for dead in [
            "No response from device",
            "send failed: Broken pipe",
            "recv timed out",
        ] {
            assert!(is_transport_failure(dead), "{dead} should read as fatal");
            assert_eq!(pnio_status_of(dead), None);
        }
    }

    #[test]
    fn pnio_status_is_passed_through_verbatim() {
        // Count discovery pivots on the exact code, so no normalising.
        for code in ["DE80B900", "DE80B000", "DE80C200"] {
            let msg = format!("read failed: PNIO error status 0x{code} (whatever)");
            assert_eq!(pnio_status_of(&msg).as_deref(), Some(code));
        }
        // A truncated code is not a code.
        assert_eq!(pnio_status_of("PNIO error status 0xDE80"), None);
    }

    #[test]
    fn serve_pacing_waits_only_when_it_must() {
        let gap = Duration::from_millis(40);
        // First request after a long idle goes straight out.
        let mut last = Instant::now() - Duration::from_millis(500);
        let t0 = Instant::now();
        serve_pace(&mut last, gap);
        assert!(t0.elapsed() < Duration::from_millis(20));
        // The next one waits out the remainder of the gap.
        let t1 = Instant::now();
        serve_pace(&mut last, gap);
        assert!(t1.elapsed() >= Duration::from_millis(30), "did not pace");
    }
}
