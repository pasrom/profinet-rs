//! Byte-exact PROFINET block/record builders, ported from
//! `profinet-py/profinet/protocol.py` (PNBlockHeader, PNIODHeader) as used by
//! `rpc.py` read()/write(). All fields are big-endian.

pub const IOD_READ_REQUEST_HEADER: u16 = 0x0009;
pub const IOD_WRITE_REQUEST_HEADER: u16 = 0x0008;
pub const IOD_WRITE_RESPONSE_HEADER: u16 = 0x8008;

/// IODWriteMultipleReq record index (IODWriteMultipleBuilder.INDEX).
pub const IOD_WRITE_MULTIPLE_INDEX: u16 = 0xE040;

fn be16(data: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([data[off], data[off + 1]])
}

fn be32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// PNBlockHeader: block_type ++ block_length ++ version_high ++ version_low
/// (6 bytes).
pub fn block_header(block_type: u16, block_length: u16, ver_high: u8, ver_low: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&block_type.to_be_bytes());
    out.extend_from_slice(&block_length.to_be_bytes());
    out.push(ver_high);
    out.push(ver_low);
    out
}

// PNIODHeader: 64 fixed bytes (block_header 6, sequence_number 2, ar_uuid 16,
// api 4, slot 2, subslot 2, padding1 2, index 2, length 4, target_ar_uuid 16,
// padding2 8) followed by the payload.
// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
fn pniod_header(
    block_type: u16,
    seq: u16,
    ar_uuid: &[u8; 16],
    api: u32,
    slot: u16,
    subslot: u16,
    index: u16,
    length: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + payload.len());
    out.extend_from_slice(&block_header(block_type, 60, 1, 0));
    out.extend_from_slice(&seq.to_be_bytes()); // sequence_number
    out.extend_from_slice(ar_uuid);
    out.extend_from_slice(&api.to_be_bytes());
    out.extend_from_slice(&slot.to_be_bytes());
    out.extend_from_slice(&subslot.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // padding1
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&[0u8; 16]); // target_ar_uuid
    out.extend_from_slice(&[0u8; 8]); // padding2
    out.extend_from_slice(payload);
    out
}

/// IODReadReq record as built by rpc.py read(): block 0x0009, length field =
/// number of bytes to read, no payload.
pub fn iod_read_request(
    ar_uuid: &[u8; 16],
    api: u32,
    slot: u16,
    subslot: u16,
    index: u16,
    length: u32,
) -> Vec<u8> {
    pniod_header(
        IOD_READ_REQUEST_HEADER,
        0,
        ar_uuid,
        api,
        slot,
        subslot,
        index,
        length,
        &[],
    )
}

/// IODWriteReq record as built by rpc.py write(): block 0x0008, length field =
/// payload length, payload appended after the 64-byte header.
pub fn iod_write_request(
    ar_uuid: &[u8; 16],
    api: u32,
    slot: u16,
    subslot: u16,
    index: u16,
    payload: &[u8],
) -> Vec<u8> {
    pniod_header(
        IOD_WRITE_REQUEST_HEADER,
        0,
        ar_uuid,
        api,
        slot,
        subslot,
        index,
        payload.len() as u32,
        payload,
    )
}

/// One write in an IODWriteMultipleReq, in the tuple shape
/// `IODWriteMultipleBuilder` stores: (api, slot, subslot, index, data).
pub type MultiWrite<'a> = (u32, u16, u16, u16, &'a [u8]);

/// IODWriteMultipleReq payload as `IODWriteMultipleBuilder.build()`: the
/// outer 64-byte header (wildcard-free fields fixed to api=0xFFFFFFFF,
/// slot/subslot=0xFFFF, index 0xE040, length = total block bytes) followed
/// by one IODWriteReq block per write (sequence number = position), each
/// padded to a 4-byte boundary except the last.
pub fn iod_write_multiple_payload(
    ar_uuid: &[u8; 16],
    seq_num: u16,
    writes: &[MultiWrite],
) -> Vec<u8> {
    let mut blocks: Vec<u8> = Vec::new();
    for (i, &(api, slot, subslot, index, data)) in writes.iter().enumerate() {
        let block = pniod_header(
            IOD_WRITE_REQUEST_HEADER,
            i as u16,
            ar_uuid,
            api,
            slot,
            subslot,
            index,
            data.len() as u32,
            data,
        );
        blocks.extend_from_slice(&block);
        if i < writes.len() - 1 {
            let pad = (4 - block.len() % 4) % 4;
            blocks.resize(blocks.len() + pad, 0);
        }
    }
    let mut out = pniod_header(
        IOD_WRITE_REQUEST_HEADER,
        seq_num,
        ar_uuid,
        0xFFFF_FFFF,
        0xFFFF,
        0xFFFF,
        IOD_WRITE_MULTIPLE_INDEX,
        blocks.len() as u32,
        &[],
    );
    out.extend_from_slice(&blocks);
    out
}

/// Result of a single write in a WriteMultiple operation
/// (WriteMultipleResult).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteMultipleResult {
    pub seq_num: u16,
    pub api: u32,
    pub slot: u16,
    pub subslot: u16,
    pub index: u16,
    pub status: u32,
    pub additional_value1: u16,
    pub additional_value2: u16,
}

impl WriteMultipleResult {
    /// True if the write succeeded (status == 0).
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// Parse an IODWriteMultipleRes NRD payload into individual results
/// (`parse_write_multiple_response`): record length from the outer IOD
/// header, then 56-byte 0x8008 entries from offset 64, each advanced by
/// 4 + block_length plus 4-byte alignment padding. A non-0x8008 block or a
/// short buffer ends the walk, as in the reference.
pub fn parse_write_multiple_response(data: &[u8]) -> Vec<WriteMultipleResult> {
    let mut results = Vec::new();
    if data.len() < 64 {
        return results;
    }
    let record_len = be32(data, 36) as usize;
    let mut offset = 64usize;
    let end = (offset + record_len).min(data.len());
    while offset + 56 <= end {
        let entry = &data[offset..offset + 56];
        if be16(entry, 0) != IOD_WRITE_RESPONSE_HEADER {
            break;
        }
        // Entry layout: block header(4) + version(2) + seq_num(2) +
        // ar_uuid(16) + api(4) + slot(2) + subslot(2) + padding(2) +
        // index(2) + record_data_length(4) + add_val1(2) + add_val2(2) +
        // status(4) + padding(8).
        results.push(WriteMultipleResult {
            seq_num: be16(entry, 6),
            api: be32(entry, 24),
            slot: be16(entry, 28),
            subslot: be16(entry, 30),
            index: be16(entry, 34),
            status: be32(entry, 44),
            additional_value1: be16(entry, 40),
            additional_value2: be16(entry, 42),
        });
        let block_size = 4 + be16(entry, 2) as usize;
        let pad = (4 - block_size % 4) % 4;
        offset += block_size + pad;
    }
    results
}
