#[derive(Debug, Clone, PartialEq)]
pub enum TcbStatus {
    OK,
    TcbSwHardeningNeeded,
    TcbConfigurationAndSwHardeningNeeded,
    TcbConfigurationNeeded,
    TcbOutOfDate,
    TcbOutOfDateConfigurationNeeded,
    TcbRevoked,
    TcbUnrecognized,
}

// serialization:
// [quote_vesion][tee_type][tcb_status][fmspc][quote_body_raw_bytes]
// 2 bytes + 4 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584)
// total: 13 + var bytes
#[derive(Debug)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: TcbStatus,
    pub fmspc: [u8; 6],
    pub quote_body: EnclaveReport,
}

impl VerifiedOutput {
    pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
        let mut quote_version = [0; 2];
        quote_version.copy_from_slice(&slice[0..2]);
        let mut tee_type = [0; 4];
        tee_type.copy_from_slice(&slice[2..6]);
        let tcb_status = match slice[6] {
            0 => TcbStatus::OK,
            1 => TcbStatus::TcbSwHardeningNeeded,
            2 => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
            3 => TcbStatus::TcbConfigurationNeeded,
            4 => TcbStatus::TcbOutOfDate,
            5 => TcbStatus::TcbOutOfDateConfigurationNeeded,
            6 => TcbStatus::TcbRevoked,
            7 => TcbStatus::TcbUnrecognized,
            _ => panic!("Invalid TCB Status"),
        };
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[7..13]);
        let mut raw_quote_body = Vec::new();
        raw_quote_body.extend_from_slice(&slice[13..]);

        let quote_body = match raw_quote_body.len() {
            ENCLAVE_REPORT_LEN => {
                EnclaveReport::from_bytes(&raw_quote_body)
            }
            _ => {
                panic!("Invalid quote body")
            }
        };

        VerifiedOutput {
            quote_version: u16::from_be_bytes(quote_version),
            tee_type: u32::from_be_bytes(tee_type),
            tcb_status,
            fmspc,
            quote_body,
        }
    }
}

const ENCLAVE_REPORT_LEN: usize = 384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnclaveReport {
    pub cpu_svn: [u8; 16],     // [16 bytes]
    pub misc_select: [u8; 4],  // [4 bytes]
    pub reserved_1: [u8; 28],  // [28 bytes]
    pub attributes: [u8; 16],  // [16 bytes]
    pub mrenclave: [u8; 32],   // [32 bytes]
    pub reserved_2: [u8; 32],  // [32 bytes]
    pub mrsigner: [u8; 32],    // [32 bytes]
    pub reserved_3: [u8; 96],  // [96 bytes]
    pub isv_prod_id: u16,      // [2 bytes]
    pub isv_svn: u16,          // [2 bytes]
    pub reserved_4: [u8; 60],  // [60 bytes]
    pub report_data: [u8; 64], // [64 bytes]
}

impl EnclaveReport {
    pub fn from_bytes(raw_bytes: &[u8]) -> EnclaveReport {
        assert_eq!(raw_bytes.len(), 384);
        let mut obj = EnclaveReport {
            cpu_svn: [0; 16],
            misc_select: [0; 4],
            reserved_1: [0; 28],
            attributes: [0; 16],
            mrenclave: [0; 32],
            reserved_2: [0; 32],
            mrsigner: [0; 32],
            reserved_3: [0; 96],
            isv_prod_id: 0,
            isv_svn: 0,
            reserved_4: [0; 60],
            report_data: [0; 64],
        };

        // parse raw bytes into obj
        obj.cpu_svn.copy_from_slice(&raw_bytes[0..16]);
        obj.misc_select.copy_from_slice(&raw_bytes[16..20]);
        obj.reserved_1.copy_from_slice(&raw_bytes[20..48]);
        obj.attributes.copy_from_slice(&raw_bytes[48..64]);
        obj.mrenclave.copy_from_slice(&raw_bytes[64..96]);
        obj.reserved_2.copy_from_slice(&raw_bytes[96..128]);
        obj.mrsigner.copy_from_slice(&raw_bytes[128..160]);
        obj.reserved_3.copy_from_slice(&raw_bytes[160..256]);
        obj.isv_prod_id = u16::from_le_bytes([raw_bytes[256], raw_bytes[257]]);
        obj.isv_svn = u16::from_le_bytes([raw_bytes[258], raw_bytes[259]]);
        obj.reserved_4.copy_from_slice(&raw_bytes[260..320]);
        obj.report_data.copy_from_slice(&raw_bytes[320..384]);

        return obj;
    }
}
