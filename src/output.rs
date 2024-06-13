#[derive(Debug, Clone, PartialEq)]
pub enum TcbStatus {
    OK,
    TcbSwHardeningNeeded,
    TcbConfigurationAndSwHardeningNeeded,
    TcbConfigurationNeeded,
    TcbOutOfDate,
    TcbOutOfDateConfigurationNeeded,
    TcbRevoked,
    TcbUnrecognized
}


#[derive(Clone, Debug)]
pub struct VerifiedOutput {
    pub tcb_status: TcbStatus,
    pub mr_enclave: [u8; 32],
    pub mr_signer: [u8; 32],
    pub report_data: [u8; 64],
    pub fmspc: [u8; 6],
}

impl VerifiedOutput {
    pub fn to_bytes(self) -> [u8; 135] {
        let mut raw_bytes = [0; 135];
        raw_bytes[0] = match self.tcb_status {
            TcbStatus::OK => 0,
            TcbStatus::TcbSwHardeningNeeded => 1,
            TcbStatus::TcbConfigurationAndSwHardeningNeeded => 2,
            TcbStatus::TcbConfigurationNeeded => 3,
            TcbStatus::TcbOutOfDate => 4,
            TcbStatus::TcbOutOfDateConfigurationNeeded => 5,
            TcbStatus::TcbRevoked => 6,
            TcbStatus::TcbUnrecognized => 7,
        };
        raw_bytes[1..33].copy_from_slice(&self.mr_enclave);
        raw_bytes[33..65].copy_from_slice(&self.mr_signer);
        raw_bytes[65..129].copy_from_slice(&self.report_data);
        raw_bytes[129..135].copy_from_slice(&self.fmspc);

        raw_bytes
    }

    pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
        let tcb_status = match slice[0] {
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
        let mut mr_enclave = [0; 32];
        mr_enclave.copy_from_slice(&slice[1..33]);
        let mut mr_signer = [0; 32];
        mr_signer.copy_from_slice(&slice[33..65]);
        let mut report_data= [0; 64];
        report_data.copy_from_slice(&slice[65..129]);
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[129..135]);

        VerifiedOutput {
            tcb_status,
            mr_enclave,
            mr_signer,
            report_data,
            fmspc,
        }
    }
    
}