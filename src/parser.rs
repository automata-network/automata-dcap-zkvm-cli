use x509_parser::oid_registry::asn1_rs::{
    oid, FromDer, OctetString, Oid, Sequence,
};

use super::chain::pccs::pcs::IPCSDao::CA;
use x509_parser::prelude::*;

const QE_AUTH_DATA_SIZE_OFFSET: usize = 1012;

pub fn get_pck_fmspc_and_issuer(quote: &[u8]) -> (String, CA, String) {
    let cert_data_offset = get_cert_data_offset(quote);
    let cert_data: Vec<u8> = (quote[cert_data_offset..]).to_vec();

    let pem = parse_pem(&cert_data).expect("Failed to parse cert data");
    let cert_chain = parse_certchain(&pem);
    let pck = &cert_chain[0];

    let pck_issuer = get_x509_issuer_cn(pck);

    let pck_ca = match pck_issuer.as_str() {
        "Intel SGX PCK Platform CA" => CA::PLATFORM,
        "Intel SGX PCK Processor CA" => CA::PROCESSOR,
        _ => panic!("Unknown PCK Issuer"),
    };

    let fmspc_slice = extract_fmspc_from_extension(pck);
    let fmspc = hex::encode(fmspc_slice);

    (fmspc, pck_ca, pck_issuer)
}

fn get_cert_data_offset(quote: &[u8]) -> usize {
    let auth_data_size = u16::from_le_bytes([
        quote[QE_AUTH_DATA_SIZE_OFFSET],
        quote[QE_AUTH_DATA_SIZE_OFFSET + 1],
    ]);

    QE_AUTH_DATA_SIZE_OFFSET + 2 + auth_data_size as usize + 2 + 4
}

fn parse_pem(raw_bytes: &[u8]) -> Result<Vec<Pem>, PEMError> {
    Pem::iter_from_buffer(raw_bytes).collect()
}

fn parse_certchain<'a>(pem_certs: &'a [Pem]) -> Vec<X509Certificate<'a>> {
    pem_certs
        .iter()
        .map(|pem| pem.parse_x509().unwrap())
        .collect()
}

fn get_x509_issuer_cn(cert: &X509Certificate) -> String {
    let issuer = cert.issuer();
    let cn = issuer.iter_common_name().next().unwrap();
    cn.as_str().unwrap().to_string()
}

fn extract_fmspc_from_extension<'a>(cert: &'a X509Certificate<'a>) -> [u8; 6] {
    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840 .113741 .1 .13 .1))
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    let mut fmspc = [0; 6];

    let mut i = sgx_extensions.content.as_ref();

    while i.len() > 0 {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                fmspc.copy_from_slice(fmspc_bytes.as_ref());
                break;
            }
            _ => continue,
        }
    }

    fmspc
}
