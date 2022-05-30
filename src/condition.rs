use num_bigint::{BigInt, BigUint};
use num_traits::cast::FromPrimitive;
use libsecp256k1::{PublicKey, Signature, SecretKey, Message, sign};
use simple_asn1::{to_der, ASN1Block, ASN1Class};
use std::collections::HashSet;

pub const MIXED_MODE: u32 = 0x01;

pub use Condition::*;
pub use crate::pad_fingerprint;
pub use crate::shrink_fingerprint;

use log::Level;
use log::info;

#[derive(Clone, PartialEq, Debug, Copy)]
pub enum ConditionType {
    AnonType,
    PreimageType,
    PrefixType,
    ThresholdType,
    Secp256k1Type,
    Secp256k1HashType,
    EvalType
}

pub use ConditionType::*;


impl ConditionType {
    pub fn id(&self) -> u8 {
        match self {
            PreimageType { .. } => 0,
            PrefixType { .. } => 1,
            ThresholdType { .. } => 2,
            Secp256k1Type { .. } => 5,
            Secp256k1HashType { .. } => 6,
            EvalType { .. } => 15,
            AnonType { .. } => 0xff
        }
    }
    pub fn name(&self) -> String {
        match self {
            PreimageType => "preimage-sha-256".into(),
            PrefixType => "prefix-sha-256".into(),
            ThresholdType => "threshold-sha-256".into(),
            Secp256k1Type => "secp256k1-sha-256".into(),
            Secp256k1HashType => "secp256k1hash-sha-256".into(),
            EvalType => "eval-sha-256".into(),
            AnonType => "(anon)".into()
        }
    }
    pub fn has_subtypes(&self) -> bool {
        *self == ThresholdType || *self == PrefixType
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Condition {
    Threshold {
        threshold: u16,
        subconditions: Vec<Condition>,
    },
    Preimage {
        preimage: Vec<u8>,
    },
    Prefix {
        prefix: Vec<u8>,
        max_message_len: u64,
        subcondition: Box<Condition>,
    },
    Secp256k1 {
        pubkey: PublicKey,
        signature: Option<Signature>,
    },
    Secp256k1Hash {
        pubkey_hash: Option<Vec<u8>>,
        pubkey: Option<PublicKey>,
        signature: Option<Signature>,
    },
    Eval {
        code: Vec<u8>,
    },
    Anon {
        cond_type: ConditionType,
        fingerprint: Vec<u8>,
        cost: u64,
        subtypes: HashSet<u8>,
    },
}

impl Condition {
    pub fn get_type(&self) -> ConditionType {
        match self {
            Preimage { .. } => PreimageType,
            Prefix { .. } => PrefixType,
            Threshold { .. } => ThresholdType,
            Secp256k1 { .. } => Secp256k1Type,
            Secp256k1Hash { .. } => Secp256k1HashType,
            Eval { .. } => EvalType,
            Anon { cond_type, .. } => *cond_type,
        }
    }
    
    fn encode_condition_asn(&self) -> ASN1Block {
        let fingerprint = shrink_fingerprint(&self.fingerprint(), &self.get_type());
        let cost = BigInt::from_u64(self.cost()).unwrap().to_signed_bytes_be();
        let mut parts = vec![fingerprint, cost];
        if self.has_subtypes() {
            parts.push(pack_set(self.get_subtypes()));
        }
        asn_choice(self.get_type().id(), &asn_data(&parts))
    }

    pub fn encode_condition(&self) -> Vec<u8> {
        encode_asn(&self.encode_condition_asn())
    }

    pub fn fingerprint(&self) -> Vec<u8> {
        match self {
            Secp256k1 { pubkey, .. } => {
                let data = asn_data(&vec![pubkey.serialize_compressed().to_vec()]);
                hash_asn(&ASN1Block::Sequence(0, data))
            }
            Secp256k1Hash { pubkey_hash, .. } => {
                let v_pubkey_hash = pubkey_hash.as_ref().unwrap().to_vec();
                pad_fingerprint(&v_pubkey_hash, &self.get_type())
            }
            Eval { code } => sha256(code.to_vec()),
            Preimage { preimage } => sha256(preimage.to_vec()),
            Prefix { 
                prefix, 
                max_message_len,
                subcondition
            } => {
                let mml_asn = BigInt::from_u64(*max_message_len).unwrap().to_signed_bytes_be();
                let mut data = asn_data(&vec![prefix.to_vec(), mml_asn ]);

                data.push(asn_choice(1, &vec![subcondition.encode_condition_asn()] ));
                hash_asn(&ASN1Block::Sequence(0, data))
            }
            Threshold {
                threshold,
                subconditions,
            } => {
                let mut asns = subconditions
                    .iter()
                    .map(|c| c.encode_condition_asn())
                    .collect();
                x690sort(&mut asns);

                let t = BigInt::from_u16(*threshold).unwrap().to_signed_bytes_be();
                let mut elems = asn_data(&vec![t]);
                elems.push(asn_choice(1, &asns));
   
                hash_asn(&ASN1Block::Sequence(0, elems))
            }
            Anon { fingerprint, .. } => { /*info!("Anon fingerprint.clone()");*/ fingerprint.clone() },
        }
    }

    pub fn cost(&self) -> u64 {
        match self {
            Preimage { preimage } => preimage.len() as u64,
            Prefix { 
                prefix,
                max_message_len,
                subcondition 
            } => 
            {                 
                (1024 as u64) + (prefix.len() as u64) + max_message_len + (subcondition.cost() as u64)
            },
            Secp256k1 { .. } => 131072,
            Secp256k1Hash { .. } => 131072,
            Eval { .. } => 1048576,
            Anon { cost, .. } => *cost,
            Threshold {
                threshold,
                subconditions,
            } => {
                let mut costs: Vec<u64> = subconditions.iter().map(|c| c.cost()).collect();
                costs.sort();
                costs.reverse();
                let expensive: u64 = costs.iter().take(*threshold as usize).sum();
                expensive + 1024 * subconditions.len() as u64
            }
        }
    }

    fn has_subtypes(&self) -> bool {
        self.get_type().has_subtypes()
    }

    fn get_subtypes(&self) -> HashSet<u8> {
        match self {
            Threshold { subconditions, .. } => {
                let mut set = HashSet::new();
                for cond in subconditions {
                    set.insert(cond.get_type().id());
                    for x in cond.get_subtypes() {
                        set.insert(x);
                    }
                }
                set.remove(&self.get_type().id());
                set
            }
            Anon { subtypes, .. } => subtypes.clone(),
            _ => HashSet::new(),
        }
    }

    fn encode_fulfillment_asn(&self, flags: u32) -> R {
        match self {
            Preimage { preimage } => Ok(asn_choice(
                self.get_type().id(),
                &asn_data(&vec![preimage.to_vec()]),
            )),
            Prefix { 
                prefix, 
                max_message_len,
                subcondition
            } => {
                let mml_asn = BigInt::from_u64(*max_message_len).unwrap().to_signed_bytes_be();
                let mut data = asn_data(&vec![prefix.to_vec(), mml_asn ]);
                data.push(asn_choice(1, &vec![subcondition.encode_condition_asn()] ));
                Ok(asn_choice(self.get_type().id(), &data))
            },
            Secp256k1 {
                pubkey,
                signature: Some(signature),
            } => {
                let body = vec![
                    pubkey.serialize_compressed().to_vec(),
                    signature.serialize().to_vec(),
                ];
                Ok(asn_choice(self.get_type().id(), &asn_data(&body)))
            },
            Secp256k1Hash {
                pubkey_hash: _,
                pubkey: Some(pubkey),
                signature: Some(signature),
            } => {
                let body = vec![
                    pubkey.serialize_compressed().to_vec(),
                    signature.serialize().to_vec(),
                ];
                Ok(asn_choice(self.get_type().id(), &asn_data(&body)))
            },
            Eval { code } => Ok(asn_choice(self.get_type().id(), &asn_data(&vec![code.to_vec()]))),
            Threshold {
                threshold,
                subconditions,
            } => threshold_fulfillment_asn(*threshold, subconditions, flags),
            _ => return Err("Cannot encode fulfillment".into()),
        }
    }

    pub fn encode_fulfillment(&self, flags: u32) -> Result<Vec<u8>, String> {
        Ok(encode_asn(&self.encode_fulfillment_asn(flags)?))
    }

    pub fn is_fulfilled(&self) -> bool {
        unimplemented!()
    }

    pub fn sign_secp256k1(&mut self, secret: &SecretKey, message: &Message) -> Result<(), libsecp256k1::Error> {

        match self {
            Secp256k1 { pubkey, ref mut signature  } => {
                if *pubkey == PublicKey::from_secret_key(secret) {
                    *signature = Some(sign(message, secret).0);
                }
            },
            Threshold { ref mut subconditions, .. } => {
                for c in subconditions.iter_mut() { c.sign_secp256k1(secret, message)?; }
            }
            _ => { }
        };
        Ok(())
    }

    pub fn sign_secp256k1hash(&mut self, secret: &SecretKey, message: &Message) -> Result<(), libsecp256k1::Error> {
        let pubkey_from_key = PublicKey::from_secret_key(secret);
        let pubkey_hash_in = ripemd_sha(&pubkey_from_key);
        match self {
            Secp256k1Hash { ref pubkey_hash, pubkey, ref mut signature  } => {
                if *pubkey_hash == Some(pubkey_hash_in[..].to_vec()) {
                    *pubkey = Some(pubkey_from_key);
                    *signature = Some(sign(message, secret).0);
                }
            },
            Threshold { ref mut subconditions, .. } => {
                for c in subconditions.iter_mut() { c.sign_secp256k1hash(secret, message)?; }
            }
            _ => { }
        };
        Ok(())
    }

    pub fn to_anon(&self) -> Condition {
        Anon {
            cond_type: self.get_type(),
            fingerprint: self.fingerprint(),
            cost: self.cost(),
            subtypes: self.get_subtypes()
        }
    }
}

type R = Result<ASN1Block, String>;

fn threshold_fulfillment_asn(threshold: u16, subconditions: &Vec<Condition>, flags: u32) -> R {
    if (flags & MIXED_MODE) != 0 { return threshold_fulfillment_asn_mixed_mode(threshold, subconditions, flags); }
    fn key_cost((c, opt_asn): &(&Condition, R)) -> (u8, u64) {
        match opt_asn {
            Ok(_) => (0, c.cost()),
            _ => (1, 0),
        }
    }
    let mut subs: Vec<(&Condition, R)> = subconditions
        .iter()
        .map(|c| (c, c.encode_fulfillment_asn(flags)))
        .collect();
    subs.sort_by(|a, b| key_cost(a).cmp(&key_cost(b)));

    let tt = threshold as usize;
    if subs.len() >= tt && subs[tt - 1].1.is_ok() {
        Ok(asn_choice(
            ThresholdType.id(),
            &vec![
                asn_choice(
                    0,
                    &subs
                        .iter()
                        .take(tt)
                        .map(|t| t.1.as_ref().unwrap().clone())
                        .collect(),
                ),
                asn_choice(
                    1,
                    &subs
                        .iter()
                        .skip(tt)
                        .map(|t| t.0.encode_condition_asn())
                        .collect(),
                ),
            ],
        ))
    } else {
        Err("Threshold is unfulfilled".into())
    }
}

fn threshold_fulfillment_asn_mixed_mode(threshold: u16, subconditions: &Vec<Condition>, flags: u32) -> R {
    let threshold_bytes = vec![ threshold as u8];
    let marker = Preimage {
        preimage: threshold_bytes 
    };
    let marker_asn = marker.encode_fulfillment_asn(flags);
    let mut ffils = vec![ marker_asn.unwrap() ];
    let mut conds = vec![ ];

    let mut i = 0;
    while i < subconditions.len() {
        let ffil = subconditions[i].encode_fulfillment_asn(flags);
        match ffil {
            Ok(c) => { ffils.push(c);  },
            Err(_e) => { conds.push(subconditions[i].encode_condition_asn()); }
        }
        i += 1;
    }

    // x690 Elements of a Set are encoded in sorted order, based on their tag value
    x690sort(&mut ffils);
    x690sort(&mut conds);

    Ok(asn_choice(ThresholdType.id(), &vec![ asn_choice(0, &ffils), asn_choice(1, &conds)]))
}


pub fn threshold_to_anon(cond: &mut Condition) {
   
    match cond {
        Threshold {
            threshold: _,
            ref mut subconditions,
        } => {
            for subcond in subconditions {
                if subcond.get_type() == ThresholdType {
                    let anon = subcond.to_anon();

                    *subcond = anon;
                    break;
                }
            }
        }
        _ => { }
    }
}

fn x690sort(asns: &mut Vec<ASN1Block>) {
    asns.sort_by(|b, a| { // reversed
        let va = encode_asn(a);
        let vb = encode_asn(b);
        //va.len().cmp(&vb.len()).then_with(|| va.cmp(&vb))
        //va.len().cmp(&vb.len()).then_with(|| vb.cmp(&va))
        vb.cmp(&va)
    })
}

pub mod internal {
    use super::*;
    use sha2::Digest;
    use ripemd::Ripemd160;
    use ripemd::Digest as RipemdDigest;

    pub fn sha256(buf: Vec<u8>) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.input(buf);
        (*hasher.result()).to_vec()
    }

    pub fn ripemd_sha(pubkey: &PublicKey) -> Vec<u8> {
        let pubkey_sha256 = sha256(pubkey.serialize_compressed().to_vec());
        let mut ripemd_hasher = Ripemd160::new();
        ripemd_hasher.update(pubkey_sha256);
        let pubkey_hash = ripemd_hasher.finalize();
        pubkey_hash.to_vec()
    }

    pub fn encode_asn(asn: &ASN1Block) -> Vec<u8> {
        to_der(asn).expect("ASN encoding broke")
    }

    pub fn pack_set(items: HashSet<u8>) -> Vec<u8> {
        // XXX: This will probably break if there are any type IDs > 31
        let mut buf = vec![0, 0, 0, 0];
        let mut max_id = 0;
        for i in items {
            max_id = std::cmp::max(i, max_id);
            buf[i as usize >> 3] |= 1 << (7 - i % 8);
        }
        buf.truncate(1 + (max_id >> 3) as usize);
        buf.insert(0, 7 - max_id % 8);

        let mut asubtypes: [u8; 4] = [0,0,0,0];
        let mut i = 0;
        while i < buf.len()   {
            asubtypes[i] = buf[i]; 
            i += 1;
        }

        buf
    }

    pub fn unpack_set(buf_: Vec<u8>) -> HashSet<u8> {
        let mut set = HashSet::new();
        let buf: Vec<&u8> = buf_.iter().skip(1).collect();

        // TODO: omg check

        for i in 0..(buf.len() * 8) {
            if buf[i >> 3] & (1 << (7 - i % 8)) != 0 {
                set.insert(i as u8);
            }
        }
        set
    }

    pub fn asn_data(vecs: &Vec<Vec<u8>>) -> Vec<ASN1Block> {
        let mut out = Vec::new();
        for (i, v) in vecs.iter().enumerate() {
            out.push(asn_unknown(false, i, v.to_vec()));
        }
        out
    }

    pub fn asn_unknown(construct: bool, tag: usize, vec: Vec<u8>) -> ASN1Block {
        ASN1Block::Unknown(
            ASN1Class::ContextSpecific,
            construct,
            0,
            BigUint::from_usize(tag).unwrap(),
            vec,
        )
    }

    pub fn asn_choice(type_id: u8, children: &Vec<ASN1Block>) -> ASN1Block {
        asn_unknown(true, type_id as usize, asns_to_vec(children))
    }

    pub fn asn_sequence(children: Vec<ASN1Block>) -> ASN1Block {
        ASN1Block::Sequence(0, children)
    }

    pub fn hash_asn(asn: &ASN1Block) -> Vec<u8> {
        sha256(encode_asn(asn))
    }

    fn asns_to_vec(asns: &Vec<ASN1Block>) -> Vec<u8> {
        let mut body = Vec::new();
        for child in asns {
            body.append(&mut encode_asn(child));
        }
        body
    }
}

use internal::*;

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::{FromHex, ToHex};

    #[test]
    fn test_pack_cost() {
        let cost = BigInt::from_u32(1010101010).unwrap();
        let asn = ASN1Block::Unknown(
            ASN1Class::ContextSpecific,
            false,
            0,
            BigUint::from_u8(0).unwrap(),
            cost.to_signed_bytes_be(),
        );
        let encoded = encode_asn(&asn);
        assert_eq!(encoded.to_hex::<String>(), "80043c34eb12");
    }

    #[test]
    fn test_pack_bit_array() {
        assert_eq!(
            internal::pack_set(vec![1, 2, 3].into_iter().collect()).to_hex::<String>(),
            "0470"
        );
        assert_eq!(
            internal::pack_set(vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into_iter().collect())
                .to_hex::<String>(),
            "067fc0"
        );
        assert_eq!(
            internal::pack_set(vec![15].into_iter().collect()).to_hex::<String>(),
            "000001"
        );
    }

    #[test]
    fn test_encode_complex() {
        let pk = "03682b255c40d0cde8faee381a1a50bbb89980ff24539cb8518e294d3a63cefe12".from_hex::<Vec<u8>>().unwrap();
        let cond = Threshold {
            threshold: 2,
            subconditions: vec![
                Threshold {
                    threshold: 1,
                    subconditions: vec![
                        Secp256k1 {
                            pubkey: PublicKey::parse_slice(&pk, None).unwrap(),
                            signature: None
                        }
                    ]
                },
                Eval { code: vec![228] }
            ]
        };

        assert_eq!(
            cond.encode_condition(),
            cond.to_anon().encode_condition());
    }

    #[test]
    // test encode_condition(cond) equals to encode_condition of to_anon(cond)
    fn test_encode_complex_secp256k1hash() {
        let pkhash = "6579c3bd574da22803234e12ddcec405e2b99092".from_hex::<Vec<u8>>().unwrap();
        let cond = Threshold {
            threshold: 2,
            subconditions: vec![
                Threshold {
                    threshold: 1,
                    subconditions: vec![
                        Secp256k1Hash {
                            pubkey_hash: Some(pkhash),
                            pubkey: None,
                            signature: None
                        }
                    ]
                },
                Eval { code: vec![0xe4] }
            ]
        };

        assert_eq!(
            cond.encode_condition(),
            cond.to_anon().encode_condition());
    }

    #[test]
    fn test_encode_complex_mixed_mode_ffil() {
        let pk = "03682b255c40d0cde8faee381a1a50bbb89980ff24539cb8518e294d3a63cefe12".from_hex::<Vec<u8>>().unwrap();
        let cond = Threshold {
            threshold: 2,
            subconditions: vec![
                Eval { code: vec![0xf4] },
                Threshold {
                    threshold: 1,
                    subconditions: vec![
                        Secp256k1 {
                            pubkey: PublicKey::parse_slice(&pk, None).unwrap(),
                            signature: None
                        }
                    ]
                }
            ]
        };

        assert_eq!(
            cond.encode_fulfillment(MIXED_MODE).unwrap(),
            "a242a03ea003800102a232a005a003800101a129a527802067a2c7c70601df5bb07d508d82e366c5c956ca646e311ab0e6b10fa24dbdf29e8103020000af038001f4a100".from_hex::<Vec<u8>>().unwrap()
        );
        assert_eq!(
            cond.encode_condition(),
            "a22c80208e78bd3a708ff57b1934777a89831633fd3fd8537b1521d4de75fbb91196beee8103120c008203000401".from_hex::<Vec<u8>>().unwrap()
        );
    }

    #[test]
    fn test_encode_complex_non_mixed_mode_secp256k1hash_ffil() {
        let pk = "035d3b0f2e98cf0fba19f80880ec7c08d770c6cf04aa5639bc57130d5ac54874db".from_hex::<Vec<u8>>().unwrap();
        let cond = Threshold {
            threshold: 1,
            subconditions: vec![
                Secp256k1Hash {
                    pubkey_hash: Some("6579c3bd574da22803234e12ddcec405e2b99092".from_hex::<Vec<u8>>().unwrap()),
                    pubkey: Some(PublicKey::parse_slice(&pk, None).unwrap()),
                    signature: Some(Signature::parse_standard_slice(&"f28d8faa163cea845b333e4f78f404e401d9ade79de458e2a78c3a3dd46944656595d5e7cf7da1b89667b44ecfcb923bf54b8462d94f2ab3b99d16a81bf81257".from_hex::<Vec<u8>>().unwrap()).unwrap())
                }
            ]
        };

        assert_eq!(
            cond.encode_fulfillment(0).unwrap(),
            "a26ba067a6658021035d3b0f2e98cf0fba19f80880ec7c08d770c6cf04aa5639bc57130d5ac54874db8140f28d8faa163cea845b333e4f78f404e401d9ade79de458e2a78c3a3dd46944656595d5e7cf7da1b89667b44ecfcb923bf54b8462d94f2ab3b99d16a81bf81257a100".from_hex::<Vec<u8>>().unwrap()
        );
        assert_eq!(
            cond.encode_condition(),
            "a22b8020e579ea97742cd8106dc84089ba816ac8fb37cebb67024d6a1610cdb271b3911f810302040082020102".from_hex::<Vec<u8>>().unwrap()
        );
    }

    #[test]
    // test threshold 1of2 with secp256k1hash anon 20b fingeprint padded
    fn test_encode_complex_non_mixed_mode_preimage_ffil() {
        let cond = Threshold {
            threshold: 3,
            subconditions: vec![
                Preimage { preimage: base64::decode("Ag").unwrap() },
                Threshold {
                    threshold: 1,
                    subconditions: vec![
                        Preimage { preimage: base64::decode("AQ").unwrap() },
                        Anon {
                            fingerprint: base64::decode("ZXnDvVdNoigDI04S3c7EBeK5kJIAAAAAAAAAAAAAAAA").unwrap(),
                            cost: 131072,
                            cond_type: Secp256k1HashType,
                            subtypes: HashSet::new()
                        }
                    ]
                },
                Eval { code: vec![0xf4] }
            ]
        };

        assert_eq!(
            cond.encode_fulfillment(0).unwrap(),
            "a236a032a003800102a226a005a003800101a11da61b80146579c3bd574da22803234e12ddcec405e2b990928103020000af038001f4a100".from_hex::<Vec<u8>>().unwrap()
            );
        //let asn = cond.encode_condition();
        //info!("encode_condition={:?}", hex::encode(&asn));
        assert_eq!(
            cond.encode_condition(),
            "a22c802071281bcd950d6dd754b72b17b35ad6ac73a477b8dce5ff5ee0081dd7e7f0a3b881031214018203008201".from_hex::<Vec<u8>>().unwrap()
        );
        
    }


}
