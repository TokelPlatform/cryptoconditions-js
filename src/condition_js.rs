use std::convert::TryInto;

//use num_bigint::{BigInt, BigUint};
use libsecp256k1::{PublicKey, Signature, SecretKey, Message};


/*use num_traits::cast::FromPrimitive;
use simple_asn1::{to_der, ASN1Block, ASN1Class};
use std::collections::HashSet;*/

//use rusthex::ToHex;
//use base64::*;
//extern crate hex;
//use hex::*;
use num_traits::ToPrimitive;

//use base64::Base64Mode;
//mod jscc {

//use crate::Condition::*; 
use crate::*; 

use log::Level;
use log::info;

//use js_sys::Reflect::*;
use js_sys::Uint8ClampedArray;
//use js_sys::Uint8Array;
use wasm_bindgen::JsValue;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;
//use js_sys::Error;

//use wasm_bindgen::Clamped;

//use wasm_bindgen::prelude::*;

//#[wasm_bindgen]
//extern {
//    pub fn JsCConditionBinary(jscond: &JsValue) -> Result<JsValue, JsValue>;
//}

/*fn cast_js_value_to_u16(js_val: &JsValue) -> u16
{
    if js_val.is_string()   {
        let r: u16 = js_val.as_string().unwrap().parse().unwrap();
        r   
    }
    else {
        let r: f64 = js_val.as_f64().unwrap();
        r as u16
    }
}

fn cast_u16_to_js_value(val: &u16) -> JsValue
{
    let js_val = JsValue::from(val.to_f64());
    js_val
    /*if js_val.is_string()   {
        let r: u16 = js_val.as_string().unwrap().parse().unwrap();
        r   
    }
    else {
        let r: f64 = js_val.as_f64().unwrap();
        r as u16
    }*/
}*/


// decode js string from hex and return decode errors
fn decode_hex_js_string(js_value: &JsValue) -> Result<Vec<u8>, JsValue>
{
    if !js_value.is_string() { return Err("hex not a string value".into()); }
    match hex::decode( js_value.as_string().unwrap() ) {
        Ok(decoded) => { Ok(decoded) },
        Err(e) => { return Err(e.to_string().into()); }
    }
}

fn decode_base64_js_string(js_value: &JsValue) -> Result<Vec<u8>, JsValue>
{
    //info!("decode_base64_js_string enterred ref jsvalue {:?}", &js_value);
    //info!("decode_base64_js_string enterred ptr jsvalue {:?}", *js_value);
    if !js_value.is_string() {  return Err("base64 not a string value".into()); }
    match base64::decode( js_value.as_string().unwrap() ) {
        Ok(decoded) => { Ok(decoded) },
        Err(e) => { return Err(e.to_string().into()); }
    }
}

/* fn decode_fingerprint_js_string(js_value: &JsValue, cond_type: &ConditionType) -> Result<Vec<u8>, JsValue>
{
    if !js_value.is_string() {  return Err("fingerprint not a string value".into()); }
    let fingerprint_as_vec =  match base64::decode( js_value.as_string().unwrap() ) {
        Ok(decoded) => { decoded },
        Err(e) => { return Err(e.to_string().into()); }
    };
    let fingerprint_truncated = match cond_type {
        Secp256k1HashType => fingerprint_as_vec[0..20].to_vec(),  // secp256k1hash is 20 bytes
        _ => fingerprint_as_vec[0..32].to_vec()
    };
    Ok(fingerprint_truncated)
} */

// parse js_cond object and make Condition 
fn parse_js_cond(js_cond: &JsValue) -> Result<Condition, JsValue> 
{
    let js_type = js_sys::Reflect::get(&js_cond, &JsValue::from_str("type"))?;
    if !js_type.is_string() {
        return Err("no \'type\" property".into());
    }
    match js_type.as_string().unwrap().as_ref() {
        "threshold-sha-256" => {
            let js_threshold = js_sys::Reflect::get(&js_cond, &JsValue::from_str("threshold"))?;
            if js_threshold.is_null()  {
                return Err("no \'threshold\" property".into());
            }

            //let t = js_threshold.as_f64().unwrap();
            //info!("threshold step 0.1 value {}", t);

            let js_subfulfillments = js_sys::Reflect::get(&js_cond, &JsValue::from_str("subfulfillments"))?;
            if !js_sys::Array::is_array(&js_subfulfillments) {
                return Err("no \'subfulfillments\" array".into());
            }
            
            let array = js_sys::Array::from(&js_subfulfillments);

            let mut subconds = vec![];
            /*array.for_each(&mut |elem, _, _| {
                //if let Condition::Threshold{threshold: _, subconditions } = &mut cond {
                //    subconditions.push(parse_js_cond(&elem).unwrap());
                //}
                //info!("threshold step 2.1");

                let subcond = parse_js_cond(&elem)?;
                //info!("threshold step 2.2");

                subconds.push(subcond);
            });*/

            for elem in array.iter() {

                let subcond = parse_js_cond(&elem)?; // propagate Err up

                subconds.push(subcond);
            }

            //info!("threshold step 3 js_threshold is str={} obj={} null={} function={} falsy={} symbol={}", js_threshold.is_string(), js_threshold.is_object(), js_threshold.is_null(), js_threshold.is_function(), js_threshold.is_falsy(), js_threshold.is_symbol());
            //info!("threshold step 3 str={}", js_threshold.as_string().unwrap());

            /*let threshold_val = match js_threshold.dyn_into::<bool>() {
                Ok(val) => val,
                Err(e) => return Err(JsValue::from_str("could no parse threshold")), 
            };*/
            //let threshold_val = cast_js_value_to_u16(&js_threshold);
            let threshold_val = js_threshold.as_f64();

            let cond = Threshold {
                threshold: threshold_val.unwrap() as u16,
                subconditions: subconds
            };
            //info!("threshold step 4 threshold_val={}", threshold_val);

            Ok(cond)
        },
        "eval-sha-256" => {
            let js_code_b64 = js_sys::Reflect::get(&js_cond, &JsValue::from_str("code"))?;
            let js_code_hex = js_sys::Reflect::get(&js_cond, &JsValue::from_str("codehex"))?;
            if !js_code_b64.is_string() && !js_code_hex.is_string()  {
                return Err("no 'code' eval property".into());
            }
            if js_code_b64.is_string() && js_code_hex.is_string()  {
                return Err("both 'code' and 'codehex' present".into());
            }

            //info!("eval step 0, code={}", js_code.as_string().unwrap());
            let code_decoded = match js_code_b64.is_string() { 
                true =>  decode_base64_js_string( &js_code_b64 )?,
                false => decode_hex_js_string( &js_code_hex )?
            };

            //info!("eval step 1, code={}", hex::encode( &code_decoded ));
            //info!("eval step 1, code={}", js_code.as_string().unwrap().parse::<u32>().unwrap());
            
            let cond = Eval {
                //code: js_code.as_string().unwrap().parse::<u32>().unwrap().to_le_bytes().iter().cloned().collect()
                code: code_decoded
            };
            Ok(cond)
        },
        "secp256k1-sha-256" => {
            let js_public_key = js_sys::Reflect::get(&js_cond, &JsValue::from_str("publicKey"))?;
            if js_public_key.is_null()  {
                return Err("no \'publicKey\' property".into());
            }
            let pubkey_value = match js_public_key.is_string() {
                true => {
                    let decoded = decode_hex_js_string(&js_public_key)?;
                    match PublicKey::parse_slice(&decoded, None) {
                        Ok(pk) => { pk },
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref()))}
                    }
                },
                false => { return Err("not a string \'publicKey\' property".into()); }
            };

            //let pk = hex::decode( js_public_key.as_string().unwrap() ).unwrap();
                        
            let js_signature = js_sys::Reflect::get(&js_cond, &JsValue::from_str("signature"))?;
            /*let sig_value = match js_signature.is_string() {
                true => Some(Signature::parse_standard_slice(&hex::decode( js_signature.as_string().unwrap() ).unwrap()).unwrap()),
                false => None,
            };*/
            let sig_value = match js_signature.is_string() {
                true => {
                    let decoded = decode_hex_js_string(&js_signature)?;
                    Some(match Signature::parse_standard_slice(&decoded) {
                        Ok(sig) => { sig },
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref()))}
                    })
                },
                false => None,
            };

            let cond = Secp256k1 {
                pubkey: pubkey_value, // PublicKey::parse_slice(&pk, None).unwrap(),
                signature: sig_value
            };

            Ok(cond)
        },

        "secp256k1hash-sha-256" => {
            //info!("secp256k1hash step 0");
            let js_public_key_hash = js_sys::Reflect::get(&js_cond, &JsValue::from_str("publicKeyHash"))?;

            //let vv = hex::decode( "y03C27DB737B92826D37FB43F3FDA3D1B1D258CD28B68FE4BE605457BF9DD9E0218" );
            //info!("secp256k1hash step 0.1 vv={:?}", vv);

            //info!("secp256k1hash step 0.1 js_public_key_hash.is_string()={} js_public_key_hash={:?}", js_public_key_hash.is_string(), js_public_key_hash);
            // strange but for empty "publicKeyHash" js_public_key_hash.is_null() == false but js_public_key_hash is 'undefined'. 
            // Maybe a wasm compiler error. So we use is_string() to determine if this is a non empty string value
            let pubkey_hash_value = match js_public_key_hash.is_string() {
                true => {
                    Some(match hex::decode( js_public_key_hash.as_string().unwrap() ) {
                        Ok(decoded) => { decoded },
                        // let pk_hash_bin = hex::decode( js_public_key_hash.as_string().unwrap() );
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref())); }
                    })
                },
                false => { return Err("no \'publicKeyHash\' property".into()); }
            };
            //info!("secp256k1hash step 1, js_public_key_hash={:?}", js_public_key_hash);

            let js_public_key = js_sys::Reflect::get(&js_cond, &JsValue::from_str("publicKey"))?;
            // strangely for empty "publicKey" js_public_key.is_null() == false but js_public_key is 'undefined'. 
            // Maybe a wasm compiler error. So we use is_string() to determine if this is a non empty value
            // info!("secp256k1hash step 0.1, js_public_key_hash.is_null() {} js_public_key_hash {:?}", js_public_key_hash.is_null(), js_public_key_hash);
            let pubkey_value = match js_public_key.is_string() {
                true => {
                    let decoded = decode_hex_js_string(&js_public_key)?;
                    Some(match PublicKey::parse_slice(&decoded, None) {
                        Ok(pk) => { pk },
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref()))}
                    })
                    /*Some( match hex::decode( js_public_key.as_string().unwrap() ) {
                        Ok(decoded) => { PublicKey::parse_slice(&decoded, None).unwrap() },
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref())); }
                    })*/
                },
                false => None,
            }; 
            //info!("secp256k1hash step 2, js_public_key={:?}", js_public_key);
            //if pubkey_hash_value == None && pubkey_value == None {
            //    return Err("no \'publicKey\' or \'publicKeyHash\' property".into());
            //}

            let js_signature = js_sys::Reflect::get(&js_cond, &JsValue::from_str("signature"))?;
            let sig_value = match js_signature.is_string() {
                true => {
                    let decoded = decode_hex_js_string(&js_signature)?;
                    Some(match Signature::parse_standard_slice(&decoded) {
                        Ok(sig) => { sig },
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref()))}
                    })
                },
                false => None,
            };
            //info!("secp256k1hash step 2.1, pubkey_hash_value={:?}  pubkey_value={:?}", pubkey_hash_value, pubkey_value);

            let cond = Secp256k1Hash {
                pubkey_hash: pubkey_hash_value,
                pubkey: pubkey_value,
                signature: sig_value
            };
            //info!("secp256k1hash step 3, cond={:?}", cond);

            Ok(cond)
        },

        "preimage-sha-256" => {
            let js_preimage = js_sys::Reflect::get(&js_cond, &JsValue::from_str("preimage"))?;
            //info!("js_preimage {:?}", &js_preimage);
            let preimage_decoded = decode_base64_js_string(&js_preimage)?;
            let cond = Preimage {
                preimage:  preimage_decoded,
            };
            Ok(cond)
        },
        "prefix-sha-256" => {
            let js_prefix = js_sys::Reflect::get(&js_cond, &JsValue::from_str("prefix"))?;
            let js_max_message_length = js_sys::Reflect::get(&js_cond, &JsValue::from_str("maxMessageLength"))?;
            let js_subfulfillment = js_sys::Reflect::get(&js_cond, &JsValue::from_str("subfulfillment"))?;

            let max_message_length_decoded = js_max_message_length.as_f64().unwrap() as u64;
            let prefix_decoded = decode_base64_js_string(&js_prefix)?;
            let subfulfillment_decoded = parse_js_cond(&js_subfulfillment);
            let cond = Prefix {
                prefix:  prefix_decoded,
                max_message_len: max_message_length_decoded,
                subcondition: Box::new(subfulfillment_decoded.unwrap()),
            };
            Ok(cond)
        },
        "(anon)" => {
            info!("start decode js anon");
            let js_cond_type = js_sys::Reflect::get(&js_cond, &JsValue::from_str("cond_type"))?;
            if js_cond_type.is_null()  {
                return Err("no \'cond_type\' property".into());
            }
            //let cond_type_decoded = js_cond_type.as_string().unwrap().parse::<u8>().unwrap();
            let cond_type_as_u8 = js_cond_type.as_f64().unwrap() as u8;
            info!("cond_type_as_u8={}", cond_type_as_u8);
            let cond_type_as_type = match condition_type_from_id(cond_type_as_u8) {
                Ok(t) => t,
                Err(_e) => return Err(JsValue::from_str("unknown cond_type")), 
            };

            let js_fingerprint = js_sys::Reflect::get(&js_cond, &JsValue::from_str("fingerprint"))?;
            //let fingerprint_decoded = decode_fingerprint_js_string(&js_fingerprint, &cond_type_as_type)?;
            if !js_fingerprint.is_string() {  return Err("fingerprint not a string value".into()); }
            let fingerprint_decoded =  match base64::decode( js_fingerprint.as_string().unwrap() ) {
                Ok(decoded) => { decoded },
                Err(e) => { return Err(e.to_string().into()); }
            };
            info!("fingerprint_decoded={}", hex::encode(&fingerprint_decoded));

            let js_cost = js_sys::Reflect::get(&js_cond, &JsValue::from_str("cost"))?;
            if js_cost.is_null()  {
                return Err("no \'cost\' property".into());
            }
            let cost_decoded = js_cost.as_f64().unwrap() as u64;
            info!("cost_decoded={}", cost_decoded);

            let mut subtypes_decoded = vec![0,0,0,0];
            let js_subtypes = js_sys::Reflect::get(&js_cond, &JsValue::from_str("subtypes"))?;
            if js_subtypes.is_string()  {
                let subtypes_bytes = js_subtypes.as_string().unwrap().parse::<u32>().unwrap().to_le_bytes();
                /*let mut i = 0;
                while i < subtypes_bytes.len() && i < subtypes_decoded.len() {
                    subtypes_decoded[i] = subtypes_bytes[i]; 
                    info!("subtypes_bytes[i]={}", subtypes_bytes[i]);
                    i += 1;
                }*/

                subtypes_decoded = subtypes_bytes.to_vec();
                //let vsubtypes = internal::pack_set(subtypes.clone());
                // convert vec[4] to u32
                //if vsubtypes.len() > 4 {
                //    return Err(JsValue::from("Internal error: expected subtypes as Vec of 4"));
                //}
                /*let mut asubtypes: [u8; 4] = [0,0,0,0];
                let mut i = 0;
                for i in 0..3   {
                    asubtypes[i] = vsubtypes[i]; 
                }*/
                //let asubtypes: [u8; 4] = vsubtypes.as_slice().try_into().expect("invalid subtypes size");
            }

            
            let cond = Anon {
                cond_type:  cond_type_as_type,
                fingerprint: fingerprint_decoded,
                cost: cost_decoded,
                subtypes: internal::unpack_set(subtypes_decoded),
            };

            Ok(cond)
        },
        _ => {
            return Err("unknown".into());
        }
    }

    //Ok(JsValue::from("hello"))
}

/// make js_cond from Condition
fn make_js_cond(cond: Condition) -> Result<JsValue, JsValue> 
{
    let js_cond = js_sys::Object::new();

    match cond {
        Secp256k1 { pubkey, signature } => {
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("secp256k1-sha-256"))?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("publicKey"), &JsValue::from_str(&hex::encode( &pubkey.serialize_compressed() )))?;
            //info!("searching for signature...");
            if signature != None {
                //info!("found signature!");
                js_sys::Reflect::set(&js_cond, &JsValue::from_str("signature"), &JsValue::from_str(&hex::encode( &signature.unwrap().serialize() )))?;
            }
        }
        Secp256k1Hash { pubkey_hash, pubkey, signature } => {
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("secp256k1hash-sha-256"))?;

            if pubkey_hash != None {
                js_sys::Reflect::set(&js_cond, &JsValue::from_str("publicKeyHash"), &JsValue::from_str(&hex::encode( &pubkey_hash.unwrap() )))?;
            }

            if pubkey != None {
                js_sys::Reflect::set(&js_cond, &JsValue::from_str("publicKey"), &JsValue::from_str(&hex::encode( &pubkey.unwrap().serialize_compressed() )))?;
            }
            //info!("searching for signature...");
            if signature != None {
                //info!("found signature!");
                js_sys::Reflect::set(&js_cond, &JsValue::from_str("signature"), &JsValue::from_str(&hex::encode( &signature.unwrap().serialize() )))?;
            }
        }
        Eval { code } => {
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("eval-sha-256"))?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("codehex"), &JsValue::from_str(&hex::encode( code )))?;
        }
        Preimage { preimage } => {
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("preimage-sha-256"))?;  
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("preimage"), &JsValue::from_str(&base64::encode(&preimage)))?; 
        }
        Prefix { prefix, max_message_len, subcondition } => {
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("prefix-sha-256"))?;  
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("maxMessageLength"), &JsValue::from_str(&base64::encode(&prefix)))?; 
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("prefix"), &JsValue::from_f64(max_message_len.to_f64().unwrap()))?; 
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("subfilfillment"), &make_js_cond(*subcondition).unwrap())?; 
        }
        Threshold {
            threshold,
            subconditions,
        } => {
            let js_subconds = js_sys::Array::new();
            for subcond in subconditions    { 
                let js_subcond = make_js_cond(subcond)?;
                js_subconds.push(&js_subcond);
            }
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("threshold-sha-256"))?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("threshold"), &JsValue::from(threshold.to_f64()) )?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("subfulfillments"), &js_subconds.as_ref())?;

        }
        Anon { ref fingerprint, ref cost, ref subtypes, .. } => {
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("cond_type"), &JsValue::from_f64( cond.get_type().id().to_f64().unwrap() ))?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("(anon)"))?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("fingerprint"), &JsValue::from_str(&base64::encode( fingerprint )))?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("cost"), &JsValue::from_f64( cost.to_f64().unwrap() ))?;
            if  cond.get_type().has_subtypes()   {
                let vsubtypes = internal::pack_set(subtypes.clone());
                // convert vec[4] to u32
                //if vsubtypes.len() > 4 {
                //    return Err(JsValue::from("Internal error: expected subtypes as Vec of 4"));
                //}
                /*let mut asubtypes: [u8; 4] = [0,0,0,0];
                let mut i = 0;
                for i in 0..3   {
                    asubtypes[i] = vsubtypes[i]; 
                }*/
                let asubtypes: [u8; 4] = vsubtypes.as_slice().try_into().expect("invalid subtypes size");
                js_sys::Reflect::set(&js_cond, &JsValue::from_str("subtypes"), &JsValue::from_str(  &u32::from_le_bytes(asubtypes).to_string()  ))?;
            }
            //js_sys::Reflect::set(&js_cond, &JsValue::from_str("subtypes"), &JsValue::from_str(  "32"  ))?;
        }
    }
    Ok(JsValue::from(js_cond))
}

/// serialise condition into asn.1 
#[wasm_bindgen]
pub fn js_cc_condition_binary(js_cond: &JsValue) -> Result<Uint8ClampedArray, JsError> 
{
    console_log::init_with_level(Level::Debug);
    
    info!("enterring parse_js_cond");
    //let cond = parse_js_cond(js_cond)?;
    // parse and convert JsValue error to JsError
    let cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))); },
    }; 

    info!("enterring cond.encode_condition");
    let encoded_cond = cond.encode_condition(); // no error returned

    //Ok(JsValue::from_str(&String::from_utf8_lossy(&encoded_cond)))
    //Ok(JsValue::from_str(&hex::encode(&encoded_cond)))
    //Ok(JsValue::from_str(&hex::encode(&encoded_cond)))
    Ok(Uint8ClampedArray::from(encoded_cond.as_slice()))
    //let jsthreshold = js_sys::Reflect::get(&target, "Threshold")?;
}

/// serialise fulfillment into asn1 
#[wasm_bindgen]
pub fn js_cc_fulfillment_binary(js_cond: &JsValue) -> Result<Uint8ClampedArray, JsError> 
{
    // console_log::init_with_level(Level::Debug);
    
    let cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))); },
    }; 
    //let encoded_ffil = cond.encode_fulfillment(0)?;
    // convert JsValue error to new JsError
    let encoded_ffil = match cond.encode_fulfillment(0) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not encode fulfillment: {}", &e.to_string())))),
    };
    Ok(Uint8ClampedArray::from(encoded_ffil.as_slice()))
}

/// serialise fulfillment into asn1 with adding special preimage cond containing the threshold value
#[wasm_bindgen]
pub fn js_cc_fulfillment_binary_mixed(js_cond: &JsValue) -> Result<Uint8ClampedArray, JsError> 
{
    //console_log::init_with_level(Level::Debug);
    
    let cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))); },
    };
    //let encoded_ffil = cond.encode_fulfillment(MIXED_MODE)?;

    // convert JsValue error to new JsError
    let encoded_ffil = match cond.encode_fulfillment(MIXED_MODE) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not encode fulfillment: {}", &e.to_string())))),
    };

    Ok(Uint8ClampedArray::from(encoded_ffil.as_slice()))
}

/// sign secp256k1 condition
#[wasm_bindgen]
pub fn js_cc_sign_secp256k1(js_cond: &JsValue, uca_secret_key: &Uint8ClampedArray, uca_msg: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    //console_log::init_with_level(Level::Debug);
    
    //let mut cond = parse_js_cond(js_cond)?;
    let mut cond = match parse_js_cond(js_cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))),
    };

    let secret_key = match SecretKey::parse_slice(&uca_secret_key.to_vec()) {
        Ok(key) => key,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not parse secret key: {}", &e.to_string())))),
    };
    let msg = match Message::parse_slice(&uca_msg.to_vec()) {
        Ok(msg) => msg,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could parse message: {}", &e.to_string())))),
    };
    //let encoded_cond = cond.encode_condition();

    if let Err(e) = cond.sign_secp256k1(&secret_key, &msg) {
        //Ok(()) => (),
        //Err(_e) => return Err(JsValue::from_str("rustlibcc: could sign cc")),
        return Err(JsError::new(&(format!("rustlibcc: could not sign cond: {}", &e.to_string()))));
    }

    //let js_signed_cond = make_js_cond(cond)?;
    let js_signed_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };
    
    Ok(js_signed_cond)
}

/// old name call
#[wasm_bindgen]
pub fn js_sign_secp256k1(js_cond: &JsValue, uca_secret_key: &Uint8ClampedArray, uca_msg: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    js_cc_sign_secp256k1(js_cond, uca_secret_key, uca_msg)
}

/// sign secp256k1hash conditions
#[wasm_bindgen]
pub fn js_cc_sign_secp256k1hash(js_cond: &JsValue, uca_secret_key: &Uint8ClampedArray, uca_msg: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    //console_log::init_with_level(Level::Debug);
    
    //let mut cond = parse_js_cond(js_cond)?;
    // parse and convert JsValue error to JsError
    let mut cond = match parse_js_cond(js_cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))),
    };

    //let secret_key = SecretKey::parse_slice(&uca_secret_key.to_vec()).unwrap();
    //let msg = Message::parse_slice(&uca_msg.to_vec()).unwrap();
    let secret_key = match SecretKey::parse_slice(&uca_secret_key.to_vec()) {
        Ok(key) => key,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not parse secret key: {}", &e.to_string())))),
    };
    let msg = match Message::parse_slice(&uca_msg.to_vec()) {
        Ok(msg) => msg,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could parse message: {}", &e.to_string())))),
    };
    //let encoded_cond = cond.encode_condition();

    if let Err(e) = cond.sign_secp256k1hash(&secret_key, &msg) {
        //Ok(()) => (),
        //Err(_e) => return Err(JsValue::from_str("rustlibcc: could sign cc")),
        return Err(JsError::new(&(format!("rustlibcc: could not sign cond: {}", &e.to_string()))));
    }

    //let js_signed_cond = make_js_cond(cond)?;
    let js_signed_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };

    Ok(js_signed_cond)
}


#[wasm_bindgen]
pub fn js_cc_read_condition_binary(js_bin: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    //console_log::init_with_level(Level::Debug);
    
    //let cond = decode_condition(&js_bin.to_vec()).unwrap();
    let cond: Condition = match decode_condition(&js_bin.to_vec()) {
            Ok(c) => c,
            Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not decode condition: {}", &e.0)))),
        };
    //let js_cond = make_js_cond(cond)?;
    let js_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };
    Ok(js_cond)
}

/// old name call forward
#[wasm_bindgen]
pub fn js_read_ccondition_binary(js_bin: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    js_cc_read_condition_binary(js_bin)
}

/// read mixed mode fulfilment (with special preimage conds containing threshold value)
#[wasm_bindgen]
pub fn js_cc_read_fulfillment_binary_mixed(js_bin: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    //console_log::init_with_level(Level::Debug);
    
    //let cond = decode_condition(&js_bin.to_vec()).unwrap();
    let cond: Condition = match decode_fulfillment(&js_bin.to_vec(), MIXED_MODE) {
            Ok(c) => c,
            Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not decode fulfillment mixed mode: {}", &e.0)))),
        };
    let js_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };

    Ok(js_cond)
}

/// old name call forward
#[wasm_bindgen]
pub fn js_read_fulfillment_binary_mixed(js_bin: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    js_cc_read_fulfillment_binary_mixed(js_bin)
}

#[wasm_bindgen]
pub fn js_cc_read_fulfillment_binary(js_bin: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    //console_log::init_with_level(Level::Debug);
    
    //let cond = decode_condition(&js_bin.to_vec()).unwrap();
    let cond: Condition = match decode_fulfillment(&js_bin.to_vec(), 0) {
            Ok(c) => c,
            Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not decode fulfillment: {}", &e.0)))),
        };
    //let js_cond = make_js_cond(cond)?;
    let js_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };
    Ok(js_cond)
}

/// old name call forward
#[wasm_bindgen]
pub fn js_read_fulfillment_binary(js_bin: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    js_cc_read_fulfillment_binary(js_bin)
}

/// convert first level threshold to anon (for cc spk mixed mode)
#[wasm_bindgen]
pub fn js_cc_threshold_to_anon(js_cond: &JsValue) -> Result<JsValue, JsError> 
{
    //console_log::init_with_level(Level::Debug);
    //info!("js_cc_threshold_to_anon enterred");
    
    let mut cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { /*info!("could not parse cond");*/ return Err(JsError::new(&(format!("rustlibcc: could parse cc: {}", &e.as_string().unwrap())))) },
    };
    // info!("calling threshold_to_anon:");
    threshold_to_anon(&mut cond);

    //let js_cond = make_js_cond(cond)?;
    let js_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };
    Ok(js_cond)
}
