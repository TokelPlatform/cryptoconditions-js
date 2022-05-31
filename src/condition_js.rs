use std::convert::TryInto;
use libsecp256k1::{PublicKey, Signature, SecretKey, Message};
use num_traits::ToPrimitive;
use wasm_bindgen::UnwrapThrowExt;
use crate::*; 
use log::info;
use log::Level;
use std::collections::HashSet;

use js_sys::Uint8ClampedArray;
use wasm_bindgen::JsValue;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;



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
    if !js_value.is_string() {  return Err("base64 not a string value".into()); }
    match base64::decode( js_value.as_string().unwrap() ) {
        Ok(decoded) => { Ok(decoded) },
        Err(e) => { return Err(e.to_string().into()); }
    }
}

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
            if js_threshold.is_undefined()  {
                return Err("no \'threshold\" property".into());
            }

            let js_subfulfillments = js_sys::Reflect::get(&js_cond, &JsValue::from_str("subfulfillments"))?;
            if !js_sys::Array::is_array(&js_subfulfillments) {
                return Err("no \'subfulfillments\" array".into());
            }
            
            let array = js_sys::Array::from(&js_subfulfillments);

            let mut subconds = vec![];

            for elem in array.iter() {

                let subcond = parse_js_cond(&elem)?; // propagate Err up

                subconds.push(subcond);
            }

            let threshold_val = js_threshold.as_f64();

            let cond = Threshold {
                threshold: threshold_val.unwrap() as u16,
                subconditions: subconds
            };

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

            let code_decoded = match js_code_b64.is_string() { 
                true =>  decode_base64_js_string( &js_code_b64 )?,
                false => decode_hex_js_string( &js_code_hex )?
            };
            
            let cond = Eval {
                code: code_decoded
            };
            Ok(cond)
        },
        "secp256k1-sha-256" => {
            let js_public_key = js_sys::Reflect::get(&js_cond, &JsValue::from_str("publicKey"))?;
            if js_public_key.is_undefined()  {
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

            let cond = Secp256k1 {
                pubkey: pubkey_value, // PublicKey::parse_slice(&pk, None).unwrap(),
                signature: sig_value
            };

            Ok(cond)
        },

        "secp256k1hash-sha-256" => {
            let js_public_key_hash = js_sys::Reflect::get(&js_cond, &JsValue::from_str("publicKeyHash"))?;

            // strange but for empty "publicKeyHash" js_public_key_hash.is_undefined() == false but js_public_key_hash is 'undefined'. 
            // Maybe a wasm compiler error. So we use is_string() to determine if this is a non empty string value
            let pubkey_hash_value = match js_public_key_hash.is_string() {
                true => {
                    Some(match hex::decode( js_public_key_hash.as_string().unwrap() ) {
                        Ok(decoded) => { decoded },
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref())); }
                    })
                },
                false => { return Err("no \'publicKeyHash\' property".into()); }
            };

            let js_public_key = js_sys::Reflect::get(&js_cond, &JsValue::from_str("publicKey"))?;
            // strangely for empty "publicKey" js_public_key.is_undefined() == false but js_public_key is 'undefined'. 
            // Maybe a wasm compiler error. So we use is_string() to determine if this is a non empty value
            let pubkey_value = match js_public_key.is_string() {
                true => {
                    let decoded = decode_hex_js_string(&js_public_key)?;
                    Some(match PublicKey::parse_slice(&decoded, None) {
                        Ok(pk) => { pk },
                        Err(e) => { return Err(JsValue::from_str(e.to_string().as_ref()))}
                    })
                },
                false => None,
            }; 

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
            let cond = Secp256k1Hash {
                pubkey_hash: pubkey_hash_value,
                pubkey: pubkey_value,
                signature: sig_value
            };
            Ok(cond)
        },

        "preimage-sha-256" => {
            let js_preimage = js_sys::Reflect::get(&js_cond, &JsValue::from_str("preimage"))?;
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
            let js_cond_type = js_sys::Reflect::get(&js_cond, &JsValue::from_str("cond_type"))?;
            if js_cond_type.is_undefined()  {
                return Err("no \'cond_type\' property".into());
            }
            let cond_type_as_u8 = js_cond_type.as_f64().unwrap() as u8;
            let cond_type_as_type = match condition_type_from_id(cond_type_as_u8) {
                Ok(t) => t,
                Err(_e) => return Err(JsValue::from_str("unknown cond_type")), 
            };

            let js_fingerprint = js_sys::Reflect::get(&js_cond, &JsValue::from_str("fingerprint"))?;
            if !js_fingerprint.is_string() {  return Err("fingerprint not a string value".into()); }
            let fingerprint_decoded =  match base64::decode( js_fingerprint.as_string().unwrap() ) {
                Ok(decoded) => { decoded },
                Err(e) => { return Err(e.to_string().into()); }
            };

            let js_cost = js_sys::Reflect::get(&js_cond, &JsValue::from_str("cost"))?;
            if js_cost.is_undefined()  {
                return Err("no \'cost\' property".into());
            }
            let cost_decoded = js_cost.as_f64().unwrap() as u64;

            let mut subtypes_hashset = HashSet::<u8>::new();
            let js_subtypes = js_sys::Reflect::get(&js_cond, &JsValue::from_str("subtypes"))?;
            if !js_subtypes.is_undefined()  {

                let mut mask = js_subtypes.as_f64().unwrap() as u32;
                let mut bit = 0; 
                while mask > 0  {
                    if (mask & 0x01) != 0 {
                        subtypes_hashset.insert(bit);
                    }
                    mask = mask >> 1;
                    bit += 1;
                    if bit > 24 { return Err("too big type value in subtypes".into()); }
                }
            }

            let cond = Anon {
                cond_type:  cond_type_as_type,
                fingerprint: fingerprint_decoded,
                cost: cost_decoded,
                //subtypes: internal::unpack_set(subtypes_decoded),
                subtypes: subtypes_hashset,
            };

            Ok(cond)
        },
        _ => {
            return Err("unknown".into());
        }
    }
}

/// make js_cond from Condition
fn make_js_cond(cond: Condition) -> Result<JsValue, JsValue> 
{
    let js_cond = js_sys::Object::new();

    match cond {
        Secp256k1 { pubkey, signature } => {
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("type"), &JsValue::from_str("secp256k1-sha-256"))?;
            js_sys::Reflect::set(&js_cond, &JsValue::from_str("publicKey"), &JsValue::from_str(&hex::encode( &pubkey.serialize_compressed() )))?;
            if signature != None {
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
            if signature != None {
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
            if  cond.get_type().has_subtypes()   
            {
                // convert subtypes as HashSet with bits to u32 mask
                let mut mask = 0;
                for bit in subtypes.to_owned().into_iter() {
                    mask |= 1 << bit;
                }
                js_sys::Reflect::set(&js_cond, &JsValue::from_str("subtypes"), &JsValue::from_f64(  mask.to_f64().unwrap()  ))?;
            }
        }
    }
    Ok(JsValue::from(js_cond))
}

/// serialise condition into asn.1 
#[wasm_bindgen]
pub fn js_cc_condition_binary(js_cond: &JsValue) -> Result<Uint8ClampedArray, JsError> 
{    
    if !js_cond.is_object() { return Err(JsError::new("not an object")); }
    // parse and convert JsValue error to JsError
    let cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))); },
    }; 
    let encoded_cond = cond.encode_condition(); // no error returned

    Ok(Uint8ClampedArray::from(encoded_cond.as_slice()))
}

/// serialise fulfillment into asn1 
#[wasm_bindgen]
pub fn js_cc_fulfillment_binary(js_cond: &JsValue) -> Result<Uint8ClampedArray, JsError> 
{
    if !js_cond.is_object() { return Err(JsError::new("not an object")); }
    let cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))); },
    }; 
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
    if !js_cond.is_object() { return Err(JsError::new("not an object")); }
    let cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could not parse js cond: {}", &e.as_string().unwrap())))); },
    };
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
    if !js_cond.is_object() { return Err(JsError::new("not an object")); }
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

    if let Err(e) = cond.sign_secp256k1(&secret_key, &msg) {
        return Err(JsError::new(&(format!("rustlibcc: could not sign cond: {}", &e.to_string()))));
    }
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
    if !js_cond.is_object() { return Err(JsError::new("not an object")); }

    // parse and convert JsValue error to JsError
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

    if let Err(e) = cond.sign_secp256k1hash(&secret_key, &msg) {
        return Err(JsError::new(&(format!("rustlibcc: could not sign cond: {}", &e.to_string()))));
    }

    let js_signed_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };

    Ok(js_signed_cond)
}


#[wasm_bindgen]
pub fn js_cc_read_condition_binary(js_bin: &Uint8ClampedArray) -> Result<JsValue, JsError> 
{
    let cond: Condition = match decode_condition(&js_bin.to_vec()) {
            Ok(c) => c,
            Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not decode condition: {}", &e.0)))),
        };
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
    let cond: Condition = match decode_fulfillment(&js_bin.to_vec(), MIXED_MODE) {
            Ok(c) => c,
            Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not decode fulfillment mixed mode: {}", &e.0)))),
        };
    let js_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))) },
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
    let cond: Condition = match decode_fulfillment(&js_bin.to_vec(), 0) {
            Ok(c) => c,
            Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not decode fulfillment: {}", &e.0)))),
        };
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
    if !js_cond.is_object() { return Err(JsError::new("not an object")); }

    let mut cond = match parse_js_cond(js_cond)  {
        Ok(c) => c,
        Err(e) => { return Err(JsError::new(&(format!("rustlibcc: could parse cc: {}", &e.as_string().unwrap())))) },
    };
    threshold_to_anon(&mut cond);

    let js_cond = match make_js_cond(cond) {
        Ok(r) => r,
        Err(e) => return Err(JsError::new(&(format!("rustlibcc: could not make cond: {}", &e.as_string().unwrap())))),
    };
    Ok(js_cond)
}
