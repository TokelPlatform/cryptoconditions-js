/* global describe, it */

var assert = require('assert');
const { stringify } = require('querystring');
var ccimp = require('../pkg/cryptoconditions.js');
var jsConds = require('./jsons/conds-mixed.json')
var jsNonMixedConds = require('./jsons/conds-non-mixed.json')


// make uniform c++ (test jsons created in c++) and rust differences for encoding into hex (letter case) and base64 (padding with '=')
let transformArg = (key, arg) => {
  if (key == 'fingerprint' || key == 'code' || key == 'preimage') 
    //arg = arg.replace(new RegExp("[" + "=" + "]+$", "g"), "")  // remove padding with '=' for base64
    arg = Buffer.from(arg, 'base64').toString('hex');  // convert base64 to hex for comparison
  else if (key == 'publicKey' || key == 'publicKeyHash' || key == 'codehex' || key == 'signature') 
    arg = arg.toLowerCase()  // assume strings contain hex encoding, make it lower case
  return arg
}

let jsonCompare = (arg1, arg2) => {
  if (Object.prototype.toString.call(arg1) === Object.prototype.toString.call(arg2)){
    if (Object.prototype.toString.call(arg1) === '[object Object]' || Object.prototype.toString.call(arg1) === '[object Array]' ){
      if (Object.keys(arg1).length !== Object.keys(arg2).length ){
        return false;
      }
      return (Object.keys(arg1).every(function(key){
        let val1 = transformArg(key, arg1[key]) 
        let val2 = transformArg(key, arg2[key]) 
        return jsonCompare(val1, val2)
      }));
    }
    // return (arg1===arg2);
    if (arg1===arg2)
      return true;
    else
      return false;
  }
  return false;
}

describe('cryptoconditons', async function () {
  let cc = await ccimp;
  describe('mixed-mode conditions', function () {
    let i = 0
    jsConds.forEach(function (js) {
      i ++
      it('encode mixed mode condition to asn, ' + String(i), function () {
        //console.log(js.id, 'js.cond', JSON.stringify(js.cond))
        let asnFfil = cc.js_cc_fulfillment_binary_mixed(js.cond)
        //console.log(js.id, 'asnFfil', Buffer.from(asnFfil).toString('hex'))
        assert.strictEqual(Buffer.from(asnFfil).toString('hex'), js.MixedModeASN)
        let asnCond = cc.js_cc_condition_binary(js.cond)
        assert.strictEqual(Buffer.from(asnCond).toString('hex'), js.CondASN) // check fulfilment serialised to asn condition correctly
      })

      it('decode mixed mode condition from asn, ' + String(i), function () {
        let jsonFfilMixed = cc.js_cc_read_fulfillment_binary_mixed(Buffer.from(js.MixedModeASN, 'hex')); 
        console.log(js.id, 'jsonFfilMixed', JSON.stringify(jsonFfilMixed))
        assert(jsonCompare(jsonFfilMixed, js.MixedModeCond))
        let asnCond = cc.js_cc_condition_binary(jsonFfilMixed)
        assert.strictEqual(Buffer.from(asnCond).toString('hex'), js.CondASN) // check mixed mode encoded fulfilment serialised to asn condition correctly
      })
    })
  })

  describe('non mixed-mode fulfillments', function () {
    let i = 0
    jsNonMixedConds.forEach(function (js) {
      i ++
      it('encode fulfillment to asn, ' + String(i), function () {
        //console.log('js.ffil', JSON.stringify(js.cond))
        let js_cond = js.cond
        // if privkey is set this is for the secp256k1hash cond to sign it to add the pk and sig
        if (js.privateKey && js.message) {
          js_cond = cc.js_cc_sign_secp256k1hash(js.cond, Buffer.from(js.privateKey, 'hex'), Buffer.from(js.message, 'hex'))
        }
        //console.log(js.id, 'js_cond', JSON.stringify(js_cond))
        let asnFfil = cc.js_cc_fulfillment_binary(js_cond); 
        //console.log(js.id, 'non-mixed asnFfil', Buffer.from(asnFfil).toString('hex'))
        assert.strictEqual(Buffer.from(asnFfil).toString('hex'), js.NonMixedModeASN)
      })

      it('decode fulfillment from asn, ' + String(i), function () {
        let jsonFfil = cc.js_read_fulfillment_binary(Buffer.from(js.NonMixedModeASN, 'hex')); 
        //console.log(js.id, 'parsed non-mixed jsonFfil', JSON.stringify(jsonFfil))
        assert(jsonCompare(jsonFfil, js.decoded))
      })
    })
  })
})
