
//var ccimp = import('./pkg/cryptoconditions.js');
var ccimp = require('./pkg/cryptoconditions.js');


//import * as ccimp from "./pkg/cryptoconditions.js";

var callCC = async function () {

    /*var json = "{   \
        \"type\":	\"threshold-sha-256\",  \
        \"threshold\":	2,                  \
        \"subfulfillments\":	[{          \
                \"type\":	\"eval-sha-256\",   \
                \"code\":	\"9A\"      \
            }, {            \
                \"type\":	\"threshold-sha-256\",  \
                \"threshold\":	1,          \
                \"subfulfillments\":	[{  \
                        \"type\":	\"secp256k1-sha-256\",  \
                        \"publicKey\":	\"03C27DB737B92826D37FB43F3FDA3D1B1D258CD28B68FE4BE605457BF9DD9E0218\"  \
                    }]  \
            }]  \
    }";*/


/*    var json = "{   \
        \"type\":	\"threshold-sha-256\",  \
        \"threshold\":	1,          \
        \"subfulfillments\":	[{  \
                \"type\":	\"secp256k1-sha-256\",  \
                \"publicKey\":	\"035d3b0f2e98cf0fba19f80880ec7c08d770c6cf04aa5639bc57130d5ac54874db\"  \
            }]  \
    }";
*/

/*
    var json = "{   \
        \"type\":	\"threshold-sha-256\",  \
        \"threshold\":	1,          \
        \"subfulfillments\":	[{  \
                \"type\":	\"secp256k1hash-sha-256\",  \
                \"publicKeyHash\":	\"6579c3bd574da22803234e12ddcec405e2b99092\"  \
            }]  \
    }"; 
*/

//    var json = '{"type":"threshold-sha-256","threshold":3,"subfulfillments":[{"type":"preimage-sha-256","preimage":"Ag"},{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"AQ"},{"type":"(anon)","fingerprint":"2P27WsN2u+Akinl8vZzYFrrN8PYCgnqsIW7oOq90oIw","cost":131072,"cond_type":6}]},{"type":"eval-sha-256","codehex":"F4"}]}'
//   var json = '{"type":"threshold-sha-256","threshold":3,"subfulfillments":[{"type":"preimage-sha-256","preimage":"Ag"},{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"AQ"},{"type":"(anon)","fingerprint":"2P27WsN2u+Akinl8vZzYFrrN8PYCgnqsIW7oOq90oIw","cost":131072,"cond_type":5}]},{"type":"eval-sha-256","codehex":"F4"}]}'
    var json = '{"type":"threshold-sha-256","threshold":2,"subfulfillments":[{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"(anon)","fingerprint":"ZXnDvVdNoigDI04S3c7EBeK5kJIAAAAAAAAAAAAAAAA","cost":131072,"cond_type":6}]},{"type":"eval-sha-256","codehex":"F4"}]}'
//    var json =  '{"type":"threshold-sha-256","threshold":2,"subfulfillments":[{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"(anon)","fingerprint":"Z6LHxwYB31uwfVCNguNmxclWymRuMRqw5rEPok298p4","cost":131072,"cond_type":5}]},{"type":"eval-sha-256","codehex":"F4"}]}'
    let cond = JSON.parse(json);

    

    /*let cond = {
        type:	"threshold-sha-256",
        threshold:	2,
        subfulfillments:	[{
              type:	"eval-sha-256",   
              code:	 '9A'     
          }, {            
              type:	"threshold-sha-256",
              threshold:	1,
              subfulfillments:	[{  
                      type:	"secp256k1-sha-256",
                      publicKey:	"03682b255c40d0cde8faee381a1a50bbb89980ff24539cb8518e294d3a63cefe12"
              }]  
          }]   
        };
    
    console.log("cond=", cond);*/

    //ccimp.then(ccjs => { 
    try {
        let cc = await ccimp;

        //let privkey = Buffer.from("0df044c4bed33b74af696b051dbf70142fc3a78da34738c0336f5015e3d285ee", 'hex'); // RJXkCF7mn2DRpUZ77XBNTKCe55M2rJbTcu
        //let signed = cc.js_cc_sign_secp256k1hash(cond, privkey, Buffer.from('4e43e43d3569c1155cc9340f46b58425e3d86890076739f19298bc66e6a7acf2', 'hex'));
        //let signed = cc.js_sign_secp256k1(cond, privkey, Buffer.from('4e43e43d3569c1155cc9340f46b58425e3d86890076739f19298bc66e6a7acf2', 'hex'));
        //console.log('signed cond=', JSON.stringify(signed));

        console.log("calling js_cc_condition_binary...");
        var r = cc.js_cc_condition_binary(cond); 
        console.log("result=", r, ' type=', typeof r, 'hex=', Buffer.from(r.buffer).toString('hex'));
        //var r = cc.js_cc_fulfillment_binary(signed); 
        //console.log("result=", r, ' type=', typeof r, 'hex=', Buffer.from(r.buffer).toString('hex')); 

        //var anon = cc.js_cc_threshold_to_anon(cond); 
        //console.log("anon=", JSON.stringify(anon));

        //var rffil = cc.js_cc_fulfillment_binary_mixed(anon); 
        //console.log("rffil=", rffil, ' type=', typeof rffil, 'hex=', Buffer.from(rffil.buffer).toString('hex'));

        /*var ffilmm = "a23ba00aa003800102af038001f5a12da22b80207dfebaac73f82b11b3ea72b0f612caa50eefd407c49e2fcc10822820cb91f91e810302040082020204";
        var ffilbufmm = Buffer.from(ffil, 'hex');
        var parsed_cond = cc.js_read_fulfillment_binary_mixed(ffilbufmm);
        console.log("parsed_cond=", parsed_cond);        
        */

        /*var ffil = "a276a072a26ba067a5658021035d3b0f2e98cf0fba19f80880ec7c08d770c6cf04aa5639bc57130d5ac54874db814077f957e93f9f291a39ce5b3a8451e4bf94fc6f3a2f4c18e701c796f1132308fc07546f7f304907d920c68a07bb398aa817c63898347d6638064dac9cf2cbf6a3a100af038001f5a100";
        var ffilbuf = Buffer.from(ffil, 'hex');
        var parsed_cond2 = cc.js_read_fulfillment_binary(ffilbuf);
        console.log("parsed_cond2=", parsed_cond2);*/
    }
    catch(err) {
        console.log("err=", err);
    }
    //}).catch(e => {
    //    console.log("err=", e);
    //})
}

callCC();