
//var ccimp = import('./pkg/cryptoconditions.js');
var ccimp = require('./pkg/cryptoconditions.js');


//import * as ccimp from "./pkg/cryptoconditions.js";

var callCC = async function () {

    var json = "{   \
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
    }";

    //let cond = JSON.parse(json);

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
        cc = await ccimp;
        //console.log("calling js_cc_condition_binary...");
        //var r = cc.js_cc_condition_binary(cond); 
        //console.log("result=", r, ' type=', typeof r, 'hex=', Buffer.from(r.buffer).toString('hex'));

        /*console.log("calling js_cc_threshold_to_anon...");
        var anon = cc.js_cc_threshold_to_anon(cond); 
        console.log("anon=", anon);

        var rffil = cc.js_cc_fulfillment_binary_mixed(anon); 
        console.log("rffil=", rffil, ' type=', typeof rffil, 'hex=', Buffer.from(rffil.buffer).toString('hex'));*/

        var ffil = "a23ba00aa003800102af038001f5a12da22b80207dfebaac73f82b11b3ea72b0f612caa50eefd407c49e2fcc10822820cb91f91e810302040082020204";
        var ffilbuf = Buffer.from(ffil, 'hex');
        var parsed_cond = cc.js_read_fulfillment_binary_mixed(ffilbuf);
        console.log("parsed_cond=", parsed_cond);
    }
    catch(err) {
        console.log("err=", err);
    }
    //}).catch(e => {
    //    console.log("err=", e);
    //})
}

callCC();