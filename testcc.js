
var ccimp = import('./pkg/cryptoconditions.js');
//import * as ccimp from "./pkg/cryptoconditions.js";

var callCC = function () {

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

    let cond = {
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
    
    console.log("cond=", cond);

    ccimp.then(ccjs => { 
        try {
            var r = ccjs.js_ccondition_binary(cond); 
            console.log("result=", r, ' type=', typeof r, 'hex=', Buffer.from(r.buffer).toString('hex'));
        }
        catch(err) {
            console.log("err=", err);
        }
    }).catch(e => {
        console.log("err=", e);
    })
}

callCC();