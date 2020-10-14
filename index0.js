//const js = import("./node_modules/hello-wasm/hello_wasm.js");
const ccimp = import("cryptoconditions/cryptoconditions.js");

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

var cond = JSON.parse(json);
ccimp.then(ccjs => { 
    try {
        var r = ccjs.js_ccondition_binary(cond); 
        console.log("result="+r);
    }
    catch(err) {
        console.log("err="+err);
    }
})
/*.catch(e => {
    console.log("err="+e);
})*/;

//ccc.JsCConditionBinary(cond).then(function(result) {
//    console.log("result="+result);
//});

//console.log("result="+result);

/*js.then(js => {
  js.greet("WebAssembly");
});*/