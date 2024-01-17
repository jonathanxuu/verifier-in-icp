//1. IMPORT IC MANAGEMENT CANISTER
//This includes all methods and types needed
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};
use serde_bytes::ByteBuf;

use ic_cdk_macros::{self, query, update};
use serde::{Serialize, Deserialize};
use serde_json::{self, Value};
use miden_vm::verify_zk_bool;

// This struct is legacy code and is not really used in the code.
#[derive(Serialize, Deserialize)]
struct Context {
    bucket_start_time_index: usize,
    closing_price_index: usize,
}
use std::str;


#[ic_cdk::query]
async fn get_icp_usd_exchange_query(str_body: String) -> String {
    return str_body.len().to_string();
    // let programHash = "79414c1c82c0ef42aff896debc5b8ed351189264f32085ea5fad753b19f48d4e";
    // let publicInput = "7,0,6,5,6,4,6,3,6,2,5,2,4,4,4,3,4,2,3,7,3,5,2,2,2,0,1,2,0,6,0,5,0,2,0,1,18,15,7,7,0,0,8,8";
    // return verify_zk_bool(programHash.to_string(), publicInput.to_string(), str_body).to_string();
}

//Update method using the HTTPS outcalls feature
#[ic_cdk::update]
async fn get_icp_usd_exchange(str_body: String) -> String {
   
    let programHash = "79414c1c82c0ef42aff896debc5b8ed351189264f32085ea5fad753b19f48d4e";
    let publicInput = "7,0,6,5,6,4,6,3,6,2,5,2,4,4,4,3,4,2,3,7,3,5,2,2,2,0,1,2,0,6,0,5,0,2,0,1,18,15,7,7,0,0,8,8";
    
    //Return the body as a string and end the method
    return verify_zk_bool(programHash.to_string(), publicInput.to_string(), str_body).to_string();
            // str_body
}
// Strips all data that is not needed from the original response.
#[query]
fn transform(raw: TransformArgs) -> HttpResponse {

    let headers = vec![
        HttpHeader {
            name: "Content-Security-Policy".to_string(),
            value: "default-src 'self'".to_string(),
        },
        HttpHeader {
            name: "Referrer-Policy".to_string(),
            value: "strict-origin".to_string(),
        },
        HttpHeader {
            name: "Permissions-Policy".to_string(),
            value: "geolocation=(self)".to_string(),
        },
        HttpHeader {
            name: "Strict-Transport-Security".to_string(),
            value: "max-age=63072000".to_string(),
        },
        HttpHeader {
            name: "X-Frame-Options".to_string(),
            value: "DENY".to_string(),
        },
        HttpHeader {
            name: "X-Content-Type-Options".to_string(),
            value: "nosniff".to_string(),
        },
    ];
    

    let mut res = HttpResponse {
        status: raw.response.status.clone(),
        body: raw.response.body.clone(),
        headers,
        ..Default::default()
    };

    if res.status == 200 {

        res.body = raw.response.body;
    } else {
        ic_cdk::api::print(format!("Received an error from coinbase: err = {:?}", raw));
    }
    res
}