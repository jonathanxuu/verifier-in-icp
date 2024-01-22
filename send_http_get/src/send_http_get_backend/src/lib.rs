use candid::candid_method;
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use ic_cdk_macros::{self, update, query};
use std::str::FromStr;

use ic_web3::transports::ICHttp;
use ic_web3::Web3;
use ic_web3::ic::{get_eth_addr, KeyInfo};
use ic_web3::{
    contract::{Contract, Options},
    ethabi::ethereum_types::{U64, U256},
    types::{Address, TransactionParameters, BlockId},
};

//const URL: &str = "https://ethereum.publicnode.com";
const URL: &str = "https://eth-sepolia.public.blastapi.io";
const CHAIN_ID: u64 = 11155111;

type Result<T, E> = std::result::Result<T, E>;



// send tx to eth
#[update(name = "send_eth")]
#[candid_method(update, rename = "send_eth")]
async fn send_eth(rawTx: String) -> Result<String, String> {
   
    let w3 = match ICHttp::new(URL, None, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };

    match w3.eth().send_raw_transaction(rawTx.clone().into()).await {
        Ok(txhash) => { 
            ic_cdk::println!("txhash: {}", hex::encode(txhash.0));
            Ok(format!("{}", hex::encode(txhash.0)))
        },
        Err(_e) => { Ok(hex::encode(rawTx)) },
    }
}