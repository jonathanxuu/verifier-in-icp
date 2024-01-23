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
// const URL: &str = "https://eth-sepolia.public.blastapi.io";
// const CHAIN_ID: u64 = 11155111;

// type Result<T, E> = std::result::Result<T, E>;

#[ic_cdk::query]
fn greet(param: String) -> String {
    format!("Hello there, the string's len is {:?}", param.len())
}