use ic_cdk_macros::{self, query, update};

use miden_vm::verify_zk_bool;
use std::str;
use cketh_common::eth_rpc_client::providers::{EthMainnetService, EthSepoliaService};


use cketh_common::eth_rpc::{
    Block, FeeHistory, LogEntry, ProviderError, RpcError, SendRawTransactionResult,
};
use candid::{candid_method, CandidType};

mod accounting;
mod auth;
mod candid_rpc;
mod constants;
mod http;
mod memory;
mod metrics;
mod providers;
mod types;
mod util;
mod validate;


pub use crate::accounting::*;
pub use crate::auth::*;
pub use crate::candid_rpc::*;
pub use crate::constants::*;
pub use crate::http::*;
pub use crate::memory::*;
pub use crate::metrics::*;
pub use crate::providers::*;
pub use crate::types::*;
pub use crate::util::*;
pub use crate::validate::*;


pub use candid::Principal;

#[update(name = "eth_sendRawTransaction")]
#[candid_method(rename = "eth_sendRawTransaction")]
pub async fn eth_send_raw_transaction(
    // source: RpcSource,
    raw_signed_transaction_hex: String,
) -> MultiRpcResult<SendRawTransactionResult> {
    let source =  RpcSource::EthSepolia(Some(vec![
        EthSepoliaService::Ankr,
        EthSepoliaService::Alchemy,
    ]));

    match CandidRpcClient::from_source(source) {
        Ok(source) => {
            source
                .eth_send_raw_transaction(raw_signed_transaction_hex)
                .await
        }
        Err(err) => Err(err).into(),
    }
}