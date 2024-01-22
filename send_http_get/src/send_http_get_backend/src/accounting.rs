use cketh_common::eth_rpc_client::providers::RpcApi;

use crate::*;

/// Returns the cycles cost of a JSON-RPC request.
pub fn get_json_rpc_cost(
    source: &ResolvedJsonRpcSource,
    payload_size_bytes: u64,
    max_response_bytes: u64,
) -> u128 {
    match source {
        ResolvedJsonRpcSource::Api(api) => {
            get_http_request_cost(api, payload_size_bytes, max_response_bytes)
        }
        ResolvedJsonRpcSource::Provider(provider) => {
            get_candid_rpc_cost(provider, payload_size_bytes, max_response_bytes)
        }
    }
}

/// Returns the cycles cost of a Candid-RPC request.
pub fn get_candid_rpc_cost(
    provider: &Provider,
    payload_size_bytes: u64,
    max_response_bytes: u64,
) -> u128 {
    let http_cost = get_http_request_cost(&provider.api(), payload_size_bytes, max_response_bytes);
    let provider_cost = get_provider_cost(provider, payload_size_bytes);
    http_cost + provider_cost
}

/// Calculates the baseline cost of sending a JSON-RPC request using HTTP outcalls.
pub fn get_http_request_cost(
    api: &RpcApi,
    payload_size_bytes: u64,
    max_response_bytes: u64,
) -> u128 {
    let nodes_in_subnet = UNSTABLE_SUBNET_SIZE.with(|n| *n.borrow());
    let ingress_bytes = payload_size_bytes as u128
        + u32::max(RPC_URL_MIN_COST_BYTES, api.url.len() as u32) as u128
        + INGRESS_OVERHEAD_BYTES;
    let base_cost = INGRESS_MESSAGE_RECEIVED_COST
        + INGRESS_MESSAGE_BYTE_RECEIVED_COST * ingress_bytes
        + HTTP_OUTCALL_REQUEST_COST
        + HTTP_OUTCALL_BYTE_RECEIVED_COST * (ingress_bytes + max_response_bytes as u128);
    base_cost * (nodes_in_subnet as u128) / NODES_IN_DEFAULT_SUBNET as u128
}

/// Calculate the additional cost for calling a registered JSON-RPC provider.
pub fn get_provider_cost(provider: &Provider, payload_size_bytes: u64) -> u128 {
    let nodes_in_subnet = UNSTABLE_SUBNET_SIZE.with(|m| *m.borrow());
    let cost_per_node = provider.cycles_per_call as u128
        + provider.cycles_per_message_byte as u128 * payload_size_bytes as u128;
    cost_per_node * (nodes_in_subnet as u128)
}

#[test]
fn test_request_cost() {
    for nodes_in_subnet in [1, NODES_IN_DEFAULT_SUBNET, NODES_IN_FIDUCIARY_SUBNET] {
        println!("Nodes in subnet: {nodes_in_subnet}");

        UNSTABLE_SUBNET_SIZE.with(|n| *n.borrow_mut() = nodes_in_subnet);

        let url = "https://cloudflare-eth.com";
        let payload = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}";
        let base_cost = get_json_rpc_cost(
            &ResolvedJsonRpcSource::Api(RpcApi {
                url: url.to_string(),
                headers: vec![],
            }),
            payload.len() as u64,
            1000,
        );
        let base_cost_10_extra_bytes = get_json_rpc_cost(
            &ResolvedJsonRpcSource::Api(RpcApi {
                url: url.to_string(),
                headers: vec![],
            }),
            payload.len() as u64 + 10,
            1000,
        );
        let estimated_cost_10_extra_bytes = base_cost
            + 10 * (INGRESS_MESSAGE_BYTE_RECEIVED_COST + HTTP_OUTCALL_BYTE_RECEIVED_COST)
                * nodes_in_subnet as u128
                / NODES_IN_DEFAULT_SUBNET as u128;
        // Request body with 10 additional bytes should be within 1 cycle of expected cost (due to rounding)
        assert_matches::assert_matches!(
            base_cost_10_extra_bytes - estimated_cost_10_extra_bytes,
            0 | 1
        );
    }
}

#[test]
fn test_provider_cost() {
    for nodes_in_subnet in [1, NODES_IN_DEFAULT_SUBNET, NODES_IN_FIDUCIARY_SUBNET] {
        println!("Nodes in subnet: {nodes_in_subnet}");

        UNSTABLE_SUBNET_SIZE.with(|n| *n.borrow_mut() = nodes_in_subnet);

        let provider = Provider {
            provider_id: 0,
            hostname: "".to_string(),
            credential_path: "".to_string(),
            credential_headers: vec![],
            owner: Principal::anonymous(),
            chain_id: 1,
            cycles_owed: 0,
            cycles_per_call: 0,
            cycles_per_message_byte: 2,
            primary: false,
        };
        let base_cost = get_provider_cost(
            &provider,
            "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".len() as u64,
        );

        let provider_10_extra_bytes = Provider {
            provider_id: 0,
            hostname: "".to_string(),
            credential_path: "".to_string(),
            credential_headers: vec![],
            owner: Principal::anonymous(),
            chain_id: 1,
            cycles_owed: 0,
            cycles_per_call: 1000,
            cycles_per_message_byte: 2,
            primary: false,
        };
        let base_cost_10_extra_bytes = get_provider_cost(
            &provider_10_extra_bytes,
            "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".len() as u64
                + 10,
        );
        assert_eq!(
            base_cost + (10 * 2 + 1000) * nodes_in_subnet as u128,
            base_cost_10_extra_bytes
        )
    }
}

#[test]
fn test_candid_rpc_cost() {
    let provider_id = do_register_provider(
        Principal::anonymous(),
        RegisterProviderArgs {
            chain_id: 0,
            hostname: "rpc.example.com".to_string(),
            credential_headers: None,
            credential_path: "".to_string(),
            cycles_per_call: 999,
            cycles_per_message_byte: 1000,
        },
    );
    let provider = PROVIDERS.with(|providers| providers.borrow().get(&provider_id).unwrap());

    // Default subnet
    assert_eq!(get_candid_rpc_cost(&provider, 0, 0), 54767387);
    assert_eq!(get_candid_rpc_cost(&provider, 123, 123), 59170787);
    assert_eq!(get_candid_rpc_cost(&provider, 123, 4567890), 47563947587);
    assert_eq!(get_candid_rpc_cost(&provider, 890, 4567890), 47583429387);

    // Fiduciary subnet
    UNSTABLE_SUBNET_SIZE.with(|n| *n.borrow_mut() = NODES_IN_FIDUCIARY_SUBNET);
    assert_eq!(get_candid_rpc_cost(&provider, 0, 0), 117960525);
    assert_eq!(get_candid_rpc_cost(&provider, 123, 123), 127444772);
    assert_eq!(get_candid_rpc_cost(&provider, 123, 4567890), 102445425572);
    assert_eq!(get_candid_rpc_cost(&provider, 890, 4567890), 102487386372);
}
