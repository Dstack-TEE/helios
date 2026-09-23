use std::sync::{Arc, Mutex};
use std::time::Duration;

use url::Url;

use alloy::consensus::proofs::calculate_transaction_root;
use alloy::consensus::transaction::SignerRecoverable;
use alloy::consensus::{Header as ConsensusHeader, Transaction as TxTrait};
use alloy::eips::eip4895::{Withdrawal, Withdrawals};
use alloy::network::Ethereum;
use alloy::primitives::{b256, fixed_bytes, Address, Bloom, B256, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rlp::Decodable;
use alloy::rpc::types::{Block, Header, Transaction as EthTransaction};
use eyre::{eyre, OptionExt, Result};
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_network::primitives::BlockTransactions;
use op_alloy_rpc_types::Transaction;
use tokio::sync::mpsc::Sender;
use tokio::sync::{
    mpsc::{channel, Receiver},
    watch,
};
use tracing::{debug, error, warn};

use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_core::consensus::Consensus;
use helios_core::execution::proof::{verify_account_proof, verify_mpt_proof};
use helios_core::time::{interval, Instant, SystemTime, UNIX_EPOCH};
use helios_ethereum::consensus::ConsensusClient as EthConsensusClient;

use helios_ethereum::database::ConfigDB;
use helios_ethereum::rpc::http_rpc::HttpRpc;

use crate::{config::Config, types::ExecutionPayload, SequencerCommitment};

// Storage slot containing the unsafe signer address in all superchain system config contracts
const UNSAFE_SIGNER_SLOT: B256 =
    b256!("65a7ed542fb37fe237fdfbdd70b31598523fe5b32879e307bae27a0bd9581c08");
/// Minimum interval between L1 proofs of the unsafe signer.
const SIGNER_CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum age of the L1 block that proved the unsafe signer.
const MAX_SIGNER_PROOF_AGE: u64 = 15 * 60;

#[derive(Clone, Copy)]
enum UnsafeSigner {
    Pinned(Address),
    Unverified,
    Proven { address: Address, l1_timestamp: u64 },
}

pub struct ConsensusClient {
    block_recv: Option<Receiver<Block<Transaction>>>,
    finalized_block_recv: Option<watch::Receiver<Option<Block<Transaction>>>>,
    chain_id: u64,
    max_head_age: u64,
}

impl ConsensusClient {
    pub fn new(config: &Config) -> Self {
        let (block_send, block_recv) = channel(256);
        let (finalized_block_send, finalized_block_recv) = watch::channel(None);

        let mut inner = Inner {
            server_url: config.consensus_rpc.clone(),
            unsafe_signer: Arc::new(Mutex::new(if config.verify_unsafe_signer {
                UnsafeSigner::Unverified
            } else {
                UnsafeSigner::Pinned(config.chain.unsafe_signer)
            })),
            chain_id: config.chain.chain_id,
            latest_block: None,
            block_send,
            finalized_block_send,
        };

        if config.verify_unsafe_signer {
            verify_unsafe_signer(config.clone(), inner.unsafe_signer.clone());
        }

        #[cfg(not(target_arch = "wasm32"))]
        let run = tokio::spawn;

        #[cfg(target_arch = "wasm32")]
        let run = wasm_bindgen_futures::spawn_local;

        run(async move {
            let mut interval = interval(Duration::from_secs(1));
            loop {
                if let Err(e) = inner.advance().await {
                    error!(target: "helios::opstack", "failed to advance: {}", e);
                }
                interval.tick().await;
            }
        });

        Self {
            block_recv: Some(block_recv),
            finalized_block_recv: Some(finalized_block_recv),
            chain_id: config.chain.chain_id,
            max_head_age: config.max_head_age.unwrap_or(60),
        }
    }
}

#[async_trait::async_trait]
impl Consensus<Block<Transaction>> for ConsensusClient {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn max_head_age(&self) -> u64 {
        self.max_head_age
    }

    fn shutdown(&self) -> eyre::Result<()> {
        Ok(())
    }

    fn block_recv(&mut self) -> Option<Receiver<Block<Transaction>>> {
        self.block_recv.take()
    }

    fn finalized_block_recv(&mut self) -> Option<watch::Receiver<Option<Block<Transaction>>>> {
        self.finalized_block_recv.take()
    }

    fn checkpoint_recv(&self) -> Option<watch::Receiver<Option<B256>>> {
        None
    }

    fn expected_highest_block(&self) -> u64 {
        u64::MAX
    }

    async fn wait_synced(&self) -> eyre::Result<()> {
        // OpStack consensus doesn't have a sync process, so immediately return Ok
        Ok(())
    }
}

#[allow(dead_code)]
struct Inner {
    server_url: Url,
    unsafe_signer: Arc<Mutex<UnsafeSigner>>,
    chain_id: u64,
    latest_block: Option<u64>,
    block_send: Sender<Block<Transaction>>,
    finalized_block_send: watch::Sender<Option<Block<Transaction>>>,
}

impl Inner {
    pub async fn advance(&mut self) -> Result<()> {
        let url = self
            .server_url
            .join("latest")
            .map_err(|e| eyre!("Failed to construct latest URL: {}", e))?;
        let commitment = reqwest::get(url)
            .await?
            .json::<SequencerCommitment>()
            .await?;

        let curr_signer = self.current_signer()?;
        if commitment.verify(curr_signer, self.chain_id).is_ok() {
            let payload = ExecutionPayload::try_from(&commitment)?;
            if self
                .latest_block
                .map(|latest| payload.block_number > latest)
                .unwrap_or(true)
            {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();

                let timestamp = Duration::from_secs(payload.timestamp);
                let age = now.saturating_sub(timestamp);
                let number = payload.block_number;

                {
                    let block =
                        payload_to_block(payload, B256::from_slice(&commitment.data[..32]))?;
                    self.latest_block = Some(block.header.number);
                    _ = self.block_send.send(block).await;

                    tracing::debug!(
                        "unsafe head updated: block={} age={}s",
                        number,
                        age.as_secs()
                    );
                }
            }
        }

        Ok(())
    }

    fn current_signer(&self) -> Result<Address> {
        let signer = *self
            .unsafe_signer
            .lock()
            .map_err(|_| eyre!("failed to lock signer"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match signer {
            UnsafeSigner::Pinned(address) => Ok(address),
            UnsafeSigner::Proven {
                address,
                l1_timestamp,
            } if now.saturating_sub(l1_timestamp) <= MAX_SIGNER_PROOF_AGE => Ok(address),
            _ => Err(eyre!("unsafe signer is not proven by a recent L1 block")),
        }
    }
}

fn verify_unsafe_signer(config: Config, signer: Arc<Mutex<UnsafeSigner>>) {
    #[cfg(not(target_arch = "wasm32"))]
    let run = tokio::spawn;

    #[cfg(target_arch = "wasm32")]
    let run = wasm_bindgen_futures::spawn_local;

    run(async move {
        let mut retry = interval(SIGNER_CHECK_INTERVAL);
        loop {
            retry.tick().await;
            if let Err(err) = track_unsafe_signer(&config, &signer).await {
                warn!(target: "helios::opstack", error = %err, "unsafe signer tracking failed");
            }
        }
    });
}

/// Follows verified L1 blocks and proves the unsafe signer from the system config contract.
async fn track_unsafe_signer(config: &Config, signer: &Mutex<UnsafeSigner>) -> Result<()> {
    let mut eth_config = config.chain.eth_network.to_base_config();
    eth_config.load_external_fallback = config.load_external_fallback.unwrap_or(false);
    if let Some(checkpoint) = config.checkpoint {
        eth_config.default_checkpoint = checkpoint;
    }
    if let Some(rpc) = &config.ethereum_consensus_rpc {
        eth_config.consensus_rpc = Some(rpc.clone());
    }
    let consensus_rpc = eth_config
        .consensus_rpc
        .clone()
        .ok_or_eyre("missing Ethereum consensus rpc")?;
    let execution_rpc = config
        .ethereum_execution_rpc
        .clone()
        .ok_or_eyre("missing Ethereum execution rpc")?;
    let provider = RootProvider::<Ethereum>::new_http(execution_rpc);

    let mut eth_consensus = EthConsensusClient::<MainnetConsensusSpec, HttpRpc, ConfigDB>::new(
        &consensus_rpc,
        Arc::new(eth_config.into()),
    )?;
    let mut blocks = eth_consensus
        .block_recv()
        .ok_or_eyre("missing Ethereum block receiver")?;

    let mut last_check: Option<Instant> = None;
    while let Some(block) = blocks.recv().await {
        if last_check.is_some_and(|checked| checked.elapsed() < SIGNER_CHECK_INTERVAL) {
            continue;
        }
        last_check = Some(Instant::now());
        match prove_unsafe_signer(&provider, config.chain.system_config_contract, &block).await {
            Ok(address) => {
                debug!(target: "helios::opstack", %address, l1_block = block.header.number, "unsafe signer proven");
                *signer.lock().map_err(|_| eyre!("failed to lock signer"))? =
                    UnsafeSigner::Proven {
                        address,
                        l1_timestamp: block.header.timestamp,
                    };
            }
            Err(err) => {
                warn!(target: "helios::opstack", error = %err, l1_block = block.header.number, "unsafe signer proof failed")
            }
        }
    }

    eth_consensus.shutdown()?;
    Err(eyre!("Ethereum consensus client stopped"))
}

async fn prove_unsafe_signer(
    provider: &RootProvider<Ethereum>,
    system_config: Address,
    block: &Block<EthTransaction>,
) -> Result<Address> {
    let proof = provider
        .get_proof(system_config, vec![UNSAFE_SIGNER_SLOT])
        .block_id(block.header.hash.into())
        .await?;
    eyre::ensure!(
        proof.address == system_config,
        "proof for unexpected account"
    );
    verify_account_proof(&proof, block.header.state_root)?;
    let storage_proof = proof
        .storage_proof
        .first()
        .ok_or_eyre("missing storage proof")?;
    eyre::ensure!(
        storage_proof.key.as_b256() == UNSAFE_SIGNER_SLOT,
        "storage proof for unexpected slot"
    );
    verify_mpt_proof(
        proof.storage_hash,
        UNSAFE_SIGNER_SLOT,
        storage_proof.value,
        &storage_proof.proof,
    )?;
    let address = Address::from_slice(&storage_proof.value.to_be_bytes::<32>()[12..]);
    eyre::ensure!(address != Address::ZERO, "unsafe signer is unset");
    Ok(address)
}

fn payload_to_block(
    value: ExecutionPayload,
    parent_beacon_block_root: B256,
) -> Result<Block<Transaction>> {
    let empty_nonce = fixed_bytes!("0000000000000000");
    let empty_uncle_hash =
        b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

    let txs = value
        .transactions
        .iter()
        .enumerate()
        .map(|(i, tx_bytes)| {
            let tx_bytes = tx_bytes.to_vec();
            let mut tx_bytes_slice = tx_bytes.as_slice();
            let tx_envelope = OpTxEnvelope::decode(&mut tx_bytes_slice)?;
            let base_fee = tx_envelope.effective_gas_price(Some(value.base_fee_per_gas.to()));
            let recovered = tx_envelope.try_into_recovered()?;

            let inner_tx = EthTransaction {
                inner: recovered,
                block_hash: Some(value.block_hash),
                block_number: Some(value.block_number),
                transaction_index: Some(i as u64),
                effective_gas_price: Some(base_fee),
            };

            Ok(match inner_tx.inner.inner() {
                OpTxEnvelope::Legacy(_)
                | OpTxEnvelope::Eip2930(_)
                | OpTxEnvelope::Eip1559(_)
                | OpTxEnvelope::Eip7702(_) => Transaction {
                    inner: inner_tx,
                    deposit_nonce: None,
                    deposit_receipt_version: None,
                },
                OpTxEnvelope::Deposit(inner) => {
                    let deposit_nonce = Some(inner.inner().nonce());

                    Transaction {
                        inner: inner_tx,
                        deposit_nonce,
                        deposit_receipt_version: None,
                    }
                }
            })
        })
        .collect::<Result<Vec<Transaction>>>()?;
    let tx_envelopes = txs
        .iter()
        .map(|tx| tx.inner.inner.clone())
        .collect::<Vec<_>>();
    let txs_root = calculate_transaction_root(&tx_envelopes);

    let withdrawals: Vec<Withdrawal> = value.withdrawals.into_iter().map(|w| w.into()).collect();
    let withdrawals_root = value.withdrawals_root;

    let logs_bloom: Bloom = Bloom::from_slice(&value.logs_bloom);

    let consensus_header = ConsensusHeader {
        parent_hash: value.parent_hash,
        ommers_hash: empty_uncle_hash,
        beneficiary: Address::from(*value.fee_recipient),
        state_root: value.state_root,
        transactions_root: txs_root,
        receipts_root: value.receipts_root,
        withdrawals_root: Some(withdrawals_root),
        difficulty: U256::ZERO,
        number: value.block_number,
        gas_limit: value.gas_limit,
        gas_used: value.gas_used,
        timestamp: value.timestamp,
        mix_hash: value.prev_randao,
        nonce: empty_nonce,
        base_fee_per_gas: Some(value.base_fee_per_gas.to::<u64>()),
        blob_gas_used: Some(value.blob_gas_used),
        excess_blob_gas: Some(value.excess_blob_gas),
        parent_beacon_block_root: Some(parent_beacon_block_root),
        extra_data: value.extra_data.to_vec().into(),
        requests_hash: Some(b256!(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )),
        logs_bloom,
    };

    eyre::ensure!(
        consensus_header.hash_slow() == value.block_hash,
        "payload block hash mismatch"
    );

    let header = Header {
        hash: value.block_hash,
        inner: consensus_header,
        total_difficulty: Some(U256::ZERO),
        size: Some(U256::ZERO),
    };

    Ok(Block::new(header, BlockTransactions::Full(txs))
        .with_withdrawals(Some(Withdrawals::new(withdrawals))))
}

#[cfg(test)]
mod phala_tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn authentic_phala_payload_reconstructs_header() {
        let commitment: SequencerCommitment = serde_json::from_str(include_str!(
            "../tests/fixtures/phala-signed-commitment.json"
        ))
        .unwrap();
        let signer = address!("F63ccBA1929a3eC32248B26c5a22D7C4c9bd3EEC");
        commitment.verify(signer, 2035).unwrap();
        assert!(commitment.verify(signer, 8453).is_err());
        assert!(commitment.verify(Address::ZERO, 2035).is_err());
        let payload = ExecutionPayload::try_from(&commitment).unwrap();
        let parent_root = B256::from_slice(&commitment.data[..32]);
        let block = payload_to_block(payload.clone(), parent_root).unwrap();
        assert_eq!(block.header.number, 5569808);
        let truncated = snap::raw::Encoder::new().compress_vec(&[0; 10]).unwrap();
        assert!(SequencerCommitment::new(&truncated).is_err());
        let mut empty = commitment.clone();
        empty.data = Default::default();
        assert!(ExecutionPayload::try_from(&empty).is_err());
        let mut forged = commitment.clone();
        let mut data = forged.data.to_vec();
        data[0] ^= 1;
        forged.data = data.into();
        assert!(forged.verify(signer, 2035).is_err());
        let mut corrupt = payload;
        corrupt.state_root = B256::ZERO;
        assert!(payload_to_block(corrupt, parent_root).is_err());
    }
}
