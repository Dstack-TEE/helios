use std::sync::atomic::{AtomicU64, Ordering};

use alloy::primitives::Address;
use libp2p::gossipsub::{IdentTopic, Message, MessageAcceptance, TopicHash};
use tokio::sync::mpsc::Sender;

use crate::{types::ExecutionPayload, SequencerCommitment};

pub struct BlockHandler {
    chain_id: u64,
    signer: Address,
    commitment_sender: Sender<SequencerCommitment>,
    blocks_v3_topic: IdentTopic,
    latest_block: AtomicU64,
}

impl BlockHandler {
    pub fn new(signer: Address, chain_id: u64, sender: Sender<SequencerCommitment>) -> Self {
        Self {
            chain_id,
            signer,
            commitment_sender: sender,
            blocks_v3_topic: IdentTopic::new(format!("/optimism/{chain_id}/3/blocks")),
            latest_block: AtomicU64::new(0),
        }
    }

    pub fn topics(&self) -> Vec<TopicHash> {
        vec![self.blocks_v3_topic.hash()]
    }

    /// Highest block number among accepted commitments.
    pub fn latest_block(&self) -> u64 {
        self.latest_block.load(Ordering::Relaxed)
    }

    pub fn handle(&self, msg: Message) -> MessageAcceptance {
        let Ok(commitment) = SequencerCommitment::new(&msg.data) else {
            return MessageAcceptance::Reject;
        };

        if commitment.verify(self.signer, self.chain_id).is_ok() {
            if let Ok(payload) = ExecutionPayload::try_from(&commitment) {
                self.latest_block
                    .fetch_max(payload.block_number, Ordering::Relaxed);
            }
            _ = self.commitment_sender.try_send(commitment);
            MessageAcceptance::Accept
        } else {
            MessageAcceptance::Reject
        }
    }
}
