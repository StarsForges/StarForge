use crate::sep31::domain::{Sep31Status, Sep31Transaction};
use anyhow::{bail, Result};
use chrono::Utc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionDecision {
    pub from: Sep31Status,
    pub to: Sep31Status,
    pub terminal: bool,
}

pub fn can_transition(from: Sep31Status, to: Sep31Status) -> bool {
    use Sep31Status::*;
    if from == to {
        return true;
    }
    match from {
        PendingSender => matches!(
            to,
            PendingStellar
                | PendingCustomerInfoUpdate
                | PendingTransactionInfoUpdate
                | Expired
                | Error
        ),
        PendingCustomerInfoUpdate | PendingTransactionInfoUpdate => {
            matches!(to, PendingSender | PendingStellar | Expired | Error)
        }
        PendingStellar => matches!(to, PendingReceiver | PendingExternal | Completed | Error),
        PendingReceiver => matches!(to, PendingExternal | Completed | Refunded | Error),
        PendingExternal => matches!(to, PendingReceiver | Completed | Refunded | Error),
        Completed => matches!(to, Refunded),
        Refunded | Expired | Error => false,
    }
}

pub fn validate_transition(from: Sep31Status, to: Sep31Status) -> Result<TransitionDecision> {
    if !can_transition(from, to) {
        bail!("invalid SEP-31 status transition from {:?} to {:?}", from, to);
    }
    Ok(TransitionDecision {
        from,
        to,
        terminal: to.is_terminal(),
    })
}

pub fn transition_transaction(
    transaction: &mut Sep31Transaction,
    next: Sep31Status,
    message: Option<String>,
) -> Result<TransitionDecision> {
    let decision = validate_transition(transaction.status, next)?;
    let now = Utc::now();
    transaction.status = next;
    transaction.updated_at = now;
    transaction.message = message;
    if next == Sep31Status::Completed {
        transaction.completed_at = Some(now);
    }
    transaction.validate()?;
    Ok(decision)
}

pub fn validate_anchor_update(
    previous: &Sep31Transaction,
    incoming: &Sep31Transaction,
) -> Result<TransitionDecision> {
    if previous.id != incoming.id {
        bail!("anchor response changed transaction id");
    }
    if previous.sender_id != incoming.sender_id || previous.receiver_id != incoming.receiver_id {
        bail!("anchor response changed sender or receiver customer id");
    }
    if previous.asset_in != incoming.asset_in || previous.asset_out != incoming.asset_out {
        bail!("anchor response changed source or destination asset");
    }
    if previous.quote_id.is_some() && previous.quote_id != incoming.quote_id {
        bail!("anchor response conflicts with the persisted SEP-38 quote id");
    }
    incoming.validate()?;
    validate_transition(previous.status, incoming.status)
}
