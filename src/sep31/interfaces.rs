use crate::sep31::domain::{
    Asset, Sep31CreateRequest, Sep31CreateResponse, Sep31Transaction, Sep31UpdateRequest,
};
use anyhow::Result;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sep10Token(String);

impl Sep10Token {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            anyhow::bail!("SEP-10 token cannot be empty");
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Sep10Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sep10Token([REDACTED])")
    }
}

pub trait Sep10SessionProvider {
    fn token_for(&self, anchor: &str) -> Result<Sep10Token>;
}

pub trait Sep12CustomerProvider {
    fn ensure_customer(&self, anchor: &str, role: CustomerRole) -> Result<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomerRole {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sep38QuoteReference {
    pub id: String,
    pub sell_asset: Asset,
    pub buy_asset: Asset,
    pub expires_at_unix: i64,
}

pub trait Sep38QuoteProvider {
    fn resolve_quote(&self, quote_id: &str) -> Result<Sep38QuoteReference>;
}

pub trait Sep31Transport {
    fn create_transaction(
        &self,
        endpoint: &str,
        token: &Sep10Token,
        request: &Sep31CreateRequest,
    ) -> Result<Sep31CreateResponse>;

    fn get_transaction(
        &self,
        endpoint: &str,
        token: &Sep10Token,
        transaction_id: &str,
    ) -> Result<Sep31Transaction>;

    fn update_transaction(
        &self,
        endpoint: &str,
        token: &Sep10Token,
        transaction_id: &str,
        request: &Sep31UpdateRequest,
    ) -> Result<Sep31Transaction>;

    fn cancel_transaction(
        &self,
        endpoint: &str,
        token: &Sep10Token,
        transaction_id: &str,
    ) -> Result<Sep31Transaction>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    Never,
    Retryable,
    AuthenticationRequired,
    CustomerActionRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFailure {
    pub status_code: Option<u16>,
    pub code: String,
    pub message: String,
    pub retry_class: RetryClass,
}

impl TransportFailure {
    pub fn classify(status_code: Option<u16>, code: impl Into<String>, message: impl Into<String>) -> Self {
        let retry_class = match status_code {
            Some(401 | 403) => RetryClass::AuthenticationRequired,
            Some(408 | 425 | 429 | 500 | 502 | 503 | 504) | None => RetryClass::Retryable,
            Some(400 | 409 | 422) => RetryClass::CustomerActionRequired,
            Some(_) => RetryClass::Never,
        };
        Self {
            status_code,
            code: code.into(),
            message: message.into(),
            retry_class,
        }
    }
}
