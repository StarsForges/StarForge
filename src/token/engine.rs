//! Token operation orchestrator.

use crate::token::batch::BatchExecutor;
use crate::token::domain::*;
use crate::token::read::TokenReader;
use crate::token::transport::{AnyTokenTransport, MockTokenTransport, UreqTokenTransport};
use crate::token::write::TokenWriter;
use anyhow::Result;

pub struct TokenEngine {
    transport: AnyTokenTransport,
}

impl TokenEngine {
    pub fn live(timeout_ms: u64) -> Self {
        Self {
            transport: AnyTokenTransport::Live(UreqTokenTransport::with_timeout_ms(timeout_ms)),
        }
    }

    pub fn mock(spec_json: &str) -> Self {
        Self {
            transport: AnyTokenTransport::Mock(MockTokenTransport::from_fixture_spec(spec_json)),
        }
    }

    fn reader(&self) -> TokenReader<'_, AnyTokenTransport> {
        TokenReader::new(&self.transport)
    }

    fn writer(&self) -> TokenWriter<'_, AnyTokenTransport> {
        TokenWriter::new(&self.transport)
    }

    pub fn inspect(&self, options: &ReadOptions) -> Result<TokenInspectReport> {
        self.reader().inspect(options)
    }

    pub fn balance(
        &self,
        options: &ReadOptions,
        account: &str,
        decimals: u8,
    ) -> Result<TokenBalance> {
        self.reader().balance(options, account, decimals)
    }

    pub fn allowance(
        &self,
        options: &ReadOptions,
        owner: &str,
        spender: &str,
        decimals: u8,
    ) -> Result<AllowanceState> {
        self.reader().allowance(options, owner, spender, decimals)
    }

    pub fn transfer(&self, options: &WriteOptions, to: &str, amount: &str) -> Result<TokenReceipt> {
        let read_opts = read_options_from_write(options);
        let inspect = self.reader().inspect(&read_opts)?;
        let plan = self.writer().plan_transfer(
            options,
            &inspect.metadata.capabilities,
            to,
            amount,
            inspect.metadata.decimals,
        )?;
        self.writer()
            .execute_simulate_only(&plan, inspect.metadata.decimals)
    }

    pub fn approve(
        &self,
        options: &WriteOptions,
        spender: &str,
        amount: &str,
    ) -> Result<TokenReceipt> {
        let read_opts = read_options_from_write(options);
        let inspect = self.reader().inspect(&read_opts)?;
        let plan = self.writer().plan_approve(
            options,
            &inspect.metadata.capabilities,
            spender,
            amount,
            inspect.metadata.decimals,
        )?;
        self.writer()
            .execute_simulate_only(&plan, inspect.metadata.decimals)
    }

    pub fn mint(&self, options: &WriteOptions, to: &str, amount: &str) -> Result<TokenReceipt> {
        let read_opts = read_options_from_write(options);
        let inspect = self.reader().inspect(&read_opts)?;
        let plan = self.writer().plan_mint(
            options,
            &inspect.metadata.capabilities,
            to,
            amount,
            inspect.metadata.decimals,
        )?;
        self.writer()
            .execute_simulate_only(&plan, inspect.metadata.decimals)
    }

    pub fn burn(&self, options: &WriteOptions, amount: &str) -> Result<TokenReceipt> {
        let read_opts = read_options_from_write(options);
        let inspect = self.reader().inspect(&read_opts)?;
        let plan = self.writer().plan_burn(
            options,
            &inspect.metadata.capabilities,
            amount,
            inspect.metadata.decimals,
        )?;
        self.writer()
            .execute_simulate_only(&plan, inspect.metadata.decimals)
    }

    pub fn authorize(
        &self,
        options: &WriteOptions,
        account: &str,
        authorized: bool,
    ) -> Result<TokenReceipt> {
        let read_opts = read_options_from_write(options);
        let inspect = self.reader().inspect(&read_opts)?;
        let plan = self.writer().plan_authorize(
            options,
            &inspect.metadata.capabilities,
            account,
            authorized,
        )?;
        self.writer()
            .execute_simulate_only(&plan, inspect.metadata.decimals)
    }

    pub fn admin(&self, options: &WriteOptions, new_admin: &str) -> Result<TokenReceipt> {
        let read_opts = read_options_from_write(options);
        let inspect = self.reader().inspect(&read_opts)?;
        let plan = self
            .writer()
            .plan_admin(options, &inspect.metadata.capabilities, new_admin)?;
        self.writer()
            .execute_simulate_only(&plan, inspect.metadata.decimals)
    }

    pub fn execute_batch(
        &self,
        manifest: &BatchManifest,
        simulate_only: bool,
    ) -> Result<BatchExecutionReport> {
        BatchExecutor::new(&self.transport).execute(manifest, simulate_only)
    }
}

fn read_options_from_write(write: &WriteOptions) -> ReadOptions {
    ReadOptions {
        network: write.network.clone(),
        contract_id: write.contract_id.clone(),
        timeout_ms: write.timeout_ms,
    }
}
