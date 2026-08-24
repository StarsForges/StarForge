use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn set_balance(env: Env, owner: Address, balance: i128) {
        let previous = env.storage().persistent().get(&owner).unwrap();
        env.storage().persistent().set(&owner, &(previous + balance));
    }
}

