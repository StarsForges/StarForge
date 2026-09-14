use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;
use stellar_xdr::curr::{
    DataValue, DecoratedSignature, Limits, ManageDataOp, Memo, MuxedAccount, Operation,
    OperationBody, Preconditions, SequenceNumber, Signature as XdrSignature, SignatureHint,
    String64, TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionV1Envelope,
    Uint256, WriteXdr,
};

/// Deterministic mock keypair for server and client in unit test fixtures.
pub struct MockKeypair {
    pub signing_key: SigningKey,
    pub public_key_str: String,
    pub public_key_bytes: [u8; 32],
}

impl MockKeypair {
    pub fn from_seed_byte(b: u8) -> Self {
        let seed = [b; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let public_key_str = StellarPublicKey(pub_bytes).to_string();
        Self {
            signing_key,
            public_key_str,
            public_key_bytes: pub_bytes,
        }
    }
}

/// Helper builder for creating test fixture challenge transactions.
pub struct MockChallengeBuilder {
    server_key: MockKeypair,
    client_pubkey_str: String,
    home_domain: String,
    web_auth_domain: Option<String>,
    client_domain: Option<String>,
    sequence_number: i64,
    min_time: u64,
    max_time: u64,
    nonce: Vec<u8>,
    network_passphrase: String,
    replace_op0_with_payment: bool,
}

impl MockChallengeBuilder {
    pub fn new(server_seed: u8, client_pubkey_str: &str, home_domain: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            server_key: MockKeypair::from_seed_byte(server_seed),
            client_pubkey_str: client_pubkey_str.to_string(),
            home_domain: home_domain.to_string(),
            web_auth_domain: None,
            client_domain: None,
            sequence_number: 0,
            min_time: now.saturating_sub(60),
            max_time: now + 300,
            nonce: vec![42u8; 64],
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            replace_op0_with_payment: false,
        }
    }

    pub fn with_web_auth_domain(mut self, domain: &str) -> Self {
        self.web_auth_domain = Some(domain.to_string());
        self
    }

    pub fn with_client_domain(mut self, domain: &str) -> Self {
        self.client_domain = Some(domain.to_string());
        self
    }

    pub fn with_sequence(mut self, seq: i64) -> Self {
        self.sequence_number = seq;
        self
    }

    pub fn with_time_bounds(mut self, min: u64, max: u64) -> Self {
        self.min_time = min;
        self.max_time = max;
        self
    }

    pub fn with_invalid_op(mut self) -> Self {
        self.replace_op0_with_payment = true;
        self
    }

    pub fn server_public_key(&self) -> String {
        self.server_key.public_key_str.clone()
    }

    /// Build the TransactionEnvelope and serialize it to base64 XDR
    pub fn build(self) -> String {
        let server_muxed = MuxedAccount::Ed25519(Uint256(self.server_key.public_key_bytes));

        let client_pk =
            StellarPublicKey::from_string(&self.client_pubkey_str).expect("Valid client pubkey");
        let client_muxed = MuxedAccount::Ed25519(Uint256(client_pk.0));

        let mut operations = Vec::new();

        if self.replace_op0_with_payment {
            // Invalid operation test case
            let op = Operation {
                source_account: Some(client_muxed.clone()),
                body: OperationBody::Inflation,
            };
            operations.push(op);
        } else {
            // Valid Operation 0: ManageData
            let key_str = format!("{} auth", self.home_domain);
            let data_name = String64(key_str.try_into().expect("String64"));
            let data_value = Some(DataValue(self.nonce.try_into().expect("64 bytes nonce")));

            let op0 = Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name,
                    data_value,
                }),
            };
            operations.push(op0);
        }

        // Optional Operation 1: web_auth_domain
        if let Some(ref wad) = self.web_auth_domain {
            let data_name = String64("web_auth_domain".to_string().try_into().unwrap());
            let data_value = Some(DataValue(wad.as_bytes().to_vec().try_into().unwrap()));
            let op = Operation {
                source_account: Some(server_muxed.clone()),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name,
                    data_value,
                }),
            };
            operations.push(op);
        }

        // Optional Operation 2: client_domain
        if let Some(ref cd) = self.client_domain {
            let data_name = String64("client_domain".to_string().try_into().unwrap());
            let data_value = Some(DataValue(cd.as_bytes().to_vec().try_into().unwrap()));
            let op = Operation {
                source_account: None,
                body: OperationBody::ManageData(ManageDataOp {
                    data_name,
                    data_value,
                }),
            };
            operations.push(op);
        }

        let time_bounds = TimeBounds {
            min_time: TimePoint(self.min_time),
            max_time: TimePoint(self.max_time),
        };

        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(self.sequence_number),
            cond: Preconditions::Time(time_bounds),
            memo: Memo::None,
            operations: operations.try_into().expect("Operations fit in VecM"),
            ext: stellar_xdr::curr::TransactionExt::V0,
        };

        // Sign with server key
        let network_id: [u8; 32] = Sha256::digest(self.network_passphrase.as_bytes()).into();
        let tx_body = tx.to_xdr(Limits::none()).expect("Serialize tx body");

        let mut payload = Vec::with_capacity(36 + tx_body.len());
        payload.extend_from_slice(&network_id);
        payload.extend_from_slice(&[0u8, 0, 0, 2]); // ENVELOPE_TYPE_TX
        payload.extend_from_slice(&tx_body);
        let hash: [u8; 32] = Sha256::digest(&payload).into();

        let sig = self.server_key.signing_key.sign(&hash);
        let hint = SignatureHint(self.server_key.public_key_bytes[28..32].try_into().unwrap());

        let dec_sig = DecoratedSignature {
            hint,
            signature: XdrSignature(sig.to_bytes().to_vec().try_into().unwrap()),
        };

        let v1 = TransactionV1Envelope {
            tx,
            signatures: vec![dec_sig].try_into().unwrap(),
        };

        let env = TransactionEnvelope::Tx(v1);
        let xdr_bytes = env.to_xdr(Limits::none()).expect("Serialize envelope");

        base64::engine::general_purpose::STANDARD.encode(&xdr_bytes)
    }
}
