//! Authenticated, run-scoped control frames for the future macOS companion.
//!
//! This module deliberately has no CLI dispatch or provider transport. A signed
//! companion may wire it only after native tests prove process attribution.

use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;

pub(crate) const CONTRACT: &str = "heimdall.macos.control/v1";
const MAX_FRAME_BYTES: usize = 65_536;
const MAX_PAYLOAD_BYTES: usize = 48_000;
const CONTROL_KEY_BYTES: usize = 32;
const RELAY_SECRET_BYTES: usize = 32;
const SHA256_HEX_BYTES: usize = 64;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    Request,
    Response,
}

impl Direction {
    const fn code(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
        }
    }

    const fn opposite(self) -> Self {
        match self {
            Self::Request => Self::Response,
            Self::Response => Self::Request,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    RegisterRun,
    RunReady,
    UnregisterRun,
    RunRemoved,
    Error,
}

impl Operation {
    const fn code(self) -> u8 {
        match self {
            Self::RegisterRun => 1,
            Self::RunReady => 2,
            Self::UnregisterRun => 3,
            Self::RunRemoved => 4,
            Self::Error => 5,
        }
    }

    const fn allowed_for(self, direction: Direction) -> bool {
        matches!(
            (direction, self),
            (Direction::Request, Self::RegisterRun | Self::UnregisterRun)
                | (
                    Direction::Response,
                    Self::RunReady | Self::RunRemoved | Self::Error
                )
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    contract: String,
    direction: Direction,
    session_id: Uuid,
    sequence: u64,
    operation: Operation,
    payload: String,
    mac: String,
}

#[derive(Debug)]
pub(crate) struct SessionCodec {
    key: ControlKey,
    session_id: Uuid,
    outbound: Direction,
    next_send_sequence: u64,
    next_receive_sequence: u64,
}

impl SessionCodec {
    pub(crate) fn requester(secret: &[u8], session_id: Uuid) -> Result<Self, ControlError> {
        Self::new(secret, session_id, Direction::Request)
    }

    pub(crate) fn responder(secret: &[u8], session_id: Uuid) -> Result<Self, ControlError> {
        Self::new(secret, session_id, Direction::Response)
    }

    fn new(secret: &[u8], session_id: Uuid, outbound: Direction) -> Result<Self, ControlError> {
        validate_v7(session_id, "session_id")?;
        Ok(Self {
            key: ControlKey::new(secret)?,
            session_id,
            outbound,
            next_send_sequence: 1,
            next_receive_sequence: 1,
        })
    }

    pub(crate) fn seal<T: Serialize>(
        &mut self,
        operation: Operation,
        payload: &T,
    ) -> Result<Envelope, ControlError> {
        if !operation.allowed_for(self.outbound) {
            return Err(ControlError::OperationDirection);
        }
        let payload = serde_json::to_vec(payload).map_err(ControlError::PayloadJson)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ControlError::PayloadTooLarge);
        }
        let sequence = self.next_send_sequence;
        let mac = self.key.sign(
            self.outbound,
            self.session_id,
            sequence,
            operation,
            &payload,
        )?;
        self.next_send_sequence = sequence
            .checked_add(1)
            .ok_or(ControlError::SequenceExhausted)?;
        Ok(Envelope {
            contract: CONTRACT.into(),
            direction: self.outbound,
            session_id: self.session_id,
            sequence,
            operation,
            payload: URL_SAFE_NO_PAD.encode(payload),
            mac: hex::encode(mac),
        })
    }

    pub(crate) fn open<T: DeserializeOwned>(
        &mut self,
        expected_operation: Operation,
        envelope: &Envelope,
    ) -> Result<T, ControlError> {
        if envelope.contract != CONTRACT {
            return Err(ControlError::Contract);
        }
        if envelope.direction != self.outbound.opposite() {
            return Err(ControlError::Direction);
        }
        if !envelope.operation.allowed_for(envelope.direction) {
            return Err(ControlError::OperationDirection);
        }
        if envelope.operation != expected_operation {
            return Err(ControlError::OperationMismatch {
                expected: expected_operation,
                actual: envelope.operation,
            });
        }
        if envelope.session_id != self.session_id {
            return Err(ControlError::Session);
        }
        if envelope.sequence != self.next_receive_sequence {
            return Err(ControlError::Sequence {
                expected: self.next_receive_sequence,
                actual: envelope.sequence,
            });
        }
        let payload = URL_SAFE_NO_PAD
            .decode(envelope.payload.as_bytes())
            .map_err(|_| ControlError::PayloadEncoding)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ControlError::PayloadTooLarge);
        }
        if URL_SAFE_NO_PAD.encode(&payload) != envelope.payload {
            return Err(ControlError::PayloadEncoding);
        }
        let mac = hex::decode(&envelope.mac).map_err(|_| ControlError::MacEncoding)?;
        if mac.len() != CONTROL_KEY_BYTES || hex::encode(&mac) != envelope.mac {
            return Err(ControlError::MacEncoding);
        }
        self.key.verify(
            envelope.direction,
            envelope.session_id,
            envelope.sequence,
            envelope.operation,
            &payload,
            &mac,
        )?;
        let value = serde_json::from_slice(&payload).map_err(ControlError::PayloadJson)?;
        self.next_receive_sequence = envelope
            .sequence
            .checked_add(1)
            .ok_or(ControlError::SequenceExhausted)?;
        Ok(value)
    }
}

struct ControlKey([u8; CONTROL_KEY_BYTES]);

impl std::fmt::Debug for ControlKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControlKey([REDACTED])")
    }
}

impl ControlKey {
    fn new(secret: &[u8]) -> Result<Self, ControlError> {
        let key: [u8; CONTROL_KEY_BYTES] =
            secret.try_into().map_err(|_| ControlError::KeyLength)?;
        Ok(Self(key))
    }

    fn sign(
        &self,
        direction: Direction,
        session_id: Uuid,
        sequence: u64,
        operation: Operation,
        payload: &[u8],
    ) -> Result<[u8; CONTROL_KEY_BYTES], ControlError> {
        let mut mac = HmacSha256::new_from_slice(&self.0).map_err(|_| ControlError::KeyLength)?;
        update_mac(
            &mut mac, direction, session_id, sequence, operation, payload,
        )?;
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify(
        &self,
        direction: Direction,
        session_id: Uuid,
        sequence: u64,
        operation: Operation,
        payload: &[u8],
        expected: &[u8],
    ) -> Result<(), ControlError> {
        let mut mac = HmacSha256::new_from_slice(&self.0).map_err(|_| ControlError::KeyLength)?;
        update_mac(
            &mut mac, direction, session_id, sequence, operation, payload,
        )?;
        mac.verify_slice(expected)
            .map_err(|_| ControlError::Authentication)
    }
}

impl Drop for ControlKey {
    fn drop(&mut self) {
        // Why: the session key is short-lived and must not remain in an
        // ordinary reusable allocation after the foreground run ends.
        self.0.fill(0);
    }
}

fn update_mac(
    mac: &mut HmacSha256,
    direction: Direction,
    session_id: Uuid,
    sequence: u64,
    operation: Operation,
    payload: &[u8],
) -> Result<(), ControlError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| ControlError::PayloadTooLarge)?;
    mac.update(CONTRACT.as_bytes());
    mac.update(&[0]);
    mac.update(&[direction.code()]);
    mac.update(session_id.as_bytes());
    mac.update(&sequence.to_be_bytes());
    mac.update(&[operation.code()]);
    mac.update(&payload_len.to_be_bytes());
    mac.update(payload);
    Ok(())
}

pub(crate) fn write_frame(
    writer: &mut impl Write,
    envelope: &Envelope,
) -> Result<(), ControlError> {
    let bytes = serde_json::to_vec(envelope).map_err(ControlError::FrameJson)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ControlError::FrameSize);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ControlError::FrameSize)?;
    writer
        .write_all(&length.to_be_bytes())
        .map_err(ControlError::Io)?;
    writer.write_all(&bytes).map_err(ControlError::Io)
}

pub(crate) fn read_frame(reader: &mut impl Read) -> Result<Option<Envelope>, ControlError> {
    let mut length = [0_u8; 4];
    match reader.read(&mut length[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("the one-byte prefix read cannot return more than one byte"),
        Err(error) if error.kind() == ErrorKind::Interrupted => return read_frame(reader),
        Err(error) => return Err(ControlError::Io(error)),
    }
    reader
        .read_exact(&mut length[1..])
        .map_err(ControlError::Io)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| ControlError::FrameSize)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ControlError::FrameSize);
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes).map_err(ControlError::Io)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(ControlError::FrameJson)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunRegistration {
    run_id: Uuid,
    owner_pid: u32,
    root_pid: u32,
    process_group_id: u32,
    process_start_unix_ns: u64,
    executable_path: String,
    relay_port: u16,
    relay_secret: String,
    policy_sha256: String,
    config_sha256: String,
    lease_ms: u32,
}

impl RunRegistration {
    fn validate(&self) -> Result<(), ControlError> {
        validate_v7(self.run_id, "run_id")?;
        if self.owner_pid == 0 || self.root_pid == 0 || self.process_group_id == 0 {
            return Err(ControlError::Registration(
                "process identifiers must be non-zero",
            ));
        }
        if self.process_start_unix_ns == 0 {
            return Err(ControlError::Registration(
                "process_start_unix_ns must be non-zero",
            ));
        }
        if !self.executable_path.starts_with('/') || self.executable_path.contains('\0') {
            return Err(ControlError::Registration(
                "executable_path must be an absolute path without NUL bytes",
            ));
        }
        if self.relay_port == 0 {
            return Err(ControlError::Registration("relay_port must be non-zero"));
        }
        validate_secret(&self.relay_secret)?;
        validate_sha256(&self.policy_sha256, "policy_sha256")?;
        validate_sha256(&self.config_sha256, "config_sha256")?;
        if !(1_000..=30_000).contains(&self.lease_ms) {
            return Err(ControlError::Registration(
                "lease_ms must be between 1000 and 30000",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunReference {
    run_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderTransition {
    None,
    Start,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryChange {
    active_runs: usize,
    provider_transition: ProviderTransition,
}

#[derive(Debug, Default)]
pub(crate) struct RunRegistry {
    runs: BTreeMap<Uuid, RegisteredRun>,
    sessions: BTreeMap<Uuid, Uuid>,
    process_groups: BTreeMap<u32, Uuid>,
}

#[derive(Debug)]
struct RegisteredRun {
    session_id: Uuid,
    registration: RunRegistration,
}

impl RunRegistry {
    pub(crate) fn register(
        &mut self,
        session_id: Uuid,
        registration: RunRegistration,
    ) -> Result<RegistryChange, ControlError> {
        validate_v7(session_id, "session_id")?;
        registration.validate()?;
        if self.runs.contains_key(&registration.run_id) {
            return Err(ControlError::DuplicateRun);
        }
        if self.sessions.contains_key(&session_id) {
            return Err(ControlError::DuplicateSession);
        }
        if self
            .process_groups
            .contains_key(&registration.process_group_id)
        {
            return Err(ControlError::DuplicateProcessGroup);
        }
        let transition = if self.runs.is_empty() {
            ProviderTransition::Start
        } else {
            ProviderTransition::None
        };
        self.sessions.insert(session_id, registration.run_id);
        self.process_groups
            .insert(registration.process_group_id, registration.run_id);
        self.runs.insert(
            registration.run_id,
            RegisteredRun {
                session_id,
                registration,
            },
        );
        Ok(RegistryChange {
            active_runs: self.runs.len(),
            provider_transition: transition,
        })
    }

    pub(crate) fn unregister(
        &mut self,
        session_id: Uuid,
        run_id: Uuid,
    ) -> Result<RegistryChange, ControlError> {
        let Some(registered) = self.runs.get(&run_id) else {
            return Err(ControlError::UnknownRun);
        };
        if registered.session_id != session_id {
            return Err(ControlError::SessionOwner);
        }
        self.remove(run_id)
    }

    pub(crate) fn owner_disconnected(
        &mut self,
        session_id: Uuid,
    ) -> Result<Option<RegistryChange>, ControlError> {
        let Some(run_id) = self.sessions.get(&session_id).copied() else {
            return Ok(None);
        };
        self.remove(run_id).map(Some)
    }

    fn remove(&mut self, run_id: Uuid) -> Result<RegistryChange, ControlError> {
        let registered = self.runs.remove(&run_id).ok_or(ControlError::UnknownRun)?;
        self.sessions.remove(&registered.session_id);
        self.process_groups
            .remove(&registered.registration.process_group_id);
        Ok(RegistryChange {
            active_runs: self.runs.len(),
            provider_transition: if self.runs.is_empty() {
                ProviderTransition::Stop
            } else {
                ProviderTransition::None
            },
        })
    }
}

fn validate_v7(value: Uuid, field: &'static str) -> Result<(), ControlError> {
    if value.get_version_num() != 7 {
        return Err(ControlError::IdentifierVersion(field));
    }
    Ok(())
}

fn validate_secret(value: &str) -> Result<(), ControlError> {
    let bytes = URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|_| {
        ControlError::Registration("relay_secret must be base64url without padding")
    })?;
    if bytes.len() != RELAY_SECRET_BYTES || URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(ControlError::Registration(
            "relay_secret must encode exactly 32 bytes",
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), ControlError> {
    let bytes = hex::decode(value).map_err(|_| ControlError::Digest(field))?;
    if value.len() != SHA256_HEX_BYTES || bytes.len() != 32 || hex::encode(bytes) != value {
        return Err(ControlError::Digest(field));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum ControlError {
    #[error("unsupported macOS control contract")]
    Contract,
    #[error("control frame direction does not match this endpoint")]
    Direction,
    #[error("control operation is invalid for its direction")]
    OperationDirection,
    #[error("control operation mismatch: expected {expected:?}, found {actual:?}")]
    OperationMismatch {
        expected: Operation,
        actual: Operation,
    },
    #[error("control frame belongs to another session")]
    Session,
    #[error("control frame sequence mismatch: expected {expected}, found {actual}")]
    Sequence { expected: u64, actual: u64 },
    #[error("control frame sequence is exhausted")]
    SequenceExhausted,
    #[error("control session keys must contain exactly 32 bytes")]
    KeyLength,
    #[error("control payload exceeds the size limit")]
    PayloadTooLarge,
    #[error("control payload is not canonical base64url")]
    PayloadEncoding,
    #[error("control MAC is not canonical lowercase SHA-256 hex")]
    MacEncoding,
    #[error("control frame authentication failed")]
    Authentication,
    #[error("control frame length is invalid")]
    FrameSize,
    #[error("control frame I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("control frame JSON is invalid: {0}")]
    FrameJson(#[source] serde_json::Error),
    #[error("control payload JSON is invalid: {0}")]
    PayloadJson(#[source] serde_json::Error),
    #[error("{0} must be a UUIDv7")]
    IdentifierVersion(&'static str),
    #[error("invalid run registration: {0}")]
    Registration(&'static str),
    #[error("{0} must be canonical lowercase SHA-256 hex")]
    Digest(&'static str),
    #[error("run ID is already registered")]
    DuplicateRun,
    #[error("control session already owns a run")]
    DuplicateSession,
    #[error("process group is already registered")]
    DuplicateProcessGroup,
    #[error("run is not registered")]
    UnknownRun,
    #[error("control session does not own this run")]
    SessionOwner,
}

impl ControlError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Contract => "macos_control_contract_unsupported",
            Self::Direction => "macos_control_direction_mismatch",
            Self::OperationDirection => "macos_control_operation_invalid",
            Self::OperationMismatch { .. } => "macos_control_operation_mismatch",
            Self::Session => "macos_control_session_mismatch",
            Self::Sequence { .. } => "macos_control_sequence_mismatch",
            Self::SequenceExhausted => "macos_control_sequence_exhausted",
            Self::KeyLength => "macos_control_key_length_invalid",
            Self::PayloadTooLarge => "macos_control_payload_too_large",
            Self::PayloadEncoding => "macos_control_payload_encoding_invalid",
            Self::MacEncoding => "macos_control_mac_encoding_invalid",
            Self::Authentication => "macos_control_authentication_failed",
            Self::FrameSize => "macos_control_frame_size_invalid",
            Self::Io(_) => "macos_control_io_failed",
            Self::FrameJson(_) => "macos_control_frame_json_invalid",
            Self::PayloadJson(_) => "macos_control_payload_json_invalid",
            Self::IdentifierVersion(_) => "macos_control_identifier_version_invalid",
            Self::Registration(_) => "macos_control_registration_invalid",
            Self::Digest(_) => "macos_control_digest_invalid",
            Self::DuplicateRun => "macos_control_duplicate_run",
            Self::DuplicateSession => "macos_control_duplicate_session",
            Self::DuplicateProcessGroup => "macos_control_duplicate_process_group",
            Self::UnknownRun => "macos_control_unknown_run",
            Self::SessionOwner => "macos_control_session_owner_mismatch",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use serde_json::json;

    use super::*;

    const SESSION: &str = "01890f47-90d4-7cc2-9f5f-6a48f59cf7ab";
    const RUN_A: &str = "01890f47-90d4-7cc2-9f5f-6a48f59cf7ac";
    const RUN_B: &str = "01890f47-90d4-7cc2-9f5f-6a48f59cf7ad";

    fn session() -> Uuid {
        Uuid::parse_str(SESSION).unwrap()
    }

    fn registration(run_id: &str, process_group_id: u32) -> RunRegistration {
        RunRegistration {
            run_id: Uuid::parse_str(run_id).unwrap(),
            owner_pid: 41,
            root_pid: 42,
            process_group_id,
            process_start_unix_ns: 1_700_000_000_000_000_000,
            executable_path: "/usr/bin/curl".into(),
            relay_port: 32_001,
            relay_secret: URL_SAFE_NO_PAD.encode([0x22; RELAY_SECRET_BYTES]),
            policy_sha256: "11".repeat(32),
            config_sha256: "33".repeat(32),
            lease_ms: 5_000,
        }
    }

    #[test]
    fn fixed_vector_is_stable_for_a_swift_implementation() {
        let secret = std::array::from_fn::<_, CONTROL_KEY_BYTES, _>(|index| index as u8);
        let mut requester = SessionCodec::requester(&secret, session()).unwrap();
        let envelope = requester
            .seal(
                Operation::RegisterRun,
                &json!({"probe": "macos-control-v1"}),
            )
            .unwrap();

        assert_eq!(
            serde_json::to_string(&envelope).unwrap(),
            "{\"contract\":\"heimdall.macos.control/v1\",\"direction\":\"request\",\"session_id\":\"01890f47-90d4-7cc2-9f5f-6a48f59cf7ab\",\"sequence\":1,\"operation\":\"register_run\",\"payload\":\"eyJwcm9iZSI6Im1hY29zLWNvbnRyb2wtdjEifQ\",\"mac\":\"eb390e73297ba508ab1ae2ad10cb22bb86d8b92502e277fc2c2e08ee61138569\"}"
        );
    }

    #[test]
    fn authenticated_frame_round_trips_and_owner_eof_removes_the_run() {
        let secret = [0x44; CONTROL_KEY_BYTES];
        let session_id = session();
        let mut requester = SessionCodec::requester(&secret, session_id).unwrap();
        let mut responder = SessionCodec::responder(&secret, session_id).unwrap();
        let (mut owner, mut helper) = UnixStream::pair().unwrap();
        let registration = registration(RUN_A, 42);

        let envelope = requester
            .seal(Operation::RegisterRun, &registration)
            .unwrap();
        write_frame(&mut owner, &envelope).unwrap();
        let received = read_frame(&mut helper).unwrap().unwrap();
        let decoded: RunRegistration = responder.open(Operation::RegisterRun, &received).unwrap();
        assert_eq!(decoded, registration);

        let mut registry = RunRegistry::default();
        let change = registry.register(session_id, decoded).unwrap();
        assert_eq!(change.active_runs, 1);
        assert_eq!(change.provider_transition, ProviderTransition::Start);

        let ready = responder
            .seal(
                Operation::RunReady,
                &RunReference {
                    run_id: registration.run_id,
                },
            )
            .unwrap();
        write_frame(&mut helper, &ready).unwrap();
        let ready = read_frame(&mut owner).unwrap().unwrap();
        let acknowledged: RunReference = requester.open(Operation::RunReady, &ready).unwrap();
        assert_eq!(acknowledged.run_id, registration.run_id);

        drop(owner);
        assert!(read_frame(&mut helper).unwrap().is_none());
        let change = registry.owner_disconnected(session_id).unwrap().unwrap();
        assert_eq!(change.active_runs, 0);
        assert_eq!(change.provider_transition, ProviderTransition::Stop);
    }

    #[test]
    fn replay_and_tampering_fail_closed() {
        let secret = [0x55; CONTROL_KEY_BYTES];
        let mut requester = SessionCodec::requester(&secret, session()).unwrap();
        let mut responder = SessionCodec::responder(&secret, session()).unwrap();
        let envelope = requester
            .seal(Operation::RegisterRun, &registration(RUN_A, 42))
            .unwrap();

        let _: RunRegistration = responder.open(Operation::RegisterRun, &envelope).unwrap();
        let replay = responder
            .open::<RunRegistration>(Operation::RegisterRun, &envelope)
            .unwrap_err();
        assert_eq!(replay.code(), "macos_control_sequence_mismatch");

        let mut responder = SessionCodec::responder(&secret, session()).unwrap();
        let mut tampered = envelope.clone();
        tampered.payload = URL_SAFE_NO_PAD.encode(b"{}");
        let error = responder
            .open::<RunRegistration>(Operation::RegisterRun, &tampered)
            .unwrap_err();
        assert_eq!(error.code(), "macos_control_authentication_failed");

        let mut wrong_key = SessionCodec::responder(&[0x56; CONTROL_KEY_BYTES], session()).unwrap();
        let error = wrong_key
            .open::<RunRegistration>(Operation::RegisterRun, &envelope)
            .unwrap_err();
        assert_eq!(error.code(), "macos_control_authentication_failed");
    }

    #[test]
    fn contract_direction_and_unknown_fields_are_rejected() {
        let secret = [0x66; CONTROL_KEY_BYTES];
        let mut requester = SessionCodec::requester(&secret, session()).unwrap();
        let envelope = requester
            .seal(Operation::RegisterRun, &registration(RUN_A, 42))
            .unwrap();

        let mut wrong_contract = envelope.clone();
        wrong_contract.contract = "heimdall.macos.control/v2".into();
        let mut responder = SessionCodec::responder(&secret, session()).unwrap();
        assert_eq!(
            responder
                .open::<RunRegistration>(Operation::RegisterRun, &wrong_contract)
                .unwrap_err()
                .code(),
            "macos_control_contract_unsupported"
        );

        let mut wrong_direction = envelope.clone();
        wrong_direction.direction = Direction::Response;
        let mut responder = SessionCodec::responder(&secret, session()).unwrap();
        assert_eq!(
            responder
                .open::<RunRegistration>(Operation::RegisterRun, &wrong_direction)
                .unwrap_err()
                .code(),
            "macos_control_direction_mismatch"
        );

        let mut wrong_session = envelope.clone();
        wrong_session.session_id = Uuid::parse_str(RUN_B).unwrap();
        let mut responder = SessionCodec::responder(&secret, session()).unwrap();
        assert_eq!(
            responder
                .open::<RunRegistration>(Operation::RegisterRun, &wrong_session)
                .unwrap_err()
                .code(),
            "macos_control_session_mismatch"
        );

        let mut responder = SessionCodec::responder(&secret, session()).unwrap();
        assert_eq!(
            responder
                .open::<RunReference>(Operation::UnregisterRun, &envelope)
                .unwrap_err()
                .code(),
            "macos_control_operation_mismatch"
        );

        let mut encoded = serde_json::to_value(envelope).unwrap();
        encoded["unexpected"] = json!(true);
        assert!(serde_json::from_value::<Envelope>(encoded).is_err());
    }

    #[test]
    fn concurrent_runs_are_isolated_and_only_the_last_removal_stops_provider() {
        let session_a = session();
        let session_b = Uuid::parse_str("01890f47-90d4-7cc2-9f5f-6a48f59cf7ae").unwrap();
        let mut registry = RunRegistry::default();

        let first = registry
            .register(session_a, registration(RUN_A, 42))
            .unwrap();
        assert_eq!(first.provider_transition, ProviderTransition::Start);
        let second = registry
            .register(session_b, registration(RUN_B, 43))
            .unwrap();
        assert_eq!(second.active_runs, 2);
        assert_eq!(second.provider_transition, ProviderTransition::None);

        let first_removed = registry
            .unregister(session_a, Uuid::parse_str(RUN_A).unwrap())
            .unwrap();
        assert_eq!(first_removed.active_runs, 1);
        assert_eq!(first_removed.provider_transition, ProviderTransition::None);
        let last_removed = registry.owner_disconnected(session_b).unwrap().unwrap();
        assert_eq!(last_removed.active_runs, 0);
        assert_eq!(last_removed.provider_transition, ProviderTransition::Stop);
    }

    #[test]
    fn duplicate_scope_and_invalid_registration_are_rejected() {
        let session_a = session();
        let session_b = Uuid::parse_str("01890f47-90d4-7cc2-9f5f-6a48f59cf7ae").unwrap();
        let mut registry = RunRegistry::default();
        registry
            .register(session_a, registration(RUN_A, 42))
            .unwrap();

        let error = registry
            .register(session_b, registration(RUN_B, 42))
            .unwrap_err();
        assert_eq!(error.code(), "macos_control_duplicate_process_group");

        let mut invalid = registration(RUN_B, 43);
        invalid.relay_secret = "not-a-secret".into();
        let error = registry.register(session_b, invalid).unwrap_err();
        assert_eq!(error.code(), "macos_control_registration_invalid");
    }

    #[test]
    fn schema_accepts_a_frame_and_rejects_unknown_fields() {
        let secret = [0x77; CONTROL_KEY_BYTES];
        let mut requester = SessionCodec::requester(&secret, session()).unwrap();
        let envelope = requester
            .seal(Operation::RegisterRun, &registration(RUN_A, 42))
            .unwrap();
        let schema = serde_json::from_str(include_str!(
            "../schemas/heimdall.macos.control.v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let value = serde_json::to_value(envelope).unwrap();
        assert!(validator.is_valid(&value));

        let mut unknown = value;
        unknown["unexpected"] = json!(true);
        assert!(!validator.is_valid(&unknown));
    }

    #[test]
    fn framing_rejects_empty_oversized_and_truncated_inputs() {
        let mut empty = &0_u32.to_be_bytes()[..];
        assert_eq!(
            read_frame(&mut empty).unwrap_err().code(),
            "macos_control_frame_size_invalid"
        );

        let oversized = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
        let mut oversized = &oversized[..];
        assert_eq!(
            read_frame(&mut oversized).unwrap_err().code(),
            "macos_control_frame_size_invalid"
        );

        let mut truncated = &[0, 0, 0, 4, b'{'][..];
        assert_eq!(
            read_frame(&mut truncated).unwrap_err().code(),
            "macos_control_io_failed"
        );
    }
}
