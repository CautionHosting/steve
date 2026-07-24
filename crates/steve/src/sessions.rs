use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use crate::protocol::{Direction, MessageType, ProtocolError, SESSION_ID_LEN, SessionSecrets};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const PENDING_TTL: Duration = Duration::from_secs(30);
pub const ACTIVE_TTL: Duration = Duration::from_secs(30 * 60);
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_MAX_SESSIONS: usize = 4_096;
const CAPACITY_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const REPLAY_WINDOW_SIZE: u64 = 64;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum SessionError {
    #[error("session not found or expired")]
    InvalidSession,
    #[error("session has not been confirmed")]
    Unconfirmed,
    #[error("session confirmation has already completed")]
    AlreadyConfirmed,
    #[error("sequence is invalid or has already been used")]
    Replay,
    #[error("session capacity reached")]
    Capacity,
    #[error("session identifier collision")]
    Collision,
    #[error("message authentication failed")]
    Authentication,
    #[error("confirmation payload does not match the transcript")]
    ConfirmationMismatch,
}

impl From<ProtocolError> for SessionError {
    fn from(_: ProtocolError) -> Self {
        Self::Authentication
    }
}

enum Lifecycle {
    Pending,
    Active { expires_at: Instant },
}

struct MutableSession {
    lifecycle: Lifecycle,
    replay: ReplayWindow,
}

pub struct Session {
    id: [u8; SESSION_ID_LEN],
    transcript_hash: [u8; 32],
    secrets: SessionSecrets,
    created_at: Instant,
    mutable: Mutex<MutableSession>,
}

impl Session {
    pub fn new(
        id: [u8; SESSION_ID_LEN],
        transcript_hash: [u8; 32],
        secrets: SessionSecrets,
    ) -> Self {
        Self {
            id,
            transcript_hash,
            secrets,
            created_at: Instant::now(),
            mutable: Mutex::new(MutableSession {
                lifecycle: Lifecycle::Pending,
                replay: ReplayWindow::default(),
            }),
        }
    }

    pub fn id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.id
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        let state = self.mutable.lock().unwrap();
        match state.lifecycle {
            Lifecycle::Pending => now.duration_since(self.created_at) >= PENDING_TTL,
            Lifecycle::Active { expires_at } => now >= expires_at,
        }
    }

    pub fn confirm(&self, sequence: u64, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if sequence != 0 {
            return Err(SessionError::Replay);
        }

        let mut state = self.mutable.lock().unwrap();
        if self.is_expired_locked(&state, Instant::now()) {
            return Err(SessionError::InvalidSession);
        }
        if matches!(state.lifecycle, Lifecycle::Active { .. }) {
            return Err(SessionError::AlreadyConfirmed);
        }

        let plaintext = self.secrets.open(
            Direction::ClientToServer,
            MessageType::Confirmation,
            &self.id,
            sequence,
            ciphertext,
        )?;
        if plaintext.as_slice() != self.transcript_hash {
            return Err(SessionError::ConfirmationMismatch);
        }

        state.lifecycle = Lifecycle::Active {
            expires_at: Instant::now() + ACTIVE_TTL,
        };
        self.secrets
            .seal(
                Direction::ServerToClient,
                MessageType::Confirmation,
                &self.id,
                sequence,
                &self.transcript_hash,
            )
            .map_err(Into::into)
    }

    pub fn open_request(&self, sequence: u64, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if sequence == 0 {
            return Err(SessionError::Replay);
        }

        let mut state = self.mutable.lock().unwrap();
        if self.is_expired_locked(&state, Instant::now()) {
            return Err(SessionError::InvalidSession);
        }
        if matches!(state.lifecycle, Lifecycle::Pending) {
            return Err(SessionError::Unconfirmed);
        }

        // Authenticate first: an attacker must not be able to consume replay-window slots.
        let plaintext = self.secrets.open(
            Direction::ClientToServer,
            MessageType::Application,
            &self.id,
            sequence,
            ciphertext,
        )?;
        state.replay.accept(sequence)?;
        Ok(plaintext)
    }

    pub fn seal_response(&self, sequence: u64, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.secrets
            .seal(
                Direction::ServerToClient,
                MessageType::Application,
                &self.id,
                sequence,
                plaintext,
            )
            .map_err(Into::into)
    }

    fn is_expired_locked(&self, state: &MutableSession, now: Instant) -> bool {
        match state.lifecycle {
            Lifecycle::Pending => now.duration_since(self.created_at) >= PENDING_TTL,
            Lifecycle::Active { expires_at } => now >= expires_at,
        }
    }
}

#[derive(Default)]
struct ReplayWindow {
    highest: u64,
    bitmap: u64,
    initialized: bool,
}

impl ReplayWindow {
    fn accept(&mut self, sequence: u64) -> Result<(), SessionError> {
        if !self.initialized {
            self.highest = sequence;
            self.bitmap = 1;
            self.initialized = true;
            return Ok(());
        }

        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bitmap = if shift >= REPLAY_WINDOW_SIZE {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = sequence;
            return Ok(());
        }

        let distance = self.highest - sequence;
        if distance >= REPLAY_WINDOW_SIZE {
            return Err(SessionError::Replay);
        }
        let bit = 1u64 << distance;
        if self.bitmap & bit != 0 {
            return Err(SessionError::Replay);
        }
        self.bitmap |= bit;
        Ok(())
    }
}

pub struct SessionStore {
    sessions: RwLock<HashMap<[u8; SESSION_ID_LEN], StoredSession>>,
    capacity: Arc<Semaphore>,
    last_capacity_prune: Mutex<Option<Instant>>,
}

struct StoredSession {
    session: Arc<Session>,
    _reservation: SessionReservation,
}

pub struct SessionReservation {
    _permit: OwnedSemaphorePermit,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SESSIONS)
    }
}

impl SessionStore {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            capacity: Arc::new(Semaphore::new(max_sessions)),
            last_capacity_prune: Mutex::new(None),
        }
    }

    pub fn reserve(&self) -> Result<SessionReservation, SessionError> {
        if let Ok(permit) = Arc::clone(&self.capacity).try_acquire_owned() {
            return Ok(SessionReservation { _permit: permit });
        }
        if self.capacity_prune_is_due() {
            self.prune();
            if let Ok(permit) = Arc::clone(&self.capacity).try_acquire_owned() {
                return Ok(SessionReservation { _permit: permit });
            }
        }
        Err(SessionError::Capacity)
    }

    pub fn insert(
        &self,
        session: Session,
        reservation: SessionReservation,
    ) -> Result<Arc<Session>, SessionError> {
        let mut sessions = self.sessions.write().unwrap();
        if sessions.contains_key(session.id()) {
            return Err(SessionError::Collision);
        }
        let session = Arc::new(session);
        sessions.insert(
            *session.id(),
            StoredSession {
                session: Arc::clone(&session),
                _reservation: reservation,
            },
        );
        Ok(session)
    }

    pub fn get(&self, id: &[u8; SESSION_ID_LEN]) -> Result<Arc<Session>, SessionError> {
        let session = self
            .sessions
            .read()
            .unwrap()
            .get(id)
            .map(|stored| Arc::clone(&stored.session));
        match session {
            Some(session) if !session.is_expired(Instant::now()) => Ok(session),
            Some(_) => {
                self.sessions.write().unwrap().remove(id);
                Err(SessionError::InvalidSession)
            }
            None => Err(SessionError::InvalidSession),
        }
    }

    pub fn prune(&self) {
        let now = Instant::now();
        self.sessions
            .write()
            .unwrap()
            .retain(|_, stored| !stored.session.is_expired(now));
    }

    fn capacity_prune_is_due(&self) -> bool {
        let now = Instant::now();
        let mut last_prune = self.last_capacity_prune.lock().unwrap();
        if last_prune.is_some_and(|previous| now.duration_since(previous) < CAPACITY_PRUNE_INTERVAL)
        {
            return false;
        }
        *last_prune = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Direction, MessageType, derive_secrets};

    fn session() -> Session {
        Session::new(
            [1u8; 16],
            [2u8; 32],
            derive_secrets(&[3u8; 32], &[4u8; 32]).unwrap(),
        )
    }

    #[test]
    fn replay_window_accepts_out_of_order_messages_within_64_entries() {
        let mut window = ReplayWindow::default();
        window.accept(70).unwrap();
        window.accept(7).unwrap();
        assert_eq!(window.accept(7), Err(SessionError::Replay));
        assert_eq!(window.accept(6), Err(SessionError::Replay));
    }

    #[test]
    fn store_enforces_capacity() {
        let store = SessionStore::new(1);
        let reservation = store.reserve().unwrap();
        store.insert(session(), reservation).unwrap();
        assert!(matches!(store.reserve(), Err(SessionError::Capacity)));
    }

    #[test]
    fn dropping_an_unused_reservation_releases_capacity() {
        let store = SessionStore::new(1);
        let reservation = store.reserve().unwrap();
        drop(reservation);
        assert!(store.reserve().is_ok());
    }

    #[test]
    fn capacity_reservation_prunes_expired_sessions() {
        let store = SessionStore::new(1);
        let mut expired = session();
        expired.created_at = Instant::now() - PENDING_TTL;
        let reservation = store.reserve().unwrap();
        store.insert(expired, reservation).unwrap();
        assert!(store.reserve().is_ok());
    }

    #[test]
    fn pending_and_active_sessions_expire() {
        let mut pending = session();
        pending.created_at = Instant::now() - PENDING_TTL;
        assert!(pending.is_expired(Instant::now()));

        let active = session();
        active.mutable.lock().unwrap().lifecycle = Lifecycle::Active {
            expires_at: Instant::now() - Duration::from_millis(1),
        };
        assert!(active.is_expired(Instant::now()));
    }

    #[test]
    fn confirmation_activates_session_and_sequence_zero_is_not_application_traffic() {
        let session = session();
        let client_secrets = derive_secrets(&[3u8; 32], &[4u8; 32]).unwrap();
        let ciphertext = client_secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Confirmation,
                session.id(),
                0,
                &[2u8; 32],
            )
            .unwrap();
        session.confirm(0, &ciphertext).unwrap();
        assert_eq!(
            session.open_request(0, &ciphertext),
            Err(SessionError::Replay)
        );
    }

    #[test]
    fn confirm_rejects_a_transcript_hash_mismatch() {
        // Correct shared secret, but the sealed payload is not the session's
        // transcript hash: a client that saw a different handshake transcript
        // (e.g. a tampered server public key) must not be able to confirm.
        let session = session();
        let client_secrets = derive_secrets(&[3u8; 32], &[4u8; 32]).unwrap();
        let ciphertext = client_secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Confirmation,
                session.id(),
                0,
                &[9u8; 32],
            )
            .unwrap();
        assert_eq!(
            session.confirm(0, &ciphertext),
            Err(SessionError::ConfirmationMismatch)
        );
    }

    #[test]
    fn confirm_rejects_confirmation_sealed_with_the_wrong_secrets() {
        // A client that never derived the shared secret cannot confirm, even
        // with the correct transcript hash as plaintext.
        let session = session();
        let wrong_secrets = derive_secrets(&[9u8; 32], &[9u8; 32]).unwrap();
        let ciphertext = wrong_secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Confirmation,
                session.id(),
                0,
                &[2u8; 32],
            )
            .unwrap();
        assert_eq!(
            session.confirm(0, &ciphertext),
            Err(SessionError::Authentication)
        );
    }
}
