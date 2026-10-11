//! One retained Charter/Follower and its original tokenless Envoy transport.
pub use cnvy::{
    Error, Result,
    cchr::{Configuration, VerifiedCharter},
    feed::{Config, State},
};
use cnvy::{cchr::Charter, feed::Follower};

/// Public trust state owned by one Foyer. It cannot be cloned, deserialized or
/// populated by a caller-provided policy snapshot. Charter alone verifies feeds.
pub struct Trust {
    charter: Charter,
    follower: Follower,
    #[cfg(any(
        all(feature = "http", not(target_arch = "wasm32")),
        all(feature = "browser", target_arch = "wasm32")
    ))]
    retry_entropy: u64,
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    transport: cnvy::http::Http,
    #[cfg(all(feature = "browser", target_arch = "wasm32"))]
    transport: cnvy::browser::Browser,
}

impl Trust {
    pub(crate) fn origin(&self) -> &str {
        self.charter.origin()
    }

    /// Configure the native original Envoy HTTPS port and Charter from the same
    /// trust anchor. Explicit operator roots supplement normal TLS validation.
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub fn native(configuration: Configuration, config: Config, roots: &[Vec<u8>]) -> Result<Self> {
        let transport = cnvy::http::Http::with_roots(&configuration, roots)?;
        Ok(Self {
            charter: Charter::new(configuration).map_err(Error::Trust)?,
            follower: Follower::new(config)?,
            retry_entropy: config.retry_entropy,
            transport,
        })
    }

    /// Configure the browser original Envoy Fetch port and Charter from the same
    /// anchor. Its original port omits cookies, bearer, redirects and referrers.
    #[cfg(all(feature = "browser", target_arch = "wasm32"))]
    pub fn browser(configuration: Configuration, config: Config) -> Result<Self> {
        let transport = cnvy::browser::Browser::new(&configuration)?;
        Ok(Self {
            charter: Charter::new(configuration).map_err(Error::Trust)?,
            follower: Follower::new(config)?,
            retry_entropy: config.retry_entropy,
            transport,
        })
    }

    /// Actual exclusive policy deadline is `VerifiedCharter::valid_until()`;
    /// consumers must still check each action's separate authority and revocations.
    pub fn current(&mut self, now: u64) -> Result<&VerifiedCharter> {
        let value = self.charter.current(now).map_err(Error::Trust)?;
        self.follower
            .permits_current(value.revision(), value.policy_epoch(), now)?;
        Ok(value)
    }

    /// Original follower state, without a second readiness flag.
    pub fn state(&self) -> State {
        self.follower.state()
    }

    /// Fence outstanding operations and make retained policy unavailable.
    pub fn stop(&mut self) {
        self.follower.stop();
    }

    /// Request an original bounded refresh; this does not install authority.
    pub fn refresh(&mut self, now: u64) -> Result<()> {
        self.follower.refresh(now)
    }

    /// Forward an untrusted revision hint using the current original revision.
    pub fn on_change(&mut self, revision: u64, now: u64) -> Result<()> {
        let current = self
            .charter
            .current(now)
            .map_or(0, |value| value.revision());
        self.follower.on_change(revision, current, now)
    }

    /// Forward an untrusted epoch hint; Envoy owns its cap and retry rules.
    pub fn on_policy_epoch(&mut self, epoch: u64, now: u64) -> Result<()> {
        let current = self
            .charter
            .current(now)
            .map_or(0, |value| value.policy_epoch());
        self.follower.on_policy_epoch(epoch, current, now)
    }
}

#[cfg(any(
    all(feature = "http", not(target_arch = "wasm32")),
    all(feature = "browser", target_arch = "wasm32")
))]
impl Trust {
    /// Start and finish one original public fetch. The trusted runtime supplies
    /// its clock; completion observes it again after the network await.
    pub async fn start(&mut self, clock: impl Fn() -> u64) -> Result<()> {
        let request = self.follower.start(clock())?;
        self.execute(request, &clock).await
    }

    /// Execute at most one due original poll/fetch. Dropping the future leaves
    /// its operation pending until Envoy's deadline/backoff fences it; no retry
    /// or successful publication is inferred from a cancelled request.
    pub async fn poll(&mut self, clock: impl Fn() -> u64) -> Result<bool> {
        let now = clock();
        let revision = self
            .charter
            .current(now)
            .map_or(0, |value| value.revision());
        let Some(request) = self.follower.next(revision, now)? else {
            return Ok(false);
        };
        self.execute(request, &clock).await?;
        Ok(true)
    }

    async fn execute(
        &mut self,
        request: cnvy::feed::Request,
        clock: &impl Fn() -> u64,
    ) -> Result<()> {
        let received = self.transport.execute(request, clock()).await;
        let now = clock();
        let received = match received {
            Ok(value) => value,
            Err(error) => {
                self.follower
                    .failed(request.id(), now, self.retry_entropy)?;
                return Err(error);
            }
        };
        match request.action() {
            cnvy::feed::Action::Fetch => {
                self.follower
                    .feed(request.id(), received.bytes(), &mut self.charter, now)
            }
            cnvy::feed::Action::Poll { .. } => {
                self.follower
                    .announcement(request.id(), received.bytes(), now)
            }
        }
    }
}
