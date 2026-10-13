//! One retained Charter/Follower and its original tokenless Envoy transport.
pub use cnvy::{
    Error, Result,
    cchr::{ChainPin, Configuration, VerifiedCharter},
    feed::{Config, State},
};
use cnvy::{cchr::Charter, feed::Follower};

/// Where a fingerprint-anchored community lives and what this device pinned.
pub struct Anchor<'a> {
    /// Exact HTTPS origin of the community feed.
    pub origin: &'a str,
    /// Community name the feed is signed for.
    pub community: &'a str,
    /// SHA-256 digest of the genesis document (the founding-key fingerprint).
    pub fingerprint: [u8; 32],
    /// Lowest acceptable feed revision (at least 1).
    pub minimum_revision: u64,
    /// Chain head this device verified before; later feeds must extend it.
    pub pin: Option<ChainPin>,
}
impl Anchor<'_> {
    fn charter(&self) -> Result<Charter> {
        let charter = Charter::from_fingerprint(
            self.origin.to_owned(),
            self.community.to_owned(),
            self.fingerprint,
            self.minimum_revision,
        )
        .map_err(Error::Trust)?;
        match self.pin {
            Some(pin) => charter.with_pin(pin).map_err(Error::Trust),
            None => Ok(charter),
        }
    }
}

/// Public trust state owned by one Foyer. It cannot be cloned, deserialized or
/// populated by a caller-provided policy snapshot. Charter alone verifies feeds.
pub struct Trust {
    charter: Charter,
    /// Set for a fingerprint-anchored community; the chain is walked from genesis.
    fingerprint: Option<[u8; 32]>,
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
        Self::native_with(configuration, config, transport)
    }

    /// Configure the same original Charter/Follower for the isolated literal
    /// wallet's fixed public endpoints. The trusted runtime supplies its wallet
    /// issuer/ring and exact HTTPS origin; no global passport ring is inferred.
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub fn wallet_native(
        configuration: Configuration,
        config: Config,
        roots: &[Vec<u8>],
    ) -> Result<Self> {
        let transport = cnvy::http::Http::wallet_with_roots(&configuration, roots)?;
        Self::native_with(configuration, config, transport)
    }

    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    fn native_with(
        configuration: Configuration,
        config: Config,
        transport: cnvy::http::Http,
    ) -> Result<Self> {
        Ok(Self {
            charter: Charter::new(configuration).map_err(Error::Trust)?,
            fingerprint: None,
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
        Self::browser_with(configuration, config, transport)
    }

    /// Configure the original browser HTTPS follower for the literal wallet
    /// issuer using its two fixed paths and unchanged signed formats.
    #[cfg(all(feature = "browser", target_arch = "wasm32"))]
    pub fn wallet_browser(configuration: Configuration, config: Config) -> Result<Self> {
        let transport = cnvy::browser::Browser::wallet(&configuration)?;
        Self::browser_with(configuration, config, transport)
    }

    #[cfg(all(feature = "browser", target_arch = "wasm32"))]
    fn browser_with(
        configuration: Configuration,
        config: Config,
        transport: cnvy::browser::Browser,
    ) -> Result<Self> {
        Ok(Self {
            charter: Charter::new(configuration).map_err(Error::Trust)?,
            fingerprint: None,
            follower: Follower::new(config)?,
            retry_entropy: config.retry_entropy,
            transport,
        })
    }

    /// Follow a community by its founding-key fingerprint: no key material is
    /// configured, the feed must carry the genesis and an unbroken key chain.
    /// A `pin` recorded by this device earlier forbids rollback and forks.
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub fn anchored_native(anchor: &Anchor<'_>, config: Config, roots: &[Vec<u8>]) -> Result<Self> {
        let transport = cnvy::http::Http::for_origin(anchor.origin, anchor.community, roots)?;
        Self::anchored_with(anchor, config, transport)
    }

    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    fn anchored_with(
        anchor: &Anchor<'_>,
        config: Config,
        transport: cnvy::http::Http,
    ) -> Result<Self> {
        Ok(Self {
            charter: anchor.charter()?,
            fingerprint: Some(anchor.fingerprint),
            follower: Follower::new(config)?,
            retry_entropy: config.retry_entropy,
            transport,
        })
    }

    /// Browser twin of [`Trust::anchored_native`].
    #[cfg(all(feature = "browser", target_arch = "wasm32"))]
    pub fn anchored_browser(anchor: &Anchor<'_>, config: Config) -> Result<Self> {
        let transport = cnvy::browser::Browser::for_origin(anchor.origin, anchor.community)?;
        Ok(Self {
            charter: anchor.charter()?,
            fingerprint: Some(anchor.fingerprint),
            follower: Follower::new(config)?,
            retry_entropy: config.retry_entropy,
            transport,
        })
    }

    /// The founding-key fingerprint this trust is anchored to, if any.
    pub fn fingerprint(&self) -> Option<&[u8; 32]> {
        self.fingerprint.as_ref()
    }

    /// The chain head of the newest verified feed, for the device to pin. It is
    /// the verified value itself, never a hint.
    pub fn chain_pin(&mut self, now: u64) -> Result<ChainPin> {
        Ok(self.current(now)?.chain_pin())
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
