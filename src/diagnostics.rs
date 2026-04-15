use std::{str::FromStr, sync::Arc};

use iroh::{Endpoint, protocol::Router};
use iroh_services::{ApiSecret, CLIENT_HOST_ALPN, Client, ClientHost, caps::NetDiagnosticsCap};
use n0_error::{Result, StackResultExt, StdResultExt};
use tracing::{info, warn};

const IROH_SERVICES_API_KEY: &str = "IROH_SERVICES_API_KEY";

/// Keeps the diagnostics client and router alive for the process lifetime.
pub struct DiagnosticsHandle {
    _client: Arc<Client>,
    _router: Router,
}

/// Read the iroh-services API key from the environment, falling back to a
/// build-time value baked in via `BUILD_IROH_SERVICES_API_KEY`. Returns
/// `None` when neither is set.
pub fn iroh_services_api_key_from_env() -> Result<Option<ApiSecret>> {
    let key_str = match std::env::var(IROH_SERVICES_API_KEY) {
        Ok(s) => s,
        Err(_) => match option_env!("BUILD_IROH_SERVICES_API_KEY") {
            None => return Ok(None),
            Some(s) => s.to_string(),
        },
    };
    let api_secret =
        ApiSecret::from_str(&key_str).context("failed to parse iroh-services API key")?;
    Ok(Some(api_secret))
}

/// Try to start net diagnostics. If an API key is available, connects to
/// iroh-services, grants `NetDiagnosticsCap::GetAny`, and registers a
/// `ClientHost` on a Router so iroh-services can dial back for active probes.
///
/// Returns `None` silently if no API key is configured. Logs a warning and
/// returns `None` if startup fails so the gateway continues without diagnostics.
pub async fn maybe_start(endpoint: &Endpoint) -> Option<DiagnosticsHandle> {
    let api_secret = match iroh_services_api_key_from_env() {
        Ok(Some(s)) => s,
        Ok(None) => {
            info!("net diagnostics disabled: IROH_SERVICES_API_KEY not set");
            return None;
        }
        Err(err) => {
            warn!("failed to read iroh-services API key: {err:#}");
            return None;
        }
    };

    let remote_id = api_secret.addr().id;
    info!(remote = %remote_id.fmt_short(), "connecting to iroh-services for net diagnostics");

    let client_builder = match Client::builder(endpoint).api_secret(api_secret) {
        Ok(b) => b,
        Err(err) => {
            warn!("failed to start net diagnostics, continuing without: {err:#}");
            return None;
        }
    };

    let client = match client_builder
        .build()
        .await
        .std_context("failed to connect to iroh-services")
    {
        Ok(c) => c,
        Err(err) => {
            warn!("failed to start net diagnostics, continuing without: {err:#}");
            return None;
        }
    };

    let grant_client = client.clone();
    tokio::spawn(async move {
        if let Err(err) = grant_client
            .grant_capability(remote_id, vec![NetDiagnosticsCap::GetAny])
            .await
        {
            warn!("failed to grant net diagnostics capability: {err:#}");
        } else {
            info!("granted NetDiagnosticsCap::GetAny to iroh-services");
        }
    });

    let host = ClientHost::new(endpoint);
    let router = Router::builder(endpoint.clone())
        .accept(CLIENT_HOST_ALPN, host)
        .spawn();

    Some(DiagnosticsHandle {
        _client: Arc::new(client),
        _router: router,
    })
}
