use innernet_shared::{interface_config::ServerInfo, INNERNET_PUBKEY_HEADER};
use serde::{de::DeserializeOwned, Serialize};
use std::{io, time::Duration};
use ureq::{Agent, AgentBuilder};

/// A REST client that can be used to communicate with an innernet REST server.
///
/// It is recommended to use [`crate::rest_api::RestApi`] when possible.
pub struct RestClient<'a> {
    agent: Agent,
    server: &'a ServerInfo,
}

impl<'a> RestClient<'a> {
    /// Create a [`Self`] to communicate with an innernet server described by [`ServerInfo`].
    pub fn new(server: &'a ServerInfo) -> Self {
        let agent = AgentBuilder::new()
            // Some platforms (e.g. OpenBSD) can take longer to complete the first WireGuard
            // handshake, hence a lower timeout value could result in an unwarranted failure
            .timeout(Duration::from_secs(10))
            .redirects(0)
            .build();
        Self { agent, server }
    }

    #[allow(clippy::result_large_err)]
    /// Perform a `verb` HTTP request at the given `endpoint`.
    ///
    /// Example: `rest_client.http("GET", "/admin/peers")?;`.
    pub fn http<T: DeserializeOwned>(&self, verb: &str, endpoint: &str) -> Result<T, ureq::Error> {
        self.request::<(), _>(verb, endpoint, None)
    }

    /// Send serializable data using a `verb` HTTP request at the given `endpoint`
    ///
    /// Example: `rest_client.http_form("POST", "/admin/peers", PeerContents { .. })?;`.
    #[allow(clippy::result_large_err)]
    pub fn http_form<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: S,
    ) -> Result<T, ureq::Error> {
        self.request(verb, endpoint, Some(form))
    }

    #[allow(clippy::result_large_err)]
    fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, ureq::Error> {
        let request = self
            .agent
            .request(
                verb,
                &format!("http://{}/v1{}", self.server.internal_endpoint, endpoint),
            )
            .set(INNERNET_PUBKEY_HEADER, &self.server.public_key);

        let response = if let Some(form) = form {
            request.send_json(serde_json::to_value(form).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to serialize JSON request: {e}"),
                )
            })?)?
        } else {
            request.call()?
        };

        let mut response = response.into_string()?;
        // A little trick for serde to parse an empty response as `()`.
        if response.is_empty() {
            response = "null".into();
        }
        Ok(serde_json::from_str(&response).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to deserialize JSON response from the server: {}, response={}",
                    e, &response
                ),
            )
        })?)
    }
}
