use innernet_shared::{
    interface_config::ServerInfo, Cidr, CidrContents, Peer, PeerContents, State,
    INNERNET_PUBKEY_HEADER,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{io, time::Duration};
use thiserror::Error;
use ureq::{Agent, AgentBuilder};

/// A REST client that can be used to communicate with an innernet REST server.
///
/// We recommend to use the high level API (like [`Self::create_peer()`]) when possible and fall
/// back on the low level [`Self::http()`] and [`Self::http_form()`] otherwise.
pub struct RestClient<'a> {
    agent: &'a Agent,
    server: &'a ServerInfo,
}

impl<'a> RestClient<'a> {
    /// Create a [`RestClient`] to communicate with an innernet server described by [`ServerInfo`].
    pub fn new(agent: &'a Agent, server: &'a ServerInfo) -> Self {
        Self { agent, server }
    }

    pub fn create_agent() -> Agent {
        AgentBuilder::new()
            // Some platforms (e.g. OpenBSD) can take longer to complete the first WireGuard
            // handshake, hence a lower timeout value could result in an unwarranted failure
            .timeout(Duration::from_secs(10))
            .redirects(0)
            .build()
    }

    pub fn create_cidr(&self, cidr_contents: &CidrContents) -> Result<Cidr, RestError> {
        let cidr = self.http_form("POST", "/admin/cidrs", cidr_contents)?;
        Ok(cidr)
    }

    pub fn get_cidrs(&self) -> Result<Vec<Cidr>, RestError> {
        let cidrs = self.http("GET", "/admin/cidrs")?;
        Ok(cidrs)
    }

    pub fn create_peer(&self, peer_contents: &PeerContents) -> Result<Peer, RestError> {
        let peer = self.http_form("POST", "/admin/peers", peer_contents)?;
        Ok(peer)
    }

    pub fn get_peers(&self) -> Result<Vec<Peer>, RestError> {
        let peers = self.http("GET", "/admin/peers")?;
        Ok(peers)
    }

    pub fn get_state(&self) -> Result<State, RestError> {
        let state = self.http("GET", "/user/state")?;
        Ok(state)
    }

    #[allow(clippy::result_large_err)]
    /// Perform a `verb` HTTP request at the given `endpoint`.
    ///
    /// Example: `rest_client.http("GET", "/admin/peers")?;`.
    pub fn http<T: DeserializeOwned>(&self, verb: &str, endpoint: &str) -> Result<T, RestError> {
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
    ) -> Result<T, RestError> {
        self.request(verb, endpoint, Some(form))
    }

    #[allow(clippy::result_large_err)]
    fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, RestError> {
        let request = self
            .agent
            .request(
                verb,
                &format!("http://{}/v1{}", self.server.internal_endpoint, endpoint),
            )
            .set(INNERNET_PUBKEY_HEADER, &self.server.public_key);

        let result = if let Some(form) = form {
            let payload = serde_json::to_value(form).map_err(RestError::RequestSerialize)?;
            request.send_json(payload)
        } else {
            request.call()
        };
        let response = result.map_err(|e| RestError::RequestSend(Box::new(e)))?;

        let mut response = response.into_string().map_err(RestError::ResponseRead)?;
        // A little trick for serde to parse an empty response as `()`.
        if response.is_empty() {
            response = "null".into();
        }
        serde_json::from_str(&response).map_err(RestError::ResponseDeserialize)
    }
}

#[derive(Debug, Error)]
pub enum RestError {
    #[error("Error sending request: {0}")]
    RequestSend(Box<ureq::Error>),
    #[error("Error serializing request: {0}")]
    RequestSerialize(serde_json::Error),
    #[error("Error deserializing response: {0}")]
    ResponseDeserialize(serde_json::Error),
    #[error("Error reading response: {0}")]
    ResponseRead(io::Error),
}

impl RestError {
    pub fn has_status_of(&self, status: u16) -> bool {
        if let RestError::RequestSend(error) = self {
            matches!(**error, ureq::Error::Status(s, _) if s == status)
        } else {
            false
        }
    }

    pub fn is_transport_error(&self) -> bool {
        if let RestError::RequestSend(error) = self {
            matches!(**error, ureq::Error::Transport(_))
        } else {
            false
        }
    }
}
