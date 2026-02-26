use crate::rest_client::RestClient;
use anyhow::Error;
use innernet_shared::{Cidr, Peer, PeerContents};

pub struct RestApi<'a> {
    rest_client: RestClient<'a>,
}

impl<'a> RestApi<'a> {
    pub fn new(rest_client: RestClient<'a>) -> Self {
        Self { rest_client }
    }

    pub fn create_peer(&self, peer_contents: &PeerContents) -> Result<Peer, Error> {
        let peer = self
            .rest_client
            .http_form("POST", "/admin/peers", peer_contents)?;
        Ok(peer)
    }

    pub fn get_peers(&self) -> Result<Vec<Peer>, Error> {
        let peers = self.rest_client.http("GET", "/admin/peers")?;
        Ok(peers)
    }

    pub fn get_cidrs(&self) -> Result<Vec<Cidr>, Error> {
        let cidrs = self.rest_client.http("GET", "/admin/cidrs")?;
        Ok(cidrs)
    }
}
