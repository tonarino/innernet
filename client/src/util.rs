use crate::{ClientError, Error};
use colored::*;
use serde::{de::DeserializeOwned, Serialize};
use shared::{interface_config::ServerInfo, INNERNET_PUBKEY_HEADER};
use std::time::Duration;

pub fn human_duration(duration: Duration) -> String {
    match duration.as_secs() {
        n if n < 1 => "just now".cyan().to_string(),
        n if n < 60 => format!("{} {} ago", n, "seconds".cyan()),
        n if n < 60 * 60 => {
            let mins = n / 60;
            let secs = n % 60;
            format!(
                "{} {}, {} {} ago",
                mins,
                if mins == 1 { "minute" } else { "minutes" }.cyan(),
                secs,
                if secs == 1 { "second" } else { "seconds" }.cyan(),
            )
        },
        n => {
            let hours = n / (60 * 60);
            let mins = (n / 60) % 60;
            format!(
                "{} {}, {} {} ago",
                hours,
                if hours == 1 { "hour" } else { "hours" }.cyan(),
                mins,
                if mins == 1 { "minute" } else { "minutes" }.cyan(),
            )
        },
    }
}

pub fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;
    match bytes {
        n if n < 2 * KB => format!("{} {}", n, "B".cyan()),
        n if n < 2 * MB => format!("{:.2} {}", n as f64 / KB as f64, "KiB".cyan()),
        n if n < 2 * GB => format!("{:.2} {}", n as f64 / MB as f64, "MiB".cyan()),
        n if n < 2 * TB => format!("{:.2} {}", n as f64 / GB as f64, "GiB".cyan()),
        n => format!("{:.2} {}", n as f64 / TB as f64, "TiB".cyan()),
    }
}

pub struct Api<'a> {
    server: &'a ServerInfo,
}

impl<'a> Api<'a> {
    pub fn new(server: &'a ServerInfo) -> Self {
        Self { server }
    }

    pub fn http<T: DeserializeOwned>(&self, verb: &str, endpoint: &str) -> Result<T, Error> {
        self.request::<(), _>(verb, endpoint, None)
    }

    pub fn http_form<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: S,
    ) -> Result<T, Error> {
        self.request(verb, endpoint, Some(form))
    }

    fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, Error> {
        let response = ureq::request(
            verb,
            &format!("http://{}/v1{}", self.server.internal_endpoint, endpoint),
        )
        .set(INNERNET_PUBKEY_HEADER, &self.server.public_key)
        .send_json(serde_json::to_value(form)?)?;

        let mut response = response.into_string()?;
        // A little trick for serde to parse an empty response as `()`.
        if response.is_empty() {
            response = "null".into();
        }
        Ok(serde_json::from_str(&response).map_err(|e| {
            ClientError(format!(
                "failed to deserialize JSON response from the server: {}, response={}",
                e, &response
            ))
        })?)
    }
}
