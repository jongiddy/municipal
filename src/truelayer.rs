use serde::Deserialize;
use std::borrow::Cow;
use std::error::Error;
use std::fs::{canonicalize, read_to_string};

#[derive(Deserialize)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}

pub trait TrueLayerAPI {
    fn auth_host(&self) -> Cow<'_, str>;

    fn api_host(&self) -> Cow<'_, str>;

    fn credentials_file(&self) -> &str;

    fn credentials(&self) -> Result<ClientCredentials, Box<dyn Error>> {
        let here = canonicalize(file!())?;
        let top = here.parent().unwrap().parent().unwrap();
        let credentials_file = top.join(self.credentials_file());
        dbg!(&credentials_file);
        let credentials_json = read_to_string(credentials_file)?;
        let credentials = serde_json::from_str::<ClientCredentials>(&credentials_json)?;
        Ok(credentials)
    }

    fn authorize_url(&self) -> String {
        format!("https://{}/", self.auth_host().as_ref())
    }

    fn token_url(&self) -> String {
        format!("https://{}/connect/token", self.auth_host().as_ref())
    }
}

pub struct TrueLayerSandboxAPI;

impl TrueLayerAPI for TrueLayerSandboxAPI {
    fn auth_host(&self) -> Cow<'_, str> {
        Cow::Borrowed("auth.truelayer-sandbox.com")
    }

    fn api_host(&self) -> Cow<'_, str> {
        Cow::Borrowed("api.truelayer-sandbox.com")
    }

    fn credentials_file(&self) -> &str {
        "truelayer-sandbox.json"
    }
}

pub struct TrueLayerLiveAPI;

impl TrueLayerAPI for TrueLayerLiveAPI {
    fn auth_host(&self) -> Cow<'_, str> {
        Cow::Borrowed("auth.truelayer.com")
    }

    fn api_host(&self) -> Cow<'_, str> {
        Cow::Borrowed("api.truelayer.com")
    }

    fn credentials_file(&self) -> &str {
        "truelayer-live.json"
    }
}
