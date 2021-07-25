use std::error::Error;
use std::time::Duration;

use oauth2::basic::BasicTokenType;
use oauth2::TokenResponse;
use reqwest::blocking::Client;
use reqwest::{header, StatusCode};
use serde_json::Value;

use crate::truelayer::TrueLayerAPI;

mod auth;
mod truelayer;

const CRATE_NAME: Option<&str> = option_env!("CARGO_PKG_NAME");
const CRATE_VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

fn main() -> Result<(), Box<dyn Error>> {
    let api = truelayer::TrueLayerSandboxAPI;
    let token = auth::authenticate(&api)?;
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_str(&format!(
            "{}/{}",
            CRATE_NAME.unwrap_or("municipal"),
            CRATE_VERSION.unwrap_or("unknown"),
        ))
        .unwrap(),
    );
    match token.token_type() {
        BasicTokenType::Bearer => {
            headers.insert(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    token.access_token().secret().to_string()
                ))
                .unwrap(),
            );
        }
        _ => {
            panic!("only support Bearer Authorization")
        }
    }
    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .default_headers(headers)
        .build()
        .unwrap();

    let api_host = api.api_host();
    let host = api_host.as_ref();
    let response = client
        .get(format!("https://{}/data/v1/accounts", host))
        .send()
        .unwrap();
    if response.status() != StatusCode::OK {
        panic!(
            "{:?} {}",
            response.status(),
            response.status().canonical_reason().unwrap()
        );
    }
    let result = response.text().unwrap();
    let accounts: Value = serde_json::from_str(&result).unwrap();
    for account in accounts["results"].as_array().unwrap() {
        let acc_id = account["account_id"].as_str().unwrap();
        let response = client
            .get(format!(
                "https://{}/data/v1/accounts/{}/balance",
                host, acc_id
            ))
            .send()
            .unwrap();
        if response.status() != StatusCode::OK {
            panic!(
                "{:?} {}",
                response.status(),
                response.status().canonical_reason().unwrap()
            );
        }
        let result = response.text().unwrap();
        let json: Value = serde_json::from_str(&result).unwrap();
        let balance = json["results"].as_array().unwrap()[0].as_object().unwrap();
        let acc_number = account["account_number"].as_object().unwrap();
        println!(
            "{} {} {} {}{}",
            account["display_name"].as_str().unwrap(),
            acc_number["sort_code"].as_str().unwrap(),
            acc_number["number"].as_str().unwrap(),
            balance["currency"].as_str().unwrap(),
            balance["current"].as_f64().unwrap()
        );
    }

    Ok(())
}
