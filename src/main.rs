use std::error::Error;

use oauth2::TokenResponse;

mod auth;
mod truelayer;

fn main() -> Result<(), Box<dyn Error>> {
    let token = auth::authenticate(&truelayer::TrueLayerSandboxAPI)?;
    dbg!(token.access_token().secret().to_string());
    Ok(())
}
