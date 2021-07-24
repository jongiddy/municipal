use std::error::Error;

use oauth2::TokenResponse;

mod auth;

const CLIENT_ID: &str = "sandbox-municipal-6a4446";

fn main() -> Result<(), Box<dyn Error>> {
    let token = auth::authenticate(CLIENT_ID.to_owned())?;
    dbg!(token.access_token().secret().to_string());
    Ok(())
}
