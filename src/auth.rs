use crate::truelayer::TrueLayerAPI;
use eyre::{bail, ensure, eyre, Result};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use open;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tiny_http::{Method, Request, Response, Server, StatusCode};
use url::Url;

fn extract_authorization_code<'a>(
    url: &'a Url,
    csrf_token: &CsrfToken,
) -> Result<std::borrow::Cow<'a, str>> {
    // Looking for
    // /redirect?code=Mac..dc6&state=DL7jz5YIW4WusaYdDZrXzA%3d%3d&scope=...
    let mut received_code = None;
    let mut received_state = None;
    for pair in url.query_pairs() {
        match pair.0.as_ref() {
            "code" => {
                ensure!(received_code.is_none(), "Duplicate code");
                received_code = Some(pair.1);
            }
            "state" => {
                ensure!(received_state.is_none(), "Duplicate state");
                received_state = Some(pair.1);
            }
            "scope" => {
                // ignore
            }
            parameter => {
                bail!("Unexpected parameter: {} {}", parameter, pair.1.as_ref());
            }
        }
    }
    match received_state {
        None => {
            bail!("No CSRF token received");
        }
        Some(state) => {
            ensure!(state.as_ref() == csrf_token.secret(), "CSRF token mismatch");
        }
    }
    match received_code {
        None => Err(eyre!("No authorization code received")),
        Some(code) => Ok(code),
    }
}

fn handle_request(request: Request, csrf_token: &CsrfToken) -> Result<String> {
    let err = match request.method() {
        Method::Get => {
            let base = Url::parse("http://localhost:3003/")?;
            let url = base.join(request.url())?;
            if url.path() == "/redirect" {
                match extract_authorization_code(&url, &csrf_token) {
                    Ok(code) => {
                        let response = Response::from_string("You may now close this window.");
                        if let Err(respond_err) = request.respond(response) {
                            eprintln!("Error sending HTTP response: {}", respond_err);
                        }
                        return Ok(code.into_owned());
                    }
                    Err(err) => err,
                }
            } else {
                eyre!("Unrecognized path: {}", request.url())
            }
        }
        _ => eyre!("Unsupported method: {}", request.method()),
    };
    let status_code = StatusCode(404);
    let response =
        Response::from_string(status_code.default_reason_phrase()).with_status_code(status_code);
    if let Err(respond_err) = request.respond(response) {
        eprintln!("Error sending HTTP response: {}", respond_err);
    }
    Err(err)
}

fn get_authorization_code(server: &Server, csrf_token: CsrfToken) -> Result<String> {
    for request in server.incoming_requests() {
        match handle_request(request, &csrf_token) {
            Ok(code) => {
                return Ok(code);
            }
            Err(err) => {
                eprintln!("Error handling HTTP request: {}", err);
            }
        }
    }

    Err(eyre!(
        "No more incoming connections and auth code not supplied",
    ))
}

fn start_server() -> Result<Server> {
    // TrueLayer requires an exact match for the redirect URL. To reduce the chance of failing
    // if a fixed port is in use, we try 3 different ports. The app must have 3 registered
    // Redirect URI's: http://localhost:<port>/redirect for each value of <port>
    let mut ports: [u16; 3] = [3003, 17465, 22496];
    // Select ports in random order to prevent herding and add a bit of security through
    // non-deterministic behavior.
    let mut rng = thread_rng();
    ports.shuffle(&mut rng);
    let mut socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    for port in &ports {
        socket.set_port(*port);
        match Server::http(socket) {
            Ok(server) => return Ok(server),
            Err(err) => {
                match err.downcast::<io::Error>() {
                    Ok(io_err) => {
                        ensure!(io_err.kind() == io::ErrorKind::AddrInUse, io_err);
                        // if this port is in use, try the next port
                    }
                    Err(err) => {
                        bail!(err);
                    }
                }
            }
        }
    }
    Err(eyre!("Could not find an available port"))
}

pub fn authenticate(truelayer: &dyn TrueLayerAPI) -> Result<BasicTokenResponse> {
    let server = start_server()?;
    let redirect_url = format!("http://localhost:{}/redirect", server.server_addr().port());

    let credentials = truelayer.credentials()?;

    let client = BasicClient::new(
        ClientId::new(credentials.client_id),
        Some(ClientSecret::new(credentials.client_secret)),
        AuthUrl::new(truelayer.authorize_url())?,
        Some(TokenUrl::new(truelayer.token_url())?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url)?);

    // Setup PKCE code challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("accounts".to_string()))
        .add_scope(Scope::new("balance".to_string()))
        .add_extra_param("providers", "uk-ob-all uk-oauth-all uk-cs-mock")
        .set_pkce_challenge(pkce_challenge)
        .url();

    if let Err(e) = open::that(auth_url.as_str()) {
        println!("{}", e);
        println!("Browse to {}", auth_url);
    }

    let authorization_code = get_authorization_code(&server, csrf_token)?;

    // close down server
    drop(server);

    let token_result = client
        .exchange_code(AuthorizationCode::new(authorization_code))
        .set_pkce_verifier(pkce_verifier)
        .request(http_client)?;

    Ok(token_result)
}
