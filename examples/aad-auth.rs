//! Use AAD-Auth to connect to SQL server.
//!
//! To Setup:
//! - Follow this [link](https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?view=azuresql&tabs=azure-powershell) to setup your Azure SQL with AAD auth;
//! - Create an AAD Service Principal [link](https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-service-principal?view=azuresql) and configure it to access your SQL instance;
//! - Setup the environment variable with:
//!   - CLIENT_ID: service principal ID;
//!   - CLIENT_SECRET: service principal secret;
//!   - TENANT_ID: tenant id of service principal and sql instance;
//!   - SERVER: SQL server URI
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use std::env;
use tiberius::{AuthMethod, Client, Config, Query};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // following code will retrive token with AAD Service Principal Auth
    let client_id =
        ClientId::new(env::var("CLIENT_ID").expect("Missing CLIENT_ID environment variable."));
    let client_secret = ClientSecret::new(
        env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET environment variable."),
    );
    let tenant_id = env::var("TENANT_ID").expect("Missing TENANT_ID environment variable.");

    let client = BasicClient::new(client_id)
        .set_client_secret(client_secret)
        .set_auth_uri(AuthUrl::new(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        ))?)
        .set_token_uri(TokenUrl::new(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ))?);

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let token_result = client
        .exchange_client_credentials()
        .add_scope(Scope::new("read".to_string()))
        .request(&http_client)?;

    // This will give you the final token to use in authorization.
    let mut config = Config::new();
    let server = env::var("SERVER").expect("Missing SERVER environment variable.");
    config.host(server);
    config.port(1433);
    config.set_authentication(AuthMethod::AADToken(
        token_result.access_token().secret().to_string(),
    ));
    config.trust_cert();

    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;

    let mut client = Client::connect(config, tcp.compat_write()).await?;
    let params = vec![String::from("foo"), String::from("bar")];
    let mut select = Query::new("SELECT @P1, @P2, @P3");

    for param in params.into_iter() {
        select.bind(param);
    }

    let _res = select.query(&mut client).await?;

    Ok(())
}
