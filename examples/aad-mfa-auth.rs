use std::env;

use once_cell::sync::Lazy;
use tiberius::{error::Error, Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        // Using a different connection string that includes Azure AD authentication parameters
        "server=tcp:myserver.database.windows.net,1433;authentication=ActiveDirectoryInteractive;user=myuser@domain.com;TrustServerCertificate=true".to_owned()
    })
});

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = Config::from_ado_string(&CONN_STR)?;

    // Connect with handling for routing responses
    let mut client = connect_with_routing(&mut config).await?;

    let stream = client.query("SELECT @P1", &[&1i32]).await?;
    let row = stream.into_row().await?.unwrap();
    println!("{:?}", row);

    let mut client = connect_with_routing(&mut config).await?;
    let stream = client.query("SELECT @P1", &[&1i32]).await?;
    let row = stream.into_row().await?.unwrap();

    println!("{:?}", row);
    drop(client);

    let mut client = connect_with_routing(&mut config).await?;
    let stream = client.query("SELECT @P1", &[&1i32]).await?;
    let row = stream.into_row().await?.unwrap();

    println!("{:?}", row);

    assert_eq!(Some(1), row.get(0));

    Ok(())
}

async fn connect_with_routing(
    config: &mut Config,
) -> anyhow::Result<Client<tokio_util::compat::Compat<TcpStream>>> {
    loop {
        let tcp = TcpStream::connect(config.get_addr()).await?;
        tcp.set_nodelay(true)?;

        match Client::connect(config.clone(), tcp.compat_write()).await {
            Ok(client) => return Ok(client),
            Err(Error::Routing { host, port }) => {
                println!("Redirecting to: {}:{}", host, port);
                // Update the config with the new routing information
                config.host(&host);
                config.port(port);
                // Try again with the new host/port
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}
