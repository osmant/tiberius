use tiberius::{Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::test]
async fn login_errors_are_propagated_on_init() -> anyhow::Result<()> {
    let conn_str =
        "server=tcp:localhost,1433;user=SA;password=ObviouslyWrong;TrustServerCertificate=true";

    let config = Config::from_ado_string(conn_str)?;
    let tcp = TcpStream::connect(config.get_addr()).await?;

    tcp.set_nodelay(true)?;

    let res = Client::connect(config, tcp.compat_write()).await;
    assert!(res.is_err());

    let err = res.unwrap_err();
    assert_eq!(Some(18456), err.code());

    Ok(())
}

#[cfg(feature = "aad")]
mod aad_tests {
    use tiberius::{AuthMethod, Config};

    #[test]
    fn test_aad_interactive_auth_cache_enabled() {
        let mut config = Config::new();
        config.set_authentication(AuthMethod::aad_interactive("test_user@domain.com"));
        
        // By default, token cache should be enabled
        if let Some(auth) = config.authentication().as_aad_auth() {
            assert!(auth.token_cache_enabled);
        } else {
            panic!("Expected AADInteractive auth method");
        }
    }

    #[test]
    fn test_aad_interactive_auth_cache_disabled() {
        let mut config = Config::new();
        config.set_authentication(AuthMethod::aad_interactive_with_cache("test_user@domain.com", false));
        
        // Token cache should be disabled
        if let Some(auth) = config.authentication().as_aad_auth() {
            assert!(!auth.token_cache_enabled);
        } else {
            panic!("Expected AADInteractive auth method");
        }
    }
}
