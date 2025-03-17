use std::fmt::Debug;

#[cfg(feature = "aad")]
pub mod token_cache;

#[derive(Clone, PartialEq, Eq)]
pub struct SqlServerAuth {
    pub(crate) user: String,
    pub(crate) password: String,
}

impl SqlServerAuth {
    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

impl Debug for SqlServerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlServerAuth")
            .field("user", &self.user)
            .field("password", &"<HIDDEN>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg(any(all(windows, feature = "winauth"), doc))]
#[cfg_attr(feature = "docs", doc(all(windows, feature = "winauth")))]
pub struct WindowsAuth {
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) domain: Option<String>,
}

#[cfg(any(all(windows, feature = "winauth"), doc))]
#[cfg_attr(feature = "docs", doc(all(windows, feature = "winauth")))]
impl Debug for WindowsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsAuth")
            .field("user", &self.user)
            .field("password", &"<HIDDEN>")
            .field("domain", &self.domain)
            .finish()
    }
}

#[cfg(feature = "aad")]
#[derive(Clone, PartialEq, Eq)]
pub struct AadAuth {
    pub(crate) user: String,
    /// Whether token caching is enabled for this authentication
    pub token_cache_enabled: bool,
}

#[cfg(feature = "aad")]
impl Debug for AadAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AadAuth")
            .field("user", &self.user)
            .field("token_cache_enabled", &self.token_cache_enabled)
            .finish()
    }
}

/// Defines the method of authentication to the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Authenticate directly with SQL Server.
    SqlServer(SqlServerAuth),
    /// Authenticate with Windows credentials.
    #[cfg(any(all(windows, feature = "winauth"), doc))]
    #[cfg_attr(feature = "docs", doc(cfg(all(windows, feature = "winauth"))))]
    Windows(WindowsAuth),
    /// Authenticate as the currently logged in user. On Windows uses SSPI and
    /// Kerberos on Unix platforms.
    #[cfg(any(
        all(windows, feature = "winauth"),
        all(unix, feature = "integrated-auth-gssapi"),
        doc
    ))]
    #[cfg_attr(
        feature = "docs",
        doc(cfg(any(windows, all(unix, feature = "integrated-auth-gssapi"))))
    )]
    Integrated,
    /// Authenticate with an AAD token. The token should encode an AAD user/service principal
    /// which has access to SQL Server.
    AADToken(String),
    #[cfg(feature = "aad")]
    /// Authenticate interactively with AAD. This is useful for CLI applications where the user
    /// can be prompted for credentials via a browser.
    AADInteractive(AadAuth),
    #[doc(hidden)]
    None,
}

impl AuthMethod {
    /// Construct a new SQL Server authentication configuration.
    pub fn sql_server(user: impl ToString, password: impl ToString) -> Self {
        Self::SqlServer(SqlServerAuth {
            user: user.to_string(),
            password: password.to_string(),
        })
    }

    /// Construct a new Windows authentication configuration.
    #[cfg(any(all(windows, feature = "winauth"), doc))]
    #[cfg_attr(feature = "docs", doc(cfg(all(windows, feature = "winauth"))))]
    pub fn windows(user: impl AsRef<str>, password: impl ToString) -> Self {
        let (domain, user) = match user.as_ref().find('\\') {
            Some(idx) => (Some(&user.as_ref()[..idx]), &user.as_ref()[idx + 1..]),
            _ => (None, user.as_ref()),
        };

        Self::Windows(WindowsAuth {
            user: user.to_string(),
            password: password.to_string(),
            domain: domain.map(|s| s.to_string()),
        })
    }

    /// Construct a new configuration with AAD auth token.
    pub fn aad_token(token: impl ToString) -> Self {
        Self::AADToken(token.to_string())
    }

    #[cfg(feature = "aad")]
    /// Construct a new configuration with AAD interactive auth.
    pub fn aad_interactive(user: impl ToString) -> Self {
        Self::AADInteractive(AadAuth {
            user: user.to_string(),
            token_cache_enabled: true, // Enable token caching by default
        })
    }

    #[cfg(feature = "aad")]
    /// Construct a new configuration with AAD interactive auth with explicit cache control
    pub fn aad_interactive_with_cache(user: impl ToString, enable_cache: bool) -> Self {
        Self::AADInteractive(AadAuth {
            user: user.to_string(),
            token_cache_enabled: enable_cache,
        })
    }

    /// Get the current auth configuration as an `AadAuth` if this is an AAD interactive auth method
    #[cfg(feature = "aad")]
    pub fn as_aad_auth(&self) -> Option<&AadAuth> {
        match self {
            Self::AADInteractive(auth) => Some(auth),
            _ => None,
        }
    }
}


#[cfg(test)]
mod tests {
    
    #[tokio::test]
    async fn test_token_cache_operations() -> Result<(), Box<dyn std::error::Error>> {
        use crate::client::token_cache::{TOKEN_CACHE, TokenCacheEntry};
        use std::time::Duration;
        
        // Clear cache before test
        TOKEN_CACHE.clear()?;

        let test_token = TokenCacheEntry::new(
            "test_access_token".to_string(),
            Some("test_refresh_token".to_string()),
            Duration::from_secs(3600),
            "test_user".to_string(),
            "test_tenant".to_string(),
            "test_spn".to_string(),
        );

        // Store token
        TOKEN_CACHE.store_token(test_token.clone())?;

        // Get valid token
        let cached = TOKEN_CACHE.get_valid_token(
            "test_tenant",
            "test_user",
            "test_spn",
        );
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.access_token, "test_access_token");
        assert_eq!(cached.refresh_token, Some("test_refresh_token".to_string()));

        // Clear cache
        TOKEN_CACHE.clear()?;
        
        // Token should be gone
        let cached = TOKEN_CACHE.get_valid_token(
            "test_tenant",
            "test_user",
            "test_spn",
        );
        assert!(cached.is_none());

        Ok(())
    }
}