use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use once_cell::sync::Lazy;

#[derive(Debug, Clone)]
pub struct TokenCacheEntry {
    /// The access token for authentication
    pub access_token: String,
    /// Optional refresh token that can be used to get a new access token
    pub refresh_token: Option<String>,
    /// When the access token expires
    pub expires_at: SystemTime,
    /// The user associated with this token
    pub username: String,
    /// The tenant ID associated with this token
    pub tenant_id: String,
    /// The service principal name (database server identifier)
    pub spn: String,
}

impl TokenCacheEntry {
    /// Create a new token cache entry
    pub fn new(
        access_token: String, 
        refresh_token: Option<String>,
        expires_in: Duration,
        username: String,
        tenant_id: String,
        spn: String,
    ) -> Self {
        let expires_at = SystemTime::now()
            .checked_add(expires_in)
            .unwrap_or_else(|| SystemTime::now().checked_add(Duration::from_secs(3600)).unwrap());
        
        Self {
            access_token,
            refresh_token,
            expires_at,
            username,
            tenant_id,
            spn,
        }
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Check if the token will expire soon (within the next minute)
    pub fn expires_soon(&self) -> bool {
        match self.expires_at.duration_since(SystemTime::now()) {
            Ok(remaining) => remaining < Duration::from_secs(60),
            Err(_) => true,
        }
    }

    /// Check if the token has a valid refresh token
    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }
}

/// A thread-safe cache for AAD tokens
pub struct TokenCache {
    /// Cache entries keyed by "{tenant_id}:{username}:{spn}"
    entries: RwLock<HashMap<String, TokenCacheEntry>>,
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a cache key from token components
    fn create_key(tenant_id: &str, username: &str, spn: &str) -> String {
        format!("{}:{}:{}", tenant_id, username, spn)
    }

    /// Store a token in the cache
    pub fn store_token(&self, entry: TokenCacheEntry) -> crate::Result<()> {
        let key = Self::create_key(&entry.tenant_id, &entry.username, &entry.spn);
        match self.entries.write() {
            Ok(mut entries) => {
                entries.insert(key, entry);
                Ok(())
            }
            Err(e) => Err(crate::Error::Protocol(format!("Failed to store token: {}", e).into())),
        }
    }

    /// Get a token from the cache if it exists and is valid
    pub fn get_valid_token(&self, tenant_id: &str, username: &str, spn: &str) -> Option<TokenCacheEntry> {
        let key = Self::create_key(tenant_id, username, spn);
        match self.entries.read() {
            Ok(entries) => entries.get(&key).filter(|entry| !entry.is_expired()).cloned(),
            Err(_) => None,
        }
    }

    /// Get a token for refresh if it exists and has a refresh token
    pub fn get_token_for_refresh(&self, tenant_id: &str, username: &str, spn: &str) -> Option<TokenCacheEntry> {
        let key = Self::create_key(tenant_id, username, spn);
        match self.entries.read() {
            Ok(entries) => entries
                .get(&key)
                .filter(|entry| entry.has_refresh_token() && (entry.is_expired() || entry.expires_soon()))
                .cloned(),
            Err(_) => None,
        }
    }

    /// Remove a token from the cache
    pub fn remove_token(&self, tenant_id: &str, username: &str, spn: &str) -> crate::Result<()> {
        let key = Self::create_key(tenant_id, username, spn);
        match self.entries.write() {
            Ok(mut entries) => {
                entries.remove(&key);
                Ok(())
            }
            Err(e) => Err(crate::Error::Protocol(format!("Failed to remove token: {}", e).into())),
        }
    }

    /// Clear all tokens
    pub fn clear(&self) -> crate::Result<()> {
        match self.entries.write() {
            Ok(mut entries) => {
                entries.clear();
                Ok(())
            }
            Err(e) => Err(crate::Error::Protocol(format!("Failed to clear token cache: {}", e).into())),
        }
    }
}

/// Global token cache instance
pub static TOKEN_CACHE: Lazy<Arc<TokenCache>> = Lazy::new(|| Arc::new(TokenCache::new()));