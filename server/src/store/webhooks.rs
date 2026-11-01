//! Each account's webhook: URL and signing secret (spec §4.5, §6.1).
//! Account configuration, not derived from a viewing key, so it is kept on
//! disk and survives restarts.

use lz_proto::webhook::SigningSecret;

use super::*;

/// An account's webhook, for the delivery worker. `Debug` hides the URL.
#[derive(Clone)]
pub struct Webhook {
    pub account: AccountId,
    pub url: String,
    pub secret: SigningSecret,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook").finish_non_exhaustive()
    }
}

impl Store {
    /// Sets the account's webhook, replacing any earlier one and its
    /// secret. Written to disk before it returns.
    pub fn set_webhook(
        &self,
        account: AccountId,
        url: &str,
        secret: &SigningSecret,
    ) -> std::io::Result<()> {
        let id = hex(&account);
        let record = WebhookRecord {
            url: url.to_owned(),
            secret: secret.encode().to_string(),
        };
        let old = self
            .state
            .lock()
            .expect("store lock")
            .webhooks
            .insert(id.clone(), record);
        if let Err(e) = self.flush_strict() {
            let mut st = self.state.lock().expect("store lock");
            match old {
                Some(o) => st.webhooks.insert(id, o),
                None => st.webhooks.remove(&id),
            };
            return Err(e);
        }
        Ok(())
    }

    /// Removes the account's webhook; returns whether it had one.
    pub fn delete_webhook(&self, account: AccountId) -> bool {
        let removed = self
            .state
            .lock()
            .expect("store lock")
            .webhooks
            .remove(&hex(&account))
            .is_some();
        if removed {
            self.flush_now();
        }
        removed
    }

    /// Every account's webhook.
    pub fn webhooks(&self) -> Vec<Webhook> {
        let st = self.state.lock().expect("store lock");
        st.webhooks
            .iter()
            .filter_map(|(id, w)| {
                Some(Webhook {
                    account: unhex::<16>(id)?,
                    url: w.url.clone(),
                    secret: SigningSecret::parse(&w.secret)?,
                })
            })
            .collect()
    }

    pub fn has_webhook(&self, account: AccountId) -> bool {
        let st = self.state.lock().expect("store lock");
        st.webhooks.contains_key(&hex(&account))
    }
}
