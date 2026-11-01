//! Registered devices and replay windows (spec §3.4, §4.1, §5.3).

use super::*;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub account: AccountId,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub seq: SeqWindow,
    /// The VAPID public key the gateway subscription is bound to (spec
    /// §4.1, §5.3). `None` only for records from before keys rotated:
    /// [`Store::pin_vapid`] sets them at start.
    #[serde(default)]
    pub vapid: Option<String>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("account", &self.account)
            .field("endpoint", &"<redacted>")
            .field("p256dh", &"<redacted>")
            .field("auth", &"<redacted>")
            .field("seq", &self.seq)
            .field("vapid", &self.vapid)
            .finish()
    }
}

impl Store {
    pub fn register_device(
        &self,
        account: AccountId,
        reg: &DeviceRegistration,
        max_devices: usize,
    ) -> Result<String, StoreError> {
        let mut st = self.state.lock().expect("store lock");
        // Re-registering the same endpoint replaces the old record (spec §4.1).
        st.devices
            .retain(|_, d| !(d.account == account && d.endpoint == reg.endpoint));
        let count = st.devices.values().filter(|d| d.account == account).count();
        if count >= max_devices {
            return Err(StoreError::TooManyDevices);
        }
        let mut seq = SeqWindow::default();
        seq.accept(reg.seq).expect("a fresh window accepts any seq");
        let mut raw = [0u8; 16];
        rand::fill(&mut raw);
        let id = URL_SAFE_NO_PAD.encode(raw);
        st.devices.insert(
            id.clone(),
            Device {
                account,
                endpoint: reg.endpoint.clone(),
                p256dh: reg.keys.p256dh.clone(),
                auth: reg.keys.auth.clone(),
                seq,
                vapid: reg.vapid_public_key.clone(),
            },
        );
        drop(st);
        self.flush_now();
        Ok(id)
    }

    /// Checks `seq` against a device's window. The device must belong to the
    /// account.
    pub fn accept_device_seq(
        &self,
        account: AccountId,
        device_id: &str,
        seq: u64,
    ) -> Result<(), StoreError> {
        let mut st = self.state.lock().expect("store lock");
        let dev = st
            .devices
            .get_mut(device_id)
            .filter(|d| d.account == account)
            .ok_or(StoreError::UnknownDevice)?;
        accept(&mut dev.seq, seq)?;
        *self.dirty.lock().expect("dirty lock") = true;
        Ok(())
    }

    /// Checks `seq` for requests that name no device (spec §3.4).
    pub fn accept_account_seq(&self, account: AccountId, seq: u64) -> Result<(), StoreError> {
        let mut st = self.state.lock().expect("store lock");
        accept(st.account_seq.entry(hex(&account)).or_default(), seq)?;
        *self.dirty.lock().expect("dirty lock") = true;
        Ok(())
    }

    pub fn delete_device(&self, account: AccountId, device_id: &str) -> Result<(), StoreError> {
        let mut st = self.state.lock().expect("store lock");
        match st.devices.get(device_id) {
            Some(d) if d.account == account => {
                st.devices.remove(device_id);
            }
            _ => return Err(StoreError::UnknownDevice),
        }
        drop(st);
        self.flush_now();
        Ok(())
    }

    /// Removes a device whose push subscription is gone (`404`/`410`).
    /// Written with the next periodic flush, not at once: a wake round can
    /// remove many, and one lost in a crash is removed again at the next
    /// push.
    pub fn remove_device(&self, device_id: &str) {
        let removed = self
            .state
            .lock()
            .expect("store lock")
            .devices
            .remove(device_id)
            .is_some();
        if removed {
            *self.dirty.lock().expect("dirty lock") = true;
        }
    }

    /// The VAPID key recorded for the account's device at `endpoint`, if
    /// any.
    pub fn endpoint_vapid(&self, account: AccountId, endpoint: &str) -> Option<String> {
        let st = self.state.lock().expect("store lock");
        st.devices
            .values()
            .find(|d| d.account == account && d.endpoint == endpoint)
            .and_then(|d| d.vapid.clone())
    }

    /// Binds every device with no recorded VAPID key to `current`: records
    /// from before keys rotated were all made under the one key there was.
    /// Run before rotating, so they stay with the old key.
    pub fn pin_vapid(&self, current: &str) {
        let changed = {
            let mut st = self.state.lock().expect("store lock");
            let mut changed = false;
            for d in st.devices.values_mut().filter(|d| d.vapid.is_none()) {
                d.vapid = Some(current.to_owned());
                changed = true;
            }
            changed
        };
        if changed {
            self.flush_now();
        }
    }

    /// Removes devices for which `keep` is false; returns how many.
    pub fn retain_devices(&self, keep: impl Fn(&Device) -> bool) -> usize {
        let removed = {
            let mut st = self.state.lock().expect("store lock");
            let before = st.devices.len();
            st.devices.retain(|_, d| keep(d));
            before - st.devices.len()
        };
        if removed > 0 {
            self.flush_now();
        }
        removed
    }

    /// All devices, for the wake-up scheduler.
    pub fn devices(&self) -> Vec<(String, Device)> {
        let st = self.state.lock().expect("store lock");
        st.devices
            .iter()
            .map(|(id, d)| (id.clone(), d.clone()))
            .collect()
    }
}

fn accept(window: &mut SeqWindow, seq: u64) -> Result<(), StoreError> {
    window.accept(seq).map_err(|e| match e {
        ReplayError::Duplicate(_) | ReplayError::TooOld(_) => StoreError::StaleSeq {
            min_seq: window.min_seq(),
        },
    })
}
