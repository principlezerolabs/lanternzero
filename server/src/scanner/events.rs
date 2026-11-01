//! Matched payments as events: recording, confirmations and reorgs,
//! acknowledgement, pages, hints, and ping contents (spec §4.3, §4.4,
//! §5.2, invariant 3).

use super::*;

impl Scanner {
    /// Deletes acknowledged events (and so their hints) for the account.
    pub fn ack(&self, account: AccountId, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let mut inner = self.lock();
        if let Some(acct) = inner.events.get_mut(&account) {
            for id in ids {
                acct.by_id.remove(id);
            }
        }
        for id in ids {
            untrack_unfinalized(&mut inner, account, id);
        }
    }

    /// Records matches from a block at `height`. Returns the events that are
    /// new, for alerts. Accounts without an active lease are skipped.
    pub fn record(
        &self,
        block: &CompactBlock,
        matches: &[Match],
        tip: u64,
        now: SystemTime,
    ) -> Vec<(AccountId, Event)> {
        let mut new = Vec::new();
        let mut inner = self.lock();
        for m in matches {
            if inner
                .leases
                .get(&m.account)
                .is_none_or(|l| l.expires_at <= now)
            {
                continue;
            }
            let Some(tx) = block.vtx.get(m.tx) else {
                continue;
            };
            let Ok(txid) = <[u8; 32]>::try_from(&tx.txid[..]) else {
                continue;
            };
            let id = event_id(&self.secret[..], &m.account, &txid, m.pool, m.index);
            let confirmations = confirmations(block.height, tip);
            let compact_tx = URL_SAFE_NO_PAD.encode(tx.encode_to_vec());
            let acct = inner.events.entry(m.account).or_default();
            match acct.by_id.get_mut(&id) {
                Some(s) => {
                    let e = &mut s.event;
                    if e.status == EventStatus::Mined && e.height == Some(block.height) {
                        continue;
                    }
                    e.status = EventStatus::Mined;
                    e.height = Some(block.height);
                    e.confirmations = confirmations;
                    // The block's copy has the transaction's real index.
                    e.compact_tx = Some(compact_tx.clone());
                    e.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                    s.json_len = json_len(e);
                    untrack_unfinalized(&mut inner, m.account, &id);
                    track_unfinalized(&mut inner, m.account, &id, confirmations);
                }
                None => {
                    let event = Event {
                        id: id.clone(),
                        rev: 1,
                        kind: EventKind::Received,
                        status: EventStatus::Mined,
                        height: Some(block.height),
                        confirmations,
                        compact_tx: Some(compact_tx),
                    };
                    let json_len = json_len(&event);
                    acct.last_seq += 1;
                    new.push((m.account, event.clone()));
                    acct.by_id.insert(
                        id.clone(),
                        Stored {
                            event,
                            seq: acct.last_seq,
                            created: now,
                            json_len,
                            payment: webhooks::Payment {
                                txid,
                                pool: m.pool,
                                value: m.value,
                            },
                            delivery: webhooks::Delivery::default(),
                        },
                    );
                    track_unfinalized(&mut inner, m.account, &id, confirmations);
                    maybe_trim_events(&mut inner, m.account);
                }
            }
        }
        new
    }

    /// Records matches in a mempool transaction as `mempool` events. Returns
    /// the new ones, for alerts. An event already known keeps its status,
    /// except that a `reorged` one moves back to `mempool` (spec §4.3).
    pub fn record_mempool(
        &self,
        tx: &CompactTx,
        matches: &[Match],
        now: SystemTime,
    ) -> Vec<(AccountId, Event)> {
        let Ok(txid) = <[u8; 32]>::try_from(&tx.txid[..]) else {
            return vec![];
        };
        let mut new = Vec::new();
        let mut inner = self.lock();
        for m in matches {
            if inner
                .leases
                .get(&m.account)
                .is_none_or(|l| l.expires_at <= now)
            {
                continue;
            }
            let id = event_id(&self.secret[..], &m.account, &txid, m.pool, m.index);
            let acct = inner.events.entry(m.account).or_default();
            match acct.by_id.get_mut(&id) {
                Some(s) if s.event.status == EventStatus::Reorged => {
                    s.event.status = EventStatus::Mempool;
                    s.event.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                    s.json_len = json_len(&s.event);
                }
                Some(_) => {}
                None => {
                    let event = Event {
                        id: id.clone(),
                        rev: 1,
                        kind: EventKind::Received,
                        status: EventStatus::Mempool,
                        height: None,
                        confirmations: 0,
                        compact_tx: Some(URL_SAFE_NO_PAD.encode(tx.encode_to_vec())),
                    };
                    let json_len = json_len(&event);
                    acct.last_seq += 1;
                    new.push((m.account, event.clone()));
                    acct.by_id.insert(
                        id,
                        Stored {
                            event,
                            seq: acct.last_seq,
                            created: now,
                            json_len,
                            payment: webhooks::Payment {
                                txid,
                                pool: m.pool,
                                value: m.value,
                            },
                            delivery: webhooks::Delivery::default(),
                        },
                    );
                    maybe_trim_events(&mut inner, m.account);
                }
            }
        }
        new
    }

    /// Updates confirmations after the tip moved to `tip`.
    pub fn on_tip(&self, tip: u64) {
        let mut inner = self.lock();
        let pending: Vec<_> = inner.unfinalized.clone();
        let mut done = Vec::new();
        for (account, id) in pending {
            let Some(acct) = inner.events.get_mut(&account) else {
                done.push((account, id));
                continue;
            };
            let Some(s) = acct.by_id.get_mut(&id) else {
                done.push((account, id));
                continue;
            };
            let Some(h) = s.event.height else {
                done.push((account, id));
                continue;
            };
            let c = confirmations(h, tip);
            if c != s.event.confirmations {
                s.event.confirmations = c;
                s.event.rev += 1;
                acct.last_seq += 1;
                s.seq = acct.last_seq;
                s.json_len = json_len(&s.event);
            }
            if c >= FINALITY_DEPTH {
                done.push((account, id));
            }
        }
        for (account, id) in done {
            untrack_unfinalized(&mut inner, account, &id);
        }
    }

    /// Marks events in a block that left the best chain as `reorged`.
    pub fn on_disconnect(&self, height: u64) {
        let mut inner = self.lock();
        let accounts: Vec<AccountId> = inner.events.keys().copied().collect();
        let mut remove_unfinalized = Vec::new();
        for account in accounts {
            let Some(acct) = inner.events.get_mut(&account) else {
                continue;
            };
            let ids: Vec<String> = acct
                .by_id
                .iter()
                .filter(|(_, s)| s.event.height == Some(height))
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some(s) = acct.by_id.get_mut(&id) {
                    let e = &mut s.event;
                    e.status = EventStatus::Reorged;
                    e.height = None;
                    e.confirmations = 0;
                    e.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                    s.json_len = json_len(e);
                }
                remove_unfinalized.push((account, id));
            }
        }
        for (account, id) in remove_unfinalized {
            untrack_unfinalized(&mut inner, account, &id);
        }
    }

    /// Events after `after` (all unacknowledged events if `None`), in update
    /// order, as many as fit in `budget` bytes of JSON. An event too large
    /// for a page on its own is sent without its `compact_tx`.
    pub fn page(&self, account: AccountId, after: Option<u64>, budget: usize) -> Page {
        let inner = self.lock();
        let Some(acct) = inner.events.get(&account) else {
            return Page {
                events: vec![],
                cursor: after.unwrap_or(0),
                more: false,
            };
        };
        let mut pending: Vec<&Stored> = acct
            .by_id
            .values()
            .filter(|s| after.is_none_or(|a| s.seq > a))
            .collect();
        pending.sort_unstable_by_key(|s| s.seq);
        let mut events = Vec::new();
        let mut used = 2; // `[]`
        let mut cursor = after.unwrap_or(acct.last_seq);
        let mut taken = 0;
        for s in &pending {
            let mut event = s.event.clone();
            let mut size = s.json_len + 1;
            if size > budget.saturating_sub(2) {
                event.compact_tx = None;
                size = json_len(&event) + 1;
            }
            if used + size > budget {
                break;
            }
            used += size;
            cursor = s.seq;
            events.push(event);
            taken += 1;
        }
        if taken == pending.len() {
            cursor = cursor.max(acct.last_seq);
        }
        Page {
            events,
            cursor,
            more: taken < pending.len(),
        }
    }

    /// Whether the account has events after `after`.
    pub fn has_after(&self, account: AccountId, after: u64) -> bool {
        self.lock()
            .events
            .get(&account)
            .is_some_and(|a| a.by_id.values().any(|s| s.seq > after))
    }

    /// Half-open height ranges holding the account's mined events.
    pub fn hints(&self, account: AccountId) -> Vec<Hint> {
        let inner = self.lock();
        let mut heights: Vec<u64> = inner
            .events
            .get(&account)
            .map(|a| a.by_id.values().filter_map(|s| s.event.height).collect())
            .unwrap_or_default();
        heights.sort_unstable();
        heights.dedup();
        let mut hints: Vec<Hint> = Vec::new();
        for h in heights {
            match hints.last_mut() {
                Some(last) if last.end == h => last.end = h + 1,
                _ => hints.push(Hint {
                    start: h,
                    end: h + 1,
                }),
            }
        }
        hints
    }

    /// Events for the next scheduled ping of a `private`-mode lease (spec
    /// §5.2): up to [`MAX_PING_EVENTS`] unacknowledged ones, oldest first,
    /// without `compact_tx`. Empty for other accounts.
    pub fn ping_events(&self, account: AccountId, now: SystemTime) -> Vec<Event> {
        let inner = self.lock();
        let private = inner
            .leases
            .get(&account)
            .is_some_and(|l| l.expires_at > now && l.alert_mode == AlertMode::Private);
        if !private {
            return vec![];
        }
        let mut stored: Vec<&Stored> = inner
            .events
            .get(&account)
            .map(|a| a.by_id.values().collect())
            .unwrap_or_default();
        stored.sort_unstable_by_key(|s| (s.created, s.seq));
        stored
            .into_iter()
            .take(MAX_PING_EVENTS)
            .map(|s| Event {
                compact_tx: None,
                ..s.event.clone()
            })
            .collect()
    }
}
