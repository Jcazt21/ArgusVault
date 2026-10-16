//! In-memory, case-insensitive search. Nothing is ever indexed to disk.

use zeroize::Zeroizing;

use crate::model::{Entry, EntryKind};

/// Indices of entries whose title, host, username or URL contains `query`
/// (case-insensitive). An empty query matches everything. Results are
/// sorted by title.
#[must_use]
pub fn search(entries: &[Entry], query: &str) -> Vec<usize> {
    search_kind(entries, query, None)
}

/// Like [`search`], optionally limited to one [`EntryKind`].
#[must_use]
pub fn search_kind(entries: &[Entry], query: &str, kind: Option<EntryKind>) -> Vec<usize> {
    let q = Zeroizing::new(query.trim().to_lowercase());
    let mut hits: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| kind.map_or(true, |k| e.kind == k))
        .filter(|(_, e)| {
            q.is_empty()
                || [&e.title, &e.host, &e.username, &e.url]
                    .iter()
                    .any(|f| Zeroizing::new(f.to_lowercase()).contains(q.as_str()))
        })
        .map(|(i, _)| i)
        .collect();
    hits.sort_by(|&a, &b| {
        let ta = entries.get(a).map(|e| e.title.as_str()).unwrap_or_default();
        let tb = entries.get(b).map(|e| e.title.as_str()).unwrap_or_default();
        ta.chars().flat_map(char::to_lowercase).cmp(tb.chars().flat_map(char::to_lowercase))
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, user: &str, url: &str) -> Entry {
        let mut e = Entry::new(title).unwrap();
        e.username = user.into();
        e.url = url.into();
        e.password = "needle".into();
        e
    }

    #[test]
    fn host_is_searched_and_kind_filters() {
        let mut srv = entry("Prod", "admin", "");
        srv.kind = EntryKind::Server;
        srv.host = "srv-01.corp.local".into();
        let es = vec![srv, entry("Site", "bob", "https://corp.example")];
        assert_eq!(search(&es, "srv-01"), vec![0]);
        assert_eq!(search(&es, "corp"), vec![0, 1]);
        assert_eq!(search_kind(&es, "corp", Some(EntryKind::Web)), vec![1]);
        assert_eq!(search_kind(&es, "", Some(EntryKind::Server)), vec![0]);
    }

    #[test]
    fn matches_fields_case_insensitively() {
        let es = vec![
            entry("GitHub", "alice", "https://github.com"),
            entry("bank", "BOB", "https://bank.example"),
            entry("Email", "carol", ""),
        ];
        assert_eq!(search(&es, ""), vec![1, 2, 0]);
        assert_eq!(search(&es, "GIT"), vec![0]);
        assert_eq!(search(&es, "bob"), vec![1]);
        assert_eq!(search(&es, "example"), vec![1]);
        // Passwords and notes are never searched.
        assert_eq!(search(&es, "needle"), Vec::<usize>::new());
    }
}
