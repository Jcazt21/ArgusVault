//! Icons for well-known websites and self-hosted tools, bundled in the program (no network).
//!
//! 50 single-colour SVGs from Simple Icons (see `icons/ICONS.txt` for source, version, licence and
//! trademark notes). An entry is matched, in this order of preference, by:
//!
//! 1. its URL's host being, or ending in, a known domain (`accounts.google.com` → Google; the
//!    longest matching domain wins, so `mail.google.com` → Gmail and not Google);
//! 2. one of the host's labels being the name of a *self-hosted tool* (`gitlab.corp.local` →
//!    GitLab, `vault.lan` → Vault). Public sites (`GitHub`, Google, `PayPal`…) are never matched this
//!    way;
//! 3. a word of the entry's title being a known name (`GitHub work` → GitHub).
//!
//! The icon is only a visual hint, but in a password manager a wrong one can mislead, so a host
//! that merely *contains* a known domain without ending in it (`github.com.evil.example`,
//! `paypal.com-login.net`) gets no icon at all, not even from the title.
//!
//! Nothing is fetched and nothing is stored: the table is `include_bytes!`ed into the binary.

use std::cell::RefCell;
use std::collections::HashMap;

use slint::Image;

/// One bundled icon.
struct Icon {
    /// File name without extension; also the cache key.
    slug: &'static str,
    /// Domains this icon stands for (the host equals one or ends in `.<domain>`).
    domains: &'static [&'static str],
    /// Words that identify the tool in a host label or in a title.
    names: &'static [&'static str],
    svg: &'static [u8],
}

macro_rules! icon {
    ($slug:literal, [$($d:literal),* $(,)?], [$($n:literal),* $(,)?]) => {
        Icon {
            slug: $slug,
            domains: &[$($d),*],
            names: &[$($n),*],
            svg: include_bytes!(concat!("../icons/", $slug, ".svg")),
        }
    };
}

/// Tools people run themselves, on hosts of their own: only these are matched by a host label.
const SELF_HOSTED: &[&str] = &[
    "gitlab",
    "gitea",
    "vault",
    "portainer",
    "docker",
    "kubernetes",
    "grafana",
    "prometheus",
    "jenkins",
    "proxmox",
    "vmware",
    "nginx",
    "ansible",
    "terraform",
    "sentry",
    "tailscale",
    "nextcloud",
    "bitwarden",
    "jira",
    "confluence",
    "okta",
];

static ICONS: &[Icon] = &[
    icon!("github", ["github.com", "githubusercontent.com"], ["github"]),
    icon!("gitlab", ["gitlab.com"], ["gitlab"]),
    icon!("gitea", ["gitea.io", "gitea.com"], ["gitea"]),
    icon!("bitbucket", ["bitbucket.org"], ["bitbucket"]),
    icon!("vault", ["vaultproject.io", "hashicorp.com"], ["vault", "hashicorp"]),
    icon!("portainer", ["portainer.io"], ["portainer"]),
    icon!("docker", ["docker.com", "docker.io"], ["docker"]),
    icon!("kubernetes", ["kubernetes.io"], ["kubernetes", "k8s"]),
    icon!("grafana", ["grafana.com", "grafana.net"], ["grafana"]),
    icon!("prometheus", ["prometheus.io"], ["prometheus"]),
    icon!("jenkins", ["jenkins.io"], ["jenkins"]),
    icon!("proxmox", ["proxmox.com"], ["proxmox", "pve"]),
    icon!("vmware", ["vmware.com"], ["vmware", "vcenter", "vsphere", "esxi"]),
    icon!("nginx", ["nginx.com", "nginx.org"], ["nginx"]),
    icon!("ansible", ["ansible.com"], ["ansible", "awx"]),
    icon!("terraform", ["terraform.io"], ["terraform"]),
    icon!("sentry", ["sentry.io"], ["sentry"]),
    icon!("tailscale", ["tailscale.com"], ["tailscale"]),
    icon!("nextcloud", ["nextcloud.com"], ["nextcloud"]),
    icon!("bitwarden", ["bitwarden.com", "bitwarden.eu"], ["bitwarden"]),
    icon!("jira", ["jira.com"], ["jira"]),
    icon!("confluence", [], ["confluence"]),
    icon!("notion", ["notion.so", "notion.com"], ["notion"]),
    icon!("trello", ["trello.com"], ["trello"]),
    icon!("figma", ["figma.com"], ["figma"]),
    icon!("zoom", ["zoom.us", "zoom.com"], ["zoom"]),
    icon!("okta", ["okta.com", "oktapreview.com"], ["okta"]),
    icon!("cloudflare", ["cloudflare.com"], ["cloudflare"]),
    icon!("digitalocean", ["digitalocean.com"], ["digitalocean"]),
    icon!("hetzner", ["hetzner.com", "hetzner.cloud"], ["hetzner"]),
    icon!("godaddy", ["godaddy.com"], ["godaddy"]),
    icon!("namecheap", ["namecheap.com"], ["namecheap"]),
    icon!("vercel", ["vercel.com"], ["vercel"]),
    icon!("netlify", ["netlify.com"], ["netlify"]),
    icon!("google", ["google.com"], ["google"]),
    icon!("gmail", ["gmail.com", "mail.google.com"], ["gmail"]),
    icon!("googledrive", ["drive.google.com"], ["drive"]),
    icon!("apple", ["apple.com", "icloud.com"], ["apple", "icloud"]),
    icon!("facebook", ["facebook.com", "fb.com"], ["facebook"]),
    icon!("instagram", ["instagram.com"], ["instagram"]),
    icon!("x", ["x.com", "twitter.com"], ["twitter"]),
    icon!("youtube", ["youtube.com", "youtu.be"], ["youtube"]),
    icon!("reddit", ["reddit.com"], ["reddit"]),
    icon!("discord", ["discord.com", "discord.gg", "discordapp.com"], ["discord"]),
    icon!("telegram", ["telegram.org", "t.me"], ["telegram"]),
    icon!("whatsapp", ["whatsapp.com"], ["whatsapp"]),
    icon!("paypal", ["paypal.com"], ["paypal"]),
    icon!("stripe", ["stripe.com"], ["stripe"]),
    icon!("dropbox", ["dropbox.com"], ["dropbox"]),
    icon!("protonmail", ["proton.me", "protonmail.com", "protonmail.ch"], ["proton", "protonmail"]),
];

/// Lower-case host of a URL: scheme, credentials, port, path, query and fragment removed. Accepts
/// a bare `host/path` too, since people often type URLs without the scheme.
fn host_of(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = match host_port.strip_prefix('[') {
        // IPv6 literal: never an icon.
        Some(_) => return None,
        None => host_port.split(':').next()?,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn ends_with_domain(host: &str, domain: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|before| before.ends_with('.'))
}

/// Index into [`ICONS`] of the icon for an entry with this URL and title, if any.
fn find(url: &str, title: &str) -> Option<usize> {
    if let Some(host) = host_of(url) {
        // 1. Known domain; the longest (most specific) one wins.
        let by_domain = ICONS
            .iter()
            .enumerate()
            .flat_map(|(i, icon)| icon.domains.iter().map(move |d| (i, *d)))
            .filter(|(_, d)| ends_with_domain(&host, d))
            .max_by_key(|(_, d)| d.len())
            .map(|(i, _)| i);
        if by_domain.is_some() {
            return by_domain;
        }
        // A known domain somewhere in the host that is not its ending: a lookalike. No icon.
        if ICONS.iter().flat_map(|icon| icon.domains).any(|d| host.contains(d)) {
            return None;
        }
        // 2. A host label that names a self-hosted tool.
        let labels: Vec<&str> = host.split('.').collect();
        // Never the last label: that is the TLD (`something.zoom` is not Zoom).
        let labels = labels.split_last().map_or(&[][..], |(_, rest)| rest);
        let by_label = ICONS.iter().position(|icon| {
            SELF_HOSTED.contains(&icon.slug) && icon.names.iter().any(|n| labels.contains(n))
        });
        if by_label.is_some() {
            return by_label;
        }
    }
    // 3. A word of the title.
    let title = title.to_lowercase();
    let words: Vec<&str> = title.split(|c: char| !c.is_alphanumeric()).collect();
    ICONS.iter().position(|icon| icon.names.iter().any(|n| words.contains(n)))
}

thread_local! {
    /// Parsed images, built on first use (UI thread only: `Image` is not `Send`).
    static CACHE: RefCell<HashMap<&'static str, Option<Image>>> = RefCell::new(HashMap::new());
}

/// The bundled icon for an entry, if one matches. The image is a single-colour vector: tint it
/// with `colorize` so it follows the theme.
pub(crate) fn for_entry(url: &str, title: &str) -> Option<Image> {
    let icon = ICONS.get(find(url, title)?)?;
    CACHE.with(|cache| {
        cache
            .borrow_mut()
            .entry(icon.slug)
            .or_insert_with(|| Image::load_from_svg_data(icon.svg).ok())
            .clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slug(url: &str, title: &str) -> Option<&'static str> {
        find(url, title).and_then(|i| ICONS.get(i)).map(|i| i.slug)
    }

    #[test]
    fn there_are_fifty_unique_icons_and_each_parses() {
        assert_eq!(ICONS.len(), 50);
        let mut slugs: Vec<_> = ICONS.iter().map(|i| i.slug).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), 50);
        for icon in ICONS {
            assert!(
                Image::load_from_svg_data(icon.svg).is_ok(),
                "{} is not a loadable SVG",
                icon.slug
            );
            assert!(icon.svg.len() < 6000, "{} is suspiciously large", icon.slug);
        }
    }

    #[test]
    fn hosts_are_extracted_from_urls() {
        assert_eq!(
            host_of("https://User:pw@GitHub.com:8443/a/b?c#d").as_deref(),
            Some("github.com")
        );
        assert_eq!(host_of("github.com/login").as_deref(), Some("github.com"));
        assert_eq!(host_of("  http://gitlab.corp.local./x ").as_deref(), Some("gitlab.corp.local"));
        assert_eq!(host_of("https://[::1]:8200/"), None);
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https://"), None);
    }

    #[test]
    fn known_domains_match_including_subdomains() {
        assert_eq!(slug("https://github.com/login", ""), Some("github"));
        assert_eq!(slug("https://gist.github.com", ""), Some("github"));
        assert_eq!(slug("https://accounts.google.com", ""), Some("google"));
        assert_eq!(slug("https://twitter.com", ""), Some("x"));
    }

    #[test]
    fn the_most_specific_domain_wins() {
        assert_eq!(slug("https://mail.google.com", ""), Some("gmail"));
        assert_eq!(slug("https://drive.google.com/x", ""), Some("googledrive"));
    }

    #[test]
    fn lookalike_domains_do_not_match() {
        assert_eq!(slug("https://notgithub.com", ""), None);
        // Contains a known domain without ending in it: a lookalike, no icon (not even by title).
        assert_eq!(slug("https://github.com.evil.example", ""), None);
        assert_eq!(slug("https://paypal.com-login.net", "PayPal"), None);
        assert_eq!(slug("https://login-google.com", ""), None);
        assert_eq!(slug("https://fakegoogle.com", ""), None);
    }

    #[test]
    fn self_hosted_tools_match_on_a_host_label() {
        assert_eq!(slug("https://gitlab.corp.local", ""), Some("gitlab"));
        assert_eq!(slug("http://vault.lan:8200/ui", ""), Some("vault"));
        assert_eq!(slug("https://portainer.mybank.com", ""), Some("portainer"));
        assert_eq!(slug("10.0.0.5:9000", ""), None);
        // The top-level label is never a name.
        assert_eq!(slug("https://something.zoom", ""), None);
        // Public sites are not matched by label: only their real domains get their icon.
        assert_eq!(slug("https://github.intranet.example", ""), None);
        assert_eq!(slug("https://google.intranet.example", ""), None);
    }

    #[test]
    fn the_title_is_a_last_resort() {
        assert_eq!(slug("", "GitHub (work)"), Some("github"));
        assert_eq!(slug("https://intranet.example", "Grafana prod"), Some("grafana"));
        assert_eq!(slug("", "Router"), None);
        // A known domain beats a different name in the title.
        assert_eq!(slug("https://gitlab.com", "github backup"), Some("gitlab"));
    }
}
