use std::collections::{HashMap, HashSet};
use std::env;
use std::time::Duration;
use serde_json::{json, Value};

const PREFIX_LIST: &str = "CF_AdBlock_Rust_Part_";
const PREFIX_RULE: &str = "CF_AdBlock_Rust_Policy_";

const CHUNK_SIZE: usize = 1000;
const MAX_DOMAINS: usize = 300_000;
const LISTS_PER_RULE: usize = 100;

const PAGE_SIZE: u64 = 100;
const MAX_PAGES: u64 = 1_000;
const RETRIES: u32 = 3;
const HTTP_TIMEOUT_SECS: u64 = 60;
const USER_AGENT: &str = "cf-gateway-sync/0.1";

type BoxError = Box<dyn std::error::Error>;

struct CfClient {
    account_id: String,
    token: String,
}

impl CfClient {
    fn new(account_id: String, token: String) -> Self {
        Self { account_id, token }
    }

    fn lists_url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/gateway/lists",
            self.account_id
        )
    }

    fn rules_url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/gateway/rules",
            self.account_id
        )
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn backoff_ms(attempt: u32) -> u64 {
        std::cmp::min(10_000, 500 * (1u64 << attempt))
    }

    fn is_retryable(err: &ureq::Error) -> bool {
        match err {
            ureq::Error::Status(code, _) => {
                let code = *code;
                code == 429 || (500..=599).contains(&code)
            }
            ureq::Error::Transport(_) => true,
        }
    }

    fn into_boxed_error(err: ureq::Error) -> BoxError {
        match err {
            ureq::Error::Status(code, response) => {
                let body = response.into_string().unwrap_or_default();
                format!("Cloudflare HTTP {}: {}", code, body).into()
            }
            other => Box::new(other),
        }
    }

    fn check_cf_success(value: Value) -> Result<Value, BoxError> {
        if value.get("success").and_then(Value::as_bool) == Some(false) {
            let errors = value.get("errors").cloned().unwrap_or(json!([]));
            return Err(format!("Cloudflare API error: {}", errors).into());
        }
        Ok(value)
    }

    fn call_with_retry<F>(&self, mut request: F) -> Result<Value, BoxError>
    where
        F: FnMut() -> Result<Value, ureq::Error>,
    {
        let mut last_err: Option<ureq::Error> = None;

        for attempt in 0..=RETRIES {
            match request() {
                Ok(value) => return Self::check_cf_success(value),
                Err(err) => {
                    let retryable = Self::is_retryable(&err);
                    last_err = Some(err);

                    if !retryable || attempt == RETRIES {
                        break;
                    }

                    let delay = Self::backoff_ms(attempt);
                    eprintln!(
                        "Retryable Cloudflare error, attempt {}/{}, sleeping {} ms",
                        attempt + 1,
                        RETRIES,
                        delay
                    );
                    std::thread::sleep(Duration::from_millis(delay));
                }
            }
        }

        match last_err {
            Some(err) => Err(Self::into_boxed_error(err)),
            None => Err("unknown retry error".into()),
        }
    }

    fn get(&self, url: &str) -> Result<Value, BoxError> {
        let auth = self.auth();

        self.call_with_retry(move || {
            let response = ureq::get(url)
                .set("Authorization", &auth)
                .set("User-Agent", USER_AGENT)
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .call()?;

            let value: Value = response.into_json()?;
            Ok(value)
        })
    }

    fn post(&self, url: &str, payload: Value) -> Result<Value, BoxError> {
        let auth = self.auth();

        self.call_with_retry(move || {
            let response = ureq::post(url)
                .set("Authorization", &auth)
                .set("User-Agent", USER_AGENT)
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .send_json(payload.clone())?;

            let value: Value = response.into_json()?;
            Ok(value)
        })
    }

    fn put(&self, url: &str, payload: Value) -> Result<Value, BoxError> {
        let auth = self.auth();

        self.call_with_retry(move || {
            let response = ureq::put(url)
                .set("Authorization", &auth)
                .set("User-Agent", USER_AGENT)
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .send_json(payload.clone())?;

            let value: Value = response.into_json()?;
            Ok(value)
        })
    }

    fn delete(&self, url: &str) -> Result<(), BoxError> {
        let auth = self.auth();
        let mut last_err: Option<ureq::Error> = None;

        for attempt in 0..=RETRIES {
            match ureq::delete(url)
                .set("Authorization", &auth)
                .set("User-Agent", USER_AGENT)
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .call()
            {
                Ok(_) => return Ok(()),
                Err(err) => {
                    let retryable = Self::is_retryable(&err);
                    last_err = Some(err);

                    if !retryable || attempt == RETRIES {
                        break;
                    }

                    let delay = Self::backoff_ms(attempt);
                    eprintln!(
                        "Retryable Cloudflare delete error, attempt {}/{}, sleeping {} ms",
                        attempt + 1,
                        RETRIES,
                        delay
                    );
                    std::thread::sleep(Duration::from_millis(delay));
                }
            }
        }

        match last_err {
            Some(err) => Err(Self::into_boxed_error(err)),
            None => Err("unknown delete error".into()),
        }
    }

    fn get_all(&self, base_url: &str) -> Result<Vec<Value>, BoxError> {
        let mut out = Vec::new();

        for page in 1..=MAX_PAGES {
            let paged_url = format!("{}?page={}&per_page={}", base_url, page, PAGE_SIZE);

            let json = match self.get(&paged_url) {
                Ok(value) => value,
                Err(err) if page == 1 => {
                    eprintln!(
                        "WARN: paginated GET failed, falling back to plain GET: {}",
                        err
                    );
                    self.get(base_url)?
                }
                Err(err) => return Err(err),
            };

            let items = json["result"].as_array().cloned().unwrap_or_default();
            let count = items.len() as u64;
            out.extend(items);

            let total_pages = json["result_info"]["total_pages"].as_u64().unwrap_or(1);

            if count == 0 || page >= total_pages || page == MAX_PAGES {
                if page == MAX_PAGES && page < total_pages {
                    eprintln!("WARN: reached MAX_PAGES while reading {}", base_url);
                }
                break;
            }
        }

        Ok(out)
    }
}

fn required_env(name: &str) -> Result<String, BoxError> {
    env::var(name).map_err(|_| format!("{} is missing", name).into())
}

fn normalize_domain(raw: &str) -> Option<String> {
    let line = raw.trim();

    if line.is_empty()
        || line.starts_with('#')
        || line.starts_with('!')
        || line.starts_with(';')
        || line.starts_with('[')
        || line.starts_with("@@")
    {
        return None;
    }

    let no_comment = line.split('#').next()?.trim();
    if no_comment.is_empty() {
        return None;
    }

    let mut fields = no_comment.split_whitespace();
    let first = fields.next()?;

    let candidate = if first == "0.0.0.0"
        || first == "127.0.0.1"
        || first == "::"
        || first == "::1"
    {
        fields.next()?
    } else {
        first
    };

    let mut domain = candidate.trim().to_lowercase();

    if domain.starts_with("||") {
        domain = domain.trim_start_matches("||").to_string();
    }

    if let Some(pos) = domain.find('^') {
        domain.truncate(pos);
    }

    if let Some(pos) = domain.find('$') {
        domain.truncate(pos);
    }

    while domain.ends_with('^') || domain.ends_with('.') {
        domain.pop();
    }

    while domain.starts_with('.') {
        domain.remove(0);
    }

    if domain.is_empty() || domain == "localhost" || !domain.contains('.') {
        return None;
    }

    if domain.contains("..") || domain.starts_with('-') || domain.ends_with('-') {
        return None;
    }

    if domain
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_'))
    {
        return None;
    }

    if domain
        .rsplit('.')
        .next()
        .map_or(false, |tld| !tld.is_empty() && tld.chars().all(|ch| ch.is_ascii_digit()))
    {
        return None;
    }

    Some(domain)
}

fn parse_domains(text: &str, domains: &mut HashSet<String>) {
    for line in text.lines() {
        if let Some(domain) = normalize_domain(line) {
            domains.insert(domain);
        }
    }
}

fn fetch_domains(urls_env: &str) -> Result<Vec<String>, BoxError> {
    let mut domains = HashSet::new();
    let mut total_sources = 0usize;
    let mut ok_sources = 0usize;

    for url in urls_env.split(',').map(str::trim).filter(|u| !u.is_empty()) {
        total_sources += 1;
        println!("Fetching: {}", url);

        match ureq::get(url)
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .call()
        {
            Ok(response) => match response.into_string() {
                Ok(text) => {
                    ok_sources += 1;
                    parse_domains(&text, &mut domains);
                }
                Err(err) => eprintln!("WARN: failed to read body from {}: {}", url, err),
            },
            Err(err) => eprintln!("WARN: failed to fetch {}: {}", url, err),
        }
    }

    if total_sources == 0 {
        return Err("BLOCKLIST_URLS is empty".into());
    }

    if ok_sources == 0 {
        return Err("all blocklist sources failed".into());
    }

    if domains.is_empty() {
        return Err("no valid domains parsed".into());
    }

    let mut domains: Vec<String> = domains.into_iter().collect();
    domains.sort_unstable();

    if domains.len() > MAX_DOMAINS {
        eprintln!(
            "WARN: truncating domain count {} -> {}",
            domains.len(),
            MAX_DOMAINS
        );
        domains.truncate(MAX_DOMAINS);
    }

    Ok(domains)
}

fn map_prefixed(items: Vec<Value>, prefix: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    for item in items {
        let name = item["name"].as_str().unwrap_or_default();
        let id = item["id"].as_str().unwrap_or_default();

        if name.starts_with(prefix) && !id.is_empty() {
            map.insert(name.to_string(), id.to_string());
        }
    }

    map
}

fn sync_lists(
    client: &CfClient,
    domains: &[String],
    existing_lists: &HashMap<String, String>,
) -> Result<(Vec<String>, HashSet<String>), BoxError> {
    let base_url = client.lists_url();
    let mut target_ids = Vec::new();
    let mut target_names = HashSet::new();

    for (index, chunk) in domains.chunks(CHUNK_SIZE).enumerate() {
        let name = format!("{}{}", PREFIX_LIST, index + 1);
        target_names.insert(name.clone());

        let items: Vec<Value> = chunk.iter().map(|d| json!({ "value": d })).collect();
        let description = "Managed by cf-gateway-sync (Rust)";

        if let Some(id) = existing_lists.get(&name) {
            let payload = json!({
                "name": name,
                "description": description,
                "items": items
            });

            client.put(&format!("{}/{}", base_url, id), payload)?;
            target_ids.push(id.clone());
            println!("Updated list: {}", name);
        } else {
            let payload = json!({
                "name": name,
                "type": "DOMAIN",
                "description": description,
                "items": items
            });

            let response = client.post(&base_url, payload)?;

            let id = response["result"]["id"]
                .as_str()
                .ok_or("Cloudflare create list response missing result.id")?
                .to_string();

            target_ids.push(id);
            println!("Created list: {}", name);
        }
    }

    Ok((target_ids, target_names))
}

fn sync_rules(
    client: &CfClient,
    list_ids: &[String],
    existing_rules: &HashMap<String, String>,
) -> Result<HashSet<String>, BoxError> {
    let base_url = client.rules_url();
    let mut target_names = HashSet::new();

    for (index, chunk) in list_ids.chunks(LISTS_PER_RULE).enumerate() {
        let name = format!("{}{}", PREFIX_RULE, index + 1);
        target_names.insert(name.clone());

        // Рабочий синтаксис Cloudflare Gateway для нескольких списков:
        // any(dns.domains[*] in $id1) or any(dns.domains[*] in $id2) or ...
        let traffic = chunk
            .iter()
            .map(|id| format!("any(dns.domains[*] in ${})", id))
            .collect::<Vec<String>>()
            .join(" or ");

        // precedence убран: при POST Cloudflare поставит правило в конец (низкий приоритет),
        // при PUT сохранит текущую позицию — это предотвращает конфликты с DnsConf.
        let payload = json!({
            "name": name,
            "description": "Auto-generated AdBlock policy",
            "action": "block",
            "filters": ["dns"],
            "traffic": traffic,
            "enabled": true
        });

        if let Some(id) = existing_rules.get(&name) {
            client.put(&format!("{}/{}", base_url, id), payload)?;
            println!("Updated rule: {}", name);
        } else {
            let response = client.post(&base_url, payload)?;

            if response["result"]["id"].as_str().is_none() {
                return Err(
                    format!("Cloudflare create rule response missing result.id for {}", name)
                        .into(),
                );
            }

            println!("Created rule: {}", name);
        }
    }

    Ok(target_names)
}

fn delete_missing(
    client: &CfClient,
    base_url: &str,
    existing: &HashMap<String, String>,
    target: &HashSet<String>,
    kind: &str,
) {
    for (name, id) in existing {
        if target.contains(name) {
            continue;
        }

        let url = format!("{}/{}", base_url, id);

        match client.delete(&url) {
            Ok(_) => println!("Deleted old {}: {}", kind, name),
            Err(err) => eprintln!("WARN: failed to delete old {} {}: {}", kind, name, err),
        }
    }
}

fn main() -> Result<(), BoxError> {
    let api_token = required_env("CF_API_TOKEN")?;
    let account_id = required_env("CF_ACCOUNT_ID")?;
    let urls_env = required_env("BLOCKLIST_URLS")?;

    let domains = fetch_domains(&urls_env)?;

    println!("Total unique domains: {}", domains.len());
    println!("Total chunks to sync: {}", domains.chunks(CHUNK_SIZE).count());

    let client = CfClient::new(account_id, api_token);

    let lists_url = client.lists_url();
    let rules_url = client.rules_url();

    let existing_lists = map_prefixed(client.get_all(&lists_url)?, PREFIX_LIST);
    let existing_rules = map_prefixed(client.get_all(&rules_url)?, PREFIX_RULE);

    let (target_list_ids, target_list_names) =
        sync_lists(&client, &domains, &existing_lists)?;

    // Определяем, какие правила будут существовать после синхронизации.
    // Удаляем старые правила ДО создания новых, чтобы освободить их precedence.
    let target_rule_count = (target_list_ids.len() + LISTS_PER_RULE - 1) / LISTS_PER_RULE;
    let mut target_rule_names = HashSet::new();
    for i in 0..target_rule_count {
        target_rule_names.insert(format!("{}{}", PREFIX_RULE, i + 1));
    }

    delete_missing(
        &client,
        &rules_url,
        &existing_rules,
        &target_rule_names,
        "rule",
    );

    let actual_rule_names = sync_rules(&client, &target_list_ids, &existing_rules)?;

    // Удаляем старые списки после обновления правил.
    delete_missing(
        &client,
        &lists_url,
        &existing_lists,
        &target_list_names,
        "list",
    );

    println!(
        "Sync completed successfully. Rules created/updated: {}",
        actual_rule_names.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_line() {
        assert_eq!(
            normalize_domain("0.0.0.0 Example.COM # comment"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn parses_adblock_line() {
        assert_eq!(
            normalize_domain("||Example.com^"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn skips_comments_and_invalid() {
        assert_eq!(normalize_domain("! comment"), None);
        assert_eq!(normalize_domain("# comment"), None);
        assert_eq!(normalize_domain("1.2.3.4"), None);
        assert_eq!(normalize_domain("localhost"), None);
    }
}
