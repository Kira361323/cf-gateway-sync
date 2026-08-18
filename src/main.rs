use std::collections::{HashMap, HashSet};
use std::env;
use ureq;
use serde_json::json;

const PREFIX_LIST: &str = "CF_AdBlock_Rust_Part_";
const PREFIX_RULE: &str = "CF_AdBlock_Rust_Policy_";
const CHUNK_SIZE: usize = 1000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_token = env::var("CF_API_TOKEN").expect("CF_API_TOKEN is missing");
    let account_id = env::var("CF_ACCOUNT_ID").expect("CF_ACCOUNT_ID is missing");
    let urls_env = env::var("BLOCKLIST_URLS").expect("BLOCKLIST_URLS is missing");
    
    let base_url_lists = format!("https://api.cloudflare.com/client/v4/accounts/{}/gateway/lists", account_id);
    let base_url_rules = format!("https://api.cloudflare.com/client/v4/accounts/{}/gateway/rules", account_id);

    // 1. Скачиваем и парсим домены
    let mut domains = HashSet::new();
    for url in urls_env.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        println!("Fetching: {}", url);
        if let Ok(res) = ureq::get(url).timeout(std::time::Duration::from_secs(15)).call() {
            if let Ok(text) = res.into_string() {
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with('!') { continue; }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let domain = if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                        parts[1]
                    } else {
                        parts[0]
                    };
                    let domain = domain.to_lowercase();
                    if domain.contains('.') && domain != "localhost" {
                        domains.insert(domain);
                    }
                }
            }
        }
    }

    let mut domains: Vec<String> = domains.into_iter().collect();
    domains.sort();
    println!("Total unique domains: {}", domains.len());

    let chunks: Vec<&[String]> = domains.chunks(CHUNK_SIZE).collect();
    println!("Total chunks to sync: {}", chunks.len());

    // 2. Получаем текущие списки из CF (только наши)
    let req_lists = ureq::get(&base_url_lists).set("Authorization", &format!("Bearer {}", api_token)).call()?;
    let json_lists: serde_json::Value = req_lists.into_json()?;
    let mut existing_lists: HashMap<String, String> = HashMap::new();
    
    if let Some(items) = json_lists["result"].as_array() {
        for item in items {
            let name = item["name"].as_str().unwrap_or("");
            if name.starts_with(PREFIX_LIST) {
                existing_lists.insert(name.to_string(), item["id"].as_str().unwrap_or("").to_string());
            }
        }
    }

    // 3. Загружаем чанки
    let mut current_list_ids = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let list_name = format!("{}{}", PREFIX_LIST, i + 1);
        let items: Vec<serde_json::Value> = chunk.iter().map(|d| json!({"value": d})).collect();
        let payload = json!({
            "name": list_name,
            "type": "DOMAIN",
            "description": "Managed by cf-gateway-sync (Rust)",
            "items": items
        });

        if let Some(id) = existing_lists.get(&list_name) {
            let url = format!("{}/{}", base_url_lists, id);
            ureq::put(&url).set("Authorization", &format!("Bearer {}", api_token)).send_json(payload)?;
            current_list_ids.push(id.clone());
            println!("Updated list: {}", list_name);
        } else {
            let res = ureq::post(&base_url_lists).set("Authorization", &format!("Bearer {}", api_token)).send_json(payload)?;
            let res_json: serde_json::Value = res.into_json()?;
            if let Some(id) = res_json["result"]["id"].as_str() {
                current_list_ids.push(id.to_string());
                println!("Created list: {}", list_name);
            }
        }
    }

    // Удаляем наши списки, которые больше не нужны (если база уменьшилась)
    for (name, id) in &existing_lists {
        let index: usize = name.replace(PREFIX_LIST, "").parse().unwrap_or(9999);
        if index > chunks.len() {
            let url = format!("{}/{}", base_url_lists, id);
            let _ = ureq::delete(&url).set("Authorization", &format!("Bearer {}", api_token)).call();
            println!("Deleted old list: {}", name);
        }
    }

    // 4. Управление правилами Firewall (Policies)
    // Разбиваем ID списков по 100 штук на правило (ограничение Cloudflare)
    let policy_chunks: Vec<&[String]> = current_list_ids.chunks(100).collect();
    
    let req_rules = ureq::get(&base_url_rules).set("Authorization", &format!("Bearer {}", api_token)).call()?;
    let json_rules: serde_json::Value = req_rules.into_json()?;
    let mut existing_rules: HashMap<String, String> = HashMap::new();
    
    if let Some(items) = json_rules["result"].as_array() {
        for item in items {
            let name = item["name"].as_str().unwrap_or("");
            if name.starts_with(PREFIX_RULE) {
                existing_rules.insert(name.to_string(), item["id"].as_str().unwrap_or("").to_string());
            }
        }
    }

    for (i, p_chunk) in policy_chunks.iter().enumerate() {
        let rule_name = format!("{}{}", PREFIX_RULE, i + 1);
        let ids_str = p_chunk.iter().map(|s| format!("${}", s)).collect::<Vec<String>>().join(" ");
        let traffic = format!("any(dns.domains in {{{}}})", ids_str);
        
        let payload = json!({
            "name": rule_name,
            "description": "Auto-generated AdBlock policy",
            "precedence": 10000 + i as u64, // Низкий приоритет, чтобы пропускать DnsConf
            "action": "block",
            "filters": ["dns"],
            "traffic": traffic,
            "enabled": true
        });

        if let Some(id) = existing_rules.get(&rule_name) {
            let url = format!("{}/{}", base_url_rules, id);
            ureq::put(&url).set("Authorization", &format!("Bearer {}", api_token)).send_json(payload)?;
            println!("Updated rule: {}", rule_name);
        } else {
            let _ = ureq::post(&base_url_rules).set("Authorization", &format!("Bearer {}", api_token)).send_json(payload)?;
            println!("Created rule: {}", rule_name);
        }
    }

    println!("Sync completed successfully.");
    Ok(())
}
