# cf-gateway-sync

Автоматическая доставка блок-листов рекламы и трекеров в Cloudflare Zero Trust Gateway.

Дополнение к [noVibe/DnsConf](https://github.com/noVibe/DnsConf): расширяет DNS-блокировку, не трогая Override-правила DnsConf.

## Как это работает

1. **Fetch** — скачивает списки из `BLOCKLIST_URLS` (URL через запятую).
2. **Parse** — извлекает домены из форматов hosts (`0.0.0.0 domain`), adblock (`||domain^`), wildcard (`*.domain`) и plain-списков; пропускает комментарии, IP, `localhost`, невалидные записи.
3. **Dedupe** — убирает точные дубли и сабдомены, чей родитель уже в наборе (селектор Domain блокирует домен со всеми сабдоменами — покрытие сохраняется).
4. **Chunk** — режет на чанки по 1000 записей (лимит списка Cloudflare Standard).
5. **Sync lists** — обновляет существующие `CF_AdBlock_Rust_Part_N`, создаёт недостающие.
6. **Sync rules** — удаляет устаревшие `CF_AdBlock_Rust_Policy_N`, затем создаёт/обновляет актуальные (выражение `any(dns.domains[*] in $list) or ...`).
7. **Cleanup** — удаляет списки, которые больше не нужны.

Трогаются только ресурсы с префиксом `CF_AdBlock_Rust_`; списки и правила DnsConf не изменяются.

## Учтённые лимиты Cloudflare

| Лимит | Значение | Решение в коде |
|---|---|---|
| Размер списка (Standard) | 1 000 записей | `CHUNK_SIZE = 1000` |
| Количество списков на аккаунт | ~277 | `MAX_DOMAINS = 275_000` + сабдомен-dedupe |
| Списков в одном правиле | 100 | `LISTS_PER_RULE = 100` |
| Lists API | 600 req/min | последовательные запросы + retry на 429/5xx |

## Сосуществование с DnsConf

- Правила создаются **без** поля `precedence`: при создании Cloudflare ставит правило в конец (низший приоритет), при обновлении сохраняет позицию.
- Override-правила DnsConf оцениваются раньше, наш Block — последним.

## Структура репозитория

```
.github/workflows/build-release.yml   # сборка release-бинарника + sha256
.github/workflows/cron-sync.yml       # ежедневная синхронизация
src/main.rs                           # вся логика синхронизации
Cargo.toml
README.md
```

## Установка

### 1. Cloudflare API token

Токен с permission `Zero Trust Write` (создание/обновление/удаление Gateway lists и rules).

### 2. GitHub Secrets and variables

**Settings → Secrets and variables → Actions**:

| Тип | Имя | Значение |
|---|---|---|
| Secret | `CF_API_TOKEN` | Cloudflare API token |
| Secret | `CF_ACCOUNT_ID` | Account ID |
| Variable | `BLOCKLIST_URLS` | URL источников через запятую |

Источники по умолчанию:

```
https://small.oisd.nl/domainswild,https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts,https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt
```

### 3. Workflows

- **Build and Release Rust Binary** — сборка при push в `main`, публикация `cf-gateway-sync` и `cf-gateway-sync.sha256` в release `latest`.
- **Daily Cloudflare Sync** — cron `23 4 * * *` (04:23 UTC, после ночной регенерации источников) + ручной `workflow_dispatch`.

## Конфигурация

Константы в начале `src/main.rs`:

| Константа | Значение | Смысл |
|---|---|---|
| `CHUNK_SIZE` | 1000 | записей на список (лимит CF) |
| `MAX_DOMAINS` | 275_000 | потолок доменов (лимит числа списков) |
| `LISTS_PER_RULE` | 100 | списков на правило |
| `RETRIES` | 3 | retry с backoff на 429/5xx и transport-ошибки |
| `HTTP_TIMEOUT_SECS` | 60 | таймаут всех запросов |

## Локальная разработка

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test

CF_API_TOKEN=... CF_ACCOUNT_ID=... BLOCKLIST_URLS=... cargo run
```

## Логи

Ключевые строки успешного прогона:

```
Fetching: https://small.oisd.nl/domainswild
Subdomain dedupe: 277001 -> 225602 (parents cover subdomains)
Total unique domains: 225602
Total chunks to sync: 226
Sync completed successfully. Rules created/updated: 3
```

## Troubleshooting

| Ошибка Cloudflare | Причина | Решение |
|---|---|---|
| `cannot perform this operation on type Array(Bytes)` | неверный синтаксис traffic | `any(dns.domains[*] in $id) or ...` — уже в коде |
| `A rule with this precedence already exists` (409) | конфликт precedence | не передавать `precedence` — уже в коде |
| `Maximum number of lists reached` (2017) | лимит числа списков | сабдомен-dedupe + `MAX_DOMAINS` |
| `list size is limited to 1000 items` | лимит размера списка | `CHUNK_SIZE = 1000` |
| `WARN: failed to fetch ...` | источник недоступен | прогон продолжается с остальными источниками; падает только если упали все |

## Безопасность

- Секреты — только GitHub Secrets; в код и логи не попадают.
- Release-бинарник проверяется sha256-чексуммой перед запуском (альтернатива — сборка из исходников прямо в cron).
- Деструктивные операции (delete) — только над ресурсами с префиксом `CF_AdBlock_Rust_`.
