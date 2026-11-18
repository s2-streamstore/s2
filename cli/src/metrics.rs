//! Output of metric sets beyond the generic per-metric rendering.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use colored::Colorize;
use s2_sdk::types::{Metric, MetricUnit, RecordMetric, TimeseriesInterval};
use serde_json::{Value, json};

pub fn format_unit(unit: &MetricUnit) -> &str {
    match unit {
        MetricUnit::Bytes => "bytes",
        MetricUnit::Operations => "operations",
        MetricUnit::Usd => "usd",
        MetricUnit::Unknown(name) => name,
        _ => "unknown",
    }
}

fn format_interval(interval: &TimeseriesInterval) -> &str {
    match interval {
        TimeseriesInterval::Minute => "minute",
        TimeseriesInterval::Hour => "hour",
        TimeseriesInterval::Day => "day",
        TimeseriesInterval::Unknown(name) => name,
        _ => "unknown",
    }
}

/// `2h 5m` for a time in the past, by its two largest units, and `None` for one that is not (a
/// clock behind the server's would otherwise give a negative age).
pub fn format_age(ts: u32, now: SystemTime) -> Option<String> {
    let elapsed = now
        .duration_since(UNIX_EPOCH + Duration::from_secs(ts as u64))
        .ok()?;
    let elapsed = humantime::format_duration(Duration::from_secs(elapsed.as_secs())).to_string();
    let largest: Vec<&str> = elapsed.split(' ').take(2).collect();
    Some(largest.join(" "))
}

/// The metric set in the shape of the API response.
pub fn to_json(metrics: &[Metric]) -> Value {
    let values: Vec<Value> = metrics
        .iter()
        .map(|metric| match metric {
            Metric::Scalar(m) => json!({"scalar": {
                "name": m.name,
                "unit": format_unit(&m.unit),
                "value": m.value,
            }}),
            Metric::Accumulation(m) => json!({"accumulation": {
                "name": m.name,
                "unit": format_unit(&m.unit),
                "interval": format_interval(&m.interval),
                "values": m.values,
            }}),
            Metric::Gauge(m) => json!({"gauge": {
                "name": m.name,
                "unit": format_unit(&m.unit),
                "values": m.values,
            }}),
            Metric::Label(m) => json!({"label": {
                "name": m.name,
                "values": m.values,
            }}),
            Metric::Record(m) => json!({"record": {
                "name": m.name,
                "timestamp": m.timestamp,
                "fields": m.fields,
            }}),
            Metric::Unknown(kind) => json!({ kind: {} }),
            _ => Value::Null,
        })
        .collect();
    json!({ "values": values })
}

fn field<'a>(record: &'a RecordMetric, name: &str) -> &'a str {
    record.fields.get(name).map_or("", String::as_str)
}

/// Token activity as one section per outcome, with a line for each source address: the address,
/// how long ago it last used the token, why it was denied (if it was), and its user agent.
/// Sections are under a token ID heading when the records cover more than one token.
pub fn render_token_activity(
    records: &[&RecordMetric],
    now: SystemTime,
    width: Option<usize>,
) -> String {
    const OUTCOMES: [&str; 2] = ["accepted", "denied"];

    let mut tokens: BTreeMap<&str, BTreeMap<(usize, &str), Vec<&RecordMetric>>> = BTreeMap::new();
    for record in records {
        let outcome = field(record, "outcome");
        let rank = OUTCOMES
            .iter()
            .position(|known| *known == outcome)
            .unwrap_or(OUTCOMES.len());
        tokens
            .entry(field(record, "token_id"))
            .or_default()
            .entry((rank, outcome))
            .or_default()
            .push(record);
    }

    let indent = if tokens.len() > 1 { "  " } else { "" };
    let mut out = String::new();
    for (token_id, outcomes) in tokens {
        if !indent.is_empty() {
            out.push_str(&format!("{}\n", token_id.bold()));
        }
        for ((_, outcome), mut records) in outcomes {
            records.sort_by_key(|record| std::cmp::Reverse(record.timestamp));
            let heading = match outcome {
                "accepted" => outcome.green().bold(),
                "denied" => outcome.red().bold(),
                _ => outcome.bold(),
            };
            out.push_str(&format!("{indent}{heading}\n"));

            let rows: Vec<[String; 4]> = records
                .iter()
                .map(|record| {
                    let address = match field(record, "private_net_id") {
                        "" => field(record, "ip_address").to_string(),
                        net => format!("{} ({net})", field(record, "ip_address")),
                    };
                    let age = format_age(record.timestamp, now)
                        .map_or_else(|| "just now".to_string(), |age| format!("{age} ago"));
                    [
                        address,
                        age,
                        field(record, "reason").to_string(),
                        field(record, "user_agent").to_string(),
                    ]
                })
                .collect();
            let widths: [usize; 3] = std::array::from_fn(|column| {
                rows.iter()
                    .map(|row| row[column].chars().count())
                    .max()
                    .unwrap_or(0)
            });
            for row in rows {
                let mut line = format!("{indent}  ");
                for (cell, width) in row.iter().zip(widths) {
                    if width > 0 {
                        line.push_str(&format!("{cell:<width$}  "));
                    }
                }
                line.push_str(&row[3]);
                let line = line.trim_end();
                match width {
                    Some(width) if line.chars().count() > width && width > 1 => {
                        out.extend(line.chars().take(width - 1));
                        out.push('…');
                    }
                    _ => out.push_str(line),
                }
                out.push('\n');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(timestamp: u32, fields: &[(&str, &str)]) -> Metric {
        let api = s2_api::v1::metrics::RecordMetric {
            name: "last_use".into(),
            timestamp,
            fields: fields
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        };
        Metric::from(s2_api::v1::MaybeKnown::Known(
            s2_api::v1::metrics::Metric::Record(api),
        ))
    }

    fn records(metrics: &[Metric]) -> Vec<&RecordMetric> {
        metrics
            .iter()
            .map(|metric| match metric {
                Metric::Record(record) => record,
                _ => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn token_activity_groups_by_outcome() {
        colored::control::set_override(false);
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let metrics = [
            record(
                6_400,
                &[
                    ("token_id", "t"),
                    ("outcome", "accepted"),
                    ("ip_address", "99.43.255.71"),
                    ("user_agent", "s2-sdk-rust/0.35.1"),
                ],
            ),
            record(
                9_000,
                &[
                    ("token_id", "t"),
                    ("outcome", "denied"),
                    ("ip_address", "10.0.0.7"),
                    ("private_net_id", "vpce-1"),
                    ("reason", "token_revoked"),
                    ("user_agent", "curl/8.5"),
                ],
            ),
            record(
                9_898,
                &[
                    ("token_id", "t"),
                    ("outcome", "accepted"),
                    ("ip_address", "2600:1700::c97a"),
                    ("user_agent", "s2-cli/0.45.0 (channel=source-build)"),
                ],
            ),
        ];
        assert_eq!(
            render_token_activity(&records(&metrics), now, Some(40)),
            "accepted\n  2600:1700::c97a  1m 42s ago  s2-cli/0…\n  99.43.255.71     1h ago      \
             s2-sdk-r…\ndenied\n  10.0.0.7 (vpce-1)  16m 40s ago  token…\n"
        );
    }

    #[test]
    fn token_activity_heads_each_of_several_tokens() {
        colored::control::set_override(false);
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let metrics = [
            record(
                40,
                &[
                    ("token_id", "b"),
                    ("outcome", "accepted"),
                    ("ip_address", "::1"),
                ],
            ),
            record(
                200,
                &[
                    ("token_id", "a"),
                    ("outcome", "accepted"),
                    ("ip_address", "::2"),
                ],
            ),
        ];
        assert_eq!(
            render_token_activity(&records(&metrics), now, None),
            "a\n  accepted\n    ::2  just now\nb\n  accepted\n    ::1  1m ago\n"
        );
    }

    #[test]
    fn json_follows_api_shape() {
        let metrics = [record(7, &[("outcome", "accepted")])];
        assert_eq!(
            to_json(&metrics),
            json!({"values": [{"record": {
                "name": "last_use",
                "timestamp": 7,
                "fields": {"outcome": "accepted"},
            }}]})
        );
    }
}
