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

/// Token activity under a heading per token ID and, within it, per outcome, with a line for each
/// source address: the address, how long ago it last used the token, why it was denied (if it
/// was), and its user agent. Columns line up across all sections.
pub fn render_token_activity(
    records: &[&RecordMetric],
    now: SystemTime,
    width: Option<usize>,
) -> String {
    const OUTCOMES: [&str; 2] = ["accepted", "denied"];
    const INDENT: &str = "    ";
    type Row = [String; 4];

    if records.is_empty() {
        return String::new();
    }

    let mut tokens: BTreeMap<&str, BTreeMap<(usize, &str), Vec<Row>>> = BTreeMap::new();
    let mut sorted = records.to_vec();
    sorted.sort_by_key(|record| std::cmp::Reverse(record.timestamp));
    for record in sorted {
        let outcome = field(record, "outcome");
        let rank = OUTCOMES
            .iter()
            .position(|known| *known == outcome)
            .unwrap_or(OUTCOMES.len());
        let address = match field(record, "private_net_id") {
            "" => field(record, "ip_address").to_string(),
            net => format!("{} ({net})", field(record, "ip_address")),
        };
        let age = format_age(record.timestamp, now)
            .map_or_else(|| "just now".to_string(), |age| format!("{age} ago"));
        tokens
            .entry(field(record, "token_id"))
            .or_default()
            .entry((rank, outcome))
            .or_default()
            .push([
                address,
                age,
                field(record, "reason").to_string(),
                field(record, "user_agent").to_string(),
            ]);
    }

    let header = ["ADDRESS", "LAST USE", "REASON", "USER AGENT"].map(str::to_string);
    let rows = || tokens.values().flat_map(BTreeMap::values).flatten();
    // A column no record has a value for is left out, heading included.
    let widths: [usize; 4] =
        std::array::from_fn(
            |column| match rows().map(|row| row[column].chars().count()).max() {
                Some(0) | None => 0,
                Some(widest) => widest.max(header[column].len()),
            },
        );
    let line = |row: &Row| {
        let mut line = INDENT.to_string();
        for (cell, width) in row.iter().zip(widths) {
            if width > 0 {
                line.push_str(&format!("{cell:<width$}  "));
            }
        }
        let line = line.trim_end();
        match width {
            Some(width) if line.chars().count() > width && width > 1 => {
                let mut cut: String = line.chars().take(width - 1).collect();
                cut.push('…');
                cut
            }
            _ => line.to_string(),
        }
    };

    let mut out = format!("{}\n", line(&header).dimmed());
    for (token_id, outcomes) in &tokens {
        out.push_str(&format!("{}\n", token_id.bold()));
        for ((_, outcome), rows) in outcomes {
            let heading = match *outcome {
                "accepted" => outcome.green().bold(),
                "denied" => outcome.red().bold(),
                _ => outcome.bold(),
            };
            out.push_str(&format!("  {heading}\n"));
            for row in rows {
                out.push_str(&line(row));
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
        let rendered = render_token_activity(&records(&metrics), now, Some(70));
        let expected = [
            "    ADDRESS            LAST USE     REASON         USER AGENT",
            "t",
            "  accepted",
            "    2600:1700::c97a    1m 42s ago                  s2-cli/0.45.0 (cha…",
            "    99.43.255.71       1h ago                      s2-sdk-rust/0.35.1",
            "  denied",
            "    10.0.0.7 (vpce-1)  16m 40s ago  token_revoked  curl/8.5",
            "",
        ]
        .join("\n");
        assert_eq!(rendered, expected);
    }

    #[test]
    fn token_activity_heads_each_token_and_omits_empty_columns() {
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
        let rendered = render_token_activity(&records(&metrics), now, None);
        let expected = "    ADDRESS  LAST USE\na\n  accepted\n    ::2      just now\nb\n  accepted\n    \
                        ::1      1m ago\n";
        assert_eq!(rendered, expected);
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
