//! Output of metric sets beyond the generic per-metric rendering.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use colored::Colorize;
use s2_sdk::types::{AccumulationMetric, Metric, MetricUnit, RecordMetric, TimeseriesInterval};
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
    // Denials first: they are what a reader checking a policy or a leaked token looks for.
    const OUTCOMES: [&str; 2] = ["denied", "accepted"];
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
                field(record, "context").to_string(),
                field(record, "user_agent").to_string(),
            ]);
    }

    let header = ["ADDRESS", "LAST ACTIVITY", "CONTEXT", "USER AGENT"].map(str::to_string);
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

/// Estimated billable usage in US dollars: each dimension with usage summed over the time range,
/// or with `by_interval` the total of each interval. Both end with the total over the range.
pub fn render_estimated_billable_usage(metrics: &[Metric], by_interval: bool) -> String {
    const TOTAL: &str = "total";

    let series: Vec<&AccumulationMetric> = metrics
        .iter()
        .filter_map(|metric| match metric {
            Metric::Accumulation(series) => Some(series),
            _ => None,
        })
        .collect();
    let Some(total) = series.iter().find(|series| series.name == TOTAL) else {
        return String::new();
    };
    let sum = |series: &AccumulationMetric| series.values.iter().map(|(_, usd)| usd).sum::<f64>();
    let timestamp = |ts: u32| {
        humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(ts as u64)).to_string()
    };

    let mut out = String::new();
    let (heading, mut rows): (&str, Vec<(String, f64)>) = if by_interval {
        let rows = total.values.iter().map(|(ts, usd)| (timestamp(*ts), *usd));
        ("interval start", rows.collect())
    } else {
        // Only finalized hours are counted, so say which hours the sums cover.
        if let (Some((first, _)), Some((last, _))) = (total.values.first(), total.values.last()) {
            let interval = match total.interval {
                TimeseriesInterval::Minute => 60,
                TimeseriesInterval::Hour => 60 * 60,
                TimeseriesInterval::Day => 24 * 60 * 60,
                _ => 0,
            };
            out.push_str(&format!(
                "Estimated billable usage, {} to {}\n\n",
                timestamp(*first),
                timestamp(last.saturating_add(interval))
            ));
        }
        let rows = series
            .iter()
            .filter(|series| series.name != TOTAL)
            .map(|series| (series.name.clone(), sum(series)));
        ("dimension", rows.collect())
    };
    rows.push((TOTAL.to_string(), sum(total)));

    let rows: Vec<(String, String)> = rows
        .into_iter()
        .map(|(name, usd)| (name, format!("{usd:.6}")))
        .collect();
    let name_width = rows
        .iter()
        .map(|(name, _)| name.len())
        .chain([heading.len()])
        .max()
        .unwrap_or_default();
    let usd_width = rows
        .iter()
        .map(|(_, usd)| usd.len())
        .max()
        .unwrap_or_default();
    let line = |name: &str, usd: &str| format!("{name:<name_width$}  {usd:>usd_width$}");

    out.push_str(&format!("{}\n", line(heading, "usd").dimmed()));
    for (i, (name, usd)) in rows.iter().enumerate() {
        let line = line(name, usd);
        if i + 1 == rows.len() {
            out.push_str(&format!("{}\n", line.bold()));
        } else {
            out.push_str(&format!("{line}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd(name: &str, values: &[(u32, f64)]) -> Metric {
        let api = s2_api::v1::metrics::AccumulationMetric {
            name: name.into(),
            unit: s2_api::v1::MaybeKnown::Known(s2_api::v1::metrics::MetricUnit::Usd),
            interval: s2_api::v1::MaybeKnown::Known(s2_api::v1::metrics::TimeseriesInterval::Hour),
            values: values.to_vec(),
        };
        Metric::from(s2_api::v1::MaybeKnown::Known(
            s2_api::v1::metrics::Metric::Accumulation(api),
        ))
    }

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
                    ("context", "token_revoked"),
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
            "    ADDRESS            LAST ACTIVITY  CONTEXT        USER AGENT",
            "t",
            "  denied",
            "    10.0.0.7 (vpce-1)  16m 40s ago    token_revoked  curl/8.5",
            "  accepted",
            "    2600:1700::c97a    1m 42s ago                    s2-cli/0.45.0 (c…",
            "    99.43.255.71       1h ago                        s2-sdk-rust/0.35…",
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
        let expected = [
            "    ADDRESS  LAST ACTIVITY",
            "a",
            "  accepted",
            "    ::2      just now",
            "b",
            "  accepted",
            "    ::1      1m ago",
            "",
        ]
        .join("\n");
        assert_eq!(rendered, expected);
    }

    #[test]
    fn estimated_billable_usage_sums_dimensions_or_lists_interval_totals() {
        colored::control::set_override(false);
        let metrics = [
            usd("ops.stream", &[(0, 0.25), (3600, 1.5)]),
            usd("storage.data", &[(0, 0.000001), (3600, 0.000002)]),
            usd("total", &[(0, 0.250001), (3600, 1.500002)]),
        ];
        let expected = [
            "Estimated billable usage, 1970-01-01T00:00:00Z to 1970-01-01T02:00:00Z",
            "",
            "dimension          usd",
            "ops.stream    1.750000",
            "storage.data  0.000003",
            "total         1.750003",
            "",
        ]
        .join("\n");
        assert_eq!(render_estimated_billable_usage(&metrics, false), expected);

        let expected = [
            "interval start             usd",
            "1970-01-01T00:00:00Z  0.250001",
            "1970-01-01T01:00:00Z  1.500002",
            "total                 1.750003",
            "",
        ]
        .join("\n");
        assert_eq!(render_estimated_billable_usage(&metrics, true), expected);
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
