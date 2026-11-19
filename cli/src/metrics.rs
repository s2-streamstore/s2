//! Output of metric sets beyond the generic per-metric rendering.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use colored::Colorize;
use s2_sdk::types::{
    AccumulationMetric, GaugeMetric, Metric, MetricUnit, RecordMetric, TimeseriesInterval,
};
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

fn timestamp(ts: u32) -> String {
    humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(ts as u64)).to_string()
}

fn value(unit: &MetricUnit, value: f64) -> String {
    match unit {
        // Usage of a small account is fractions of a cent.
        MetricUnit::Usd => format!("{value:.6}"),
        _ => value.to_string(),
    }
}

fn sum(series: &AccumulationMetric) -> f64 {
    series.values.iter().map(|(_, value)| value).sum()
}

/// Two columns under a dimmed heading, the second right-aligned, with the last row in bold if it
/// is a total.
fn table(heading: [&str; 2], rows: &[(String, String)], total: bool) -> String {
    let width = |column: fn(&(String, String)) -> &String, heading: &str| {
        let cells = rows.iter().map(|row| column(row).chars().count());
        cells.chain([heading.len()]).max().unwrap_or_default()
    };
    let (left, right) = (
        width(|row| &row.0, heading[0]),
        width(|row| &row.1, heading[1]),
    );
    let line = |name: &str, value: &str| format!("{name:<left$}  {value:>right$}");

    let mut out = format!("{}\n", line(heading[0], heading[1]).dimmed());
    for (i, (name, value)) in rows.iter().enumerate() {
        let line = line(name, value);
        if total && i + 1 == rows.len() {
            out.push_str(&format!("{}\n", line.bold()));
        } else {
            out.push_str(&format!("{line}\n"));
        }
    }
    out
}

/// Each series summed over the time range it was asked for, and their total if there are several.
pub fn render_sums(start: u32, end: u32, series: &[&AccumulationMetric]) -> String {
    let Some(first) = series.first() else {
        return String::new();
    };
    let mut rows: Vec<(String, String)> = series
        .iter()
        .map(|series| (series.name.clone(), value(&series.unit, sum(series))))
        .collect();
    // A total of unlike units would mean nothing.
    let total = series.len() > 1 && series.iter().all(|series| series.unit == first.unit);
    if total {
        let all = series.iter().map(|series| sum(series)).sum();
        rows.push(("total".to_string(), value(&first.unit, all)));
    }
    format!(
        "{} to {}\n\n{}",
        timestamp(start),
        timestamp(end),
        table(["", format_unit(&first.unit)], &rows, total)
    )
}

/// The latest value of a gauge, then its values over time: all of them, or of a long series, a
/// few spread evenly from the first to the latest.
pub fn render_gauge(gauge: &GaugeMetric) -> String {
    const POINTS: usize = 12;

    let Some((latest_at, latest)) = gauge.values.last() else {
        return String::new();
    };
    let len = gauge.values.len();
    let shown: Vec<usize> = if len <= POINTS {
        (0..len).collect()
    } else {
        (0..POINTS).map(|i| i * (len - 1) / (POINTS - 1)).collect()
    };
    let rows: Vec<(String, String)> = shown
        .iter()
        .map(|i| gauge.values[*i])
        .map(|(ts, point)| (timestamp(ts), value(&gauge.unit, point)))
        .collect();

    let unit = format_unit(&gauge.unit);
    let mut out = format!(
        "{}: {} {unit} at {}\n\n{}",
        gauge.name,
        value(&gauge.unit, *latest).bold(),
        timestamp(*latest_at),
        table(["time", unit], &rows, false)
    );
    if shown.len() < len {
        let note = format!("{} of {len} points, see -o json for all", shown.len());
        out.push_str(&format!("{}\n", note.dimmed()));
    }
    out
}

/// Estimated billable usage in US dollars: each dimension with usage summed over the hours
/// counted, or with `by_interval` the total of each interval. Both end with the total over the
/// range.
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
    let usd = |usd: f64| value(&MetricUnit::Usd, usd);

    let mut out = String::new();
    let (heading, mut rows): (&str, Vec<(String, String)>) = if by_interval {
        let rows = total.values.iter().map(|(ts, v)| (timestamp(*ts), usd(*v)));
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
        let dimensions = series.iter().filter(|series| series.name != TOTAL);
        let rows = dimensions.map(|series| (series.name.clone(), usd(sum(series))));
        ("dimension", rows.collect())
    };
    rows.push((TOTAL.to_string(), usd(sum(total))));
    out.push_str(&table([heading, "usd"], &rows, true));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(name: &str, unit: &str, values: &[(u32, f64)]) -> AccumulationMetric {
        let api = s2_api::v1::metrics::AccumulationMetric {
            name: name.into(),
            unit: s2_api::v1::MaybeKnown::Unknown(unit.into()),
            interval: s2_api::v1::MaybeKnown::Known(s2_api::v1::metrics::TimeseriesInterval::Hour),
            values: values.to_vec(),
        };
        let metric = s2_api::v1::metrics::Metric::Accumulation(api);
        match Metric::from(s2_api::v1::MaybeKnown::Known(metric)) {
            Metric::Accumulation(series) => series,
            _ => unreachable!(),
        }
    }

    fn usd(name: &str, values: &[(u32, f64)]) -> Metric {
        let mut series = series(name, "usd", values);
        series.unit = MetricUnit::Usd;
        Metric::Accumulation(series)
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
    fn default_views_sum_counters_and_sample_gauges() {
        colored::control::set_override(false);
        let appends = [
            series("standard", "operations", &[(0, 2.0), (3600, 3.0)]),
            series("express", "operations", &[(3600, 40.0)]),
        ];
        let expected = [
            "1970-01-01T00:00:00Z to 1970-01-01T02:00:00Z",
            "",
            "          operations",
            "standard           5",
            "express           40",
            "total             45",
            "",
        ]
        .join("\n");
        let appends: Vec<&AccumulationMetric> = appends.iter().collect();
        assert_eq!(render_sums(0, 7200, &appends), expected);

        let api = s2_api::v1::metrics::GaugeMetric {
            name: "storage".into(),
            unit: s2_api::v1::MaybeKnown::Known(s2_api::v1::metrics::MetricUnit::Bytes),
            values: (0..100).map(|i| (i * 60, f64::from(i))).collect(),
        };
        let gauge = s2_api::v1::metrics::Metric::Gauge(api);
        let Metric::Gauge(gauge) = Metric::from(s2_api::v1::MaybeKnown::Known(gauge)) else {
            unreachable!()
        };
        let rendered = render_gauge(&gauge);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "storage: 99 bytes at 1970-01-01T01:39:00Z");
        assert_eq!(lines[3], "1970-01-01T00:00:00Z      0");
        assert_eq!(lines[14], "1970-01-01T01:39:00Z     99");
        assert_eq!(lines[15], "12 of 100 points, see -o json for all");
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
