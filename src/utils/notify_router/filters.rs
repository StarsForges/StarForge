//! Event filtering logic for routing rules

use crate::utils::notify_router::events::{Event, Severity};
use chrono::{DateTime, Datelike, NaiveTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

/// Filter conditions for routing rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Filter {
    /// Event type filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<EventTypeFilter>,
    /// Severity filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<SeverityFilter>,
    /// Source filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<StringFilter>,
    /// Time-based filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<TimeFilter>,
    /// Field-based filters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<FieldFilter>>,
}

/// Event type filter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventTypeFilter {
    /// Match specific event type
    Equals(String),
    /// Match any event type except this one
    NotEquals(String),
    /// Match any of the given types
    In(Vec<String>),
    /// Match event types starting with prefix
    StartsWith(String),
}

/// Severity filter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SeverityFilter {
    /// Match specific severity
    Equals(Severity),
    /// Match severities at or above this level
    AtLeast(Severity),
    /// Match severities at or below this level
    AtMost(Severity),
    /// Match any of the given severities
    In(Vec<Severity>),
}

/// String filter for source, metadata, and string fields
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StringFilter {
    /// Exact match
    Equals(String),
    /// Not equal
    NotEquals(String),
    /// Case-insensitive match
    EqualsIgnoreCase(String),
    /// Contains substring
    Contains(String),
    /// Starts with prefix
    StartsWith(String),
    /// Ends with suffix
    EndsWith(String),
    /// Match regex pattern
    Matches(String),
    /// Match any of the given values
    In(Vec<String>),
}

/// Time-based filter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TimeFilter {
    /// Only match events after this time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<DateTime<Utc>>,
    /// Only match events before this time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<DateTime<Utc>>,
    /// Only match on specific days of week (0=Sunday, 6=Saturday)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_of_week: Option<Vec<u8>>,
    /// Only match during specific hours (0-23)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hours: Option<Vec<u32>>,
}

/// Field-based filter for event data and envelope properties
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldFilter {
    /// JSON path to the field (e.g., "data.command", "data.exit_code", "metadata.env")
    pub path: String,
    /// Filter operation
    pub op: FieldOp,
}

/// Field operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FieldOp {
    /// String equals
    Equals(String),
    /// String not equals
    NotEquals(String),
    /// String contains
    Contains(String),
    /// String starts with
    StartsWith(String),
    /// String ends with
    EndsWith(String),
    /// Regex match
    Matches(String),
    /// Number greater than
    Gt(f64),
    /// Number greater than or equal to
    Gte(f64),
    /// Number less than
    Lt(f64),
    /// Number less than or equal to
    Lte(f64),
    /// Number equals
    Eq(f64),
    /// Boolean equals
    Bool(bool),
    /// Value exists (field is present and not null)
    Exists,
    /// Value is null or absent
    IsNull,
}

impl Filter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an event matches this filter
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(ref event_type_filter) = self.event_type {
            if !self.matches_event_type(event, event_type_filter) {
                return false;
            }
        }

        if let Some(ref severity_filter) = self.severity {
            if !self.matches_severity(event, severity_filter) {
                return false;
            }
        }

        if let Some(ref source_filter) = self.source {
            if !self.matches_source(event, source_filter) {
                return false;
            }
        }

        if let Some(ref time_filter) = self.time {
            if !self.matches_time(event, time_filter) {
                return false;
            }
        }

        if let Some(ref field_filters) = self.fields {
            if !self.matches_fields(event, field_filters) {
                return false;
            }
        }

        true
    }

    fn matches_event_type(&self, event: &Event, filter: &EventTypeFilter) -> bool {
        let event_type_str = event.event_type.to_string();
        match filter {
            EventTypeFilter::Equals(t) => event_type_str == *t,
            EventTypeFilter::NotEquals(t) => event_type_str != *t,
            EventTypeFilter::In(types) => types.contains(&event_type_str),
            EventTypeFilter::StartsWith(prefix) => event_type_str.starts_with(prefix),
        }
    }

    fn matches_severity(&self, event: &Event, filter: &SeverityFilter) -> bool {
        match filter {
            SeverityFilter::Equals(s) => event.severity == *s,
            SeverityFilter::AtLeast(s) => event.severity >= *s,
            SeverityFilter::AtMost(s) => event.severity <= *s,
            SeverityFilter::In(severities) => severities.contains(&event.severity),
        }
    }

    fn matches_source(&self, event: &Event, filter: &StringFilter) -> bool {
        Self::eval_string_filter(&event.source, filter)
    }

    pub fn eval_string_filter(value: &str, filter: &StringFilter) -> bool {
        match filter {
            StringFilter::Equals(s) => value == s,
            StringFilter::NotEquals(s) => value != s,
            StringFilter::EqualsIgnoreCase(s) => value.eq_ignore_ascii_case(s),
            StringFilter::Contains(s) => value.contains(s),
            StringFilter::StartsWith(s) => value.starts_with(s),
            StringFilter::EndsWith(s) => value.ends_with(s),
            StringFilter::Matches(pattern) => regex::Regex::new(pattern)
                .map(|re| re.is_match(value))
                .unwrap_or(false),
            StringFilter::In(values) => values.iter().any(|v| v == value),
        }
    }

    fn matches_time(&self, event: &Event, filter: &TimeFilter) -> bool {
        if let Some(after) = filter.after {
            if event.timestamp < after {
                return false;
            }
        }

        if let Some(before) = filter.before {
            if event.timestamp > before {
                return false;
            }
        }

        if let Some(ref days) = filter.days_of_week {
            let day = event.timestamp.weekday().num_days_from_sunday() as u8;
            if !days.contains(&day) {
                return false;
            }
        }

        if let Some(ref hours) = filter.hours {
            if !hours.contains(&event.timestamp.hour()) {
                return false;
            }
        }

        true
    }

    fn matches_fields(&self, event: &Event, filters: &[FieldFilter]) -> bool {
        let event_value = serde_json::to_value(event).unwrap_or_default();

        filters.iter().all(|filter| {
            let field_value = self.get_field_value(&event_value, &filter.path);
            self.matches_field_op(&field_value, &filter.op)
        })
    }

    fn get_field_value(&self, value: &serde_json::Value, path: &str) -> serde_json::Value {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value.clone();

        for part in parts {
            if let Some(obj) = current.as_object() {
                current = obj.get(part).cloned().unwrap_or(serde_json::Value::Null);
            } else if let Some(arr) = current.as_array() {
                if let Ok(index) = part.parse::<usize>() {
                    current = arr.get(index).cloned().unwrap_or(serde_json::Value::Null);
                } else {
                    return serde_json::Value::Null;
                }
            } else {
                return serde_json::Value::Null;
            }
        }

        current
    }

    fn matches_field_op(&self, value: &serde_json::Value, op: &FieldOp) -> bool {
        match op {
            FieldOp::Equals(s) => value.as_str().map(|v| v == s).unwrap_or(false),
            FieldOp::NotEquals(s) => value.as_str().map(|v| v != s).unwrap_or(true),
            FieldOp::Contains(s) => value.as_str().map(|v| v.contains(s)).unwrap_or(false),
            FieldOp::StartsWith(s) => value.as_str().map(|v| v.starts_with(s)).unwrap_or(false),
            FieldOp::EndsWith(s) => value.as_str().map(|v| v.ends_with(s)).unwrap_or(false),
            FieldOp::Matches(pat) => value
                .as_str()
                .and_then(|v| regex::Regex::new(pat).ok().map(|re| re.is_match(v)))
                .unwrap_or(false),
            FieldOp::Gt(n) => value.as_f64().map(|v| v > *n).unwrap_or(false),
            FieldOp::Gte(n) => value.as_f64().map(|v| v >= *n).unwrap_or(false),
            FieldOp::Lt(n) => value.as_f64().map(|v| v < *n).unwrap_or(false),
            FieldOp::Lte(n) => value.as_f64().map(|v| v <= *n).unwrap_or(false),
            FieldOp::Eq(n) => value
                .as_f64()
                .map(|v| (v - n).abs() < f64::EPSILON)
                .unwrap_or(false),
            FieldOp::Bool(b) => value.as_bool().map(|v| v == *b).unwrap_or(false),
            FieldOp::Exists => !value.is_null(),
            FieldOp::IsNull => value.is_null(),
        }
    }
}

/// Evaluates if the current time or event timestamp is within a quiet hours window
pub fn is_in_quiet_hours(timestamp: &DateTime<Utc>, start_hh_mm: &str, end_hh_mm: &str) -> bool {
    let start = match NaiveTime::parse_from_str(start_hh_mm, "%H:%M") {
        Ok(t) => t,
        Err(_) => return false,
    };
    let end = match NaiveTime::parse_from_str(end_hh_mm, "%H:%M") {
        Ok(t) => t,
        Err(_) => return false,
    };

    let event_time = timestamp.time();

    if start <= end {
        // Quiet hours within the same calendar day (e.g. 13:00 to 15:00)
        event_time >= start && event_time < end
    } else {
        // Quiet hours cross midnight (e.g. 22:00 to 07:00)
        event_time >= start || event_time < end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::notify_router::events::{CommandOutcomeData, EventData, EventType};
    use chrono::TimeZone;

    #[test]
    fn test_filter_event_type() {
        let event = Event::new(EventType::CommandOutcome, "Test");

        let filter = Filter {
            event_type: Some(EventTypeFilter::Equals("command_outcome".to_string())),
            ..Default::default()
        };
        assert!(filter.matches(&event));

        let filter = Filter {
            event_type: Some(EventTypeFilter::Equals("deployment".to_string())),
            ..Default::default()
        };
        assert!(!filter.matches(&event));

        let filter = Filter {
            event_type: Some(EventTypeFilter::StartsWith("command_".to_string())),
            ..Default::default()
        };
        assert!(filter.matches(&event));
    }

    #[test]
    fn test_filter_severity() {
        let event = Event::new(EventType::CommandOutcome, "Test").with_severity(Severity::Error);

        let filter = Filter {
            severity: Some(SeverityFilter::AtLeast(Severity::Warning)),
            ..Default::default()
        };
        assert!(filter.matches(&event));

        let filter = Filter {
            severity: Some(SeverityFilter::AtMost(Severity::Warning)),
            ..Default::default()
        };
        assert!(!filter.matches(&event));

        let filter = Filter {
            severity: Some(SeverityFilter::AtLeast(Severity::Critical)),
            ..Default::default()
        };
        assert!(!filter.matches(&event));
    }

    #[test]
    fn test_filter_source() {
        let event =
            Event::new(EventType::CommandOutcome, "Test").with_source("starforge-cli".to_string());

        let filter = Filter {
            source: Some(StringFilter::Equals("starforge-cli".to_string())),
            ..Default::default()
        };
        assert!(filter.matches(&event));

        let filter = Filter {
            source: Some(StringFilter::StartsWith("starforge".to_string())),
            ..Default::default()
        };
        assert!(filter.matches(&event));

        let filter = Filter {
            source: Some(StringFilter::Matches(r"^starforge-[a-z]+$".to_string())),
            ..Default::default()
        };
        assert!(filter.matches(&event));
    }

    #[test]
    fn test_field_filter() {
        let event = Event::new(EventType::CommandOutcome, "Test").with_data(
            EventData::CommandOutcome(CommandOutcomeData {
                command: "deploy".to_string(),
                exit_code: 0,
                duration_ms: 1000,
                success: true,
                error_message: None,
            }),
        );

        let filter = Filter {
            fields: Some(vec![
                FieldFilter {
                    path: "data.command".to_string(),
                    op: FieldOp::Equals("deploy".to_string()),
                },
                FieldFilter {
                    path: "data.duration_ms".to_string(),
                    op: FieldOp::Gte(500.0),
                },
                FieldFilter {
                    path: "data.success".to_string(),
                    op: FieldOp::Bool(true),
                },
            ]),
            ..Default::default()
        };
        assert!(filter.matches(&event));
    }

    #[test]
    fn test_quiet_hours() {
        // 23:30 is within 22:00 -> 07:00 (overnight)
        let t1 = Utc.with_ymd_and_hms(2026, 8, 30, 23, 30, 0).unwrap();
        assert!(is_in_quiet_hours(&t1, "22:00", "07:00"));

        // 03:00 is within 22:00 -> 07:00
        let t2 = Utc.with_ymd_and_hms(2026, 8, 30, 3, 0, 0).unwrap();
        assert!(is_in_quiet_hours(&t2, "22:00", "07:00"));

        // 12:00 is NOT within 22:00 -> 07:00
        let t3 = Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap();
        assert!(!is_in_quiet_hours(&t3, "22:00", "07:00"));
    }
}
