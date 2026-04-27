use crate::config::Config;
use crate::models::AppState;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// JSON Export Structures
// ---------------------------------------------------------------------------
#[derive(Serialize)]
struct JsonExport {
    session_metadata: SessionMetadata,
    indicators: Vec<JsonIndicator>,
}

#[derive(Serialize)]
struct SessionMetadata {
    exported_at: String,
    total_indicators: usize,
    tagged_count: usize,
    tool_version: String,
}

#[derive(Serialize)]
struct JsonIndicator {
    id: usize,
    value: String,
    #[serde(rename = "type")]
    ioc_type: String,
    priority: String,
    tag: String,
    note: String,
    lookup_urls: Vec<JsonLookupUrl>,
    created_at: String,
}

#[derive(Serialize)]
struct JsonLookupUrl {
    platform: String,
    url: String,
}

// ---------------------------------------------------------------------------
// Export Functions
// ---------------------------------------------------------------------------

/// Generate the export file path with timestamp.
fn export_path(config: &Config, extension: &str) -> PathBuf {
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    config
        .export_dir
        .join(format!("ioc_triage_{}.{}", timestamp, extension))
}

/// Export session data to JSON.
pub fn export_json(state: &AppState, config: &Config) -> Result<String> {
    let path = export_path(config, "json");

    let indicators: Vec<JsonIndicator> = state
        .entries
        .iter()
        .map(|e| JsonIndicator {
            id: e.id,
            value: e.value.clone(),
            ioc_type: e.ioc_type.to_string(),
            priority: e.priority.to_string(),
            tag: e.tag.to_string(),
            note: e.note.clone(),
            lookup_urls: e
                .lookup_urls
                .iter()
                .map(|lu| JsonLookupUrl {
                    platform: lu.platform.clone(),
                    url: lu.url.clone(),
                })
                .collect(),
            created_at: e.created_at.to_rfc3339(),
        })
        .collect();

    let export = JsonExport {
        session_metadata: SessionMetadata {
            exported_at: Utc::now().to_rfc3339(),
            total_indicators: state.entries.len(),
            tagged_count: state.tagged_count(),
            tool_version: "0.1.0".to_string(),
        },
        indicators,
    };

    let json_str = serde_json::to_string_pretty(&export)?;
    let mut file = std::fs::File::create(&path)?;
    file.write_all(json_str.as_bytes())?;

    Ok(path.display().to_string())
}

/// Export session data to CSV.
pub fn export_csv(state: &AppState, config: &Config) -> Result<String> {
    let path = export_path(config, "csv");

    let mut wtr = csv::Writer::from_path(&path)?;

    // Write header
    wtr.write_record([
        "id",
        "value",
        "type",
        "priority",
        "tag",
        "note",
        "created_at",
    ])?;

    for entry in &state.entries {
        wtr.write_record([
            &entry.id.to_string(),
            &entry.value,
            &entry.ioc_type.to_string(),
            &entry.priority.to_string(),
            &entry.tag.to_string(),
            &entry.note,
            &entry.created_at.to_rfc3339(),
        ])?;
    }

    wtr.flush()?;

    Ok(path.display().to_string())
}
