use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// IocType — every supported indicator type
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    IPv4,
    IPv6,
    Domain,
    URL,
    MD5,
    SHA1,
    SHA256,
    Email,
    CVE,
    BitcoinWallet,
    Unknown,
}

impl fmt::Display for IocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IocType::IPv4 => write!(f, "IPv4"),
            IocType::IPv6 => write!(f, "IPv6"),
            IocType::Domain => write!(f, "Domain"),
            IocType::URL => write!(f, "URL"),
            IocType::MD5 => write!(f, "MD5"),
            IocType::SHA1 => write!(f, "SHA1"),
            IocType::SHA256 => write!(f, "SHA256"),
            IocType::Email => write!(f, "Email"),
            IocType::CVE => write!(f, "CVE"),
            IocType::BitcoinWallet => write!(f, "Bitcoin"),
            IocType::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Priority — triage priority level
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    High,
    Medium,
    Low,
    Unknown,
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Priority::High => write!(f, "HIGH"),
            Priority::Medium => write!(f, "MED"),
            Priority::Low => write!(f, "LOW"),
            Priority::Unknown => write!(f, "UNK"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tag — analyst verdict
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tag {
    Untagged,
    Clean,
    Suspicious,
    Malicious,
    FalsePositive,
}

impl Tag {
    /// Cycle tag forward: Untagged → Clean → Suspicious → Malicious → FalsePositive → Untagged
    pub fn cycle_forward(&self) -> Tag {
        match self {
            Tag::Untagged => Tag::Clean,
            Tag::Clean => Tag::Suspicious,
            Tag::Suspicious => Tag::Malicious,
            Tag::Malicious => Tag::FalsePositive,
            Tag::FalsePositive => Tag::Untagged,
        }
    }

    /// Cycle tag backward: reverse direction
    pub fn cycle_backward(&self) -> Tag {
        match self {
            Tag::Untagged => Tag::FalsePositive,
            Tag::Clean => Tag::Untagged,
            Tag::Suspicious => Tag::Clean,
            Tag::Malicious => Tag::Suspicious,
            Tag::FalsePositive => Tag::Malicious,
        }
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tag::Untagged => write!(f, "-"),
            Tag::Clean => write!(f, "CLN"),
            Tag::Suspicious => write!(f, "SUS"),
            Tag::Malicious => write!(f, "MAL"),
            Tag::FalsePositive => write!(f, "FP"),
        }
    }
}

// ---------------------------------------------------------------------------
// LookupUrl — named URL for external platform
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupUrl {
    pub platform: String,
    pub url: String,
}

// ---------------------------------------------------------------------------
// IocEntry — single indicator with all metadata
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub id: usize,
    pub value: String,
    pub ioc_type: IocType,
    pub priority: Priority,
    pub tag: Tag,
    pub note: String,
    pub lookup_urls: Vec<LookupUrl>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// AppMode — current UI mode
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppMode {
    Normal,
    InputPaste,
    NoteEditing,
    ExportConfirm,
    Help,
    DeleteConfirm,
}

// ---------------------------------------------------------------------------
// AppState — full runtime application state
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct AppState {
    pub entries: Vec<IocEntry>,
    pub selected_index: usize,
    pub mode: AppMode,
    pub status_message: String,
    pub input_buffer: String,
    pub note_buffer: String,
    pub show_side_panel: bool,
    pub scroll_offset: usize,
    pub total_input_count: usize,
    pub duplicate_count: usize,
    pub has_unsaved_changes: bool,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            selected_index: 0,
            mode: AppMode::InputPaste,
            status_message: String::from("Paste IOCs and press Enter twice to begin"),
            input_buffer: String::new(),
            note_buffer: String::new(),
            show_side_panel: true,
            scroll_offset: 0,
            total_input_count: 0,
            duplicate_count: 0,
            has_unsaved_changes: false,
        }
    }

    /// Get the currently selected entry, if any
    pub fn selected_entry(&self) -> Option<&IocEntry> {
        self.entries.get(self.selected_index)
    }

    /// Get a mutable reference to the currently selected entry
    pub fn selected_entry_mut(&mut self) -> Option<&mut IocEntry> {
        self.entries.get_mut(self.selected_index)
    }

    /// Count of entries that have been tagged (not Untagged)
    pub fn tagged_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.tag != Tag::Untagged)
            .count()
    }

    /// Move selection up by n
    pub fn move_up(&mut self, n: usize) {
        self.selected_index = self.selected_index.saturating_sub(n);
    }

    /// Move selection down by n
    pub fn move_down(&mut self, n: usize) {
        if !self.entries.is_empty() {
            self.selected_index = (self.selected_index + n).min(self.entries.len() - 1);
        }
    }

    /// Jump to first entry
    pub fn jump_home(&mut self) {
        self.selected_index = 0;
    }

    /// Jump to last entry
    pub fn jump_end(&mut self) {
        if !self.entries.is_empty() {
            self.selected_index = self.entries.len() - 1;
        }
    }

    /// Delete the currently selected entry
    pub fn delete_selected(&mut self) {
        if !self.entries.is_empty() {
            self.entries.remove(self.selected_index);
            if self.selected_index >= self.entries.len() && !self.entries.is_empty() {
                self.selected_index = self.entries.len() - 1;
            }
            self.has_unsaved_changes = true;
        }
    }
}
