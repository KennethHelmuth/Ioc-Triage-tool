use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;

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
            IocType::BitcoinWallet => write!(f, "Crypto"),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    SearchEditing,
    SortSelect,
    TypeFilterSelect,
    CommandInput,
}

// ---------------------------------------------------------------------------
// AppView — View tab/page in the console
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppView {
    Dashboard,
    TriageList,
    LookupManager,
    Settings,
}

impl fmt::Display for AppView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppView::Dashboard => write!(f, "Dashboard"),
            AppView::TriageList => write!(f, "Triage Grid"),
            AppView::LookupManager => write!(f, "Lookup Manager"),
            AppView::Settings => write!(f, "Global Settings"),
        }
    }
}

// ---------------------------------------------------------------------------
// TagFilter — filter by tag
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagFilter {
    All,
    Tag(Tag),
}

impl fmt::Display for TagFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagFilter::All => write!(f, "ALL"),
            TagFilter::Tag(Tag::Untagged) => write!(f, "Untagged"),
            TagFilter::Tag(Tag::Clean) => write!(f, "Clean"),
            TagFilter::Tag(Tag::Suspicious) => write!(f, "Suspicious"),
            TagFilter::Tag(Tag::Malicious) => write!(f, "Malicious"),
            TagFilter::Tag(Tag::FalsePositive) => write!(f, "False Positive"),
        }
    }
}

// ---------------------------------------------------------------------------
// SortBy — sort keys
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Id,
    Value,
    Type,
    Priority,
    Tag,
}

impl fmt::Display for SortBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortBy::Id => write!(f, "ID"),
            SortBy::Value => write!(f, "Value"),
            SortBy::Type => write!(f, "Type"),
            SortBy::Priority => write!(f, "Priority"),
            SortBy::Tag => write!(f, "Tag"),
        }
    }
}

// ---------------------------------------------------------------------------
// SortOrder — sorting direction
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

impl fmt::Display for SortOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortOrder::Ascending => write!(f, "▲"),
            SortOrder::Descending => write!(f, "▼"),
        }
    }
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

    // Search and filtering
    pub search_query: String,
    pub tag_filter: TagFilter,
    pub type_filters: HashSet<IocType>,
    pub sort_by: SortBy,
    pub sort_order: SortOrder,
    pub selected_ids: HashSet<usize>,

    // View tab and CLI/pipe states
    pub active_view: AppView,
    pub command_buffer: String,
    pub session_logs: Vec<String>,
    pub export_dir: PathBuf,
    pub max_ioc_limit: usize,

    // Settings page interaction
    pub settings_selected_index: usize,
    pub settings_active_edit: bool,
    pub settings_text_buffer: String,

    // Lookup manager list checkbox selection
    pub lookup_checked_platforms: HashSet<String>,
    pub lookup_selected_index: usize,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            selected_index: 0,
            mode: AppMode::Normal,
            status_message: String::from("Console initialized. Press 'I' to paste raw text or ':' for command palette."),
            input_buffer: String::new(),
            note_buffer: String::new(),
            show_side_panel: true,
            scroll_offset: 0,
            total_input_count: 0,
            duplicate_count: 0,
            has_unsaved_changes: false,

            search_query: String::new(),
            tag_filter: TagFilter::All,
            type_filters: HashSet::new(),
            sort_by: SortBy::Id,
            sort_order: SortOrder::Ascending,
            selected_ids: HashSet::new(),

            active_view: AppView::Dashboard,
            command_buffer: String::new(),
            session_logs: Vec::new(),
            export_dir: PathBuf::from("."),
            max_ioc_limit: 10000,

            settings_selected_index: 0,
            settings_active_edit: false,
            settings_text_buffer: String::new(),

            lookup_checked_platforms: HashSet::new(),
            lookup_selected_index: 0,
        }
    }

    /// Add a message to the internal session history log feed
    pub fn add_log(&mut self, message: &str) {
        let timestamp = chrono::Utc::now().format("%H:%M:%S").to_string();
        self.session_logs.push(format!("{} - {}", timestamp, message));
        if self.session_logs.len() > 100 {
            self.session_logs.remove(0);
        }
    }

    /// Compute list of entries matching current filters and sorting settings
    pub fn get_filtered_entries(&self) -> Vec<&IocEntry> {
        let mut result: Vec<&IocEntry> = self
            .entries
            .iter()
            .filter(|e| {
                // Search query filter (matches value or note)
                if !self.search_query.is_empty() {
                    let q = self.search_query.to_lowercase();
                    if !e.value.to_lowercase().contains(&q) && !e.note.to_lowercase().contains(&q) {
                        return false;
                    }
                }
                // Tag filter
                match self.tag_filter {
                    TagFilter::All => {}
                    TagFilter::Tag(ref t) => {
                        if e.tag != *t {
                            return false;
                        }
                    }
                }
                // Type filter
                if !self.type_filters.is_empty() {
                    if !self.type_filters.contains(&e.ioc_type) {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Sort
        result.sort_by(|a, b| {
            let cmp = match self.sort_by {
                SortBy::Id => a.id.cmp(&b.id),
                SortBy::Value => a.value.to_lowercase().cmp(&b.value.to_lowercase()),
                SortBy::Type => a.ioc_type.to_string().cmp(&b.ioc_type.to_string()),
                SortBy::Priority => {
                    let prio_val = |p: &Priority| match p {
                        Priority::High => 0,
                        Priority::Medium => 1,
                        Priority::Low => 2,
                        Priority::Unknown => 3,
                    };
                    prio_val(&a.priority).cmp(&prio_val(&b.priority))
                }
                SortBy::Tag => {
                    let tag_val = |t: &Tag| match t {
                        Tag::Malicious => 0,
                        Tag::Suspicious => 1,
                        Tag::Clean => 2,
                        Tag::FalsePositive => 3,
                        Tag::Untagged => 4,
                    };
                    tag_val(&a.tag).cmp(&tag_val(&b.tag))
                }
            };
            if self.sort_order == SortOrder::Descending {
                cmp.reverse()
            } else {
                cmp
            }
        });

        result
    }

    /// Get the currently selected entry, if any
    pub fn selected_entry(&self) -> Option<&IocEntry> {
        let filtered = self.get_filtered_entries();
        filtered.get(self.selected_index).copied()
    }

    /// Get a mutable reference to the currently selected entry
    pub fn selected_entry_mut(&mut self) -> Option<&mut IocEntry> {
        let filtered = self.get_filtered_entries();
        let selected_id = filtered.get(self.selected_index).map(|e| e.id)?;
        self.entries.iter_mut().find(|e| e.id == selected_id)
    }

    /// Count of entries that have been tagged (not Untagged)
    pub fn tagged_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.tag != Tag::Untagged)
            .count()
    }

    /// Move selection up by n in the filtered view
    pub fn move_up(&mut self, n: usize) {
        self.selected_index = self.selected_index.saturating_sub(n);
    }

    /// Move selection down by n in the filtered view
    pub fn move_down(&mut self, n: usize) {
        let count = self.get_filtered_entries().len();
        if count > 0 {
            self.selected_index = (self.selected_index + n).min(count - 1);
        }
    }

    /// Jump to first entry in the filtered view
    pub fn jump_home(&mut self) {
        self.selected_index = 0;
    }

    /// Jump to last entry in the filtered view
    pub fn jump_end(&mut self) {
        let count = self.get_filtered_entries().len();
        if count > 0 {
            self.selected_index = count - 1;
        }
    }

    /// Delete the currently selected entry (taking filtered list into account)
    pub fn delete_selected(&mut self) {
        let filtered = self.get_filtered_entries();
        if let Some(to_delete) = filtered.get(self.selected_index) {
            let id_to_delete = to_delete.id;
            let val = to_delete.value.clone();
            self.entries.retain(|e| e.id != id_to_delete);
            self.selected_ids.remove(&id_to_delete);
            
            // Adjust selected index if it is now out of bounds of the new filtered list
            let new_count = self.get_filtered_entries().len();
            if self.selected_index >= new_count && new_count > 0 {
                self.selected_index = new_count - 1;
            } else if new_count == 0 {
                self.selected_index = 0;
            }
            self.add_log(&format!("Deleted indicator: {}", val));
            self.has_unsaved_changes = true;
        }
    }

    /// Multi-select helpers
    pub fn toggle_select_selected(&mut self) {
        if let Some(entry) = self.selected_entry() {
            let id = entry.id;
            if self.selected_ids.contains(&id) {
                self.selected_ids.remove(&id);
            } else {
                self.selected_ids.insert(id);
            }
        }
    }

    pub fn select_all_filtered(&mut self) {
        let ids: Vec<usize> = self.get_filtered_entries().iter().map(|e| e.id).collect();
        for id in ids {
            self.selected_ids.insert(id);
        }
    }

    pub fn clear_all_selection(&mut self) {
        self.selected_ids.clear();
    }

    /// Bulk action: Cycle tags for all selected. If none selected, cycle for current highlighted.
    pub fn cycle_tags_for_selected(&mut self, forward: bool) {
        if self.selected_ids.is_empty() {
            if let Some(entry) = self.selected_entry_mut() {
                entry.tag = if forward {
                    entry.tag.cycle_forward()
                } else {
                    entry.tag.cycle_backward()
                };
                let val = entry.value.clone();
                let tag = entry.tag;
                self.add_log(&format!("Tagged {} as {}", val, tag));
                self.has_unsaved_changes = true;
            }
        } else {
            let selected = self.selected_ids.clone();
            for entry in &mut self.entries {
                if selected.contains(&entry.id) {
                    entry.tag = if forward {
                        entry.tag.cycle_forward()
                    } else {
                        entry.tag.cycle_backward()
                    };
                }
            }
            self.add_log(&format!("Tagged {} selected indicators", selected.len()));
            self.has_unsaved_changes = true;
        }
    }

    /// Bulk action: Delete all selected. If none selected, delete current highlighted.
    pub fn delete_selected_bulk(&mut self) {
        if self.selected_ids.is_empty() {
            self.delete_selected();
        } else {
            let selected = self.selected_ids.clone();
            self.entries.retain(|e| !selected.contains(&e.id));
            self.selected_ids.clear();
            
            // Adjust selected index
            let new_count = self.get_filtered_entries().len();
            if self.selected_index >= new_count && new_count > 0 {
                self.selected_index = new_count - 1;
            } else if new_count == 0 {
                self.selected_index = 0;
            }
            self.add_log(&format!("Deleted {} selected indicators", selected.len()));
            self.has_unsaved_changes = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_entry(id: usize, value: &str, ioc_type: IocType, priority: Priority, tag: Tag) -> IocEntry {
        IocEntry {
            id,
            value: value.to_string(),
            ioc_type,
            priority,
            tag,
            note: String::new(),
            lookup_urls: Vec::new(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_searching_and_filtering() {
        let mut state = AppState::new();
        state.entries = vec![
            make_test_entry(1, "192.168.1.1", IocType::IPv4, Priority::Medium, Tag::Malicious),
            make_test_entry(2, "evil.com", IocType::Domain, Priority::Medium, Tag::Suspicious),
            make_test_entry(3, "clean-domain.com", IocType::Domain, Priority::Medium, Tag::Clean),
            make_test_entry(4, "attacker@evil.com", IocType::Email, Priority::Low, Tag::Malicious),
        ];

        // Search filter
        state.search_query = "evil".to_string();
        let filtered = state.get_filtered_entries();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].id, 2);
        assert_eq!(filtered[1].id, 4);

        // Tag filter
        state.search_query = "".to_string();
        state.tag_filter = TagFilter::Tag(Tag::Malicious);
        let filtered = state.get_filtered_entries();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].id, 1);
        assert_eq!(filtered[1].id, 4);

        // Type filter
        state.tag_filter = TagFilter::All;
        state.type_filters.insert(IocType::Domain);
        let filtered = state.get_filtered_entries();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].id, 2);
        assert_eq!(filtered[1].id, 3);
    }

    #[test]
    fn test_sorting() {
        let mut state = AppState::new();
        state.entries = vec![
            make_test_entry(1, "b.com", IocType::Domain, Priority::Low, Tag::Clean),
            make_test_entry(2, "a.com", IocType::Domain, Priority::High, Tag::Malicious),
            make_test_entry(3, "c.com", IocType::Domain, Priority::Medium, Tag::Suspicious),
        ];

        // Sort by Value (Ascending)
        state.sort_by = SortBy::Value;
        state.sort_order = SortOrder::Ascending;
        let filtered = state.get_filtered_entries();
        assert_eq!(filtered[0].value, "a.com");
        assert_eq!(filtered[1].value, "b.com");
        assert_eq!(filtered[2].value, "c.com");

        // Sort by Value (Descending)
        state.sort_order = SortOrder::Descending;
        let filtered = state.get_filtered_entries();
        assert_eq!(filtered[0].value, "c.com");
        assert_eq!(filtered[1].value, "b.com");
        assert_eq!(filtered[2].value, "a.com");

        // Sort by Priority (High to Low)
        state.sort_by = SortBy::Priority;
        state.sort_order = SortOrder::Ascending;
        let filtered = state.get_filtered_entries();
        assert_eq!(filtered[0].priority, Priority::High);
        assert_eq!(filtered[1].priority, Priority::Medium);
        assert_eq!(filtered[2].priority, Priority::Low);
    }

    #[test]
    fn test_multi_select_and_bulk_actions() {
        let mut state = AppState::new();
        state.entries = vec![
            make_test_entry(1, "1.1.1.1", IocType::IPv4, Priority::Medium, Tag::Untagged),
            make_test_entry(2, "2.2.2.2", IocType::IPv4, Priority::Medium, Tag::Untagged),
            make_test_entry(3, "3.3.3.3", IocType::IPv4, Priority::Medium, Tag::Untagged),
        ];

        // Select and tag bulk
        state.selected_ids.insert(1);
        state.selected_ids.insert(3);
        state.cycle_tags_for_selected(true); // Untagged -> Clean

        assert_eq!(state.entries[0].tag, Tag::Clean);
        assert_eq!(state.entries[1].tag, Tag::Untagged);
        assert_eq!(state.entries[2].tag, Tag::Clean);

        // Delete bulk
        state.delete_selected_bulk();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].id, 2);
    }
}
