use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Partie 2 : seulement le modèle.
/// La quarantaine réelle sera implémentée plus tard.
/// Règle : jamais de suppression définitive ; déplacement réversible + manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineManifestEntry {
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub created_at: Option<DateTime<Local>>,
    pub modified_at: Option<DateTime<Local>>,
    pub reason: String,
    pub rule: String,
    pub confidence: u8,
    pub action_date: DateTime<Local>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineManifest {
    pub entries: Vec<QuarantineManifestEntry>,
}

impl QuarantineManifest {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}
