use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

pub type AppResult<T> = Result<T, IssaError>;

/// Alias gardé pour compatibilité avec les parties précédentes.
pub type ReportData = Report;

static ACTION_COUNTER: AtomicUsize = AtomicUsize::new(1);
static TIMELINE_COUNTER: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug, thiserror::Error)]
pub enum IssaError {
    #[error("erreur d'entrée/sortie : {0}")]
    Io(#[from] std::io::Error),

    #[error("erreur JSON : {0}")]
    Json(#[from] serde_json::Error),

    #[error("mode d'exécution invalide : {0}")]
    InvalidMode(String),

    #[error("commande PowerShell échouée : {0}")]
    PowerShell(String),

    #[error("rapport invalide : {0}")]
    InvalidReport(String),

    #[error("aucun rapport IssaGuard trouvé sur le Bureau")]
    NoReportFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    AuditOnly,
    AuditAndPlan,
    GuidedCleanup,
    DefenderOfflinePlan,
    OpenLastReport,
}

impl ExecutionMode {
    pub fn from_menu_choice(choice: &str) -> AppResult<Self> {
        match choice.trim() {
            "1" => Ok(Self::AuditOnly),
            "2" => Ok(Self::AuditAndPlan),
            "3" => Ok(Self::GuidedCleanup),
            "4" => Ok(Self::DefenderOfflinePlan),
            "5" => Ok(Self::OpenLastReport),
            other => Err(IssaError::InvalidMode(other.to_string())),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AuditOnly => "Audit sans modification",
            Self::AuditAndPlan => "Audit + plan de nettoyage",
            Self::GuidedCleanup => "Nettoyage guidé",
            Self::DefenderOfflinePlan => "Planifier / proposer Defender Offline",
            Self::OpenLastReport => "Ouvrir le dernier rapport",
        }
    }

    pub fn is_remediation_mode(self) -> bool {
        matches!(self, Self::GuidedCleanup | Self::DefenderOfflinePlan)
    }
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskAssessmentScope {
    FoundationOnly,
    DataAndReportOnly,
    AuditEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    NotAssessed,
    Green,
    Orange,
    Red,
}

impl RiskLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotAssessed => "NON ÉVALUÉ",
            Self::Green => "VERT",
            Self::Orange => "ORANGE",
            Self::Red => "ROUGE",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NotAssessed => {
                "Score non calculé : cette étape définit les données et les rapports, mais ne collecte pas encore les preuves système."
            }
            Self::Green => {
                "Aucune preuve locale d'exécution ou de persistance suspecte dans le périmètre audité. Scan Defender recommandé."
            }
            Self::Orange => {
                "Exécution probable ou tentative bloquée. Nettoyage Defender et scan hors ligne recommandés."
            }
            Self::Red => {
                "Compromission probable ou traces fortes. Nettoyage local + révocation sessions/mots de passe/tokens conseillés."
            }
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceLevel {
    Informational,
    Suspicion,
    Weak,
    Strong,
}

impl EvidenceLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Informational => "information",
            Self::Suspicion => "suspicion",
            Self::Weak => "preuve faible",
            Self::Strong => "preuve forte",
        }
    }

    pub fn affects_incident_risk(self) -> bool {
        !matches!(self, Self::Informational)
    }
}

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    Architecture,
    DataModel,
    SafetyPolicy,
    IocDefinition,
    PathResolution,
    AdminStatus,
    Logging,
    Defender,
    Process,
    File,
    Registry,
    ScheduledTask,
    Service,
    PowerShellHistory,
    RunMru,
    RemediationPlan,
    ReportGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    Url,
    Domain,
    Process,
    CommandLine,
    File,
    RegistryValue,
    ScheduledTask,
    Service,
    DefenderThreat,
    EventLog,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_type: ArtifactType,
    pub display_name: String,
    pub path: Option<PathBuf>,
    pub command_line: Option<String>,
    pub registry_key: Option<String>,
    pub registry_value_name: Option<String>,
    pub url_or_domain: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub created_at: Option<DateTime<Local>>,
    pub modified_at: Option<DateTime<Local>>,
}

impl ArtifactRef {
    pub fn new(artifact_type: ArtifactType, display_name: impl Into<String>) -> Self {
        Self {
            artifact_type,
            display_name: display_name.into(),
            path: None,
            command_line: None,
            registry_key: None,
            registry_value_name: None,
            url_or_domain: None,
            sha256: None,
            size_bytes: None,
            created_at: None,
            modified_at: None,
        }
    }

    pub fn command_line(display_name: impl Into<String>, command_line: impl Into<String>) -> Self {
        Self {
            artifact_type: ArtifactType::CommandLine,
            display_name: display_name.into(),
            path: None,
            command_line: Some(command_line.into()),
            registry_key: None,
            registry_value_name: None,
            url_or_domain: None,
            sha256: None,
            size_bytes: None,
            created_at: None,
            modified_at: None,
        }
    }

    pub fn file(display_name: impl Into<String>, path: PathBuf) -> Self {
        Self {
            artifact_type: ArtifactType::File,
            display_name: display_name.into(),
            path: Some(path),
            command_line: None,
            registry_key: None,
            registry_value_name: None,
            url_or_domain: None,
            sha256: None,
            size_bytes: None,
            created_at: None,
            modified_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub timestamp: DateTime<Local>,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub evidence_level: EvidenceLevel,
    pub source: String,
    pub artifact: Option<ArtifactRef>,
    pub related_iocs: Vec<String>,
    pub tags: Vec<String>,
    pub affects_risk: bool,
    pub confidence: u8,
    pub recommended_action: Option<String>,
    pub notes: Vec<String>,
}

impl Finding {
    pub fn informational(
        id: impl Into<String>,
        category: FindingCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self::new(
            id,
            category,
            title,
            description,
            EvidenceLevel::Informational,
            source,
            false,
            100,
        )
    }

    pub fn risk_finding(
        id: impl Into<String>,
        category: FindingCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence_level: EvidenceLevel,
        source: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self::new(
            id,
            category,
            title,
            description,
            evidence_level,
            source,
            evidence_level.affects_incident_risk(),
            confidence,
        )
    }

    pub fn new(
        id: impl Into<String>,
        category: FindingCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence_level: EvidenceLevel,
        source: impl Into<String>,
        affects_risk: bool,
        confidence: u8,
    ) -> Self {
        Self {
            id: id.into(),
            timestamp: Local::now(),
            category,
            title: title.into(),
            description: description.into(),
            evidence_level,
            source: source.into(),
            artifact: None,
            related_iocs: Vec::new(),
            tags: Vec::new(),
            affects_risk,
            confidence: confidence.min(100),
            recommended_action: None,
            notes: Vec::new(),
        }
    }

    pub fn with_artifact(mut self, artifact: ArtifactRef) -> Self {
        self.artifact = Some(artifact);
        self
    }

    pub fn with_ioc(mut self, ioc: impl Into<String>) -> Self {
        self.related_iocs.push(ioc.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn with_recommended_action(mut self, action: impl Into<String>) -> Self {
        self.recommended_action = Some(action.into());
        self
    }

    pub fn short_line(&self) -> String {
        format!(
            "[{}] {} | niveau={} | confiance={} | risque={}",
            self.id,
            self.title,
            self.evidence_level.label(),
            self.confidence,
            if self.affects_risk { "oui" } else { "non" }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineKind {
    App,
    Collector,
    Finding,
    Action,
    Report,
    Safety,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: DateTime<Local>,
    pub kind: TimelineKind,
    pub title: String,
    pub details: String,
    pub related_finding_id: Option<String>,
    pub related_action_id: Option<String>,
}

impl TimelineEvent {
    pub fn now(title: impl Into<String>, details: impl Into<String>) -> Self {
        Self::with_kind(TimelineKind::App, title, details)
    }

    pub fn with_kind(
        kind: TimelineKind,
        title: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            id: next_id("TL", &TIMELINE_COUNTER),
            timestamp: Local::now(),
            kind,
            title: title.into(),
            details: details.into(),
            related_finding_id: None,
            related_action_id: None,
        }
    }

    pub fn related_to_finding(mut self, finding_id: impl Into<String>) -> Self {
        self.related_finding_id = Some(finding_id.into());
        self
    }

    pub fn related_to_action(mut self, action_id: impl Into<String>) -> Self {
        self.related_action_id = Some(action_id.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    Noop,
    ReportOnly,
    Defender,
    ProcessKill,
    FileQuarantine,
    RegistryDisable,
    ScheduledTaskDisable,
    ServiceDisable,
    OfflineScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    Planned,
    Skipped,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub id: String,
    pub timestamp: DateTime<Local>,
    pub mode: ExecutionMode,
    pub kind: ActionKind,
    pub action: String,
    pub target: Option<String>,
    pub reason: String,
    pub status: ActionStatus,
    pub reversible: bool,
    pub requires_confirmation: bool,
    pub evidence_ids: Vec<String>,
    pub rollback_hint: Option<String>,
    pub result: Option<String>,
}

impl ActionRecord {
    pub fn planned(
        mode: ExecutionMode,
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            mode,
            ActionKind::ReportOnly,
            action,
            reason,
            ActionStatus::Planned,
        )
    }

    pub fn skipped(
        mode: ExecutionMode,
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            mode,
            ActionKind::Noop,
            action,
            reason,
            ActionStatus::Skipped,
        )
    }

    pub fn new(
        mode: ExecutionMode,
        kind: ActionKind,
        action: impl Into<String>,
        reason: impl Into<String>,
        status: ActionStatus,
    ) -> Self {
        Self {
            id: next_id("ACT", &ACTION_COUNTER),
            timestamp: Local::now(),
            mode,
            kind,
            action: action.into(),
            target: None,
            reason: reason.into(),
            status,
            reversible: true,
            requires_confirmation: matches!(
                mode,
                ExecutionMode::GuidedCleanup | ExecutionMode::DefenderOfflinePlan
            ),
            evidence_ids: Vec::new(),
            rollback_hint: None,
            result: None,
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_evidence(mut self, evidence_id: impl Into<String>) -> Self {
        self.evidence_ids.push(evidence_id.into());
        self
    }

    pub fn with_rollback_hint(mut self, rollback_hint: impl Into<String>) -> Self {
        self.rollback_hint = Some(rollback_hint.into());
        self
    }

    pub fn not_reversible(mut self) -> Self {
        self.reversible = false;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsPaths {
    pub current_dir: PathBuf,
    pub executable_path: Option<PathBuf>,
    pub user_profile: Option<PathBuf>,
    pub desktop_dir: PathBuf,
    pub downloads_dir: Option<PathBuf>,
    pub temp_dir: PathBuf,
    pub local_appdata: Option<PathBuf>,
    pub roaming_appdata: Option<PathBuf>,
    pub program_data: Option<PathBuf>,
    pub user_startup_dir: Option<PathBuf>,
    pub machine_startup_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSignatureInfo {
    pub tool_name: String,
    pub version: String,
    pub build_profile: String,
    pub target_os: String,
    pub target_arch: String,
    pub executable_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyPolicy {
    pub local_only: bool,
    pub no_contact_with_suspicious_domains: bool,
    pub no_password_or_cookie_collection: bool,
    pub no_blind_deletion: bool,
    pub quarantine_instead_of_delete: bool,
    pub prefer_disable_over_delete_for_persistence: bool,
    pub defender_updates_allowed: bool,
    pub rules: Vec<String>,
    pub limitations: Vec<String>,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            local_only: true,
            no_contact_with_suspicious_domains: true,
            no_password_or_cookie_collection: true,
            no_blind_deletion: true,
            quarantine_instead_of_delete: true,
            prefer_disable_over_delete_for_persistence: true,
            defender_updates_allowed: true,
            rules: vec![
                "Ne jamais rouvrir ni télécharger claud-hub.com ou le faux site.".into(),
                "Ne jamais exécuter de code Internet pendant l'analyse.".into(),
                "Ne pas supprimer aveuglément setup/install/update : classer, justifier, quarantaine.".into(),
                "Ne pas lire, déchiffrer ni exporter les mots de passe/cookies navigateurs.".into(),
                "Ne rien envoyer vers Internet ; local-only sauf Microsoft Defender/Microsoft Update.".into(),
                "Retirer uniquement les autorisations Defender liées à l'incident.".into(),
                "Exporter avant modification registre/tâche/service.".into(),
                "Préférer désactivation à suppression pour les persistances.".into(),
                "Conserver rollback et manifest pour toute action réversible.".into(),
                "Ne jamais promettre que les comptes sont sûrs après une possible exfiltration.".into(),
            ],
            limitations: vec![
                "Un nettoyage local ne peut pas annuler une exfiltration déjà réalisée.".into(),
                "Un score Vert signifie seulement absence de preuve dans le périmètre audité.".into(),
                "Une preuve faible ne doit pas déclencher seule une suppression destructive.".into(),
                "IssaGuard orchestre et documente ; il ne remplace pas Microsoft Defender.".into(),
                "La Partie 3 ne collecte pas encore les preuves réelles Defender/processus/fichiers.".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSet {
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub process_patterns: Vec<String>,
    pub command_patterns: Vec<String>,
    pub suspicious_file_names: Vec<String>,
    pub suspicious_extensions: Vec<String>,
    pub suspicious_locations: Vec<String>,
    pub persistence_locations: Vec<String>,
    pub defender_event_ids: Vec<u32>,
}

impl Default for IocSet {
    fn default() -> Self {
        Self {
            urls: vec![
                "https://claud-hub.com/app".into(),
                "https://claude-desktop-lm.gitlab.io/var/".into(),
                "https://claude-desktop-lm.gitlab.io/var/analytics.js".into(),
            ],
            domains: vec![
                "claud-hub.com".into(),
                "claude-desktop-lm.gitlab.io".into(),
                "download.active-version.com".into(),
                "active-version.com".into(),
                "desktop-version.com".into(),
                "official-version.com".into(),
                "claude-code.official-version.com".into(),
                "download-version".into(),
            ],
            process_patterns: vec![
                "mshta.exe + URL distante".into(),
                "powershell.exe + iex/irm/iwr/Invoke-WebRequest/Invoke-RestMethod".into(),
                "wscript.exe ou cscript.exe".into(),
                "chrome/msedge/brave/firefox --headless".into(),
                "AddInProcess32.exe suspect".into(),
                "cmd -> powershell -> mshta".into(),
                "Code.exe -> powershell -> mshta".into(),
            ],
            command_patterns: vec![
                "mshta https://claud-hub.com/app".into(),
                "powershell iex".into(),
                "powershell irm".into(),
                "powershell iwr".into(),
                "Invoke-WebRequest".into(),
                "Invoke-RestMethod".into(),
                "--headless".into(),
            ],
            suspicious_file_names: vec![
                "claude-code.exe".into(),
                "app".into(),
                "setup.exe".into(),
                "install.exe".into(),
                "update.exe".into(),
            ],
            suspicious_extensions: vec![
                ".hta".into(),
                ".js".into(),
                ".jse".into(),
                ".vbs".into(),
                ".vbe".into(),
                ".ps1".into(),
                ".cmd".into(),
                ".bat".into(),
                ".scr".into(),
                ".pif".into(),
                ".msi".into(),
                ".msix".into(),
                ".msixbundle".into(),
            ],
            suspicious_locations: vec![
                "%TEMP%".into(),
                "%LOCALAPPDATA%\\Temp".into(),
                "%USERPROFILE%\\Downloads".into(),
                "%USERPROFILE%\\Desktop".into(),
                "%APPDATA%".into(),
                "%LOCALAPPDATA%".into(),
                "%ProgramData%".into(),
                "Startup utilisateur".into(),
                "Startup machine".into(),
            ],
            persistence_locations: vec![
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU".into(),
                "Tâches planifiées".into(),
                "Services Windows".into(),
                "Dossiers Startup".into(),
            ],
            defender_event_ids: vec![1116, 1117, 1118, 1119, 1007, 1008, 5007],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub schema_version: String,
    pub tool_name: String,
    pub tool_version: String,
    pub generated_at: DateTime<Local>,
    pub report_dir: PathBuf,
    pub hostname: String,
    pub username: String,
    pub is_admin: bool,
    pub mode: ExecutionMode,
    pub scope: RiskAssessmentScope,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiagnosticCounts {
    pub findings_total: usize,
    pub risk_findings_total: usize,
    pub informational_total: usize,
    pub suspicion_total: usize,
    pub weak_total: usize,
    pub strong_total: usize,
    pub actions_total: usize,
    pub actions_planned: usize,
    pub actions_skipped: usize,
    pub actions_completed: usize,
    pub actions_failed: usize,
}

impl DiagnosticCounts {
    pub fn from_parts(findings: &[Finding], actions: &[ActionRecord]) -> Self {
        Self {
            findings_total: findings.len(),
            risk_findings_total: findings.iter().filter(|f| f.affects_risk).count(),
            informational_total: findings
                .iter()
                .filter(|f| matches!(f.evidence_level, EvidenceLevel::Informational))
                .count(),
            suspicion_total: findings
                .iter()
                .filter(|f| matches!(f.evidence_level, EvidenceLevel::Suspicion))
                .count(),
            weak_total: findings
                .iter()
                .filter(|f| matches!(f.evidence_level, EvidenceLevel::Weak))
                .count(),
            strong_total: findings
                .iter()
                .filter(|f| matches!(f.evidence_level, EvidenceLevel::Strong))
                .count(),
            actions_total: actions.len(),
            actions_planned: actions
                .iter()
                .filter(|a| matches!(a.status, ActionStatus::Planned))
                .count(),
            actions_skipped: actions
                .iter()
                .filter(|a| matches!(a.status, ActionStatus::Skipped))
                .count(),
            actions_completed: actions
                .iter()
                .filter(|a| matches!(a.status, ActionStatus::Completed))
                .count(),
            actions_failed: actions
                .iter()
                .filter(|a| matches!(a.status, ActionStatus::Failed))
                .count(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub metadata: ReportMetadata,
    pub risk_level: RiskLevel,
    pub risk_message: String,
    pub counts: DiagnosticCounts,
    pub safety_policy: SafetyPolicy,
    pub iocs: IocSet,
    pub system_paths: WindowsPaths,
    pub signature: ToolSignatureInfo,
    pub findings: Vec<Finding>,
    pub actions: Vec<ActionRecord>,
    pub timeline: Vec<TimelineEvent>,
}

impl Report {
    pub fn new(
        tool_version: impl Into<String>,
        report_dir: PathBuf,
        is_admin: bool,
        mode: ExecutionMode,
        scope: RiskAssessmentScope,
        system_paths: WindowsPaths,
        signature: ToolSignatureInfo,
    ) -> Self {
        let risk_level = RiskLevel::NotAssessed;
        let tool_version = tool_version.into();

        Self {
            metadata: ReportMetadata {
                schema_version: "3".into(),
                tool_name: "IssaGuard".into(),
                tool_version,
                generated_at: Local::now(),
                report_dir,
                hostname: std::env::var("COMPUTERNAME")
                    .or_else(|_| std::env::var("HOSTNAME"))
                    .unwrap_or_else(|_| "inconnu".into()),
                username: std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_else(|_| "inconnu".into()),
                is_admin,
                mode,
                scope,
            },
            risk_level,
            risk_message: risk_level.message().to_string(),
            counts: DiagnosticCounts::default(),
            safety_policy: SafetyPolicy::default(),
            iocs: IocSet::default(),
            system_paths,
            signature,
            findings: Vec::new(),
            actions: Vec::new(),
            timeline: vec![TimelineEvent::now(
                "Initialisation",
                "Création du contexte IssaGuard Partie 3.",
            )],
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        let event = TimelineEvent::with_kind(
            TimelineKind::Finding,
            "Constat ajouté",
            finding.short_line(),
        )
        .related_to_finding(finding.id.clone());

        self.timeline.push(event);
        self.findings.push(finding);
        self.recalculate_counts();
    }

    pub fn extend_findings<I>(&mut self, findings: I)
    where
        I: IntoIterator<Item = Finding>,
    {
        for finding in findings {
            self.add_finding(finding);
        }
    }

    pub fn add_action(&mut self, action: ActionRecord) {
        let event = TimelineEvent::with_kind(
            TimelineKind::Action,
            "Action enregistrée",
            format!("{} | statut={:?}", action.action, action.status),
        )
        .related_to_action(action.id.clone());

        self.timeline.push(event);
        self.actions.push(action);
        self.recalculate_counts();
    }

    pub fn extend_actions<I>(&mut self, actions: I)
    where
        I: IntoIterator<Item = ActionRecord>,
    {
        for action in actions {
            self.add_action(action);
        }
    }

    pub fn add_timeline(
        &mut self,
        kind: TimelineKind,
        title: impl Into<String>,
        details: impl Into<String>,
    ) {
        self.timeline
            .push(TimelineEvent::with_kind(kind, title, details));
    }

    pub fn recalculate_counts(&mut self) {
        self.counts = DiagnosticCounts::from_parts(&self.findings, &self.actions);
    }

    pub fn finalize_risk(&mut self) {
        self.recalculate_counts();
        self.risk_level =
            crate::core::risk_score::RiskScoreEngine::evaluate(self.metadata.scope, &self.findings);
        self.risk_message = self.risk_level.message().to_string();
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.metadata.tool_name.trim().is_empty() {
            return Err(IssaError::InvalidReport("tool_name vide".into()));
        }

        if self.metadata.report_dir.as_os_str().is_empty() {
            return Err(IssaError::InvalidReport("report_dir vide".into()));
        }

        for finding in &self.findings {
            if finding.id.trim().is_empty() {
                return Err(IssaError::InvalidReport("finding avec id vide".into()));
            }

            if finding.confidence > 100 {
                return Err(IssaError::InvalidReport(format!(
                    "finding {} avec confiance > 100",
                    finding.id
                )));
            }
        }

        for action in &self.actions {
            if action.id.trim().is_empty() {
                return Err(IssaError::InvalidReport("action avec id vide".into()));
            }
        }

        Ok(())
    }
}

fn next_id(prefix: &str, counter: &AtomicUsize) -> String {
    let value = counter.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{value:04}")
}
