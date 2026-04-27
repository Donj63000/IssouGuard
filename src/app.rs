use crate::collectors;
use crate::core::model::{AppResult, ExecutionMode, Report, RiskAssessmentScope, TimelineKind};
use crate::core::report;
use crate::remediation;
use crate::tui;
use crate::windows;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub version: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct App {
    config: AppConfig,
}

impl App {
    pub fn run(&self) -> AppResult<()> {
        tui::print_banner(&self.config.version);

        let mode = tui::prompt_mode()?;

        if mode == ExecutionMode::OpenLastReport {
            let path = report::open_latest_report_dir()?;
            tui::print_opened_report(&path);
            return Ok(());
        }

        let system_paths = windows::paths::resolve_system_paths();
        let report_dir = report::create_report_dir(&system_paths)?;
        report::write_log_line(&report_dir, "Initialisation IssaGuard Partie 4")?;

        let is_admin = windows::admin::is_elevated();
        let signature = windows::signature::current_tool_signature(&self.config.version);

        let mut report_data = Report::new(
            self.config.version.clone(),
            report_dir,
            is_admin,
            mode,
            RiskAssessmentScope::DefenderEvidenceOnly,
            system_paths,
            signature,
        );

        self.populate_defender_audit(&mut report_data)?;
        report_data.finalize_risk();

        report::write_report_package(&report_data)?;
        tui::print_result_summary(&report_data);

        Ok(())
    }

    fn populate_defender_audit(&self, report_data: &mut Report) -> AppResult<()> {
        report_data.add_timeline(
            TimelineKind::App,
            "Mode sélectionné",
            format!("{}", report_data.metadata.mode),
        );

        report_data.add_timeline(
            TimelineKind::Safety,
            "Statut administrateur",
            windows::admin::admin_message(report_data.metadata.is_admin),
        );

        report_data.add_timeline(
            TimelineKind::Collector,
            "Collecte Defender lecture seule",
            "Collecte Get-MpComputerStatus, Get-MpPreference, Get-MpThreat, Get-MpThreatDetection et événements Defender.",
        );

        report::write_log_line(
            &report_data.metadata.report_dir,
            "Début collecte Defender lecture seule",
        )?;

        report_data.extend_findings(collectors::collect_foundation_findings(
            &report_data.system_paths,
            report_data.metadata.is_admin,
        ));

        report_data.extend_findings(collectors::collect_data_model_findings());

        let defender_collection =
            collectors::defender::collect_defender_snapshot(&report_data.iocs);

        report_data.add_timeline(
            TimelineKind::Collector,
            "Collecte Defender terminée",
            format!(
                "Commandes={}, événements={}, erreurs={}",
                defender_collection.snapshot.command_captures.len(),
                defender_collection.snapshot.events.len(),
                defender_collection.snapshot.errors.len()
            ),
        );

        report_data.defender = Some(defender_collection.snapshot);
        report_data.extend_findings(defender_collection.findings);

        report_data.extend_actions(remediation::part4_planned_actions(
            report_data.metadata.mode,
        ));

        if report_data.metadata.mode.is_remediation_mode() {
            report_data.add_timeline(
                TimelineKind::Safety,
                "Remédiation non exécutée",
                "La Partie 4 collecte Defender uniquement. Aucune préférence Defender n'est modifiée.",
            );
        }

        report::write_log_line(
            &report_data.metadata.report_dir,
            "Fin collecte Defender lecture seule",
        )?;

        Ok(())
    }
}
