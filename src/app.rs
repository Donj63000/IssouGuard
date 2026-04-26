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
        report::write_log_line(&report_dir, "Initialisation IssaGuard Partie 3")?;

        let is_admin = windows::admin::is_elevated();
        let signature = windows::signature::current_tool_signature(&self.config.version);

        let mut report_data = Report::new(
            self.config.version.clone(),
            report_dir,
            is_admin,
            mode,
            RiskAssessmentScope::DataAndReportOnly,
            system_paths,
            signature,
        );

        self.populate_data_and_report_model(&mut report_data)?;
        report_data.finalize_risk();

        report::write_report_package(&report_data)?;
        tui::print_result_summary(&report_data);

        Ok(())
    }

    fn populate_data_and_report_model(&self, report_data: &mut Report) -> AppResult<()> {
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
            TimelineKind::Report,
            "Modèles de données",
            "Chargement des types Finding, EvidenceLevel, RiskLevel, ActionRecord, TimelineEvent et Report.",
        );

        report::write_log_line(
            &report_data.metadata.report_dir,
            "Chargement des modèles de données et du générateur de rapports",
        )?;

        report_data.extend_findings(collectors::collect_foundation_findings(
            &report_data.system_paths,
            report_data.metadata.is_admin,
        ));

        report_data.extend_findings(collectors::collect_data_model_findings());

        report_data.extend_actions(remediation::part3_planned_actions(
            report_data.metadata.mode,
        ));

        if report_data.metadata.mode.is_remediation_mode() {
            report_data.add_timeline(
                TimelineKind::Safety,
                "Remédiation non exécutée",
                "La Partie 3 documente les actions futures mais ne modifie pas le système.",
            );
        }

        Ok(())
    }
}
