use crate::collectors;
use crate::core::model::{
    AppResult, ExecutionMode, ReportData, RiskAssessmentScope, TimelineEvent,
};
use crate::core::report;
use crate::core::risk_score::RiskScoreEngine;
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
        report::write_log_line(&report_dir, "Initialisation IssaGuard Partie 2")?;

        let is_admin = windows::admin::is_elevated();
        let signature = windows::signature::current_tool_signature(&self.config.version);

        let mut report_data = ReportData::new(
            self.config.version.clone(),
            report_dir,
            is_admin,
            mode,
            RiskAssessmentScope::FoundationOnly,
            system_paths,
            signature,
        );

        self.populate_foundation_report(&mut report_data)?;

        report_data.risk_level =
            RiskScoreEngine::evaluate(report_data.metadata.scope, &report_data.findings);
        report_data.risk_message = report_data.risk_level.message().to_string();

        report::write_report_package(&report_data)?;
        tui::print_result_summary(&report_data);

        Ok(())
    }

    fn populate_foundation_report(&self, report_data: &mut ReportData) -> AppResult<()> {
        report_data.timeline.push(TimelineEvent::now(
            "Mode sélectionné",
            format!("{}", report_data.metadata.mode),
        ));

        report_data.timeline.push(TimelineEvent::now(
            "Statut administrateur",
            windows::admin::admin_message(report_data.metadata.is_admin),
        ));

        report_data.timeline.push(TimelineEvent::now(
            "Chemins Windows",
            "Résolution des chemins locaux utiles : Bureau, Temp, AppData, ProgramData, Downloads, Startup.",
        ));

        report_data.timeline.push(TimelineEvent::now(
            "Sécurité",
            "Partie 2 : aucun nettoyage, aucune suppression, aucune exécution distante, aucun contact avec les domaines IOC.",
        ));

        report::write_log_line(
            &report_data.metadata.report_dir,
            "Collecte socle : architecture, chemins, droits admin, politique sécurité",
        )?;

        report_data
            .findings
            .extend(collectors::collect_foundation_findings(
                &report_data.system_paths,
                report_data.metadata.is_admin,
            ));

        report_data
            .actions
            .extend(remediation::part2_planned_actions(
                report_data.metadata.mode,
            ));

        if report_data.metadata.mode.is_remediation_mode() {
            report_data.timeline.push(TimelineEvent::now(
                "Remédiation non exécutée",
                "Le mode choisi prévoit une remédiation future, mais la Partie 2 ne modifie pas encore le système.",
            ));
        }

        Ok(())
    }
}
