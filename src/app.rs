use crate::collectors;
use crate::core::model::{
    AppResult, ExecutionMode, ReportData, RiskAssessmentScope, TimelineEvent,
};
use crate::core::report;
use crate::core::risk_score::RiskScoreEngine;
use crate::core::timeline::push_event;
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

        let is_admin = windows::admin::is_elevated();
        let report_dir = report::create_report_dir()?;

        let mut report = ReportData::new(
            self.config.version.clone(),
            report_dir,
            is_admin,
            mode,
            RiskAssessmentScope::ArchitectureOnly,
        );

        self.populate_part1_report(&mut report);

        report.risk_level = RiskScoreEngine::evaluate(report.metadata.scope, &report.findings);
        report.risk_message = report.risk_level.message().to_string();

        report::write_report_package(&report)?;
        tui::print_result_summary(&report);

        Ok(())
    }

    fn populate_part1_report(&self, report: &mut ReportData) {
        push_event(
            &mut report.timeline,
            "Mode sélectionné",
            format!("{}", report.metadata.mode),
        );

        let admin_msg = windows::admin::admin_message(report.metadata.is_admin);
        report
            .timeline
            .push(TimelineEvent::now("Statut administrateur", admin_msg));

        report.timeline.push(TimelineEvent::now(
            "Chargement IOC",
            "IOC incident chargés depuis le modèle statique Partie 1",
        ));

        report
            .findings
            .extend(collectors::collect_architecture_findings());
        report
            .actions
            .extend(remediation::part1_planned_actions(report.metadata.mode));

        if report.metadata.mode.is_remediation_mode() {
            report.timeline.push(TimelineEvent::now(
                "Sécurité remédiation",
                "Partie 1 : aucune action système exécutée malgré le mode choisi ; seules les intentions sont documentées.",
            ));
        }

        let signature = windows::signature::current_tool_signature(&self.config.version);
        report.timeline.push(TimelineEvent::now(
            "Signature outil",
            format!(
                "{} v{} | profil={} | os={}",
                signature.tool_name,
                signature.version,
                signature.build_profile,
                signature.target_os
            ),
        ));
    }
}
