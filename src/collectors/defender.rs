use crate::core::model::{
    ArtifactRef, DefenderCommandCapture, DefenderEventRecord, DefenderSnapshot, EvidenceLevel,
    Finding, FindingCategory, IocSet,
};
use crate::windows::powershell;
use chrono::Local;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct DefenderCollection {
    pub snapshot: DefenderSnapshot,
    pub findings: Vec<Finding>,
}

pub fn collect_defender_snapshot(iocs: &IocSet) -> DefenderCollection {
    let mut snapshot = DefenderSnapshot {
        generated_at: Local::now(),
        ..DefenderSnapshot::default()
    };

    if !cfg!(target_os = "windows") {
        snapshot.notes.push(
            "Collecte Defender non exécutée : système non Windows détecté à la compilation."
                .to_string(),
        );

        let finding = Finding::informational(
            "DEFENDER-000",
            FindingCategory::Defender,
            "Collecte Defender non disponible hors Windows",
            "IssaGuard peut compiler hors Windows, mais la collecte Defender nécessite Windows et PowerShell Defender.",
            "collectors::defender::collect_defender_snapshot",
        )
        .with_tag("defender")
        .with_tag("non-windows");

        return DefenderCollection {
            snapshot,
            findings: vec![finding],
        };
    }

    let mut findings = Vec::new();

    let status_capture = run_json_capture("Get-MpComputerStatus", STATUS_SCRIPT);
    snapshot.status = accepted_value(&status_capture.parsed_json);
    snapshot.command_captures.push(status_capture);

    let pref_capture = run_json_capture("Get-MpPreference", PREFERENCE_SCRIPT);
    snapshot.preferences = accepted_value(&pref_capture.parsed_json);
    snapshot.command_captures.push(pref_capture);

    let threat_capture = run_json_capture("Get-MpThreat", THREAT_SCRIPT);
    snapshot.threats = array_values(&threat_capture.parsed_json);
    snapshot.command_captures.push(threat_capture);

    let detection_capture = run_json_capture("Get-MpThreatDetection", DETECTION_SCRIPT);
    snapshot.detections = array_values(&detection_capture.parsed_json);
    snapshot.command_captures.push(detection_capture);

    let event_capture = run_json_capture("Get-WinEvent Defender Operational", EVENT_SCRIPT);
    snapshot.events = array_values(&event_capture.parsed_json)
        .iter()
        .map(event_record_from_value)
        .collect();
    snapshot.command_captures.push(event_capture);

    snapshot.available = snapshot
        .command_captures
        .iter()
        .any(|c| c.success && c.parsed_json.is_some() && !json_has_issa_error(&c.parsed_json));

    for capture in &snapshot.command_captures {
        if !capture.success {
            snapshot.errors.push(format!(
                "{} a échoué : {}",
                capture.label,
                first_non_empty(&capture.stderr, &capture.stdout)
            ));
        }

        if json_has_issa_error(&capture.parsed_json) {
            snapshot.errors.push(format!(
                "{} indisponible : {}",
                capture.label,
                value_to_flat_text(capture.parsed_json.as_ref().unwrap_or(&Value::Null))
            ));
        }
    }

    findings.extend(findings_from_availability(&snapshot));
    findings.extend(findings_from_status(snapshot.status.as_ref()));
    findings.extend(findings_from_preferences(
        snapshot.preferences.as_ref(),
        iocs,
    ));
    findings.extend(findings_from_threats(&snapshot.threats, iocs));
    findings.extend(findings_from_detections(&snapshot.detections, iocs));
    findings.extend(findings_from_events(&snapshot.events, iocs));

    DefenderCollection { snapshot, findings }
}

fn run_json_capture(label: &str, script: &str) -> DefenderCommandCapture {
    match powershell::run_powershell_capture(script) {
        Ok(output) => {
            let parsed = parse_json_maybe(&output.stdout);
            DefenderCommandCapture {
                label: label.to_string(),
                command_kind: "PowerShell lecture seule".into(),
                success: true,
                status_code: output.status_code,
                stdout: output.stdout,
                stderr: output.stderr,
                parsed_json: parsed,
            }
        }
        Err(error) => DefenderCommandCapture {
            label: label.to_string(),
            command_kind: "PowerShell lecture seule".into(),
            success: false,
            status_code: None,
            stdout: String::new(),
            stderr: error.to_string(),
            parsed_json: None,
        },
    }
}

fn parse_json_maybe(stdout: &str) -> Option<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Some(Value::Array(Vec::new()));
    }

    serde_json::from_str(trimmed).ok()
}

fn accepted_value(value: &Option<Value>) -> Option<Value> {
    match value {
        Some(v) if !json_value_has_issa_error(v) => Some(v.clone()),
        _ => None,
    }
}

fn array_values(value: &Option<Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(values)) => values
            .iter()
            .filter(|v| !json_value_has_issa_error(v))
            .cloned()
            .collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) if json_value_has_issa_error(other) => Vec::new(),
        Some(other) => vec![other.clone()],
    }
}

fn json_has_issa_error(value: &Option<Value>) -> bool {
    value
        .as_ref()
        .map(json_value_has_issa_error)
        .unwrap_or(false)
}

fn json_value_has_issa_error(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.contains_key("IssaGuardError"),
        Value::Array(items) => items.iter().any(json_value_has_issa_error),
        _ => false,
    }
}

fn findings_from_availability(snapshot: &DefenderSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();

    if snapshot.available {
        findings.push(
            Finding::informational(
                "DEFENDER-001",
                FindingCategory::Defender,
                "Module Defender accessible",
                "Au moins une commande Defender a répondu. La collecte est exploitable dans le périmètre Defender.",
                "collectors::defender::findings_from_availability",
            )
            .with_tag("defender")
            .with_tag("availability"),
        );
    } else {
        findings.push(
            Finding::risk_finding(
                "DEFENDER-002",
                FindingCategory::Defender,
                "Collecte Defender indisponible ou vide",
                "Aucune commande Defender exploitable n'a répondu. Cela peut arriver si le module Defender est absent, bloqué, ou si l'outil n'est pas lancé sur Windows.",
                EvidenceLevel::Weak,
                "collectors::defender::findings_from_availability",
                60,
            )
            .with_tag("defender")
            .with_tag("risk:orange")
            .with_recommended_action("Relancer IssaGuard sur Windows, idéalement en administrateur, puis vérifier Microsoft Defender manuellement."),
        );
    }

    for (idx, error) in snapshot.errors.iter().take(5).enumerate() {
        findings.push(
            Finding::risk_finding(
                format!("DEFENDER-ERR-{idx:03}"),
                FindingCategory::Defender,
                "Erreur de collecte Defender",
                error.clone(),
                EvidenceLevel::Suspicion,
                "collectors::defender::findings_from_availability",
                50,
            )
            .with_tag("defender")
            .with_tag("collector-error")
            .with_recommended_action("Examiner defender_before.txt ; une erreur de collecte n'est pas une preuve de compromission mais réduit la visibilité."),
        );
    }

    findings
}

fn findings_from_status(status: Option<&Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(status) = status else {
        return findings;
    };

    let disabled_checks = [
        (
            "RealTimeProtectionEnabled",
            "Protection temps réel désactivée",
        ),
        (
            "BehaviorMonitorEnabled",
            "Surveillance comportementale désactivée",
        ),
        (
            "IoavProtectionEnabled",
            "Protection IOAV/script/téléchargements désactivée",
        ),
        ("AntivirusEnabled", "Antivirus Defender désactivé"),
        ("AMServiceEnabled", "Service antimalware Defender désactivé"),
    ];

    for (field, title) in disabled_checks {
        if get_bool_ci(status, field) == Some(false) {
            findings.push(
                Finding::risk_finding(
                    format!("DEFENDER-STATUS-{field}"),
                    FindingCategory::Defender,
                    title,
                    format!("Get-MpComputerStatus indique {field}=False."),
                    EvidenceLevel::Strong,
                    "Get-MpComputerStatus",
                    90,
                )
                .with_artifact(ArtifactRef::defender_preference(field))
                .with_tag("defender")
                .with_tag("status")
                .with_tag("risk:red")
                .with_recommended_action("Prévoir réactivation guidée Defender dans la Partie 9, puis scans ciblés/full/offline selon le rapport."),
            );
        }
    }

    if get_bool_ci(status, "IsTamperProtected") == Some(false) {
        findings.push(
            Finding::risk_finding(
                "DEFENDER-STATUS-TAMPER",
                FindingCategory::Defender,
                "Protection antialtération Defender non active ou non disponible",
                "Get-MpComputerStatus indique IsTamperProtected=False. Ce n'est pas une preuve directe de l'incident, mais cela réduit la résistance aux modifications Defender.",
                EvidenceLevel::Weak,
                "Get-MpComputerStatus",
                65,
            )
            .with_artifact(ArtifactRef::defender_preference("IsTamperProtected"))
            .with_tag("defender")
            .with_tag("status")
            .with_tag("risk:orange")
            .with_recommended_action("Vérifier l'état de la protection antialtération dans Sécurité Windows / gestion MDE si applicable."),
        );
    }

    if findings.is_empty() {
        findings.push(
            Finding::informational(
                "DEFENDER-STATUS-OK",
                FindingCategory::Defender,
                "État Defender lisible",
                "Aucune désactivation évidente n'a été relevée dans les champs Defender vérifiés par cette partie.",
                "Get-MpComputerStatus",
            )
            .with_tag("defender")
            .with_tag("status"),
        );
    }

    findings
}

fn findings_from_preferences(preferences: Option<&Value>, iocs: &IocSet) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(preferences) = preferences else {
        return findings;
    };

    let bool_disabled = [
        (
            "DisableRealtimeMonitoring",
            "Préférence DisableRealtimeMonitoring active",
        ),
        (
            "DisableBehaviorMonitoring",
            "Préférence DisableBehaviorMonitoring active",
        ),
        (
            "DisableScriptScanning",
            "Préférence DisableScriptScanning active",
        ),
        (
            "DisableIOAVProtection",
            "Préférence DisableIOAVProtection active",
        ),
    ];

    for (field, title) in bool_disabled {
        if get_bool_ci(preferences, field) == Some(true) {
            findings.push(
                Finding::risk_finding(
                    format!("DEFENDER-PREF-{field}"),
                    FindingCategory::Defender,
                    title,
                    format!("Get-MpPreference indique {field}=True."),
                    EvidenceLevel::Strong,
                    "Get-MpPreference",
                    90,
                )
                .with_artifact(ArtifactRef::defender_preference(field))
                .with_tag("defender")
                .with_tag("preference")
                .with_tag("risk:red")
                .with_recommended_action("Prévoir réactivation guidée Defender dans la Partie 9 ; ne pas modifier silencieusement en Partie 4."),
            );
        }
    }

    let exclusions = [
        ("ExclusionPath", "chemin exclu"),
        ("ExclusionProcess", "processus exclu"),
        ("ExclusionExtension", "extension exclue"),
    ];

    for (field, label) in exclusions {
        let values = get_string_list_ci(preferences, field);
        if values.is_empty() {
            continue;
        }

        findings.push(
            Finding::informational(
                format!("DEFENDER-PREF-{field}-COUNT"),
                FindingCategory::Defender,
                format!("Exclusions Defender présentes : {field}"),
                format!(
                    "{} valeur(s) détectée(s). Elles ne sont pas retirées en Partie 4.",
                    values.len()
                ),
                "Get-MpPreference",
            )
            .with_artifact(ArtifactRef::defender_preference(field))
            .with_tag("defender")
            .with_tag("exclusion"),
        );

        for (idx, value) in values.iter().take(20).enumerate() {
            let lower = value.to_lowercase();
            let ioc_hits = ioc_hits(&lower, iocs);
            let risky_exclusion = is_risky_exclusion(field, &lower, iocs);

            if risky_exclusion || !ioc_hits.is_empty() {
                findings.push(
                    Finding::risk_finding(
                        format!("DEFENDER-PREF-{field}-{idx:03}"),
                        FindingCategory::Defender,
                        format!("Exclusion Defender suspecte ({label})"),
                        format!("{field} contient : {value}"),
                        EvidenceLevel::Strong,
                        "Get-MpPreference",
                        85,
                    )
                    .with_artifact(ArtifactRef::defender_preference(format!(
                        "{field}: {value}"
                    )))
                    .with_iocs(ioc_hits)
                    .with_tag("defender")
                    .with_tag("exclusion")
                    .with_tag("risk:red")
                    .with_recommended_action("Ne pas retirer aveuglément. Confirmer le lien incident, exporter/rollback, puis retirer uniquement l'exclusion liée en Partie 9."),
                );
            }
        }
    }

    let default_ids = get_string_list_ci(preferences, "ThreatIDDefaultAction_Ids");
    let default_actions = get_string_list_ci(preferences, "ThreatIDDefaultAction_Actions");

    if !default_ids.is_empty() || !default_actions.is_empty() {
        let joined = format!(
            "Ids=[{}], Actions=[{}]",
            default_ids.join(", "),
            default_actions.join(", ")
        );

        let lower = joined.to_lowercase();
        let has_allow = lower.contains("allow")
            || lower.contains("autoriser")
            || lower.contains("ignore")
            || lower.contains("ignorer");

        let mut finding = Finding::risk_finding(
            "DEFENDER-PREF-THREAT-DEFAULT-ACTION",
            FindingCategory::Defender,
            "Actions par défaut Defender configurées pour des ThreatID",
            joined,
            if has_allow {
                EvidenceLevel::Strong
            } else {
                EvidenceLevel::Weak
            },
            "Get-MpPreference",
            if has_allow { 85 } else { 65 },
        )
        .with_artifact(ArtifactRef::defender_preference(
            "ThreatIDDefaultAction_Ids / ThreatIDDefaultAction_Actions",
        ))
        .with_tag("defender")
        .with_tag("threat-default-action")
        .with_recommended_action(
            "Vérifier si ces ThreatID sont liés à l'incident avant toute suppression/modification.",
        );

        finding = if has_allow {
            finding.with_tag("risk:red")
        } else {
            finding.with_tag("risk:orange")
        };

        findings.push(finding);
    }

    findings
}

fn findings_from_threats(threats: &[Value], iocs: &IocSet) -> Vec<Finding> {
    findings_from_json_list(
        threats,
        iocs,
        "DEFENDER-THREAT",
        "Get-MpThreat",
        "Menace Defender liée ou compatible incident",
        "Get-MpThreat a retourné une menace contenant des indicateurs incident ou un libellé Trojan/Stealer.",
    )
}

fn findings_from_detections(detections: &[Value], iocs: &IocSet) -> Vec<Finding> {
    findings_from_json_list(
        detections,
        iocs,
        "DEFENDER-DETECTION",
        "Get-MpThreatDetection",
        "Détection Defender liée ou compatible incident",
        "Get-MpThreatDetection a retourné une détection contenant des indicateurs incident ou un libellé Trojan/Stealer.",
    )
}

fn findings_from_json_list(
    values: &[Value],
    iocs: &IocSet,
    id_prefix: &str,
    source: &str,
    title: &str,
    description_prefix: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if values.is_empty() {
        findings.push(
            Finding::informational(
                format!("{id_prefix}-NONE"),
                FindingCategory::Defender,
                format!("Aucune entrée {source}"),
                format!("{source} n'a retourné aucune entrée exploitable."),
                source,
            )
            .with_tag("defender"),
        );
        return findings;
    }

    findings.push(
        Finding::informational(
            format!("{id_prefix}-COUNT"),
            FindingCategory::Defender,
            format!("Entrées {source} présentes"),
            format!(
                "{} entrée(s) collectée(s). Les entrées liées à l'incident sont détaillées si détectées.",
                values.len()
            ),
            source,
        )
        .with_tag("defender"),
    );

    for (idx, value) in values.iter().take(80).enumerate() {
        let text = value_to_flat_text(value);
        let lower = text.to_lowercase();
        let ioc_hits = ioc_hits(&lower, iocs);
        let malware_hit = contains_malware_keyword(&lower);
        let bad_action = contains_bad_defender_action(&lower);

        if !ioc_hits.is_empty() || malware_hit {
            let mut finding = Finding::risk_finding(
                format!("{id_prefix}-{idx:03}"),
                FindingCategory::Defender,
                title,
                format!("{description_prefix}\nRésumé : {}", truncate(&text, 900)),
                if bad_action || malware_hit {
                    EvidenceLevel::Strong
                } else {
                    EvidenceLevel::Weak
                },
                source,
                if bad_action || malware_hit { 90 } else { 75 },
            )
            .with_artifact(ArtifactRef::defender_threat(format!("{source} entrée {idx}")))
            .with_iocs(ioc_hits)
            .with_tag("defender")
            .with_tag("threat-or-detection")
            .with_recommended_action("Conserver la preuve. Ne pas supprimer manuellement. Prévoir Remove-MpThreat/scans guidés en Partie 9 selon confirmation.");

            finding = if bad_action || lower.contains("stealer") || lower.contains("trojan") {
                finding.with_tag("risk:red")
            } else {
                finding.with_tag("risk:orange")
            };

            findings.push(finding);
        }
    }

    findings
}

fn findings_from_events(events: &[DefenderEventRecord], iocs: &IocSet) -> Vec<Finding> {
    let mut findings = Vec::new();

    if events.is_empty() {
        findings.push(
            Finding::informational(
                "DEFENDER-EVENT-NONE",
                FindingCategory::Defender,
                "Aucun événement Defender ciblé collecté",
                "Aucun événement 1116/1117/1118/1119/1007/1008/5007 n'a été retourné dans la fenêtre collectée.",
                "Get-WinEvent Defender Operational",
            )
            .with_tag("defender")
            .with_tag("eventlog"),
        );
        return findings;
    }

    findings.push(
        Finding::informational(
            "DEFENDER-EVENT-COUNT",
            FindingCategory::Defender,
            "Événements Defender ciblés collectés",
            format!(
                "{} événement(s) Defender collecté(s) dans la fenêtre de 30 jours.",
                events.len()
            ),
            "Get-WinEvent Defender Operational",
        )
        .with_tag("defender")
        .with_tag("eventlog"),
    );

    for (idx, event) in events.iter().take(80).enumerate() {
        let text = event_to_flat_text(event);
        let lower = text.to_lowercase();
        let ioc_hits = ioc_hits(&lower, iocs);
        let malware_hit = contains_malware_keyword(&lower);
        let bad_action = contains_bad_defender_action(&lower)
            || matches!(event.event_id, Some(1008 | 1118 | 1119));
        let config_change = matches!(event.event_id, Some(5007));

        if !ioc_hits.is_empty() || malware_hit || bad_action || config_change {
            let mut finding = Finding::risk_finding(
                format!("DEFENDER-EVENT-{idx:03}"),
                FindingCategory::Defender,
                event_title(event.event_id),
                truncate(&text, 1100),
                if bad_action || malware_hit {
                    EvidenceLevel::Strong
                } else if config_change {
                    EvidenceLevel::Weak
                } else {
                    EvidenceLevel::Suspicion
                },
                "Get-WinEvent Defender Operational",
                if bad_action || malware_hit { 88 } else { 65 },
            )
            .with_artifact(ArtifactRef::event_log(format!(
                "Defender Event ID {}",
                event
                    .event_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "inconnu".into())
            )))
            .with_iocs(ioc_hits)
            .with_tag("defender")
            .with_tag("eventlog")
            .with_recommended_action("Lire defender_events.txt. Si l'action est autorisée/échouée ou liée à un Stealer, traiter comme risque élevé.");

            finding = if bad_action || malware_hit {
                finding.with_tag("risk:red")
            } else {
                finding.with_tag("risk:orange")
            };

            findings.push(finding);
        }
    }

    findings
}

fn event_title(event_id: Option<u32>) -> String {
    match event_id {
        Some(1116) => "Defender a détecté un malware/PUA".into(),
        Some(1117) | Some(1007) => "Defender a effectué une action".into(),
        Some(1118) | Some(1008) => "Action Defender échouée".into(),
        Some(1119) => "Defender a ignoré ou rencontré un état critique".into(),
        Some(5007) => "Configuration Defender modifiée".into(),
        Some(other) => format!("Événement Defender {other}"),
        None => "Événement Defender sans ID".into(),
    }
}

fn get_bool_ci(value: &Value, key: &str) -> Option<bool> {
    find_key_ci(value, key).and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" | "oui" => Some(true),
            "false" | "0" | "no" | "non" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_i64().map(|i| i != 0),
        _ => None,
    })
}

fn get_string_list_ci(value: &Value, key: &str) -> Vec<String> {
    find_key_ci(value, key)
        .map(value_to_string_list)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect()
}

fn find_key_ci<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v),
        Value::Array(items) => items.iter().find_map(|item| find_key_ci(item, key)),
        _ => None,
    }
}

fn value_to_string_list(value: &Value) -> Vec<String> {
    match value {
        Value::Null => Vec::new(),
        Value::Bool(b) => vec![b.to_string()],
        Value::Number(n) => vec![n.to_string()],
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items.iter().flat_map(value_to_string_list).collect(),
        Value::Object(_) => vec![value_to_flat_text(value)],
    }
}

fn event_record_from_value(value: &Value) -> DefenderEventRecord {
    DefenderEventRecord {
        time_created: get_string_ci(value, "TimeCreated"),
        event_id: get_u32_ci(value, "Id"),
        provider_name: get_string_ci(value, "ProviderName"),
        level_display_name: get_string_ci(value, "LevelDisplayName"),
        record_id: get_u64_ci(value, "RecordId"),
        machine_name: get_string_ci(value, "MachineName"),
        message: get_string_ci(value, "Message"),
    }
}

fn get_string_ci(value: &Value, key: &str) -> Option<String> {
    find_key_ci(value, key).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

fn get_u32_ci(value: &Value, key: &str) -> Option<u32> {
    find_key_ci(value, key).and_then(|v| match v {
        Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        Value::String(s) => s.trim().parse::<u32>().ok(),
        _ => None,
    })
}

fn get_u64_ci(value: &Value, key: &str) -> Option<u64> {
    find_key_ci(value, key).and_then(|v| match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    })
}

fn ioc_hits(text_lower: &str, iocs: &IocSet) -> Vec<String> {
    let mut hits = Vec::new();

    for item in iocs
        .urls
        .iter()
        .chain(iocs.domains.iter())
        .chain(iocs.command_patterns.iter())
        .chain(iocs.suspicious_file_names.iter())
    {
        let needle = item.to_lowercase();
        if !needle.trim().is_empty() && text_lower.contains(&needle) {
            hits.push(item.clone());
        }
    }

    let extra_needles = [
        "mshta",
        "claud-hub",
        "claude-desktop-lm",
        "active-version",
        "desktop-version",
        "official-version",
        "download-version",
        "addinprocess32",
        "amatera",
        "aura",
        "trojan",
        "stealer",
    ];

    for needle in extra_needles {
        if text_lower.contains(needle) && !hits.iter().any(|h| h.eq_ignore_ascii_case(needle)) {
            hits.push(needle.to_string());
        }
    }

    hits.sort();
    hits.dedup();
    hits
}

fn contains_malware_keyword(text_lower: &str) -> bool {
    [
        "trojan",
        "stealer",
        "infostealer",
        "credential",
        "password",
        "amatera",
        "aura",
        "malware",
        "pua:",
        "puadetection",
    ]
    .iter()
    .any(|needle| text_lower.contains(needle))
}

fn contains_bad_defender_action(text_lower: &str) -> bool {
    [
        "allow",
        "allowed",
        "autoriser",
        "autorisé",
        "ignore",
        "ignored",
        "ignorer",
        "failed",
        "échec",
        "echec",
        "no action",
        "aucune action",
    ]
    .iter()
    .any(|needle| text_lower.contains(needle))
}

fn is_risky_exclusion(field: &str, value_lower: &str, iocs: &IocSet) -> bool {
    if !ioc_hits(value_lower, iocs).is_empty() {
        return true;
    }

    if field.eq_ignore_ascii_case("ExclusionProcess") {
        return [
            "mshta",
            "powershell",
            "pwsh",
            "wscript",
            "cscript",
            "cmd.exe",
            "addinprocess32",
            "chrome",
            "msedge",
            "brave",
            "firefox",
        ]
        .iter()
        .any(|needle| value_lower.contains(needle));
    }

    if field.eq_ignore_ascii_case("ExclusionPath") {
        return [
            "\\temp",
            "appdata",
            "downloads",
            "programdata",
            "startup",
            "start menu",
        ]
        .iter()
        .any(|needle| value_lower.contains(needle));
    }

    if field.eq_ignore_ascii_case("ExclusionExtension") {
        return iocs.suspicious_extensions.iter().any(|ext| {
            value_lower
                .trim_start_matches('.')
                .eq_ignore_ascii_case(ext.trim_start_matches('.'))
        });
    }

    false
}

fn value_to_flat_text(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(value_to_flat_text)
            .collect::<Vec<_>>()
            .join(" | "),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}={}", value_to_flat_text(v)))
            .collect::<Vec<_>>()
            .join(" | "),
    }
}

fn event_to_flat_text(event: &DefenderEventRecord) -> String {
    format!(
        "TimeCreated={} | Id={} | Level={} | RecordId={} | Machine={} | Message={}",
        event.time_created.as_deref().unwrap_or("inconnu"),
        event
            .event_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "inconnu".into()),
        event.level_display_name.as_deref().unwrap_or("inconnu"),
        event
            .record_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "inconnu".into()),
        event.machine_name.as_deref().unwrap_or("inconnu"),
        event.message.as_deref().unwrap_or("")
    )
}

fn first_non_empty<'a>(a: &'a str, b: &'a str) -> &'a str {
    if !a.trim().is_empty() {
        a.trim()
    } else {
        b.trim()
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let truncated: String = value.chars().take(max_chars).collect();
    format!("{truncated}…")
}

const STATUS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
    $result = @(Get-MpComputerStatus | Select-Object `
        AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,`
        NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,IsTamperProtected,`
        AntivirusSignatureVersion,AntivirusSignatureLastUpdated,AMProductVersion,AMEngineVersion,`
        QuickScanAge,FullScanAge,ComputerID)
    $result | ConvertTo-Json -Depth 8 -Compress
} catch {
    [pscustomobject]@{
        IssaGuardError = $_.Exception.Message
        Command = 'Get-MpComputerStatus'
    } | ConvertTo-Json -Depth 4 -Compress
}
"#;

const PREFERENCE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
    $result = @(Get-MpPreference | Select-Object `
        DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableScriptScanning,DisableIOAVProtection,`
        PUAProtection,MAPSReporting,SubmitSamplesConsent,ExclusionPath,ExclusionProcess,ExclusionExtension,`
        ThreatIDDefaultAction_Ids,ThreatIDDefaultAction_Actions,ControlledFolderAccessAllowedApplications,`
        ControlledFolderAccessProtectedFolders,AttackSurfaceReductionOnlyExclusions)
    $result | ConvertTo-Json -Depth 8 -Compress
} catch {
    [pscustomobject]@{
        IssaGuardError = $_.Exception.Message
        Command = 'Get-MpPreference'
    } | ConvertTo-Json -Depth 4 -Compress
}
"#;

const THREAT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
    $result = @(Get-MpThreat | Select-Object *)
    $result | ConvertTo-Json -Depth 10 -Compress
} catch {
    [pscustomobject]@{
        IssaGuardError = $_.Exception.Message
        Command = 'Get-MpThreat'
    } | ConvertTo-Json -Depth 4 -Compress
}
"#;

const DETECTION_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
    $result = @(Get-MpThreatDetection | Select-Object *)
    $result | ConvertTo-Json -Depth 10 -Compress
} catch {
    [pscustomobject]@{
        IssaGuardError = $_.Exception.Message
        Command = 'Get-MpThreatDetection'
    } | ConvertTo-Json -Depth 4 -Compress
}
"#;

const EVENT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
    $ids = @(1116,1117,1118,1119,1007,1008,5007)
    $start = (Get-Date).AddDays(-30)
    $result = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=$ids; StartTime=$start} -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 120 `
            @{Name='TimeCreated';Expression={$_.TimeCreated.ToString('o')}},Id,ProviderName,LevelDisplayName,RecordId,MachineName,Message)
    $result | ConvertTo-Json -Depth 8 -Compress
} catch {
    [pscustomobject]@{
        IssaGuardError = $_.Exception.Message
        Command = 'Get-WinEvent Defender Operational'
    } | ConvertTo-Json -Depth 4 -Compress
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ioc_hits_detects_incident_domain_and_mshta() {
        let iocs = IocSet::default();
        let hits = ioc_hits("mshta https://claud-hub.com/app", &iocs);

        assert!(hits.iter().any(|hit| hit == "https://claud-hub.com/app"));
        assert!(hits.iter().any(|hit| hit == "claud-hub.com"));
        assert!(hits.iter().any(|hit| hit == "mshta"));
    }

    #[test]
    fn risky_exclusion_detects_script_extension_without_dot() {
        let iocs = IocSet::default();

        assert!(is_risky_exclusion("ExclusionExtension", "ps1", &iocs));
    }

    #[test]
    fn defender_event_parser_is_case_insensitive() {
        let value = json!({
            "timecreated": "2026-04-27T18:00:00Z",
            "id": "5007",
            "providername": "Microsoft-Windows-Windows Defender",
            "leveldisplayname": "Information",
            "recordid": "42",
            "machinename": "VAL",
            "message": "Configuration changed"
        });

        let event = event_record_from_value(&value);

        assert_eq!(Some(5007), event.event_id);
        assert_eq!(Some(42), event.record_id);
        assert_eq!(Some("VAL".to_string()), event.machine_name);
    }

    #[test]
    fn config_change_event_creates_orange_weak_finding() {
        let event = DefenderEventRecord {
            time_created: Some("2026-04-27T18:00:00Z".into()),
            event_id: Some(5007),
            provider_name: Some("Microsoft-Windows-Windows Defender".into()),
            level_display_name: Some("Information".into()),
            record_id: Some(42),
            machine_name: Some("VAL".into()),
            message: Some("Configuration Defender modifiée.".into()),
        };

        let findings = findings_from_events(&[event], &IocSet::default());

        assert!(findings.iter().any(|finding| {
            finding.affects_risk
                && finding.tags.iter().any(|tag| tag == "risk:orange")
                && matches!(finding.evidence_level, EvidenceLevel::Weak)
        }));
    }
}
