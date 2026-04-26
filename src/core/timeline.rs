use crate::core::model::{TimelineEvent, TimelineKind};

pub fn push_event(
    timeline: &mut Vec<TimelineEvent>,
    title: impl Into<String>,
    details: impl Into<String>,
) {
    timeline.push(TimelineEvent::now(title, details));
}

pub fn push_event_with_kind(
    timeline: &mut Vec<TimelineEvent>,
    kind: TimelineKind,
    title: impl Into<String>,
    details: impl Into<String>,
) {
    timeline.push(TimelineEvent::with_kind(kind, title, details));
}
