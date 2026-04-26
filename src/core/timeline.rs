use crate::core::model::TimelineEvent;

pub fn push_event(
    timeline: &mut Vec<TimelineEvent>,
    title: impl Into<String>,
    details: impl Into<String>,
) {
    timeline.push(TimelineEvent::now(title, details));
}
