//! 在滑动窗口中寻找真实事件序列；同一事件不能冒充有序链的多个步骤。
use super::{BTreeSet, Event, Id, TemporalOutcome, TemporalRule};

pub(super) fn evaluate(rule: &TemporalRule, events: &[Event]) -> TemporalOutcome {
    evaluate_containing(rule, events, None)
}

pub(super) fn evaluate_containing(rule: &TemporalRule, events: &[Event], anchor: Option<Id>) -> TemporalOutcome {
    let mut events: Vec<_> = events.iter().collect();
    events.sort_by_key(|event| event.time);
    let mut seen = BTreeSet::new();
    events.retain(|event| seen.insert(event.id));
    let mut result = outcome(rule, &events, false);
    if rule.window_secs <= 0
        || rule.steps.is_empty()
        || rule.steps.iter().all(|step| step.optional)
        || events.first().is_some_and(|first| events.iter().any(|e| e.tenant_id != first.tenant_id))
    {
        result.matched = false;
        return result;
    }
    // 从每个左边界看完整窗口；无关旧日志不应让窗口内的有效链失效。
    let mut end = 0;
    for start in 0..events.len() {
        end = end.max(start);
        while end < events.len() && events[end].time.since_secs(&events[start].time) <= rule.window_secs {
            end += 1;
        }
        let candidate = outcome(rule, &events[start..end], true);
        if candidate.matched && anchor.is_none_or(|id| candidate.matched_event_ids.contains(&id)) {
            return candidate;
        }
    }
    result.matched = false;
    result
}

fn outcome(rule: &TemporalRule, events: &[&Event], within_window: bool) -> TemporalOutcome {
    let matches: Vec<Vec<usize>> = rule
        .steps
        .iter()
        .map(|step| events.iter().enumerate().filter_map(|(i, event)| step.matches(event).then_some(i)).collect())
        .collect();
    let missing_steps = rule
        .steps
        .iter()
        .zip(&matches)
        .filter(|(step, ids)| !step.optional && ids.len() < step.min_events.max(1) as usize)
        .map(|(step, _)| step.name.clone())
        .collect::<Vec<_>>();
    let mut hit_steps =
        rule.steps.iter().zip(&matches).filter(|(step, ids)| ids.len() >= step.min_events.max(1) as usize).count();
    let ordered = ordered_selection(rule, &matches);
    let order_ok = !rule.order_required || ordered.is_some();
    let selected = if rule.order_required { ordered.unwrap_or_default() } else { matches };
    if rule.order_required && order_ok {
        hit_steps =
            rule.steps.iter().zip(&selected).filter(|(step, ids)| ids.len() >= step.min_events.max(1) as usize).count();
    }
    let indexes = selected.iter().flatten().copied().collect::<BTreeSet<_>>();
    let matched_event_ids: Vec<Id> = indexes.iter().map(|i| events[*i].id).collect();
    let span_secs =
        indexes.first().zip(indexes.last()).map_or(0, |(a, b)| events[*b].time.since_secs(&events[*a].time));
    let window_ok = within_window || (span_secs <= rule.window_secs && rule.window_secs > 0);
    TemporalOutcome {
        rule_key: rule.key.clone(),
        matched: missing_steps.is_empty() && window_ok && order_ok,
        hit_steps,
        total_steps: rule.steps.len().max(1),
        missing_steps,
        matched_event_ids,
        span_secs,
        window_secs: rule.window_secs,
        order_ok,
        window_ok,
    }
}

fn ordered_selection(rule: &TemporalRule, matches: &[Vec<usize>]) -> Option<Vec<Vec<usize>>> {
    let mut selected = vec![Vec::new(); rule.steps.len()];
    let mut next = 0;
    // 先选必需步骤，避免可选步骤抢占后续必需步骤的事件。
    for (i, step) in rule.steps.iter().enumerate().filter(|(_, step)| !step.optional) {
        let needed = step.min_events.max(1) as usize;
        selected[i] = matches[i].iter().copied().filter(|position| *position >= next).take(needed).collect();
        if selected[i].len() < needed {
            return None;
        }
        next = selected[i].last().copied().unwrap_or(next) + 1;
    }
    for (i, step) in rule.steps.iter().enumerate().filter(|(_, step)| step.optional) {
        let lower = selected[..i].iter().flatten().max().map_or(0, |position| position + 1);
        let upper = selected[i + 1..].iter().flatten().min().copied().unwrap_or(usize::MAX);
        let ids: Vec<_> = matches[i]
            .iter()
            .copied()
            .filter(|p| *p >= lower && *p < upper)
            .take(step.min_events.max(1) as usize)
            .collect();
        if ids.len() >= step.min_events.max(1) as usize {
            selected[i] = ids;
        }
    }
    Some(selected)
}
