use super::*;

pub(super) fn validate(schema: &Value, input: Option<&Value>, name: &str) -> DomainResult<()> {
    let required = schema.get("required").and_then(Value::as_bool).unwrap_or(false);
    let Some(value) = input.filter(|value| !value.is_null()) else {
        return if required { invalid(name, "必填") } else { Ok(()) };
    };
    let kind = schema.get("type").and_then(Value::as_str).unwrap_or_default();
    let valid = match kind {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "" => true,
        _ => false,
    };
    if !valid {
        return invalid(name, &format!("必须是 {kind}"));
    }
    if let Some(text) = value.as_str() {
        let len = text.chars().count() as f64;
        if required && text.trim().is_empty() {
            return invalid(name, "不能为空");
        }
        if outside(len, schema, "minLength", "maxLength") {
            return invalid(name, "长度超出接口限制");
        }
    }
    if let Some(number) = value.as_f64() {
        if outside(number, schema, "minimum", "maximum") {
            return invalid(name, "数值超出接口限制");
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array).filter(|list| !list.is_empty()) {
        let candidate = value.as_str().map_or_else(|| value.to_string(), str::to_string);
        if !allowed.iter().any(|item| item.as_str().map_or_else(|| item.to_string(), str::to_string) == candidate) {
            return invalid(name, "取值不在接口允许范围内");
        }
    }
    if let Some(values) = value.as_array() {
        if values.len() > 1000 {
            return invalid(name, "每次最多 1000 项");
        }
        if let Some(items) = schema.get("items") {
            for (index, value) in values.iter().enumerate() {
                validate(items, Some(value), &format!("{name}[{index}]"))?;
            }
        }
    }
    if let (Some(fields), Some(values)) = (schema.get("properties").and_then(Value::as_object), value.as_object()) {
        for key in values.keys() {
            if !fields.contains_key(key) {
                return invalid(&format!("{name}.{key}"), "接口未定义该字段");
            }
        }
        for (key, field) in fields {
            validate(field, values.get(key), &format!("{name}.{key}"))?;
        }
    }
    Ok(())
}
fn invalid<T>(name: &str, reason: &str) -> DomainResult<T> {
    Err(DomainError::Validation(format!("云 API 参数 {name} {reason}")))
}
fn outside(value: f64, schema: &Value, min: &str, max: &str) -> bool {
    let limit = |key| schema.get(key).and_then(|value| value.as_f64().or_else(|| value.as_str()?.parse::<f64>().ok()));
    limit(min).is_some_and(|min| value < min) || limit(max).is_some_and(|max| value > max)
}
