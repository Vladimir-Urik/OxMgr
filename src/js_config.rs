//! Helpers for extracting plain object literals from simple CommonJS-style
//! config files such as `module.exports = { ... }`.

use anyhow::Result;

/// Returns the outermost object literal found in the payload.
///
/// This intentionally supports the simple config shapes used by PM2 ecosystem
/// files and Oxmgr deploy config wrappers, not arbitrary JavaScript parsing.
pub fn extract_js_object_literal(payload: &str, context: &str) -> Result<String> {
    let trimmed = payload.trim();
    if trimmed.starts_with('{') {
        return Ok(trimmed.to_string());
    }

    let Some(start) = trimmed.find('{') else {
        anyhow::bail!("failed to locate JS object in {context}");
    };
    let Some(end) = trimmed.rfind('}') else {
        anyhow::bail!("failed to locate JS object end in {context}");
    };
    if end < start {
        anyhow::bail!("invalid JS object boundaries in {context}");
    }

    Ok(trimmed[start..=end].to_string())
}

#[cfg(test)]
mod tests {
    use super::extract_js_object_literal;

    #[test]
    fn extract_js_object_literal_handles_module_exports_wrapping() {
        let source = r#"
module.exports = {
  apps: [{ script: "api.js" }]
};
"#;

        let object =
            extract_js_object_literal(source, "ecosystem config").expect("expected extraction");
        assert!(object.starts_with('{'));
        assert!(object.ends_with('}'));
        assert!(object.contains("apps"));
    }

    #[test]
    fn extract_js_object_literal_handles_export_default_wrapping() {
        let source = r#"
export default {
  apps: [{ script: "api.js" }]
};
"#;

        let object =
            extract_js_object_literal(source, "ecosystem config").expect("expected extraction");
        assert!(object.starts_with('{'));
        assert!(object.ends_with('}'));
        assert!(object.contains("apps"));
    }
}
