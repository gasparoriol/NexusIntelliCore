//! Text-tier (N3) rules for infrastructure files: Dockerfiles, YAML
//! (compose, Kubernetes, CI), shell scripts and framework configuration.
//!
//! Configuration files are matched on the output of
//! `sanitizer::sanitize_config_text`, so secret values are redacted before any
//! rule sees them; findings carry only rule, line and a fixed description.

use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use super::rules::{Confidence, RuleMeta, Severity, Tier};
use super::types::AuditFinding;
use crate::sanitizer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Dockerfile,
    /// `.yaml` / `.yml` (compose, Kubernetes, CI pipelines).
    Yaml,
    /// Spring-style `.properties`.
    Properties,
    Shell,
}

pub struct InfraRule {
    pub meta: RuleMeta,
    targets: &'static [Target],
    /// Matched against each logical line (Dockerfile `\` continuations joined).
    pattern: &'static str,
}

const fn meta(
    id: &'static str,
    cwe: &'static str,
    owasp: Option<&'static str>,
    category: &'static str,
    severity: Severity,
    description: &'static str,
    remediation: &'static str,
) -> RuleMeta {
    RuleMeta {
        id,
        legacy_id: None,
        cwe,
        owasp,
        category,
        tier: Tier::Text,
        severity,
        confidence: Confidence::High,
        description,
        remediation,
    }
}

const SCRIPT_TARGETS: &[Target] = &[Target::Dockerfile, Target::Yaml, Target::Shell];

pub static INFRA_RULES: &[InfraRule] = &[
    InfraRule {
        meta: meta(
            "docker-root-user",
            "CWE-250",
            Some("A05:2021"),
            "container_hardening",
            Severity::Medium,
            "Container runs as root",
            "Create an unprivileged user and switch to it with USER.",
        ),
        targets: &[Target::Dockerfile],
        pattern: r"(?i)^\s*USER\s+(root|0)(\s|:|$)",
    },
    InfraRule {
        meta: meta(
            "docker-remote-add",
            "CWE-829",
            Some("A08:2021"),
            "supply_chain",
            Severity::Medium,
            "ADD downloads a remote URL without integrity verification",
            "Download with a pinned checksum (RUN curl … && sha256sum -c) or use COPY.",
        ),
        targets: &[Target::Dockerfile],
        pattern: r"(?i)^\s*ADD\s+(--\S+\s+)*https?://",
    },
    InfraRule {
        meta: meta(
            "any-download-pipe-to-shell",
            "CWE-494",
            Some("A08:2021"),
            "supply_chain",
            Severity::High,
            "Downloaded script piped straight into a shell",
            "Download to a file, verify its checksum or signature, then execute it.",
        ),
        targets: SCRIPT_TARGETS,
        pattern: r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|ash|dash)\b",
    },
    InfraRule {
        meta: meta(
            "docker-secret-in-env",
            "CWE-798",
            Some("A07:2021"),
            "hardcoded_secret",
            Severity::High,
            "Secret-like variable baked into the image via ENV/ARG",
            "Pass secrets at runtime or with BuildKit secret mounts (RUN --mount=type=secret).",
        ),
        targets: &[Target::Dockerfile],
        pattern: r"(?i)^\s*(ENV\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)\w*(\s*=\s*|\s+)\S|ARG\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)\w*)",
    },
    InfraRule {
        meta: meta(
            "docker-ssh-port-exposed",
            "CWE-284",
            Some("A05:2021"),
            "container_hardening",
            Severity::Low,
            "SSH port exposed by the image",
            "Do not run SSH in containers; use `docker exec` / `kubectl exec`.",
        ),
        targets: &[Target::Dockerfile],
        pattern: r"(?i)^\s*EXPOSE\s+(.*\s)?22(/tcp)?(\s|$)",
    },
    InfraRule {
        meta: meta(
            "docker-unpinned-base-image",
            "CWE-829",
            Some("A06:2021"),
            "supply_chain",
            Severity::Low,
            "Base image not pinned to a version or digest",
            "Pin the base image to a version tag or, better, an @sha256 digest.",
        ),
        targets: &[Target::Dockerfile],
        // Refined in code: stage aliases and `scratch` are not images.
        pattern: r"(?i)^\s*FROM\s+(--\S+\s+)*(?P<image>[^\s@]+?)(?P<tag>:[^\s/@]+)?(\s|$)",
    },
    InfraRule {
        meta: meta(
            "yaml-privileged-container",
            "CWE-250",
            Some("A05:2021"),
            "container_hardening",
            Severity::High,
            "Container runs in privileged mode",
            "Drop `privileged`; grant only the specific capabilities required.",
        ),
        targets: &[Target::Yaml],
        pattern: r"^\s*privileged\s*:\s*true\b",
    },
    InfraRule {
        meta: meta(
            "spring-actuator-endpoints-exposed",
            "CWE-200",
            Some("A05:2021"),
            "exposure",
            Severity::Medium,
            "All Spring Boot actuator endpoints exposed over the web",
            "Expose only the endpoints you need (e.g. health,info) and secure them.",
        ),
        targets: &[Target::Properties, Target::Yaml],
        pattern: r#"(management\.endpoints\.web\.exposure\.include\s*[=:]\s*["']?\*|^\s*include\s*:\s*["']\*["'])"#,
    },
    InfraRule {
        meta: meta(
            "spring-ssl-disabled",
            "CWE-319",
            Some("A02:2021"),
            "transport_security",
            Severity::Medium,
            "TLS explicitly disabled for the embedded server",
            "Enable server.ssl or terminate TLS at a trusted proxy.",
        ),
        targets: &[Target::Properties, Target::Yaml],
        pattern: r"server\.ssl\.enabled\s*[=:]\s*false\b",
    },
];

static COMPILED: LazyLock<Vec<(&'static InfraRule, Regex)>> = LazyLock::new(|| {
    INFRA_RULES
        .iter()
        .filter_map(|r| match Regex::new(r.pattern) {
            Ok(re) => Some((r, re)),
            Err(e) => {
                tracing::warn!(rule = r.meta.id, error = %e, "invalid infra rule pattern; skipped");
                None
            }
        })
        .collect()
});

fn target_of(path: &Path) -> Option<Target> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    if lower == "dockerfile"
        || lower.starts_with("dockerfile.")
        || lower.ends_with(".dockerfile")
        || lower == "containerfile"
    {
        return Some(Target::Dockerfile);
    }
    match path.extension()?.to_str()? {
        "yaml" | "yml" => Some(Target::Yaml),
        "properties" => Some(Target::Properties),
        "sh" | "bash" => Some(Target::Shell),
        _ => None,
    }
}

/// Run the infrastructure rules on one file.
#[must_use]
pub fn audit_infra(path: &Path, source: &str) -> Vec<AuditFinding> {
    let Some(target) = target_of(path) else {
        return Vec::new();
    };
    let sanitized;
    let text = if sanitizer::is_config_file(path) {
        sanitized = sanitizer::sanitize_config_text(source).0;
        sanitized.as_str()
    } else {
        source
    };

    let lines = logical_lines(text, target == Target::Dockerfile);
    let stages: HashSet<String> = if target == Target::Dockerfile {
        stage_aliases(&lines)
    } else {
        HashSet::new()
    };

    let mut findings = Vec::new();
    for (rule, re) in COMPILED.iter() {
        if !rule.targets.contains(&target) {
            continue;
        }
        for (line_no, line) in &lines {
            let Some(caps) = re.captures(line) else {
                continue;
            };
            if rule.meta.id == "docker-unpinned-base-image" && !is_unpinned_image(&caps, &stages) {
                continue;
            }
            findings.push(AuditFinding {
                rule: &rule.meta,
                line: *line_no,
                is_write_sink: false,
                description: rule.meta.description.to_owned(),
                flow: None,
                function: None,
            });
        }
    }
    findings.sort_by_key(|f| (f.line, f.rule.id));
    findings
}

/// Lines with their 1-based start line; comments dropped and, for
/// Dockerfiles, `\`-continued lines joined.
fn logical_lines(text: &str, join_continuations: bool) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        if raw.trim_start().starts_with('#') {
            continue;
        }
        let (start, mut acc) = pending.take().unwrap_or((i + 1, String::new()));
        let continued = join_continuations && raw.trim_end().ends_with('\\');
        acc.push_str(raw.trim_end().trim_end_matches('\\'));
        if continued {
            acc.push(' ');
            pending = Some((start, acc));
        } else {
            out.push((start, acc));
        }
    }
    out.extend(pending);
    out
}

/// Build stage names declared with `FROM … AS <name>`.
fn stage_aliases(lines: &[(usize, String)]) -> HashSet<String> {
    static AS: LazyLock<Option<Regex>> =
        LazyLock::new(|| Regex::new(r"(?i)^\s*FROM\s+.*\s+AS\s+(\S+)").ok());
    let Some(re) = AS.as_ref() else {
        return HashSet::new();
    };
    lines
        .iter()
        .filter_map(|(_, l)| re.captures(l))
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_ascii_lowercase()))
        .collect()
}

fn is_unpinned_image(caps: &regex::Captures<'_>, stages: &HashSet<String>) -> bool {
    let image = caps.name("image").map_or("", |m| m.as_str());
    let lower = image.to_ascii_lowercase();
    if lower == "scratch" || stages.contains(&lower) || image.contains('$') {
        return false;
    }
    caps.name("tag")
        .is_none_or(|t| t.as_str().eq_ignore_ascii_case(":latest"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(file: &str, src: &str) -> Vec<&'static str> {
        audit_infra(Path::new(file), src)
            .iter()
            .map(|f| f.rule.id)
            .collect()
    }

    /// (rule, file, source, expected to fire)
    const CASES: &[(&str, &str, &str, bool)] = &[
        (
            "docker-root-user",
            "Dockerfile",
            "FROM alpine:3.20\nUSER root\n",
            true,
        ),
        (
            "docker-root-user",
            "Dockerfile",
            "FROM alpine:3.20\nUSER app\n",
            false,
        ),
        (
            "docker-root-user",
            "Dockerfile",
            "FROM alpine:3.20\nUSER 0:0\n",
            true,
        ),
        (
            "docker-remote-add",
            "Dockerfile",
            "ADD https://example.org/app.tgz /opt/\n",
            true,
        ),
        (
            "docker-remote-add",
            "Dockerfile",
            "ADD app.tgz /opt/\n",
            false,
        ),
        (
            "docker-remote-add",
            "Dockerfile",
            "ADD --chown=app http://example.org/x /x\n",
            true,
        ),
        (
            "any-download-pipe-to-shell",
            "Dockerfile",
            "RUN curl -fsSL https://get.example.org | sh\n",
            true,
        ),
        (
            "any-download-pipe-to-shell",
            "Dockerfile",
            "RUN curl -fsSLo i.sh https://get.example.org && sha256sum -c i.sha256\n",
            false,
        ),
        (
            "any-download-pipe-to-shell",
            "Dockerfile",
            "RUN wget -qO- https://get.example.org \\\n    | sudo bash\n",
            true,
        ),
        (
            "any-download-pipe-to-shell",
            "ci.yml",
            "steps:\n  - run: curl -s https://x.example.org/install | bash\n",
            true,
        ),
        (
            "any-download-pipe-to-shell",
            "setup.sh",
            "curl -s https://x.example.org/install | grep v\n",
            false,
        ),
        (
            "docker-secret-in-env",
            "Dockerfile",
            "ENV DB_PASSWORD=hunter2\n",
            true,
        ),
        (
            "docker-secret-in-env",
            "Dockerfile",
            "ENV APP_PORT=8080\n",
            false,
        ),
        (
            "docker-secret-in-env",
            "Dockerfile",
            "ARG NPM_TOKEN\n",
            true,
        ),
        (
            "docker-ssh-port-exposed",
            "Dockerfile",
            "EXPOSE 8080 22\n",
            true,
        ),
        (
            "docker-ssh-port-exposed",
            "Dockerfile",
            "EXPOSE 8080 2222\n",
            false,
        ),
        (
            "docker-ssh-port-exposed",
            "Dockerfile",
            "EXPOSE 22/tcp\n",
            true,
        ),
        (
            "docker-unpinned-base-image",
            "Dockerfile",
            "FROM node\n",
            true,
        ),
        (
            "docker-unpinned-base-image",
            "Dockerfile",
            "FROM node:22-alpine AS build\nFROM build\nFROM scratch\n",
            false,
        ),
        (
            "docker-unpinned-base-image",
            "Dockerfile.prod",
            "FROM --platform=linux/amd64 python:latest\n",
            true,
        ),
        (
            "yaml-privileged-container",
            "docker-compose.yml",
            "services:\n  app:\n    privileged: true\n",
            true,
        ),
        (
            "yaml-privileged-container",
            "docker-compose.yml",
            "services:\n  app:\n    privileged: false\n",
            false,
        ),
        (
            "yaml-privileged-container",
            "pod.yaml",
            "securityContext:\n  privileged: true  # debugging\n",
            true,
        ),
        (
            "spring-actuator-endpoints-exposed",
            "application.properties",
            "management.endpoints.web.exposure.include=*\n",
            true,
        ),
        (
            "spring-actuator-endpoints-exposed",
            "application.properties",
            "management.endpoints.web.exposure.include=health,info\n",
            false,
        ),
        (
            "spring-actuator-endpoints-exposed",
            "application.yml",
            "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n",
            true,
        ),
        (
            "spring-ssl-disabled",
            "application.properties",
            "server.ssl.enabled=false\n",
            true,
        ),
        (
            "spring-ssl-disabled",
            "application.properties",
            "server.ssl.enabled=true\n",
            false,
        ),
        (
            "spring-ssl-disabled",
            "application.yml",
            "spring.profiles: prod\nserver.ssl.enabled: false\n",
            true,
        ),
    ];

    #[test]
    fn infra_rules_corpus() {
        let failures: Vec<String> = CASES
            .iter()
            .filter(|(rule, file, src, expected)| ids(file, src).contains(rule) != *expected)
            .map(|(rule, file, src, expected)| {
                format!("{rule} on {file} expected {expected}: {src:?}")
            })
            .collect();
        assert!(
            failures.is_empty(),
            "infra corpus:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn every_infra_rule_has_positive_and_negative_cases() {
        for rule in INFRA_RULES {
            for expected in [true, false] {
                assert!(
                    CASES
                        .iter()
                        .any(|(id, _, _, e)| *id == rule.meta.id && *e == expected),
                    "{} lacks a {} case",
                    rule.meta.id,
                    if expected { "positive" } else { "negative" }
                );
            }
        }
    }

    #[test]
    fn every_infra_pattern_compiles() {
        assert_eq!(COMPILED.len(), INFRA_RULES.len());
    }

    #[test]
    fn config_rules_never_see_secret_values() {
        let findings = audit_infra(
            Path::new("application.properties"),
            "spring.datasource.password=s3cr3t-Value\nserver.ssl.enabled=false\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings.iter().all(|f| !f.description.contains("s3cr3t")));
    }

    #[test]
    fn non_infra_files_are_ignored() {
        assert!(target_of(Path::new("src/main.rs")).is_none());
        assert_eq!(
            target_of(Path::new("deploy/Dockerfile")),
            Some(Target::Dockerfile)
        );
        assert!(ids("main.rs", "USER root\n").is_empty());
    }
}
