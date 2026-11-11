//! The doctor rows of the combined endpoint (ADR-0059 decision 22): a
//! `qsh listen` with `[listen].serve = true`. Kept apart from `doctor.rs`
//! because they are only about that one mode.

use super::*;

/// Whether `config` makes `qsh listen` a combined endpoint. The inferred run
/// mode stays `listen` (`[listen]` present wins in [`infer_run_mode`]), so
/// the unit and its argv do not change; only the key says it also serves.
pub(super) fn is_combined(mode: &str, config: &Config) -> bool {
    mode == "listen" && config.listen.serve
}

impl Ops {
    /// `listen_serve_ignores_serve_bind` and `serve_unit_beside_listen_serve`.
    /// Both are silent outside the combined mode.
    pub(super) fn doctor_combined_findings(
        &self,
        config: &Config,
        env: &DoctorEnvironment<'_>,
    ) -> Vec<DoctorFinding> {
        let mut out = Vec::new();
        if config.serve.bind.is_some() {
            let diag = &crate::doctor::LISTEN_SERVE_IGNORES_SERVE_BIND;
            out.push(DoctorFinding {
                code: diag.code.to_string(),
                status: "info".to_string(),
                detail: diag.message.to_string(),
                remedy: Some(diag.remedy.to_string()),
            });
        }
        if let Some(what) = self.second_serve_present(env) {
            let diag = &crate::doctor::SERVE_UNIT_BESIDE_LISTEN_SERVE;
            out.push(DoctorFinding {
                code: diag.code.to_string(),
                status: "warn".to_string(),
                detail: format!("{} ({what})", diag.message),
                remedy: Some(diag.remedy.to_string()),
            });
        }
        out
    }

    /// What shows a `qsh serve` besides the combined endpoint: a registered
    /// `serve` unit, else a live `serve.json` whose pid is not a `qsh listen`
    /// (a process with a localctl endpoint in the runtime directory is one,
    /// and the combined endpoint writes the record itself). `None` when
    /// neither is there.
    fn second_serve_present(&self, env: &DoctorEnvironment<'_>) -> Option<&'static str> {
        let unit_registered = if env.os == probe::HostOs::Windows {
            Some(probe::windows_task_definition_present(
                &self.paths.config_dir,
                "serve",
            ))
        } else {
            probe::service_unit_registered(env.os, env.home_dir, env.system_root, "serve")
        };
        if unit_registered == Some(true) {
            return Some("a serve service unit is registered");
        }
        let record = crate::serve::record::live_serve(&self.paths)?;
        let listens = crate::localctl::client::candidate_sockets(&self.paths.runtime_dir())
            .unwrap_or_default();
        if listens.iter().any(|(pid, _)| *pid == record.pid) {
            return None;
        }
        Some("serve.json names a running qsh serve")
    }
}
