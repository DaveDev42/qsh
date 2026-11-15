//! The `reverse_config_retired` doctor row (ADR-0068 decision 4): settings or
//! service units of the retired reverse connection that a machine still has.

use super::*;

impl Ops {
    /// One `warn` finding naming every leftover retired config key and every
    /// registered `listen`/`reverse` service unit, or none when there is
    /// nothing left. Runs for client and server devices alike: a leftover
    /// key is leftover wherever it sits.
    pub(super) fn doctor_reverse_config_retired_finding(
        &self,
        config: &Config,
        env: &DoctorEnvironment<'_>,
    ) -> Option<DoctorFinding> {
        let mut found: Vec<String> = crate::retired::leftover_config_keys(config)
            .into_iter()
            .map(str::to_string)
            .collect();
        for mode in ["listen", "reverse"] {
            let registered = if env.os == probe::HostOs::Windows {
                Some(probe::windows_task_definition_present(
                    &self.paths.config_dir,
                    mode,
                ))
            } else {
                probe::service_unit_registered(env.os, env.home_dir, env.system_root, mode)
            };
            if registered == Some(true) {
                found.push(format!("{mode} service unit"));
            }
        }
        if found.is_empty() {
            return None;
        }
        let diag = &crate::doctor::REVERSE_CONFIG_RETIRED;
        Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "warn".to_string(),
            detail: format!("{} (left over: {})", diag.message, found.join(", ")),
            remedy: Some(diag.remedy.to_string()),
        })
    }
}
