use std::{fs, path::Path};

fn read(relative: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|error| panic!("cannot read {relative}: {error}"))
}

#[test]
fn rootless_namespace_changes_reinstall_policy_before_attesting_ready() {
    let path_unit = read("deployments/systemd/shennong-runtime-egress-policy@.path");
    let service_unit = read("deployments/systemd/shennong-runtime-egress-policy@.service");
    let reconciler = read("scripts/reconcile-egress-policy.sh");
    let installer = read("scripts/install-egress-policy-guard.sh");
    let tmpfiles = read("deployments/tmpfiles/shennong-runtime-egress.conf");

    assert!(path_unit.contains("PathChanged=/run/user/%i/shennong-runtime-rootlesskit/child_pid"));
    assert!(path_unit.contains("Unit=shennong-runtime-egress-policy@%i.service"));
    assert!(service_unit.contains("EnvironmentFile=/etc/shennong-runtime/egress-policy-%i.env"));
    assert!(service_unit.contains(
        "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_PTRACE"
    ));
    assert!(service_unit.contains("ProtectHome=read-only"));
    assert!(service_unit.contains("Restart=on-failure"));
    assert!(tmpfiles.contains("d /run/shennong-runtime-egress 0755 root root -"));
    assert!(installer.contains(
        "systemctl enable --now \"shennong-runtime-egress-policy@${ROOTLESS_UID}.path\""
    ));
    assert!(installer.contains(
        "systemctl enable --now \"shennong-runtime-egress-policy@${ROOTLESS_UID}.service\""
    ));

    let invalidate = reconciler
        .find("rm -f -- \"${ATTESTATION_FILE}\"")
        .expect("fail-closed attestation invalidation");
    let install = reconciler
        .find("  \"${POLICY_INSTALLER}\"\n")
        .expect("policy installation");
    let publish = reconciler
        .rfind("mv --force -- \"${temporary_attestation}\" \"${ATTESTATION_FILE}\"")
        .expect("atomic attestation publication");
    assert!(invalidate < install && install < publish);
    assert!(reconciler.contains("\"${pid_after}\" != \"${netns_pid}\""));
    assert!(reconciler.contains("\"${inode_after}\" != \"${netns_inode}\""));
    assert!(reconciler.contains("trap 'cleanup; exit 143' TERM"));
}

#[test]
fn runtime_compose_mounts_and_requires_policy_guard_inputs() {
    let compose = read("deployments/docker/compose.rootless.yaml");
    for required in [
        "SHENNONG_ROOTLESS_UID:",
        "SHENNONG_ROOTLESSKIT_CHILD_PID_FILE:",
        "SHENNONG_EGRESS_POLICY_STATE_FILE:",
        "SHENNONG_RUNTIME_PROXY_V4:",
        "target: /run/shennong-rootlesskit",
        "target: /run/shennong-egress",
    ] {
        assert!(
            compose.contains(required),
            "missing Compose guard: {required}"
        );
    }
}

#[test]
fn rootless_dockerd_accepts_child_ready_notification() {
    let unit = read("deployments/systemd/shennong-runtime-docker.service");
    assert!(unit.contains("Type=notify"));
    assert!(unit.contains("NotifyAccess=all"));
}

#[test]
fn jupyterlab_461_uses_supported_proxy_and_log_arguments() {
    let dockerfile = read("container/ide.Dockerfile");
    let launcher = read("container/ide/launch_ide.py");
    assert!(dockerfile.contains("ARG JUPYTERLAB_VERSION=4.6.1"));
    assert!(dockerfile.contains("CMD [\"python3\", \"/opt/shennong/bin/launch_ide.py\"]"));
    assert!(launcher.contains("--ServerApp.log_level=WARN"));
    assert!(launcher.contains("--ServerApp.base_url={proxy_path}/"));
    assert!(!launcher.contains("--ServerApp.log_level=WARNING"));
}

#[test]
fn rstudio_non_root_state_and_database_paths_are_explicit() {
    let dockerfile = read("container/ide.Dockerfile");
    let worker_dockerfile = read("container/worker.Dockerfile");
    let launcher = read("container/ide/launch_ide.py");
    let database = read("container/ide/rstudio-database.conf");
    assert!(dockerfile.contains("COPY --chown=0:0 container/ide/rstudio-database.conf"));
    assert!(dockerfile.contains("chmod 0444 /opt/shennong/etc/rstudio-database.conf"));
    assert_eq!(
        database,
        "provider=sqlite\ndirectory=/tmp/shennong-rstudio\n"
    );
    assert!(worker_dockerfile.contains("--home-dir /workspace/.shennong/home"));
    assert!(launcher.contains("os.makedirs(WORKSPACE_HOME, mode=0o700, exist_ok=True)"));
    for required in [
        "\"HOME\": WORKSPACE_HOME",
        "\"USER\": \"shennong\"",
        "\"LOGNAME\": \"shennong\"",
    ] {
        assert!(
            launcher.contains(required),
            "missing fixed IDE process identity: {required}"
        );
    }
    for required in [
        "--server-user=shennong",
        "--server-data-dir={RSTUDIO_STATE_DIR}",
        "--server-pid-file={RSTUDIO_STATE_DIR}/rserver.pid",
        "--secure-cookie-key-file={RSTUDIO_STATE_DIR}/secure-cookie-key",
        "--database-config-file={RSTUDIO_DATABASE_CONFIG}",
    ] {
        assert!(
            launcher.contains(required),
            "missing RStudio flag: {required}"
        );
    }
}
