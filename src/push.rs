//! Push decision and sync logic for canonical session refs.

use crate::{git, output};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

const SESSION_REFS: [&str; 3] = [
    git::SESSION_DATA_REF,
    git::SESSION_INDEX_BRANCH_REF,
    git::SESSION_INDEX_COMMITTER_REF,
];

/// Determine whether session refs should be pushed for a specific remote.
pub fn should_push_remote(remote: &str) -> bool {
    if remote.is_empty() || remote == "." {
        return false;
    }

    match git::remote_url(remote) {
        Ok(Some(_)) => {}
        _ => return false,
    }

    check_org_filter_remote(remote)
}

#[allow(dead_code)]
pub fn attempt_push_remote_at(repo: &Path, remote: &str) {
    attempt_push_remote_at_with_options(repo, remote, true);
}

pub fn attempt_push_remote_at_quiet(repo: &Path, remote: &str) {
    attempt_push_remote_at_with_options(repo, remote, false);
}

fn attempt_push_remote_at_with_options(repo: &Path, remote: &str, show_progress: bool) {
    let result = sync_session_refs_for_remote_at(repo, remote);

    if let Err(e) = result {
        if show_progress {
            output::note(&format!(
                "Could not sync session refs with {}: {}",
                remote, e
            ));
        } else if output::is_verbose() {
            output::detail(&format!(
                "Could not sync session refs with {}: {}",
                remote, e
            ));
        }
    } else if show_progress && output::is_verbose() {
        output::detail(&format!("Synced session refs with {}", remote));
    }
}

/// Legacy name retained for call-site compatibility; now syncs canonical session refs.
pub fn sync_notes_for_remote(remote: &str) {
    let result = (|| -> Result<()> {
        let repo_root = git::repo_root()?;
        sync_session_refs_for_remote_at(&repo_root, remote)
    })();

    if let Err(e) = result {
        output::note(&format!(
            "Could not sync session refs with {}: {}",
            remote, e
        ));
    }
}

fn sync_session_refs_for_remote_at(repo: &Path, remote: &str) -> Result<()> {
    if remote.is_empty() || remote == "." {
        anyhow::bail!("invalid remote name");
    }

    for ref_name in SESSION_REFS {
        sync_ref_for_remote_at(repo, remote, ref_name)?;
    }
    Ok(())
}

/// Fetch and merge remote session refs into local refs without pushing.
pub fn fetch_merge_notes_for_remote_at(repo: &Path, remote: &str) -> Result<()> {
    if remote.is_empty() || remote == "." {
        anyhow::bail!("invalid remote name");
    }
    for ref_name in SESSION_REFS {
        fetch_merge_ref_for_remote_at(repo, remote, ref_name)?;
    }
    Ok(())
}

fn fetch_merge_ref_for_remote_at(repo: &Path, remote: &str, ref_name: &str) -> Result<()> {
    let temp_ref = temp_ref_name(ref_name, remote);
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
    let fetch_result = git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref)?;
    if !fetch_result.fetched {
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
        return Ok(());
    }

    let merged = merge_ref_maps(repo, ref_name, &temp_ref)?;
    if let Some(new_tip) = merged {
        git::update_ref_at(Some(repo), ref_name, &new_tip)?;
    }
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
    Ok(())
}

fn sync_ref_for_remote_at(repo: &Path, remote: &str, ref_name: &str) -> Result<()> {
    sync_ref_for_remote_inner(repo, remote, ref_name, true)
}

fn sync_ref_for_remote_inner(
    repo: &Path,
    remote: &str,
    ref_name: &str,
    allow_retry: bool,
) -> Result<()> {
    let pre_remote_hash = git::remote_ref_hash_at(Some(repo), remote, ref_name).unwrap_or(None);
    let local_hash = git::local_ref_hash_at(Some(repo), ref_name).unwrap_or(None);

    if local_hash == pre_remote_hash {
        return Ok(());
    }

    if pre_remote_hash.is_none() {
        if local_hash.is_none() {
            return Ok(());
        }
        let push_res = git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash);
        if let Err(e) = push_res {
            let msg = e.to_string();
            if allow_retry && is_ref_push_race(&msg, ref_name) {
                return sync_ref_for_remote_inner(repo, remote, ref_name, false);
            }
            return Err(e);
        }
        return Ok(());
    }

    if local_hash.is_none() {
        let temp_ref = temp_ref_name(ref_name, remote);
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
        let fetch_result = git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref)?;
        if fetch_result.fetched {
            let remote_tip = git::rev_parse_at(Some(repo), &temp_ref)?;
            git::update_ref_at(Some(repo), ref_name, &remote_tip)?;
            let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
        }
        return Ok(());
    }

    let temp_ref = temp_ref_name(ref_name, remote);
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
    let fetch_result = git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref)?;
    if !fetch_result.fetched {
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
        let push_res = git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash);
        if let Err(e) = push_res {
            let msg = e.to_string();
            if allow_retry && is_ref_push_race(&msg, ref_name) {
                return sync_ref_for_remote_inner(repo, remote, ref_name, false);
            }
            return Err(e);
        }
        return Ok(());
    }

    let fetched_hash = git::rev_parse_at(Some(repo), &temp_ref).ok();
    if fetched_hash == local_hash {
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
        return Ok(());
    }

    let merged = merge_ref_maps(repo, ref_name, &temp_ref)?;
    if let Some(new_tip) = merged {
        git::update_ref_at(Some(repo), ref_name, &new_tip)?;
    }

    let push_res = git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash);
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]);
    if let Err(e) = push_res {
        let msg = e.to_string();
        if allow_retry && is_ref_push_race(&msg, ref_name) {
            return sync_ref_for_remote_inner(repo, remote, ref_name, false);
        }
        return Err(e);
    }

    Ok(())
}

fn merge_ref_maps(repo: &Path, local_ref: &str, remote_temp_ref: &str) -> Result<Option<String>> {
    let mut merged = ref_map_from_ref(repo, local_ref)?;
    for (path, sha) in ref_map_from_ref(repo, remote_temp_ref)? {
        merged.entry(path).or_insert(sha);
    }

    if merged.is_empty() {
        return Ok(None);
    }

    let new_tree = build_tree_from_map(repo, &merged)?;
    let current_tip = git::rev_parse_at(Some(repo), local_ref).ok();
    let current_tree = current_tip
        .as_deref()
        .and_then(|_| git::rev_parse_at(Some(repo), &format!("{}^{{tree}}", local_ref)).ok());
    if current_tree.as_deref() == Some(new_tree.as_str()) {
        return Ok(current_tip);
    }

    let commit = git::commit_tree_at(
        Some(repo),
        &new_tree,
        "cadence sessions sync",
        current_tip.as_deref(),
    )?;
    Ok(Some(commit))
}

fn ref_map_from_ref(repo: &Path, ref_name: &str) -> Result<BTreeMap<String, String>> {
    if !git::ref_exists_at(Some(repo), ref_name)? {
        return Ok(BTreeMap::new());
    }
    let tree_rev = format!("{}^{{tree}}", ref_name);
    let mut out = BTreeMap::new();
    for root in git::list_tree_entries_at(Some(repo), &tree_rev)? {
        let Some((_mode, kind, sha, name)) = parse_tree_line(&root) else {
            continue;
        };
        if kind == "blob" {
            out.insert(name, sha);
            continue;
        }
        if kind != "tree" {
            continue;
        }
        for child in git::list_tree_entries_at(Some(repo), &sha)? {
            if let Some((_cmode, ckind, csha, cname)) = parse_tree_line(&child)
                && ckind == "blob"
            {
                out.insert(format!("{}/{}", name, cname), csha);
            }
        }
    }
    Ok(out)
}

fn build_tree_from_map(repo: &Path, map: &BTreeMap<String, String>) -> Result<String> {
    let mut fanout: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut root_files: Vec<String> = Vec::new();

    for (path, sha) in map {
        if let Some((dir, file)) = path.split_once('/') {
            fanout
                .entry(dir.to_string())
                .or_default()
                .push(format!("100644 blob {}\t{}", sha, file));
        } else {
            root_files.push(format!("100644 blob {}\t{}", sha, path));
        }
    }

    let mut root_entries = root_files;
    for (dir, mut entries) in fanout {
        entries.sort();
        let subtree = git::mktree_at(Some(repo), &entries)?;
        root_entries.push(format!("040000 tree {}\t{}", subtree, dir));
    }
    root_entries.sort();
    git::mktree_at(Some(repo), &root_entries)
}

fn parse_tree_line(line: &str) -> Option<(String, String, String, String)> {
    let (meta, path) = line.split_once('\t')?;
    let mut parts = meta.split_whitespace();
    Some((
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        path.to_string(),
    ))
}

fn temp_ref_name(ref_name: &str, remote: &str) -> String {
    let safe = ref_name.replace('/', "-");
    format!("refs/cadence/tmp/{}/{}", remote, safe)
}

fn is_ref_push_race(stderr_trim: &str, ref_name: &str) -> bool {
    let is_lock_conflict = stderr_trim.contains("cannot lock ref")
        && stderr_trim.contains(ref_name)
        && stderr_trim.contains("expected");
    let is_non_fast_forward = stderr_trim.contains("non-fast-forward");
    let is_lease_rejected =
        stderr_trim.contains("stale info") || stderr_trim.contains("failed to push");
    is_lock_conflict || is_non_fast_forward || is_lease_rejected
}

/// Check the org filter: if a global org is configured, verify that the
/// selected remote belongs to that org.
pub fn check_org_filter_remote(remote: &str) -> bool {
    let configured_org = match git::config_get_global("ai.cadence.org") {
        Ok(Some(org)) => org,
        _ => return true,
    };

    let url = match git::remote_url(remote) {
        Ok(Some(u)) => u,
        _ => return false,
    };

    let remote_org = match git::parse_org_from_url(&url) {
        Some(org) => org,
        None => return false,
    };

    remote_org.eq_ignore_ascii_case(&configured_org)
}
