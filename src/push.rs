//! Push decision and sync logic for canonical session refs.

use crate::git;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;
use tracing::{info, warn};

const SESSION_REFS: [&str; 3] = [
    git::SESSION_DATA_REF,
    git::SESSION_INDEX_BRANCH_REF,
    git::SESSION_INDEX_COMMITTER_REF,
];

/// Determine whether session refs should be pushed for a specific remote.
pub async fn should_push_remote(remote: &str) -> bool {
    if remote.is_empty() || remote == "." {
        return false;
    }

    match git::remote_url(remote).await {
        Ok(Some(_)) => {}
        _ => return false,
    }

    check_org_filter_remote(remote).await
}

pub async fn try_push_remote_at_quiet(repo: &Path, remote: &str) -> Result<()> {
    sync_session_refs_for_remote_at(repo, remote).await
}

pub async fn sync_session_refs_for_remote_at(repo: &Path, remote: &str) -> Result<()> {
    if remote.is_empty() || remote == "." {
        anyhow::bail!("invalid remote name");
    }

    // Fast no-op path: skip all work if local and remote hashes match for all refs.
    let remote_hashes = git::remote_ref_hashes_at(Some(repo), remote, &SESSION_REFS)
        .await
        .with_context(|| format!("read remote ref hashes for {remote}"))?;
    let local_hashes = git::local_ref_hashes_at(Some(repo), &SESSION_REFS)
        .await
        .context("read local session ref hashes")?;
    let all_match = SESSION_REFS
        .iter()
        .all(|r| local_hashes.get(*r) == remote_hashes.get(*r));
    info!(
        remote = %remote,
        repo = %repo.display(),
        refs_total = SESSION_REFS.len(),
        refs_equal = all_match,
        "starting session ref sync"
    );
    if all_match {
        info!(remote = %remote, "no session ref changes detected; skipping sync");
        return Ok(());
    }

    // Sync refs serially to avoid concurrent fetch/update-ref lock contention
    // in the same repository.
    for ref_name in SESSION_REFS {
        let pre_remote_hash = remote_hashes.get(ref_name).cloned();
        let local_hash = local_hashes.get(ref_name).cloned();
        info!(
            remote = %remote,
            ref_name = %ref_name,
            remote_tip = %short_hash(pre_remote_hash.as_deref()),
            local_tip = %short_hash(local_hash.as_deref()),
            "starting per-ref sync"
        );
        if let Err(e) =
            sync_ref_for_remote_with_state(repo, remote, ref_name, pre_remote_hash, local_hash)
                .await
        {
            warn!(
                remote = %remote,
                ref_name = %ref_name,
                error = %e,
                "per-ref sync failed"
            );
            return Err(e);
        }
    }
    info!(remote = %remote, "session ref sync finished");
    Ok(())
}

/// Fetch and merge remote session refs into local refs without pushing.
pub async fn fetch_merge_notes_for_remote_at(repo: &Path, remote: &str) -> Result<()> {
    if remote.is_empty() || remote == "." {
        anyhow::bail!("invalid remote name");
    }
    for ref_name in SESSION_REFS {
        fetch_merge_ref_for_remote_at(repo, remote, ref_name).await?;
    }
    Ok(())
}

async fn fetch_merge_ref_for_remote_at(repo: &Path, remote: &str, ref_name: &str) -> Result<()> {
    let temp_ref = temp_ref_name(ref_name, remote);
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
    let fetch_result = git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref).await?;
    if !fetch_result.fetched {
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
        return Ok(());
    }

    let merged = merge_ref_maps(repo, ref_name, &temp_ref).await?;
    if let Some(new_tip) = merged {
        git::update_ref_at(Some(repo), ref_name, &new_tip).await?;
    }
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
    Ok(())
}

async fn sync_ref_for_remote_with_state(
    repo: &Path,
    remote: &str,
    ref_name: &str,
    pre_remote_hash: Option<String>,
    local_hash: Option<String>,
) -> Result<()> {
    let local_has_new_content = local_hash.is_some() && local_hash != pre_remote_hash;
    info!(
        remote = %remote,
        ref_name = %ref_name,
        remote_tip = %short_hash(pre_remote_hash.as_deref()),
        local_tip = %short_hash(local_hash.as_deref()),
        local_has_new_content,
        "evaluating ref sync state"
    );

    if local_hash == pre_remote_hash {
        info!(remote = %remote, ref_name = %ref_name, "ref already in sync");
        return Ok(());
    }

    if pre_remote_hash.is_none() {
        if local_hash.is_none() {
            info!(
                remote = %remote,
                ref_name = %ref_name,
                "remote and local ref missing; nothing to sync"
            );
            return Ok(());
        }
        info!(
            remote = %remote,
            ref_name = %ref_name,
            "remote ref missing; pushing local content to remote"
        );
        let push_res =
            git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash).await;
        if let Err(e) = push_res {
            let msg = e.to_string();
            if is_ref_push_race(&msg, ref_name) {
                warn!(
                    remote = %remote,
                    ref_name = %ref_name,
                    "push raced; retrying with refresh flow"
                );
                return sync_ref_for_remote_inner(repo, remote, ref_name, false).await;
            }
            return Err(e);
        }
        info!(
            remote = %remote,
            ref_name = %ref_name,
            pushed_local_new_content = true,
            "pushed local ref successfully"
        );
        return Ok(());
    }

    if local_hash.is_none() {
        info!(
            remote = %remote,
            ref_name = %ref_name,
            "local ref missing; attempting to fetch remote content"
        );
        let temp_ref = temp_ref_name(ref_name, remote);
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
        let fetch_result =
            git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref).await?;
        if fetch_result.fetched {
            let remote_tip = git::rev_parse_at(Some(repo), &temp_ref).await?;
            git::update_ref_at(Some(repo), ref_name, &remote_tip).await?;
            info!(
                remote = %remote,
                ref_name = %ref_name,
                remote_tip = %short_hash(Some(remote_tip.as_str())),
                pulled_remote_new_content = true,
                "updated local ref from remote"
            );
        } else {
            info!(
                remote = %remote,
                ref_name = %ref_name,
                pulled_remote_new_content = false,
                "remote ref not fetched; nothing to apply locally"
            );
        }
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
        return Ok(());
    }

    let temp_ref = temp_ref_name(ref_name, remote);
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
    let fetch_result = git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref).await?;
    if !fetch_result.fetched {
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
        info!(
            remote = %remote,
            ref_name = %ref_name,
            pulled_remote_new_content = false,
            pushed_local_new_content = true,
            "remote ref absent during fetch; pushing local content"
        );
        let push_res =
            git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash).await;
        if let Err(e) = push_res {
            let msg = e.to_string();
            if is_ref_push_race(&msg, ref_name) {
                warn!(
                    remote = %remote,
                    ref_name = %ref_name,
                    "push raced after missing fetch; retrying with refresh flow"
                );
                return sync_ref_for_remote_inner(repo, remote, ref_name, false).await;
            }
            return Err(e);
        }
        info!(remote = %remote, ref_name = %ref_name, "pushed local ref successfully");
        return Ok(());
    }

    let fetched_hash = git::rev_parse_at(Some(repo), &temp_ref).await.ok();
    if fetched_hash == local_hash {
        info!(
            remote = %remote,
            ref_name = %ref_name,
            pulled_remote_new_content = false,
            pushed_local_new_content = false,
            "remote content matches local; no merge or push needed"
        );
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
        return Ok(());
    }

    info!(
        remote = %remote,
        ref_name = %ref_name,
        fetched_remote_tip = %short_hash(fetched_hash.as_deref()),
        pulled_remote_new_content = true,
        "remote contains new content; merging with local ref"
    );
    let merged = merge_ref_maps(repo, ref_name, &temp_ref).await?;
    if let Some(new_tip) = merged {
        git::update_ref_at(Some(repo), ref_name, &new_tip).await?;
        info!(
            remote = %remote,
            ref_name = %ref_name,
            merged_tip = %short_hash(Some(new_tip.as_str())),
            "updated local ref with merged content"
        );
    }
    let push_res =
        git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash).await;
    let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
    if let Err(e) = push_res {
        let msg = e.to_string();
        if is_ref_push_race(&msg, ref_name) {
            warn!(
                remote = %remote,
                ref_name = %ref_name,
                "push raced after merge; retrying with refresh flow"
            );
            return sync_ref_for_remote_inner(repo, remote, ref_name, false).await;
        }
        return Err(e);
    }
    info!(
        remote = %remote,
        ref_name = %ref_name,
        pulled_remote_new_content = true,
        pushed_local_new_content = true,
        "pushed merged ref successfully"
    );
    Ok(())
}

async fn sync_ref_for_remote_inner(
    repo: &Path,
    remote: &str,
    ref_name: &str,
    allow_retry: bool,
) -> Result<()> {
    let mut may_retry = allow_retry;
    loop {
        let pre_remote_hash = git::remote_ref_hash_at(Some(repo), remote, ref_name)
            .await
            .unwrap_or(None);
        let local_hash = git::local_ref_hash_at(Some(repo), ref_name)
            .await
            .unwrap_or(None);

        if local_hash == pre_remote_hash {
            info!(
                remote = %remote,
                ref_name = %ref_name,
                "fallback sync observed ref already in sync"
            );
            return Ok(());
        }

        if pre_remote_hash.is_none() {
            if local_hash.is_none() {
                return Ok(());
            }
            let push_res =
                git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash).await;
            if let Err(e) = push_res {
                let msg = e.to_string();
                if may_retry && is_ref_push_race(&msg, ref_name) {
                    may_retry = false;
                    warn!(
                        remote = %remote,
                        ref_name = %ref_name,
                        "fallback push raced; retrying once"
                    );
                    continue;
                }
                return Err(e);
            }
            return Ok(());
        }

        if local_hash.is_none() {
            let temp_ref = temp_ref_name(ref_name, remote);
            let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
            let fetch_result =
                git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref).await?;
            if fetch_result.fetched {
                let remote_tip = git::rev_parse_at(Some(repo), &temp_ref).await?;
                git::update_ref_at(Some(repo), ref_name, &remote_tip).await?;
                let _ =
                    git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
            }
            return Ok(());
        }

        let temp_ref = temp_ref_name(ref_name, remote);
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
        let fetch_result =
            git::fetch_ref_to_temp_at(Some(repo), remote, ref_name, &temp_ref).await?;
        if !fetch_result.fetched {
            let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
            let push_res =
                git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash).await;
            if let Err(e) = push_res {
                let msg = e.to_string();
                if may_retry && is_ref_push_race(&msg, ref_name) {
                    may_retry = false;
                    warn!(
                        remote = %remote,
                        ref_name = %ref_name,
                        "fallback push raced after missing remote fetch; retrying once"
                    );
                    continue;
                }
                return Err(e);
            }
            return Ok(());
        }

        let fetched_hash = git::rev_parse_at(Some(repo), &temp_ref).await.ok();
        if fetched_hash == local_hash {
            let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
            return Ok(());
        }

        let merged = merge_ref_maps(repo, ref_name, &temp_ref).await?;
        if let Some(new_tip) = merged {
            git::update_ref_at(Some(repo), ref_name, &new_tip).await?;
        }

        let push_res =
            git::push_ref_with_lease_at(Some(repo), remote, ref_name, &pre_remote_hash).await;
        let _ = git::run_git_output_at(Some(repo), &["update-ref", "-d", &temp_ref], &[]).await;
        if let Err(e) = push_res {
            let msg = e.to_string();
            if may_retry && is_ref_push_race(&msg, ref_name) {
                may_retry = false;
                warn!(
                    remote = %remote,
                    ref_name = %ref_name,
                    "fallback push raced after merge; retrying once"
                );
                continue;
            }
            return Err(e);
        }

        return Ok(());
    }
}

fn short_hash(hash: Option<&str>) -> String {
    match hash {
        Some(h) => h.chars().take(12).collect(),
        None => "none".to_string(),
    }
}

async fn merge_ref_maps(
    repo: &Path,
    local_ref: &str,
    remote_temp_ref: &str,
) -> Result<Option<String>> {
    let mut merged = ref_map_from_ref(repo, local_ref).await?;
    let remote_map = ref_map_from_ref(repo, remote_temp_ref).await?;
    let merge_index_shards =
        local_ref == git::SESSION_INDEX_BRANCH_REF || local_ref == git::SESSION_INDEX_COMMITTER_REF;
    for (path, remote_sha) in remote_map {
        match merged.get(&path).cloned() {
            None => {
                merged.insert(path, remote_sha);
            }
            Some(local_sha) => {
                if local_sha == remote_sha {
                    continue;
                }
                if merge_index_shards {
                    let merged_sha = merge_index_shard_blobs(repo, &local_sha, &remote_sha).await?;
                    merged.insert(path, merged_sha);
                }
            }
        }
    }

    if merged.is_empty() {
        return Ok(None);
    }

    let new_tree = build_tree_from_map(repo, &merged).await?;
    let current_tip = git::rev_parse_at(Some(repo), local_ref).await.ok();
    let current_tree = if current_tip.is_some() {
        git::rev_parse_at(Some(repo), &format!("{}^{{tree}}", local_ref))
            .await
            .ok()
    } else {
        None
    };
    if current_tree.as_deref() == Some(new_tree.as_str()) {
        return Ok(current_tip);
    }

    let commit = git::commit_tree_at(
        Some(repo),
        &new_tree,
        "cadence sessions sync",
        current_tip.as_deref(),
    )
    .await?;
    Ok(Some(commit))
}

async fn merge_index_shard_blobs(repo: &Path, local_sha: &str, remote_sha: &str) -> Result<String> {
    let local_blob = git::read_blob_at(Some(repo), local_sha).await?;
    let remote_blob = git::read_blob_at(Some(repo), remote_sha).await?;
    let local_text = String::from_utf8(local_blob)?;
    let remote_text = String::from_utf8(remote_blob)?;

    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut merged_lines = Vec::<String>::new();
    for line in local_text.lines().chain(remote_text.lines()) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            merged_lines.push(trimmed.to_string());
        }
    }

    if merged_lines.is_empty() {
        return git::store_blob_at(Some(repo), b"").await;
    }

    let merged_text = format!("{}\n", merged_lines.join("\n"));
    git::store_blob_at(Some(repo), merged_text.as_bytes()).await
}

async fn ref_map_from_ref(repo: &Path, ref_name: &str) -> Result<BTreeMap<String, String>> {
    if !git::ref_exists_at(Some(repo), ref_name).await? {
        return Ok(BTreeMap::new());
    }
    let tree_rev = format!("{}^{{tree}}", ref_name);
    let mut out = BTreeMap::new();
    for root in git::list_tree_entries_at(Some(repo), &tree_rev).await? {
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
        for child in git::list_tree_entries_at(Some(repo), &sha).await? {
            if let Some((_cmode, ckind, csha, cname)) = parse_tree_line(&child)
                && ckind == "blob"
            {
                out.insert(format!("{}/{}", name, cname), csha);
            }
        }
    }
    Ok(out)
}

async fn build_tree_from_map(repo: &Path, map: &BTreeMap<String, String>) -> Result<String> {
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
        let subtree = git::mktree_at(Some(repo), &entries).await?;
        root_entries.push(format!("040000 tree {}\t{}", subtree, dir));
    }
    root_entries.sort();
    git::mktree_at(Some(repo), &root_entries).await
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
pub async fn check_org_filter_remote(remote: &str) -> bool {
    let configured_org = match git::config_get_global("ai.cadence.org").await {
        Ok(Some(org)) => org,
        _ => return true,
    };

    let url = match git::remote_url(remote).await {
        Ok(Some(u)) => u,
        _ => return false,
    };

    let remote_org = match git::parse_org_from_url(&url) {
        Some(org) => org,
        None => return false,
    };

    remote_org.eq_ignore_ascii_case(&configured_org)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    async fn run_git(repo: &Path, args: &[&str]) -> String {
        let out = crate::git::run_git_output_at(Some(repo), args, &[])
            .await
            .expect("run git");
        assert!(
            out.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout)
            .expect("utf8")
            .trim()
            .to_string()
    }

    async fn init_repo() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        run_git(dir.path(), &["init", "-q"]).await;
        run_git(dir.path(), &["config", "user.name", "Test User"]).await;
        run_git(dir.path(), &["config", "user.email", "test@example.com"]).await;
        tokio::fs::write(dir.path().join("README.md"), "hello")
            .await
            .expect("write");
        run_git(dir.path(), &["add", "README.md"]).await;
        run_git(dir.path(), &["commit", "-m", "init"]).await;
        dir
    }

    async fn init_repo_with_remote() -> (TempDir, TempDir) {
        let local = init_repo().await;
        let remote = TempDir::new().expect("tempdir");
        run_git(remote.path(), &["init", "--bare", "-q"]).await;
        run_git(
            local.path(),
            &["remote", "add", "origin", &remote.path().to_string_lossy()],
        )
        .await;
        (local, remote)
    }

    async fn write_ref_map(repo: &Path, ref_name: &str, map: &BTreeMap<String, String>) {
        let tree = build_tree_from_map(repo, map).await.expect("build tree");
        let parent = git::rev_parse_at(Some(repo), ref_name).await.ok();
        let commit = git::commit_tree_at(Some(repo), &tree, "test ref map", parent.as_deref())
            .await
            .expect("commit tree");
        git::update_ref_at(Some(repo), ref_name, &commit)
            .await
            .expect("update ref");
    }

    #[tokio::test]
    async fn merge_ref_maps_unions_conflicting_index_shards() {
        let repo = init_repo().await;
        let path = "aa/bb--0001.ndjson".to_string();
        let local_blob = git::store_blob_at(
            Some(repo.path()),
            br#"{"session_uid":"local","session_blob_sha":"a","agent":"claude","ingested_at":"1"}
"#,
        )
        .await
        .expect("store local blob");
        let remote_blob = git::store_blob_at(
            Some(repo.path()),
            br#"{"session_uid":"remote","session_blob_sha":"b","agent":"codex","ingested_at":"2"}
"#,
        )
        .await
        .expect("store remote blob");

        let mut local_map = BTreeMap::new();
        local_map.insert(path.clone(), local_blob);
        write_ref_map(repo.path(), git::SESSION_INDEX_BRANCH_REF, &local_map).await;

        let remote_temp_ref = "refs/cadence/tmp/test/index-branch";
        let mut remote_map = BTreeMap::new();
        remote_map.insert(path.clone(), remote_blob);
        write_ref_map(repo.path(), remote_temp_ref, &remote_map).await;

        let merged_tip =
            merge_ref_maps(repo.path(), git::SESSION_INDEX_BRANCH_REF, remote_temp_ref)
                .await
                .expect("merge ref maps")
                .expect("merged tip");
        git::update_ref_at(
            Some(repo.path()),
            git::SESSION_INDEX_BRANCH_REF,
            &merged_tip,
        )
        .await
        .expect("update merged tip");

        let merged_map = ref_map_from_ref(repo.path(), git::SESSION_INDEX_BRANCH_REF)
            .await
            .expect("read merged map");
        let merged_sha = merged_map.get(&path).expect("merged shard exists");
        let merged_blob = git::read_blob_at(Some(repo.path()), merged_sha)
            .await
            .expect("read blob");
        let merged_text = String::from_utf8(merged_blob).expect("utf8");
        assert!(merged_text.contains("\"session_uid\":\"local\""));
        assert!(merged_text.contains("\"session_uid\":\"remote\""));
    }

    #[tokio::test]
    async fn sync_session_refs_returns_error_when_remote_hash_lookup_fails() {
        let repo = init_repo().await;
        let err = sync_session_refs_for_remote_at(repo.path(), "origin")
            .await
            .expect_err("missing remote should error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("read remote ref hashes") || msg.contains("ls-remote"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn sync_session_refs_pushes_local_content_when_remote_ref_missing() {
        let (local, remote) = init_repo_with_remote().await;
        let mut map = BTreeMap::new();
        let blob = git::store_blob_at(Some(local.path()), br#"{"k":"v"}"#)
            .await
            .expect("store blob");
        map.insert("item.json".to_string(), blob);
        write_ref_map(local.path(), git::SESSION_DATA_REF, &map).await;

        sync_session_refs_for_remote_at(local.path(), "origin")
            .await
            .expect("sync refs");

        let local_tip = git::rev_parse_at(Some(local.path()), git::SESSION_DATA_REF)
            .await
            .expect("local tip");
        let remote_tip = git::rev_parse_at(Some(remote.path()), git::SESSION_DATA_REF)
            .await
            .expect("remote tip");
        assert_eq!(local_tip, remote_tip);
    }

    #[tokio::test]
    async fn sync_session_refs_fetches_remote_content_when_local_ref_missing() {
        let (local, remote) = init_repo_with_remote().await;
        let mut map = BTreeMap::new();
        let blob = git::store_blob_at(Some(local.path()), br#"{"k":"v2"}"#)
            .await
            .expect("store blob");
        map.insert("item.json".to_string(), blob);
        write_ref_map(local.path(), git::SESSION_DATA_REF, &map).await;
        sync_session_refs_for_remote_at(local.path(), "origin")
            .await
            .expect("initial push");

        run_git(local.path(), &["update-ref", "-d", git::SESSION_DATA_REF]).await;
        assert!(
            !git::ref_exists_at(Some(local.path()), git::SESSION_DATA_REF)
                .await
                .expect("ref exists check"),
            "local ref should be deleted before sync"
        );

        sync_session_refs_for_remote_at(local.path(), "origin")
            .await
            .expect("sync should fetch remote ref");

        let local_tip = git::rev_parse_at(Some(local.path()), git::SESSION_DATA_REF)
            .await
            .expect("local tip restored");
        let remote_tip = git::rev_parse_at(Some(remote.path()), git::SESSION_DATA_REF)
            .await
            .expect("remote tip");
        assert_eq!(local_tip, remote_tip);
    }
}
