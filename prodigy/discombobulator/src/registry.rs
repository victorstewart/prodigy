use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOCK_EXCLUSIVE: i32 = 2;
const LOCK_UNLOCK: i32 = 8;

#[derive(Clone, Debug)]
pub struct StorageRoot {
    root: PathBuf,
}

impl StorageRoot {
    pub fn discover(cwd: PathBuf) -> Self {
        Self {
            root: cwd.join(".discombobulator"),
        }
    }

    pub fn ensure_layout(&self) -> Result<()> {
        for relative in [
            "registry",
            "locks",
            "cache",
            "imports/oci",
            "artifacts/apps",
            "artifacts/bases",
            "work",
            "tmp",
        ] {
            fs::create_dir_all(self.root.join(relative))?;
        }

        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn registry_db_path(&self) -> PathBuf {
        self.root.join("registry/registry.sqlite")
    }

    pub fn locks_dir(&self) -> PathBuf {
        self.root.join("locks")
    }

    pub fn imports_dir(&self) -> PathBuf {
        self.root.join("imports/oci")
    }

    pub fn work_dir(&self) -> PathBuf {
        self.root.join("work")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub fn step_cache_dir(&self, arch: &str) -> PathBuf {
        self.root.join("cache/steps").join(arch)
    }

    pub fn step_cache_root(&self, arch: &str, key: &str) -> PathBuf {
        self.step_cache_dir(arch).join(key)
    }

    pub fn import_root(&self, arch: &str, manifest_digest: &str) -> PathBuf {
        self.imports_dir()
            .join(arch)
            .join(manifest_digest.replace(':', "_"))
    }

    pub fn artifact_dir(&self, kind: &str, arch: &str) -> PathBuf {
        let directory = match kind {
            "app" => "artifacts/apps",
            "base" => "artifacts/bases",
            other => panic!("unsupported artifact kind {other}"),
        };
        self.root.join(directory).join(arch)
    }

    pub fn artifact_blob_path(&self, kind: &str, arch: &str, artifact_key: &str) -> PathBuf {
        self.artifact_dir(kind, arch)
            .join(format!("{artifact_key}.zst"))
    }

    pub fn lock_path(&self, namespace: &str, key: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(b"\n");
        hasher.update(key.as_bytes());
        let digest = hex::encode(hasher.finalize());
        self.locks_dir()
            .join(namespace)
            .join(format!("{digest}.lock"))
    }
}

pub struct Registry {
    connection: Connection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RemoteRecord {
    pub name: String,
    pub registry_host: String,
    pub repository_prefix: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactRecord {
    pub kind: String,
    pub arch: String,
    pub name: Option<String>,
    pub tag: Option<String>,
    pub digest: String,
    pub path: String,
    pub size_bytes: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OciImportRecord {
    pub remote_name: String,
    pub image: String,
    pub arch: String,
    pub manifest_digest: String,
    pub path: String,
}

impl Registry {
    pub fn open(storage: &StorageRoot) -> Result<Self> {
        let _schema_lock =
            FileLockGuard::acquire(&storage.locks_dir().join("registry-schema.lock"))?;
        let connection = Connection::open(storage.registry_db_path())?;
        connection.busy_timeout(Duration::from_secs(30))?;
        let registry = Self { connection };
        registry.ensure_schema()?;
        Ok(registry)
    }

    pub fn upsert_remote(
        &self,
        name: &str,
        registry_host: &str,
        repository_prefix: Option<&str>,
    ) -> Result<()> {
        let now = epoch_seconds();
        self.connection.execute(
         "INSERT INTO remotes (name, registry_host, repository_prefix, created_at, updated_at, last_used_at)
          VALUES (?1, ?2, ?3, ?4, ?4, ?4)
          ON CONFLICT(name) DO UPDATE SET
             registry_host=excluded.registry_host,
             repository_prefix=excluded.repository_prefix,
             updated_at=excluded.updated_at,
             last_used_at=excluded.last_used_at",
         params![name, registry_host, repository_prefix, now],
      )?;
        Ok(())
    }

    pub fn list_remotes(&self) -> Result<Vec<RemoteRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT name, registry_host, repository_prefix
          FROM remotes
          ORDER BY name ASC",
        )?;

        let rows = statement.query_map([], |row| {
            Ok(RemoteRecord {
                name: row.get(0)?,
                registry_host: row.get(1)?,
                repository_prefix: row.get(2)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn remove_remote(&self, name: &str) -> Result<bool> {
        Ok(self
            .connection
            .execute("DELETE FROM remotes WHERE name=?1", params![name])?
            > 0)
    }

    pub fn lookup_remote(&self, name: &str) -> Result<Option<RemoteRecord>> {
        self.connection
            .query_row(
                "SELECT name, registry_host, repository_prefix FROM remotes WHERE name=?1",
                params![name],
                |row| {
                    Ok(RemoteRecord {
                        name: row.get(0)?,
                        registry_host: row.get(1)?,
                        repository_prefix: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn touch_remote_last_used(&self, name: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE remotes SET last_used_at=?2 WHERE name=?1",
            params![name, epoch_seconds()],
        )?;
        Ok(())
    }

    pub fn upsert_artifact(&self, record: &ArtifactRecord) -> Result<()> {
        let now = epoch_seconds();
        self.connection.execute(
         "INSERT INTO artifacts (kind, arch, name, tag, digest, path, size_bytes, created_at, updated_at, last_used_at)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?8)
          ON CONFLICT(digest) DO UPDATE SET
             kind=excluded.kind,
             arch=excluded.arch,
             name=excluded.name,
             tag=excluded.tag,
             path=excluded.path,
             size_bytes=excluded.size_bytes,
             updated_at=excluded.updated_at,
             last_used_at=excluded.last_used_at",
         params![
            record.kind,
            record.arch,
            record.name,
            record.tag,
            record.digest,
            record.path,
            record.size_bytes,
            now
         ],
      )?;
        Ok(())
    }

    pub fn lookup_named_base(
        &self,
        name: &str,
        tag: &str,
        arch: &str,
    ) -> Result<Option<ArtifactRecord>> {
        self.connection
            .query_row(
                "SELECT kind, arch, name, tag, digest, path, size_bytes
                 FROM artifacts
                 WHERE kind='base' AND name=?1 AND tag=?2 AND arch=?3",
                params![name, tag, arch],
                |row| {
                    Ok(ArtifactRecord {
                        kind: row.get(0)?,
                        arch: row.get(1)?,
                        name: row.get(2)?,
                        tag: row.get(3)?,
                        digest: row.get(4)?,
                        path: row.get(5)?,
                        size_bytes: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_artifact_paths(&self) -> Result<Vec<PathBuf>> {
        let mut statement = self
            .connection
            .prepare("SELECT path FROM artifacts ORDER BY path ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(PathBuf::from(row?));
        }
        Ok(results)
    }

    pub fn lookup_oci_import(
        &self,
        remote_name: &str,
        image: &str,
        arch: &str,
    ) -> Result<Option<OciImportRecord>> {
        self.connection
            .query_row(
                "SELECT remote_name, image, arch, manifest_digest, path
                 FROM oci_imports
                 WHERE remote_name=?1 AND image=?2 AND arch=?3",
                params![remote_name, image, arch],
                |row| {
                    Ok(OciImportRecord {
                        remote_name: row.get(0)?,
                        image: row.get(1)?,
                        arch: row.get(2)?,
                        manifest_digest: row.get(3)?,
                        path: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn upsert_oci_import(&self, record: &OciImportRecord) -> Result<()> {
        let now = epoch_seconds();
        self.connection.execute(
            "INSERT INTO oci_imports (remote_name, image, arch, manifest_digest, path, created_at, updated_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)
             ON CONFLICT(remote_name, image, arch) DO UPDATE SET
                manifest_digest=excluded.manifest_digest,
                path=excluded.path,
                updated_at=excluded.updated_at,
                last_used_at=excluded.last_used_at",
            params![
                record.remote_name,
                record.image,
                record.arch,
                record.manifest_digest,
                record.path,
                now
            ],
      )?;
        Ok(())
    }

    pub fn list_oci_import_paths(&self) -> Result<Vec<PathBuf>> {
        let mut statement = self
            .connection
            .prepare("SELECT path FROM oci_imports ORDER BY path ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(PathBuf::from(row?));
        }
        Ok(results)
    }

    pub fn touch_oci_import_last_used(
        &self,
        remote_name: &str,
        image: &str,
        arch: &str,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE oci_imports SET last_used_at=?4 WHERE remote_name=?1 AND image=?2 AND arch=?3",
            params![remote_name, image, arch, epoch_seconds()],
        )?;
        Ok(())
    }

    fn ensure_schema(&self) -> Result<()> {
        self.connection.execute_batch(
            "PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS remotes (
             name TEXT PRIMARY KEY,
             registry_host TEXT NOT NULL,
             repository_prefix TEXT,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL,
             last_used_at INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS artifacts (
             digest TEXT PRIMARY KEY,
             kind TEXT NOT NULL,
             arch TEXT NOT NULL,
             name TEXT,
             tag TEXT,
             path TEXT NOT NULL,
             size_bytes INTEGER NOT NULL,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL,
             last_used_at INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS oci_imports (
             remote_name TEXT NOT NULL,
             image TEXT NOT NULL,
             arch TEXT NOT NULL,
             manifest_digest TEXT NOT NULL,
             path TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL,
             last_used_at INTEGER NOT NULL,
             PRIMARY KEY (remote_name, image, arch)
          );",
        )?;
        Ok(())
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

struct FileLockGuard {
    file: fs::File,
}

impl FileLockGuard {
    fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open lock file {}", path.display()))?;
        let result = unsafe { libc_flock(file.as_raw_fd(), LOCK_EXCLUSIVE) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to lock {}", path.display()));
        }
        Ok(Self { file })
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc_flock(self.file.as_raw_fd(), LOCK_UNLOCK) };
    }
}

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

unsafe fn libc_flock(fd: i32, operation: i32) -> i32 {
    unsafe { flock(fd, operation) }
}
