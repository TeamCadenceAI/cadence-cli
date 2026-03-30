use std::ffi::OsString;
use std::path::Path;

pub(crate) struct EnvGuard {
    key: String,
    original: Option<OsString>,
}

impl EnvGuard {
    pub(crate) fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        Self {
            original: std::env::var_os(&key),
            key,
        }
    }

    pub(crate) fn set_str(&self, value: &str) {
        unsafe { std::env::set_var(&self.key, value) };
    }

    pub(crate) fn set_path(&self, value: &Path) {
        self.set_str(&value.to_string_lossy());
    }

    #[allow(dead_code)]
    pub(crate) fn clear(&self) {
        unsafe { std::env::remove_var(&self.key) };
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => unsafe { std::env::set_var(&self.key, value) },
            None => unsafe { std::env::remove_var(&self.key) },
        }
    }
}
