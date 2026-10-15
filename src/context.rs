//! Operation-local caller identity/data, instead of changing process environment.
use std::{cell::RefCell, collections::BTreeMap, path::PathBuf};
#[derive(Clone, Default)]
pub(crate) struct CallerScope {
    pub data: PathBuf,
    pub hive_sid: Option<String>,
    pub environment: BTreeMap<String, String>,
}
thread_local! {static SCOPE:RefCell<Option<CallerScope>>=const{RefCell::new(None)};}
pub(crate) fn data() -> Option<PathBuf> {
    SCOPE.with(|s| s.borrow().as_ref().map(|s| s.data.clone()))
}
pub(crate) fn hive_sid() -> Option<String> {
    SCOPE.with(|s| s.borrow().as_ref().and_then(|s| s.hive_sid.clone()))
}
pub(crate) fn variable(name: &str) -> Option<std::ffi::OsString> {
    SCOPE
        .with(|s| {
            s.borrow().as_ref().and_then(|scope| {
                scope
                    .environment
                    .get(&name.to_ascii_uppercase())
                    .map(std::ffi::OsString::from)
            })
        })
        .or_else(|| std::env::var_os(name))
}
pub(crate) fn expand(value: &str) -> Option<String> {
    SCOPE.with(|s| {
        s.borrow().as_ref().map(|s| {
            let mut result = String::new();
            let mut remaining = value;
            while let Some(start) = remaining.find('%') {
                result.push_str(&remaining[..start]);
                let token = &remaining[start + 1..];
                let Some(end) = token.find('%') else {
                    result.push_str(&remaining[start..]);
                    return result;
                };
                let name = &token[..end];
                if let Some(replacement) = s.environment.get(&name.to_ascii_uppercase()) {
                    result.push_str(replacement);
                } else {
                    result.push('%');
                    result.push_str(name);
                    result.push('%');
                }
                remaining = &token[end + 1..];
            }
            result.push_str(remaining);
            result
        })
    })
}
pub(crate) fn with_scope<T>(scope: CallerScope, call: impl FnOnce() -> T) -> T {
    struct Reset(Option<CallerScope>);
    impl Drop for Reset {
        fn drop(&mut self) {
            SCOPE.with(|s| *s.borrow_mut() = self.0.take());
        }
    }
    let previous = SCOPE.with(|s| s.borrow_mut().replace(scope));
    let _reset = Reset(previous);
    call()
}
