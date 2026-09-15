use anyhow::{Context, Result, ensure};

use super::{FunctionKind, display_name, function_kind, is_skip_symbol, is_special_mangled};
use crate::util::manifest::{FLAG_CODE, FLAG_DISPLAY, ManifestSymbol};

/// Lexical debug paths must work independently of the machine reading them.
#[derive(Debug)]
struct DebugPath {
    prefix: String,
    components: Vec<String>,
    windows: bool,
}

impl DebugPath {
    fn parse(path: &str) -> Self {
        let path = path.replace('\\', "/");
        let (prefix, rest, windows) = if let Some(rest) = path.strip_prefix("//") {
            let mut parts = rest.splitn(3, '/');
            let server = parts.next().unwrap_or_default();
            let share = parts.next().unwrap_or_default();
            (format!("//{server}/{share}"), parts.next().unwrap_or_default(), true)
        } else if path.as_bytes().get(1) == Some(&b':') && path.as_bytes()[0].is_ascii_alphabetic()
        {
            (path[..2].to_owned(), &path[2..], true)
        } else if let Some(rest) = path.strip_prefix('/') {
            ("/".to_owned(), rest, false)
        } else {
            (String::new(), path.as_str(), false)
        };
        let mut result = Self { prefix, components: Vec::new(), windows };
        result.extend(rest);
        result
    }

    fn extend(&mut self, path: &str) {
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." if self.components.last().is_some_and(|p| p != "..") => {
                    self.components.pop();
                }
                ".." if !self.prefix.is_empty() => {}
                _ => self.components.push(part.to_owned()),
            }
        }
    }

    fn resolve(path: &str, base: &Self) -> Self {
        let mut result = Self::parse(path);
        if result.prefix.is_empty() {
            result = Self {
                prefix: base.prefix.clone(),
                components: base.components.clone(),
                windows: base.windows,
            };
            result.extend(&path.replace('\\', "/"));
        }
        result
    }
}

pub(super) struct SourceRoot(DebugPath);

impl SourceRoot {
    pub fn current() -> Result<Self> {
        let root = std::env::current_dir().context("Cannot read the manifest working directory")?;
        Self::new(root.to_str().context("Manifest working directory is not UTF-8")?)
    }

    fn new(root: &str) -> Result<Self> {
        let root = DebugPath::parse(root);
        ensure!(!root.prefix.is_empty(), "Manifest root must be absolute");
        Ok(Self(root))
    }

    pub fn source(&self, name: &str, comp_dir: &str) -> Option<String> {
        let dir = DebugPath::resolve(comp_dir, &self.0);
        let source = DebugPath::resolve(name, &dir);
        let equal = |a: &str, b: &str| {
            if self.0.windows { a.eq_ignore_ascii_case(b) } else { a == b }
        };
        if name.is_empty()
            || !equal(&source.prefix, &self.0.prefix)
            || source.components.len() <= self.0.components.len()
            || !source.components.iter().zip(&self.0.components).all(|(a, b)| equal(a, b))
        {
            return None;
        }
        Some(source.components[self.0.components.len()..].join("/"))
    }
}

/// PDB procedure records and parameter-free Itanium names share this final step.
pub(super) fn canonical_name(name: &str) -> Option<String> {
    let mut name = name.to_owned();
    for anonymous in ["(anonymous namespace)::", "`anonymous namespace'::", "{anonymous}::"] {
        name = name.replace(anonymous, "");
    }
    // Function-local entities and lambdas have producer-specific spellings.
    if name.is_empty() || name.contains('`') || name.contains("{lambda") || name.contains("<lambda")
    {
        return None;
    }
    Some(name)
}

pub(super) fn binary_name(name: &str) -> Option<String> {
    if is_skip_symbol(name)
        || is_special_mangled(name)
        || !matches!(function_kind(name), FunctionKind::Normal)
    {
        return None;
    }
    if name.starts_with("_Z") { display_name(name) } else { Some(name.to_owned()) }
}

/// Object identity is retained for diagnostics; it never participates in alias spelling.
pub(super) struct FunctionRecord {
    pub source: String,
    pub name: String,
    pub rva: u64,
    pub flags: u32,
    pub provenance: String,
}

impl FunctionRecord {
    pub fn into_alias(self) -> Option<ManifestSymbol> {
        let name = canonical_name(&self.name)?;
        log::trace!("TU alias {}#{name} from {}", self.source, self.provenance);
        Some(ManifestSymbol {
            name: format!("{}#{name}", self.source),
            rva: self.rva,
            flags: self.flags | FLAG_CODE | FLAG_DISPLAY,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_source_scope() {
        let root = SourceRoot::new("/checkout/game").unwrap();
        for (name, dir, expected) in [
            ("./src/../src/a.cpp", "/checkout/game", Some("src/a.cpp")),
            ("../src/a.cpp", "/checkout/game/build", Some("src/a.cpp")),
            ("/checkout/game/src/missing.cpp", "", Some("src/missing.cpp")),
            ("vendor/lib.cpp", "", Some("vendor/lib.cpp")),
            ("generated/a.cpp", "build/debug", Some("build/debug/generated/a.cpp")),
            ("/checkout/game-extra/a.cpp", "", None),
            ("../outside.cpp", "", None),
            ("/checkout/Game/src/a.cpp", "", None),
            ("", "", None),
        ] {
            assert_eq!(root.source(name, dir).as_deref(), expected, "{name} in {dir}");
        }
    }

    #[test]
    fn windows_paths_on_any_host() {
        let root = SourceRoot::new(r"C:\Checkout\Game Space").unwrap();
        assert_eq!(
            root.source(r"c:/CHECKOUT/game space\src/./A.cpp", "").as_deref(),
            Some("src/A.cpp")
        );
        assert_eq!(
            root.source(r"..\src\A.cpp", r"c:\checkout\Game Space/build").as_deref(),
            Some("src/A.cpp")
        );
        assert_eq!(root.source("D:/Checkout/Game Space/src/A.cpp", ""), None);
        assert_eq!(root.source("C:/Checkout/Game Space2/src/A.cpp", ""), None);
        let root = SourceRoot::new(r"\\Server\Share\Game").unwrap();
        assert_eq!(root.source("//server/share/game/src/A.cpp", "").as_deref(), Some("src/A.cpp"));
        assert_eq!(root.source("//server/other/game/src/A.cpp", ""), None);
    }

    #[test]
    fn names_preserve_operators_and_named_scopes() {
        for name in [
            "ns::(anonymous namespace)::Thing::operator()",
            "ns::`anonymous namespace'::Thing::operator()",
        ] {
            assert_eq!(canonical_name(name).as_deref(), Some("ns::Thing::operator()"));
        }
        assert_eq!(canonical_name("ns::action").as_deref(), Some("ns::action"));
        assert!(canonical_name("`f'::`2'::local").is_none());
    }
}
