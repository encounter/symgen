use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::{Context, Result};

/// Expand command-line inputs prefixed with `@` as response files.
pub fn process_rsp(inputs: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(inputs.len());
    for input in inputs {
        if let Some(rsp_file) = input.strip_prefix('@') {
            let rsp = fs::read_to_string(rsp_file)
                .with_context(|| format!("Failed to read response file '{rsp_file}'"))?;
            for path in rsp.lines().flat_map(|line| line.split(';')).map(str::trim) {
                if !path.is_empty() {
                    out.push(path.to_string());
                }
            }
        } else {
            out.push(input.clone());
        }
    }
    Ok(out)
}

/// Durably replace a file while preserving its permissions and cleaning up on failure.
pub fn atomic_replace(path: &Path, data: &[u8]) -> Result<()> {
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("image");
    let temp = path.with_file_name(format!(".{file_name}.symgen.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .with_context(|| format!("Failed to create '{}'", temp.display()))?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::metadata(path)?.permissions())?;
        fs::rename(&temp, path)
            .with_context(|| format!("Failed to replace '{}'", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn expands_prefixed_response_files() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let rsp = std::env::temp_dir().join(format!("symgen-{unique}.rsp"));
        fs::write(&rsp, "one.o\ntwo.a; three.o\n\n").unwrap();

        let inputs =
            vec!["direct.o".to_string(), format!("@{}", rsp.display()), "another.o".to_string()];
        let expanded = process_rsp(&inputs).unwrap();
        fs::remove_file(rsp).unwrap();

        assert_eq!(expanded, ["direct.o", "one.o", "two.a", "three.o", "another.o"]);
    }

    #[test]
    fn atomically_replaces_a_file() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("symgen-replace-{unique}"));
        fs::write(&path, b"before").unwrap();
        atomic_replace(&path, b"after").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"after");
        fs::remove_file(path).unwrap();
    }
}
