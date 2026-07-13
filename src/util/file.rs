use std::fs;

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
}
