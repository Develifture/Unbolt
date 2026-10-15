use crate::UnboltResult;
use serde::{Deserialize, Serialize};
use std::{path::Path, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree, System::Environment::ExpandEnvironmentStringsW,
    UI::Shell::CommandLineToArgvW,
};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn system_msiexec() -> UnboltResult<String> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err("Cannot resolve the Windows system directory".into());
    }
    Ok(
        Path::new(&String::from_utf16_lossy(&buffer[..length as usize]))
            .join("msiexec.exe")
            .display()
            .to_string(),
    )
}

pub fn expand_environment(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    unsafe {
        let scoped = crate::context::expand(s);
        let input = wide(scoped.as_deref().unwrap_or(s));
        let n = ExpandEnvironmentStringsW(input.as_ptr(), ptr::null_mut(), 0);
        if n == 0 {
            return s.into();
        }
        let mut output = vec![0u16; n as usize];
        if ExpandEnvironmentStringsW(input.as_ptr(), output.as_mut_ptr(), n) == 0 {
            return s.into();
        }
        String::from_utf16_lossy(
            &output[..output.iter().position(|x| *x == 0).unwrap_or(output.len())],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UninstallCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub original: String,
}

pub fn quote_argument(value: &str) -> String {
    // Some native programs (including msiexec) parse switches directly from
    // the command line and reject a quoted switch such as "/X{product}".
    // Keep simple arguments bare; retain Windows escaping when quotes are needed.
    if !value.is_empty() && !value.chars().any(|c| c.is_whitespace() || c == '"') {
        return value.into();
    }
    let mut result = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '"' {
            result.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            result.push_str(&"\\".repeat(slashes));
        }
        slashes = 0;
        result.push(c);
    }
    result.push_str(&"\\".repeat(slashes * 2));
    result.push('"');
    result
}

pub fn parse(input: &str) -> UnboltResult<UninstallCommand> {
    if input.contains('\0') || input.trim().is_empty() {
        return Err("Empty or invalid uninstall command".into());
    }
    let input = expand_environment(input.trim());
    // Unquoted paths containing spaces are ambiguous. Refuse rather than risk launching C:\Program.exe.
    if !input.starts_with('"') {
        let lower = input.to_lowercase();
        if let Some(end) = lower.find(".exe")
            && input[..end].contains(' ')
        {
            return Err("Unquoted executable path contains spaces; command needs review".into());
        }
    }
    let parts = unsafe {
        let command = wide(&input);
        let mut count = 0;
        let argv = CommandLineToArgvW(command.as_ptr(), &mut count);
        if argv.is_null() {
            return Err("Cannot parse uninstall command".into());
        }
        let values = std::slice::from_raw_parts(argv, count as usize)
            .iter()
            .map(|p| {
                let mut n = 0;
                while *p.add(n) != 0 {
                    n += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(*p, n))
            })
            .collect::<Vec<_>>();
        LocalFree(argv.cast());
        values
    };
    if parts.is_empty() {
        return Err("Command has no executable".into());
    }
    let mut executable = parts[0].clone();
    if !Path::new(&executable).is_absolute() {
        if matches!(
            executable.to_lowercase().as_str(),
            "msiexec" | "msiexec.exe"
        ) {
            executable = system_msiexec()?;
        } else {
            return Err(
                "Executable must have an absolute path; relative commands need review".into(),
            );
        }
    }
    if !Path::new(&executable).is_file() {
        return Err(format!("Executable not found: {executable}"));
    }
    Ok(UninstallCommand {
        executable,
        arguments: parts[1..].to_vec(),
        original: input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_ambiguous_unquoted_path() {
        assert!(
            parse(r"C:\Program Files\Example\uninstall.exe /S")
                .unwrap_err()
                .contains("Unquoted")
        );
    }
    #[test]
    fn preserves_quoted_arguments_and_no_shell_expansion() {
        let exe = std::env::current_exe().unwrap();
        let command = parse(&format!(
            "\"{}\" \"argument with spaces\" & literal",
            exe.display()
        ))
        .unwrap();
        assert_eq!(
            command.arguments,
            vec!["argument with spaces", "&", "literal"]
        );
    }
    #[test]
    fn refuses_path_search() {
        assert!(parse("unknown-uninstaller.exe /S").is_err());
    }
    #[test]
    fn rejects_nul() {
        assert!(parse("a\0b").is_err());
    }

    #[test]
    fn shell_parameter_quoting_round_trips_backslashes_and_quotes() {
        let arguments = vec![
            "".to_string(),
            "a b".into(),
            r"C:\ends with slash\".into(),
            "a\"b".into(),
        ];
        let exe = std::env::current_exe().unwrap();
        let command = format!(
            "{} {}",
            quote_argument(&exe.display().to_string()),
            arguments
                .iter()
                .map(|a| quote_argument(a))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(parse(&command).unwrap().arguments, arguments);
    }

    #[test]
    fn leaves_installer_switches_bare_and_quotes_paths_with_spaces() {
        for arg in [
            "/X{01234567-89AB-CDEF-0123-456789ABCDEF}",
            "/x",
            "/qn",
            "/norestart",
            "{01234567-89AB-CDEF-0123-456789ABCDEF}",
        ] {
            assert_eq!(quote_argument(arg), arg);
        }
        assert_eq!(
            quote_argument(r"C:\path with spaces\package.msi"),
            r#""C:\path with spaces\package.msi""#
        );
        assert_eq!(quote_argument(""), "\"\"");
        assert_eq!(quote_argument("a\tb"), "\"a\tb\"");
    }
}
