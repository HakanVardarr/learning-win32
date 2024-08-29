use thiserror::Error;

#[derive(Debug, Error)]
pub enum WinApiError {
    #[error("[ERROR]: Process Error: {0}")]
    ProcessError(String),
}

pub(crate) fn get_last_error() -> String {
    std::io::Error::last_os_error().to_string()
}
