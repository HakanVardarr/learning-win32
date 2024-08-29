use thiserror::Error;

#[derive(Debug, Error)]
pub enum WinApiError {
    #[error("[ERROR]: Process Error: {0}")]
    ProcessError(ProcessError),
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("Failed to open process")]
    OpenProcess,
    #[error("Failed to read the name of process")]
    ReadName,
}
