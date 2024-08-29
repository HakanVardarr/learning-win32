use crate::error::*;
use crate::types::DWORD;

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH},
    System::{
        ProcessStatus::GetModuleBaseNameA,
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE},
    },
};

pub struct Process {
    _process_id: DWORD,
    process_handle: HANDLE,
    process_name: Option<String>,
}

impl Process {
    pub fn new(process_id: DWORD) -> Result<Self, WinApiError> {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                false,
                process_id,
            )
        }
        .map_err(|_| WinApiError::ProcessError(ProcessError::OpenProcess))?;
        Ok(Self {
            _process_id: process_id,
            process_handle,
            process_name: None,
        })
    }

    pub fn name(&mut self) -> Result<String, WinApiError> {
        if self.process_name.is_some() {
            return Ok(self.process_name.clone().unwrap());
        }

        let hmod = HMODULE::default();
        let mut process_name = vec![0u8; MAX_PATH as usize];

        if unsafe { GetModuleBaseNameA(self.process_handle, hmod, &mut process_name) } == 0 {
            return Err(WinApiError::ProcessError(ProcessError::ReadName));
        }

        String::from_utf8(process_name)
            .map_err(|_| WinApiError::ProcessError(ProcessError::ReadName))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.process_handle) };
    }
}

mod test {
    #[test]
    fn process_name() {
        use crate::process::Process;
        use crate::types::*;
        use windows::Win32::System::ProcessStatus::EnumProcesses;

        let mut processes: Vec<DWORD> = vec![0; 1024];
        let mut cb_needed: DWORD = 0;

        unsafe {
            EnumProcesses(
                processes.as_mut_ptr(),
                (processes.len() * std::mem::size_of::<u32>()) as u32,
                &mut cb_needed,
            )
        }
        .unwrap();

        let process_count: DWORD = cb_needed / std::mem::size_of::<DWORD>() as u32;
        println!("Found {} processes", process_count);

        for i in 0..process_count {
            if processes[i as usize] != 0 {
                if let Ok(mut process) = Process::new(processes[i as usize]) {
                    if let Ok(process_name) = process.name() {
                        println!("{:>6} | {process_name}", processes[i as usize]);
                    }
                }
            }
        }
    }
}
