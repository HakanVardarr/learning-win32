use crate::error::*;
use crate::types::DWORD;

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH},
    System::{
        ProcessStatus::{EmptyWorkingSet, EnumProcesses, GetModuleBaseNameA},
        Threading::{
            GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_QUERY_INFORMATION,
            PROCESS_SET_QUOTA, PROCESS_TERMINATE, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

pub struct Process {
    process_id: DWORD,
    process_handle: HANDLE,
    process_name: Option<String>,
    is_terminated: bool,
}

impl Process {
    pub fn new(process_id: DWORD) -> Result<Self, WinApiError> {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION
                    | PROCESS_SET_QUOTA
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_TERMINATE,
                false,
                process_id,
            )
        }
        .map_err(|_| WinApiError::ProcessError(get_last_error()))?;
        Ok(Self {
            process_id,
            process_handle,
            process_name: None,
            is_terminated: false,
        })
    }

    pub fn name(&mut self) -> Result<String, WinApiError> {
        self.check_terminated()?;

        if self.process_name.is_some() {
            return Ok(self.process_name.clone().unwrap());
        }

        let hmod = HMODULE::default();
        let mut process_name = vec![0u8; MAX_PATH as usize];

        if unsafe { GetModuleBaseNameA(self.process_handle, hmod, &mut process_name) } == 0 {
            return Err(WinApiError::ProcessError(get_last_error()));
        }

        let process_name = String::from_utf8(process_name)
            .map_err(|_| WinApiError::ProcessError(get_last_error()))?
            .trim_matches(char::from(0))
            .to_string();

        return Ok(process_name);
    }

    pub fn id(&self) -> DWORD {
        return self.process_id;
    }

    pub fn terminate(&mut self) -> Result<(), WinApiError> {
        self.check_terminated()?;

        let mut exit_code: DWORD = 0;

        Ok(unsafe {
            GetExitCodeProcess(self.process_handle, &mut exit_code)
                .map_err(|_| WinApiError::ProcessError(get_last_error()))?;
            TerminateProcess(self.process_handle, exit_code)
                .map_err(|_| WinApiError::ProcessError(get_last_error()))?;
            self.is_terminated = true;
        })
    }

    pub fn free_page_memory(&self) -> Result<(), WinApiError> {
        self.check_terminated()?;

        Ok(unsafe {
            EmptyWorkingSet(self.process_handle)
                .map_err(|_| WinApiError::ProcessError(get_last_error()))?
        })
    }

    fn check_terminated(&self) -> Result<(), WinApiError> {
        if self.is_terminated {
            return Err(WinApiError::ProcessError(String::from(
                "Process terminated.",
            )));
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.process_handle) };
    }
}

pub fn get_all_available_processes() -> Result<Vec<Process>, WinApiError> {
    let mut processes_list = Vec::new();

    let mut processes: Vec<DWORD> = vec![0; 1024 * 5];
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

    for i in 0..process_count {
        if processes[i as usize] != 0 {
            if let Ok(mut process) = Process::new(processes[i as usize]) {
                if let Ok(_) = process.name() {
                    processes_list.push(process);
                }
            }
        }
    }
    Ok(processes_list)
}

mod test {

    #[test]
    fn process_test() -> Result<(), crate::error::WinApiError> {
        use crate::process::get_all_available_processes;

        let processes = get_all_available_processes()?;
        for mut process in processes {
            let name = process.name()?;
            println!("| {:>5} | {name:<35} | ", process.id());
        }

        Ok(())
    }
}
