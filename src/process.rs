use std::error::Error;
use windows::Win32::{
    Foundation::{HANDLE, HMODULE, MAX_PATH},
    System::{
        ProcessStatus::{EnumProcessModules, GetModuleBaseNameA},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};
pub struct Process {
    pub pid: u32,
    phandle: HANDLE,
}

impl Process {
    pub fn new(pid: u32) -> Result<Self, Box<dyn Error>> {
        unsafe {
            let phandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
            Ok(Self { pid, phandle })
        }
    }

    pub fn name(&self) -> Result<String, Box<dyn Error>> {
        unsafe {
            let mut hmod = HMODULE::default();
            let mut cb_needed: u32 = 0;

            if let Ok(_) = EnumProcessModules(
                self.phandle,
                &mut hmod,
                std::mem::size_of::<HMODULE>() as u32,
                &mut cb_needed,
            ) {
                let mut process_name = vec![0u8; MAX_PATH as usize];
                let length = GetModuleBaseNameA(self.phandle, hmod, &mut process_name);
                if length > 0 {
                    return Ok(
                        String::from_utf8_lossy(&process_name[..length as usize]).to_string()
                    );
                } else {
                    return Err(Box::new(windows::core::Error::from_win32()));
                }
            } else {
                return Err(Box::new(windows::core::Error::from_win32()));
            }
        }
    }
}
