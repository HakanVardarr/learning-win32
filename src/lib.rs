use process::Process;
use std::error::Error;
use windows::Win32::System::ProcessStatus::EnumProcesses;

mod process;

pub fn get_pids() -> Result<Vec<u32>, Box<dyn Error>> {
    let mut pids: Vec<u32> = vec![0; 1024];
    let mut bytes_returned: u32 = 0;

    unsafe {
        loop {
            EnumProcesses(
                pids.as_mut_ptr(),
                (pids.len() * std::mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            )?;

            if bytes_returned as usize > pids.len() * std::mem::size_of::<u32>() {
                pids = vec![0; (bytes_returned as usize) / std::mem::size_of::<u32>() + 1];
            } else {
                pids.truncate((bytes_returned as usize) / std::mem::size_of::<u32>());
                return Ok(pids);
            }
        }
    }
}

pub fn get_processes() -> Result<Vec<Process>, Box<dyn Error>> {
    let mut processes = Vec::new();
    let pids = get_pids()?;

    for pid in pids {
        if let Ok(process) = Process::new(pid) {
            processes.push(process);
        }
    }

    Ok(processes)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let processes = get_processes().unwrap();
        for process in processes {
            if let Ok(proccess_name) = process.name() {
                println!("{} -> {}", process.pid, proccess_name)
            }
        }
    }
}
