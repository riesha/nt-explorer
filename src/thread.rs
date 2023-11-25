use windows::Win32::Foundation::HANDLE;

use crate::process::Process;

pub struct Thread
{
    pub process: Process,
    pub id:      u32,
    pub handle:  HANDLE,
}
