use anyhow::{anyhow, Result};

use std::{
    ffi::{CStr, CString},
    mem::{size_of, size_of_val},
    ptr::{self, addr_of_mut},
};
use windows::{
    Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            Threading::{
                IsWow64Process, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION,
            },
        },
    },
};
pub struct NtapiPEB(ntapi::ntpebteb::PEB);
pub struct NtapiPEB32(ntapi::ntwow64::PEB32);
pub enum PEB
{
    PEB64(NtapiPEB),
    PEB32(NtapiPEB32),
}
#[derive(Default)]
pub struct Process
{
    pub handle:   HANDLE,
    pub is_wow64: bool,
    pub peb:      Option<PEB>,
}

impl Process
{
    pub fn open(pid: u32) -> Result<Self>
    {
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
        let mut is_wow64 = 0;
        unsafe { IsWow64Process(handle, addr_of_mut!(is_wow64) as _)? };
        Ok(Process {
            handle,
            is_wow64: is_wow64 != 0,
            peb: None,
        })
    }
    pub fn read(&self, base_addr: usize, size: usize) -> Result<Vec<u8>>
    {
        let mut buffer: Vec<u8> = Vec::with_capacity(size);
        unsafe {
            ReadProcessMemory(
                self.handle,
                base_addr as _,
                buffer.as_mut_ptr() as _,
                size,
                None,
            )?
        };
        Ok(buffer)
    }
    pub fn peb(&mut self) -> Result<()>
    {
        if self.is_wow64
        {
            let mut ptr = 0usize;
            unsafe {
                let status = NtQueryInformationProcess(
                    self.handle,
                    PROCESSINFOCLASS(26),
                    addr_of_mut!(ptr) as _,
                    size_of_val(&ptr) as _,
                    ptr::null_mut() as _,
                );
                if status.is_err()
                {
                    return Err(anyhow!("error calling NtQueryInformationProcess"));
                }
                let peb = self.read(ptr, size_of::<ntapi::ntwow64::PEB32>())?;
                let peb: ntapi::ntwow64::PEB32 = ptr::read(peb.as_ptr() as *const _);
                dbg!(peb.ImageBaseAddress);
                let peb = PEB::PEB32(NtapiPEB32(peb));
                self.peb = Some(peb);
            }
            Ok(())
        }
        else
        {
            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            unsafe {
                let status = NtQueryInformationProcess(
                    self.handle,
                    PROCESSINFOCLASS(0),
                    addr_of_mut!(pbi) as _,
                    size_of_val(&pbi) as _,
                    ptr::null_mut() as _,
                );
                if status.is_err()
                {
                    return Err(anyhow!("error calling NtQueryInformationProcess"));
                }
                let peb = self.read(pbi.PebBaseAddress as _, size_of::<ntapi::ntpebteb::PEB>())?;
                let peb: ntapi::ntpebteb::PEB = ptr::read(peb.as_ptr() as *const _);
                dbg!(peb.ImageBaseAddress);
                let peb = PEB::PEB64(NtapiPEB(peb));
                self.peb = Some(peb);
            }
            Ok(())
        }
    }
    pub fn enum_processes() -> Result<Vec<String>>
    {
        let mut processes: Vec<String> = Vec::new();
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };

        let mut process_entry = PROCESSENTRY32W::default();
        process_entry.dwSize = size_of::<PROCESSENTRY32W>() as _;
        if let Ok(()) = unsafe { Process32FirstW(snapshot, addr_of_mut!(process_entry)) }
        {
            while let Ok(()) = unsafe { Process32NextW(snapshot, addr_of_mut!(process_entry)) }
            {
                processes
                    .push(U16CStr::from_slice_truncate(&process_entry.szExeFile)?.to_string_lossy())
            }
        }
        Ok(processes)
    }
}

use std::fmt;
use widestring::{U16CStr, U16CString};
impl fmt::Debug for NtapiPEB
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        f.debug_struct("PEB")
            .field("InheritedAddressSpace", &self.0.InheritedAddressSpace)
            .field("ReadImageFileExecOptions", &self.0.ReadImageFileExecOptions)
            .field("BeingDebugged", &self.0.BeingDebugged)
            .field("BitField", &self.0.BitField)
            .field("Mutant", &self.0.Mutant)
            .field("ImageBaseAddress", &self.0.ImageBaseAddress)
            .field("Ldr", &self.0.Ldr)
            .field("ProcessParameters", &self.0.ProcessParameters)
            .field("SubSystemData", &self.0.SubSystemData)
            .field("ProcessHeap", &self.0.ProcessHeap)
            .field("FastPebLock", &self.0.FastPebLock)
            .field("IFEOKey", &self.0.IFEOKey)
            .field("AtlThunkSListPtr", &self.0.AtlThunkSListPtr)
            .field("CrossProcessFlags", &self.0.CrossProcessFlags)
            .field(
                "u",
                &format_args!(
                    "[KernelCallbackTable: {:#x?}, UserSharedInfoPtr: {:#x?}]",
                    unsafe { self.0.u.KernelCallbackTable },
                    unsafe { self.0.u.UserSharedInfoPtr }
                ),
            )
            .field("SystemReserved", &self.0.SystemReserved)
            .field("AtlThunkSListPtr32", &self.0.AtlThunkSListPtr32)
            .field("ApiSetMap", &self.0.ApiSetMap)
            .field("TlsExpansionCounter", &self.0.TlsExpansionCounter)
            .field("TlsBitmap", &self.0.TlsBitmap)
            .field("TlsBitmapBits", &self.0.TlsBitmapBits)
            .field("ReadOnlySharedMemoryBase", &self.0.ReadOnlySharedMemoryBase)
            .field("SharedData", &self.0.SharedData)
            .field("ReadOnlyStaticServerData", &self.0.ReadOnlyStaticServerData)
            .field("AnsiCodePageData", &self.0.AnsiCodePageData)
            .field("OemCodePageData", &self.0.OemCodePageData)
            .field("UnicodeCaseTableData", &self.0.UnicodeCaseTableData)
            .field("NumberOfProcessors", &self.0.NumberOfProcessors)
            .field("NtGlobalFlag", &self.0.NtGlobalFlag)
            .field(
                "CriticalSectionTimeout",
                &format_args!("{}", unsafe { self.0.CriticalSectionTimeout.QuadPart() }),
            )
            .field("HeapSegmentReserve", &self.0.HeapSegmentReserve)
            .field("HeapSegmentCommit", &self.0.HeapSegmentCommit)
            .field(
                "HeapDeCommitTotalFreeThreshold",
                &self.0.HeapDeCommitTotalFreeThreshold,
            )
            .field(
                "HeapDeCommitFreeBlockThreshold",
                &self.0.HeapDeCommitFreeBlockThreshold,
            )
            .field("NumberOfHeaps", &self.0.NumberOfHeaps)
            .field("MaximumNumberOfHeaps", &self.0.MaximumNumberOfHeaps)
            .field("ProcessHeaps", &self.0.ProcessHeaps)
            .field("GdiSharedHandleTable", &self.0.GdiSharedHandleTable)
            .field("ProcessStarterHelper", &self.0.ProcessStarterHelper)
            .field("GdiDCAttributeList", &self.0.GdiDCAttributeList)
            .field("LoaderLock", &self.0.LoaderLock)
            .field("OSMajorVersion", &self.0.OSMajorVersion)
            .field("OSMinorVersion", &self.0.OSMinorVersion)
            .field("OSBuildNumber", &self.0.OSBuildNumber)
            .field("OSCSDVersion", &self.0.OSCSDVersion)
            .field("OSPlatformId", &self.0.OSPlatformId)
            .field("ImageSubsystem", &self.0.ImageSubsystem)
            .field(
                "ImageSubsystemMajorVersion",
                &self.0.ImageSubsystemMajorVersion,
            )
            .field(
                "ImageSubsystemMinorVersion",
                &self.0.ImageSubsystemMinorVersion,
            )
            .field(
                "ActiveProcessAffinityMask",
                &self.0.ActiveProcessAffinityMask,
            )
            .field("GdiHandleBuffer", &self.0.GdiHandleBuffer)
            .field("PostProcessInitRoutine", &self.0.PostProcessInitRoutine)
            .field("TlsExpansionBitmap", &self.0.TlsExpansionBitmap)
            .field("TlsExpansionBitmapBits", &self.0.TlsExpansionBitmapBits)
            .field("SessionId", &self.0.SessionId)
            .field(
                "AppCompatFlags",
                &format_args!("{}", unsafe { self.0.AppCompatFlags.QuadPart() }),
            )
            .field(
                "AppCompatFlagsUser",
                &format_args!("{}", unsafe { self.0.AppCompatFlagsUser.QuadPart() }),
            )
            .field("pShimData", &self.0.pShimData)
            .field("AppCompatInfo", &self.0.AppCompatInfo)
            .field(
                "CSDVersion",
                &format_args!("{}", unsafe {
                    U16CString::from_ptr(self.0.CSDVersion.Buffer, self.0.CSDVersion.Length as _)
                        .unwrap()
                        .into_ustring()
                        .display()
                }),
            )
            .field("ActivationContextData", &self.0.ActivationContextData)
            .field(
                "ProcessAssemblyStorageMap",
                &self.0.ProcessAssemblyStorageMap,
            )
            .field(
                "SystemDefaultActivationContextData",
                &self.0.SystemDefaultActivationContextData,
            )
            .field("SystemAssemblyStorageMap", &self.0.SystemAssemblyStorageMap)
            .field("MinimumStackCommit", &self.0.MinimumStackCommit)
            .field("FlsCallback", &self.0.FlsCallback)
            .field(
                "FlsListHead",
                &format_args!(
                    "backlink: {:#x?} forwardlink: {:#x?}",
                    self.0.FlsListHead.Blink as usize, self.0.FlsListHead.Flink as usize
                ),
            )
            .field("FlsBitmap", &self.0.FlsBitmap)
            .field("FlsBitmapBits", &self.0.FlsBitmapBits)
            .field("FlsHighIndex", &self.0.FlsHighIndex)
            .field("WerRegistrationData", &self.0.WerRegistrationData)
            .field("WerShipAssertPtr", &self.0.WerShipAssertPtr)
            .field("pUnused", &self.0.pUnused)
            .field("pImageHeaderHash", &self.0.pImageHeaderHash)
            .field("TracingFlags", &self.0.TracingFlags)
            .field(
                "CsrServerReadOnlySharedMemoryBase",
                &self.0.CsrServerReadOnlySharedMemoryBase,
            )
            .field("TppWorkerpListLock", &self.0.TppWorkerpListLock)
            .field(
                "TppWorkerpList",
                &format_args!(
                    "backlink: {:#x?} forwardlink: {:#x?}",
                    self.0.TppWorkerpList.Blink, self.0.TppWorkerpList.Flink
                ),
            )
            .field("WaitOnAddressHashTable", &self.0.WaitOnAddressHashTable)
            .field("TelemetryCoverageHeader", &self.0.TelemetryCoverageHeader)
            .field("CloudFileFlags", &self.0.CloudFileFlags)
            .field("CloudFileDiagFlags", &self.0.CloudFileDiagFlags)
            .field(
                "PlaceholderCompatibilityMode",
                &self.0.PlaceholderCompatibilityMode,
            )
            .field(
                "PlaceholderCompatibilityModeReserved",
                &self.0.PlaceholderCompatibilityModeReserved,
            )
            .field("LeapSecondData", &self.0.LeapSecondData)
            .field("LeapSecondFlags", &self.0.LeapSecondFlags)
            .field("NtGlobalFlag2", &self.0.NtGlobalFlag2)
            .finish()
    }
}
impl fmt::Debug for NtapiPEB32
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        f.debug_struct("PEB")
            .field("InheritedAddressSpace", &self.0.InheritedAddressSpace)
            .field("ReadImageFileExecOptions", &self.0.ReadImageFileExecOptions)
            .field("BeingDebugged", &self.0.BeingDebugged)
            .field("BitField", &self.0.BitField)
            .field("Mutant", &self.0.Mutant)
            .field("ImageBaseAddress", &self.0.ImageBaseAddress)
            .field("Ldr", &self.0.Ldr)
            .field("ProcessParameters", &self.0.ProcessParameters)
            .field("SubSystemData", &self.0.SubSystemData)
            .field("ProcessHeap", &self.0.ProcessHeap)
            .field("FastPebLock", &self.0.FastPebLock)
            .field("IFEOKey", &self.0.IFEOKey)
            .field("AtlThunkSListPtr", &self.0.AtlThunkSListPtr)
            .field("CrossProcessFlags", &self.0.CrossProcessFlags)
            .field(
                "u",
                &format_args!(
                    "KernelCallbackTable: {:#x?},UserSharedInfoPtr: {:#x?}
            ",
                    unsafe { self.0.u.KernelCallbackTable },
                    unsafe { self.0.u.UserSharedInfoPtr }
                ),
            )
            .field("SystemReserved", &self.0.SystemReserved)
            .field("AtlThunkSListPtr32", &self.0.AtlThunkSListPtr32)
            .field("ApiSetMap", &self.0.ApiSetMap)
            .field("TlsExpansionCounter", &self.0.TlsExpansionCounter)
            .field("TlsBitmap", &self.0.TlsBitmap)
            .field("TlsBitmapBits", &self.0.TlsBitmapBits)
            .field("ReadOnlySharedMemoryBase", &self.0.ReadOnlySharedMemoryBase)
            // .field("SharedData", &self.0.SharedData)
            .field("ReadOnlyStaticServerData", &self.0.ReadOnlyStaticServerData)
            .field("AnsiCodePageData", &self.0.AnsiCodePageData)
            .field("OemCodePageData", &self.0.OemCodePageData)
            .field("UnicodeCaseTableData", &self.0.UnicodeCaseTableData)
            .field("NumberOfProcessors", &self.0.NumberOfProcessors)
            .field("NtGlobalFlag", &self.0.NtGlobalFlag)
            .field(
                "CriticalSectionTimeout",
                &format_args!("{}", unsafe { self.0.CriticalSectionTimeout.QuadPart() }),
            )
            .field("HeapSegmentReserve", &self.0.HeapSegmentReserve)
            .field("HeapSegmentCommit", &self.0.HeapSegmentCommit)
            .field(
                "HeapDeCommitTotalFreeThreshold",
                &self.0.HeapDeCommitTotalFreeThreshold,
            )
            .field(
                "HeapDeCommitFreeBlockThreshold",
                &self.0.HeapDeCommitFreeBlockThreshold,
            )
            .field("NumberOfHeaps", &self.0.NumberOfHeaps)
            .field("MaximumNumberOfHeaps", &self.0.MaximumNumberOfHeaps)
            .field("ProcessHeaps", &self.0.ProcessHeaps)
            .field("GdiSharedHandleTable", &self.0.GdiSharedHandleTable)
            .field("ProcessStarterHelper", &self.0.ProcessStarterHelper)
            .field("GdiDCAttributeList", &self.0.GdiDCAttributeList)
            .field("LoaderLock", &self.0.LoaderLock)
            .field("OSMajorVersion", &self.0.OSMajorVersion)
            .field("OSMinorVersion", &self.0.OSMinorVersion)
            .field("OSBuildNumber", &self.0.OSBuildNumber)
            .field("OSCSDVersion", &self.0.OSCSDVersion)
            .field("OSPlatformId", &self.0.OSPlatformId)
            .field("ImageSubsystem", &self.0.ImageSubsystem)
            .field(
                "ImageSubsystemMajorVersion",
                &self.0.ImageSubsystemMajorVersion,
            )
            .field(
                "ImageSubsystemMinorVersion",
                &self.0.ImageSubsystemMinorVersion,
            )
            .field(
                "ActiveProcessAffinityMask",
                &self.0.ActiveProcessAffinityMask,
            )
            .field("GdiHandleBuffer", &self.0.GdiHandleBuffer)
            .field("PostProcessInitRoutine", &self.0.PostProcessInitRoutine)
            .field("TlsExpansionBitmap", &self.0.TlsExpansionBitmap)
            .field("TlsExpansionBitmapBits", &self.0.TlsExpansionBitmapBits)
            .field("SessionId", &self.0.SessionId)
            .field(
                "AppCompatFlags",
                &format_args!("{}", unsafe { self.0.AppCompatFlags.QuadPart() }),
            )
            .field(
                "AppCompatFlagsUser",
                &format_args!("{}", unsafe { self.0.AppCompatFlagsUser.QuadPart() }),
            )
            .field("pShimData", &self.0.pShimData)
            .field("AppCompatInfo", &self.0.AppCompatInfo)
            //.field("CSDVersion", &self.0.CSDVersion)
            .field("ActivationContextData", &self.0.ActivationContextData)
            .field(
                "ProcessAssemblyStorageMap",
                &self.0.ProcessAssemblyStorageMap,
            )
            .field(
                "SystemDefaultActivationContextData",
                &self.0.SystemDefaultActivationContextData,
            )
            .field("SystemAssemblyStorageMap", &self.0.SystemAssemblyStorageMap)
            .field("MinimumStackCommit", &self.0.MinimumStackCommit)
            .field("FlsCallback", &self.0.FlsCallback)
            .field(
                "FlsListHead",
                &format_args!(
                    "backlink: {:#x?} forwardlink: {:#x?}",
                    self.0.FlsListHead.Blink as usize, self.0.FlsListHead.Flink as usize
                ),
            )
            .field("FlsBitmap", &self.0.FlsBitmap)
            .field("FlsBitmapBits", &self.0.FlsBitmapBits)
            .field("FlsHighIndex", &self.0.FlsHighIndex)
            .field("WerRegistrationData", &self.0.WerRegistrationData)
            .field("WerShipAssertPtr", &self.0.WerShipAssertPtr)
            // .field("pUnused", &self.0.pUnused)
            .field("pImageHeaderHash", &self.0.pImageHeaderHash)
            .field("TracingFlags", &self.0.TracingFlags)
            .field(
                "CsrServerReadOnlySharedMemoryBase",
                &self.0.CsrServerReadOnlySharedMemoryBase,
            )
            .field("TppWorkerpListLock", &self.0.TppWorkerpListLock)
            .field(
                "TppWorkerpList",
                &format_args!(
                    "backlink: {:#x?} forwardlink: {:#x?}",
                    self.0.TppWorkerpList.Blink, self.0.TppWorkerpList.Flink
                ),
            )
            .field("WaitOnAddressHashTable", &self.0.WaitOnAddressHashTable)
            .field("TelemetryCoverageHeader", &self.0.TelemetryCoverageHeader)
            .field("CloudFileFlags", &self.0.CloudFileFlags)
            .field("CloudFileDiagFlags", &self.0.CloudFileDiagFlags)
            .field(
                "PlaceholderCompatibilityMode",
                &self.0.PlaceholderCompatibilityMode,
            )
            .field(
                "PlaceholderCompatibilityModeReserved",
                &self.0.PlaceholderCompatibilityModeReserved,
            )
            // .field("LeapSecondData", &self.0.LeapSecondData)
            // .field("LeapSecondFlags", &self.0.LeapSecondFlags)
            // .field("NtGlobalFlag2", &self.0.NtGlobalFlag2)
            .finish()
    }
}
