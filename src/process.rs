use anyhow::{anyhow, bail, ensure, Result};

use std::{
    ffi::{CStr, CString},
    mem::{size_of, size_of_val},
    ptr::{self, addr_of_mut},
};
use struct_iterable::Iterable;
use windows::{
    core::PWSTR,
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    },
    Win32::{
        Foundation::{HANDLE, PSID},
        Security::{
            Authentication::Identity::{
                LsaLookupSids, LsaOpenPolicy, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES,
                LSA_REFERENCED_DOMAIN_LIST, LSA_TRANSLATED_NAME, POLICY_LOOKUP_NAMES,
            },
            GetTokenInformation, SidTypeInvalid, SidTypeUnknown, TOKEN_INFORMATION_CLASS,
            TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            Threading::{
                IsWow64Process, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS,
                PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
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
pub struct ProcessListEntry
{
    pub name:     String,
    pub pid:      u32,
    pub username: String,
    pub show:     bool,
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
    pub fn enum_processes() -> Result<Vec<ProcessListEntry>>
    {
        let mut processes: Vec<ProcessListEntry> = Vec::new();
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };

        let mut process_entry = PROCESSENTRY32W::default();
        process_entry.dwSize = size_of::<PROCESSENTRY32W>() as _;
        if let Ok(()) = unsafe { Process32FirstW(snapshot, addr_of_mut!(process_entry)) }
        {
            while let Ok(()) = unsafe { Process32NextW(snapshot, addr_of_mut!(process_entry)) }
            {
                processes.push(ProcessListEntry {
                    name:     U16CStr::from_slice_truncate(&process_entry.szExeFile)?
                        .to_string_lossy(),
                    pid:      process_entry.th32ProcessID,
                    username: Process::get_username(process_entry.th32ProcessID)?,
                    show:     true,
                })
            }
        }
        Ok(processes)
    }
    pub fn get_username(pid: u32) -> Result<String>
    {
        if pid == 0 || pid == 4
        {
            return Ok("SYSTEM".to_owned());
        }

        let mut handle;

        match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        {
            Err(e) => return Ok("".to_owned()),
            Ok(ok) => handle = ok,
        }
        let mut token = HANDLE(0);
        let mut token_user = TOKEN_USER::default();
        let mut ret_len = 0;

        if let Err(e) = unsafe { OpenProcessToken(handle, TOKEN_QUERY, addr_of_mut!(token)) }
        {
            return Ok("".to_owned());
        }

        unsafe {
            if GetTokenInformation(
                token,
                TOKEN_INFORMATION_CLASS(1),
                Some(addr_of_mut!(token_user) as _),
                size_of_val(&token_user) as _,
                addr_of_mut!(ret_len),
            )
            .is_err()
            {
                GetTokenInformation(
                    token,
                    TOKEN_INFORMATION_CLASS(1),
                    Some(addr_of_mut!(token_user) as _),
                    ret_len,
                    addr_of_mut!(ret_len),
                )?
            }
        }

        let mut lsa_handle = LSA_HANDLE::default();
        let mut object_attr = LSA_OBJECT_ATTRIBUTES::default();
        let mut sid = token_user.User.Sid;
        let mut domains = ptr::null_mut();
        let mut names = ptr::null_mut();
        let mut full_name;
        unsafe {
            let res = LsaOpenPolicy(
                None,
                addr_of_mut!(object_attr),
                POLICY_LOOKUP_NAMES as _,
                addr_of_mut!(lsa_handle),
            );
            ensure!(res.is_ok(), "LsaOpenPolicy failed with status: {:?}", res);
        }

        unsafe {
            let res = LsaLookupSids(
                lsa_handle,
                1,
                addr_of_mut!(sid),
                addr_of_mut!(domains),
                addr_of_mut!(names),
            );
            ensure!(res.is_ok(), "LsaLookupSids failed with status: {:#x?}", res);
        }
        if (unsafe { *names }).Use != SidTypeInvalid && (unsafe { *names }).Use != SidTypeUnknown
        {
            let mut domain_name_buffer: PWSTR;
            let mut domain_name_length: u32;
            if (unsafe { *names }).DomainIndex >= 0
            {
                let mut trust_info = ptr::null_mut();
                trust_info = (unsafe { *domains })
                    .Domains
                    .wrapping_add((unsafe { *names }).DomainIndex.try_into().unwrap());
                domain_name_buffer = (unsafe { *trust_info }).Name.Buffer;
                domain_name_length = (unsafe { *trust_info }).Name.Length as _;
            }
            else
            {
                domain_name_buffer = PWSTR::null();
                domain_name_length = 0;
            }
            if !domain_name_buffer.is_null() && domain_name_length != 0
            {
                full_name = unsafe { domain_name_buffer.to_string() }?;
                full_name.push('/');
                full_name.push_str(unsafe { &(*names).Name.Buffer.to_string()?.to_owned() });
            }
            else
            {
                full_name = unsafe { (*names).Name.Buffer.to_string() }?;
            }
        }
        else
        {
            full_name = String::new();
        }

        Ok(full_name)
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
