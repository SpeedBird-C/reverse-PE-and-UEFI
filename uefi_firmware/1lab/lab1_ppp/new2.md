
# Passed:10
#### common.bios_kbrd_buffer
    
    [*] running module: chipsec.modules.common.bios_kbrd_buffer
    [x][ =======================================================================
    [x][ Module: Pre-boot Passwords in the BIOS Keyboard Buffer
    [x][ =======================================================================
    [*] Keyboard buffer head pointer = 0x0 (at 0x41A), tail pointer = 0x0 (at 0x41C)
    [*] Keyboard buffer contents (at 0x41E):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |                 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |                 
    [*] Checking contents of the keyboard buffer..
    
    [+] PASSED: Keyboard buffer looks empty. Pre-boot passwords don't seem to be exposed
#### common.bios_smi
    
    [*] running module: chipsec.modules.common.bios_smi
    [x][ =======================================================================
    [x][ Module: SMI Events Configuration
    [x][ =======================================================================
    [+] SMM BIOS region write protection is enabled (SMM_BWP is used)
    
    [*] Checking SMI enables..
        Global SMI enable: 1
        TCO SMI enable   : 1
    [+] All required SMI events are enabled
    
    [*] Checking SMI configuration locks..
    [+] TCO SMI configuration is locked (TCO SMI Lock)
    [+] SMI events global configuration is locked (SMI Lock)
    
    [+] PASSED: All required SMI sources seem to be enabled and locked
#### common.bios_ts
    
    [*] running module: chipsec.modules.common.bios_ts
    [x][ =======================================================================
    [x][ Module: BIOS Interface Lock (including Top Swap Mode)
    [x][ =======================================================================
    [*] BiosInterfaceLockDown (BILD) control = 1
    [*] BIOS Top Swap mode is enabled (TSS = 1)
    [*] RTC TopSwap control (TS) = 1
    [+] PASSED: BIOS Interface is locked (including Top Swap Mode)
#### common.bios_wp
    
    [*] running module: chipsec.modules.common.bios_wp
    [x][ =======================================================================
    [x][ Module: BIOS Region Write Protection
    [x][ =======================================================================
    [*] BC = 0xFFFFFFFF << BIOS Control (b:d.f 00:31.5 + 0xDC)
        [00] BIOSWE           = 1 << BIOS Write Enable 
        [01] BLE              = 1 << BIOS Lock Enable 
        [02] SRC              = 3 << SPI Read Configuration 
        [04] TSS              = 1 << Top Swap Status 
        [05] SMM_BWP          = 1 << SMM BIOS Write Protection 
        [06] BBS              = 1 << Boot BIOS Strap 
        [07] BILD             = 1 << BIOS Interface Lock Down 
    [-] BIOS region write protection is disabled!
    
    [*] BIOS Region: Base = 0x07FFF000, Limit = 0x07FFFFFF
    SPI Protected Ranges
    ------------------------------------------------------------
    PRx (offset) | Value    | Base     | Limit    | WP? | RP?
    ------------------------------------------------------------
    PR0 (84)     | FFFFFFFF | 07FFF000 | 07FFFFFF | 1   | 1 
    PR1 (88)     | FFFFFFFF | 07FFF000 | 07FFFFFF | 1   | 1 
    PR2 (8C)     | FFFFFFFF | 07FFF000 | 07FFFFFF | 1   | 1 
    PR3 (90)     | FFFFFFFF | 07FFF000 | 07FFFFFF | 1   | 1 
    PR4 (94)     | FFFFFFFF | 07FFF000 | 07FFFFFF | 1   | 1 
    
    [+] PASSED: SPI Protected Ranges are configured to write protect BIOS
#### common.ia32cfg
    
    [*] running module: chipsec.modules.common.ia32cfg
    [x][ =======================================================================
    [x][ Module: IA32 Feature Control Lock
    [x][ =======================================================================
    [*] Verifying IA32_Feature_Control MSR is locked on all logical CPUs..
    [*] cpu0: IA32_Feature_Control Lock = 1
    [*] cpu1: IA32_Feature_Control Lock = 1
    [*] cpu2: IA32_Feature_Control Lock = 1
    [*] cpu3: IA32_Feature_Control Lock = 1
    [+] PASSED: IA32_FEATURE_CONTROL MSR is locked on all logical CPUs
#### common.me_mfg_mode
    
    [*] running module: chipsec.modules.common.me_mfg_mode
    [x][ =======================================================================
    [x][ Module: ME Manufacturing Mode
    [x][ =======================================================================
    [+] PASSED: ME is not in Manufacturing Mode
#### common.secureboot.variables
    
    [*] running module: chipsec.modules.common.secureboot.variables
    [x][ =======================================================================
    [x][ Module: Attributes of Secure Boot EFI Variables
    [x][ =======================================================================
    [*] Checking protections of UEFI variable 8BE4DF61-93CA-11D2-AA0D-00E098032B8C:SecureBoot
    [*] Checking protections of UEFI variable 8BE4DF61-93CA-11D2-AA0D-00E098032B8C:SetupMode
    [*] Checking protections of UEFI variable 8BE4DF61-93CA-11D2-AA0D-00E098032B8C:PK
    [+] Variable 8BE4DF61-93CA-11D2-AA0D-00E098032B8C:PK is authenticated (TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    [*] Checking protections of UEFI variable 8BE4DF61-93CA-11D2-AA0D-00E098032B8C:KEK
    [+] Variable 8BE4DF61-93CA-11D2-AA0D-00E098032B8C:KEK is authenticated (TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    [*] Checking protections of UEFI variable D719B2CB-3D3A-4596-A3BC-DAD00E67656F:db
    [+] Variable D719B2CB-3D3A-4596-A3BC-DAD00E67656F:db is authenticated (TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    [*] Checking protections of UEFI variable D719B2CB-3D3A-4596-A3BC-DAD00E67656F:dbx
    [+] Variable D719B2CB-3D3A-4596-A3BC-DAD00E67656F:dbx is authenticated (TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    
    [*] Secure Boot appears to be disabled
    [+] PASSED: All Secure Boot UEFI variables are protected
#### common.spi_fdopss
    
    [*] running module: chipsec.modules.common.spi_fdopss
    [x][ =======================================================================
    [x][ Module: SPI Flash Descriptor Security Override Pin-Strap
    [x][ =======================================================================
    [*] HSFS = 0xFFFFFFFF << Hardware Sequencing Flash Status Register (SPIBAR + 0x4)
        [00] FDONE            = 1 << Flash Cycle Done 
        [01] FCERR            = 1 << Flash Cycle Error 
        [02] AEL              = 1 << Access Error Log 
        [05] SCIP             = 1 << SPI cycle in progress 
        [11] WRSDIS           = 1 << Write status disable 
        [12] PR34LKD          = 1 << PRR3 PRR4 Lock-Down 
        [13] FDOPSS           = 1 << Flash Descriptor Override Pin-Strap Status 
        [14] FDV              = 1 << Flash Descriptor Valid 
        [15] FLOCKDN          = 1 << Flash Configuration Lock-Down 
        [16] FGO              = 1 << Flash cycle go 
        [17] FCYCLE           = F << Flash Cycle Type 
        [21] WET              = 1 << Write Enable Type 
        [24] FDBC             = 3F << Flash Data Byte Count 
        [31] FSMIE            = 1 << Flash SPI SMI# Enable 
    [+] PASSED: SPI Flash Descriptor Security Override is disabled
#### common.spi_lock
    
    [*] running module: chipsec.modules.common.spi_lock
    [x][ =======================================================================
    [x][ Module: SPI Flash Controller Configuration Locks
    [x][ =======================================================================
    [*] HSFS = 0xFFFFFFFF << Hardware Sequencing Flash Status Register (SPIBAR + 0x4)
        [00] FDONE            = 1 << Flash Cycle Done 
        [01] FCERR            = 1 << Flash Cycle Error 
        [02] AEL              = 1 << Access Error Log 
        [05] SCIP             = 1 << SPI cycle in progress 
        [11] WRSDIS           = 1 << Write status disable 
        [12] PR34LKD          = 1 << PRR3 PRR4 Lock-Down 
        [13] FDOPSS           = 1 << Flash Descriptor Override Pin-Strap Status 
        [14] FDV              = 1 << Flash Descriptor Valid 
        [15] FLOCKDN          = 1 << Flash Configuration Lock-Down 
        [16] FGO              = 1 << Flash cycle go 
        [17] FCYCLE           = F << Flash Cycle Type 
        [21] WET              = 1 << Write Enable Type 
        [24] FDBC             = 3F << Flash Data Byte Count 
        [31] FSMIE            = 1 << Flash SPI SMI# Enable 
    [+] SPI write status disable set.
    [+] SPI Flash Controller configuration is locked
    [+] PASSED: SPI Flash Controller locked correctly.
#### common.uefi.access_uefispec
    
    [*] running module: chipsec.modules.common.uefi.access_uefispec
    [x][ =======================================================================
    [x][ Module: Access Control of EFI Variables
    [x][ =======================================================================
    [*] Testing UEFI variables ..
    [*] Variable PK (NV+BS+RT+TBAWS)
    [*] Variable KEK (NV+BS+RT+TBAWS)
    [*] Variable db (NV+BS+RT+TBAWS)
    [*] Variable SbConfigState (NV+BS+RT+TBAWS)
    [*] Variable Lang (NV+BS+RT)
    [*] Variable PlatformLang (NV+BS+RT)
    [*] Variable ConsoleOutMode (NV+BS+RT)
    [*] Variable Boot0000 (NV+BS+RT)
    [*] Variable Boot0001 (NV+BS+RT)
    [*] Variable Boot0002 (NV+BS+RT)
    [*] Variable Boot0003 (NV+BS+RT)
    [*] Variable CurrentPolicy (NV+BS+RT+TBAWS)
    [*] Variable UnlockIDCopy (NV+BS+RT)
    [*] Variable Boot0004 (NV+BS+RT)
    [*] Variable Timeout (NV+BS+RT)
    [*] Variable HDDP (NV+BS+RT)
    [*] Variable OfflineUniqueIDRandomSeed (NV+BS+RT)
    [*] Variable OfflineUniqueIDRandomSeedCRC (NV+BS+RT)
    [*] Variable dbx (NV+BS+RT+TBAWS)
    [*] Variable SignatureSupport (BS+RT)
    [*] Variable PKDefault (BS+RT)
    [*] Variable KEKDefault (BS+RT)
    [*] Variable dbDefault (BS+RT)
    [*] Variable dbxDefault (BS+RT)
    [*] Variable SetupMode (BS+RT)
    [*] Variable SecureBoot (BS+RT)
    [*] Variable MTC (NV+BS+RT)
    [*] Variable BootOptionSupport (BS+RT)
    [*] Variable OsIndicationsSupported (BS+RT)
    [*] Variable LangCodes (BS+RT)
    [*] Variable PlatformLangCodes (BS+RT)
    [*] Variable ConOutDev (BS+RT)
    [*] Variable ConIn (NV+BS+RT)
    [*] Variable ConOut (NV+BS+RT)
    [*] Variable ConInDev (BS+RT)
    [*] Variable ErrOut (NV+BS+RT)
    [*] Variable MemoryOverwriteRequestControl (NV+BS+RT)
    [*] Variable MemoryOverwriteRequestControlLock (NV+BS+RT)
    [*] Variable BootOrder (NV+BS+RT)
    [*] Variable MemoryTypeInformation (NV+BS+RT)
    [*] Variable BootCurrent (BS+RT)
    
    [+] PASSED: All checked EFI variables are protected according to spec.

# Failed:5
#### common.memconfig
    
    [*] running module: chipsec.modules.common.memconfig
    [x][ =======================================================================
    [x][ Module: Host Bridge Memory Map Locks
    [x][ =======================================================================
    [*]
    [*] Checking register lock state:
    [-] PCI0.0.0_BDSM        = 0x               0 - UNLOCKED - Base of Graphics Stolen Memory
    [-] PCI0.0.0_BGSM        = 0x               0 - UNLOCKED - Base of GTT Stolen Memory
    [+] PCI0.0.0_DPR         = 0x           13001 - LOCKED   - DMA Protected Range
    [-] PCI0.0.0_GGC         = 0x               0 - UNLOCKED - Graphics Control
    [-] PCI0.0.0_MESEG_MASK  = 0x               0 - UNLOCKED - Manageability Engine Limit Address Register
    [-] PCI0.0.0_PAVPC       = 0x        30011000 - UNLOCKED - PAVP Configuration
    [-] PCI0.0.0_REMAPBASE   = 0x               0 - UNLOCKED - Memory Remap Base Address
    [-] PCI0.0.0_REMAPLIMIT  = 0x               0 - UNLOCKED - Memory Remap Limit Address
    [-] PCI0.0.0_TOLUD       = 0x               0 - UNLOCKED - Top of Low Usable DRAM
    [-] PCI0.0.0_TOM         = 0x               0 - UNLOCKED - Top of Memory
    [-] PCI0.0.0_TOUUD       = 0x               0 - UNLOCKED - Top of Upper Usable DRAM
    [-] PCI0.0.0_TSEGMB      = 0x               0 - UNLOCKED - TSEG Memory Base
    [*]
    [-] FAILED: Not all memory map registers are locked down
#### common.memlock
    
    [*] running module: chipsec.modules.common.memlock
    [x][ =======================================================================
    [x][ Module: Check MSR_LT_LOCK_MEMORY
    [x][ =======================================================================
    [X] Checking MSR_LT_LOCK_MEMORY status
    [*]   cpu0: MSR_LT_LOCK_MEMORY[LT_LOCK] = 0
    [*]   cpu1: MSR_LT_LOCK_MEMORY[LT_LOCK] = 0
    [*]   cpu2: MSR_LT_LOCK_MEMORY[LT_LOCK] = 0
    [*]   cpu3: MSR_LT_LOCK_MEMORY[LT_LOCK] = 0
    [-] FAILED: Check failed. MSR_LT_LOCK_MEMORY isn't configured correctly
#### common.remap
    
    [*] running module: chipsec.modules.common.remap
    [x][ =======================================================================
    [x][ Module: Memory Remapping Configuration
    [x][ =======================================================================
    [*] Registers:
    [*]   TOUUD     : 0x0000000000000000
    [*]   REMAPLIMIT: 0x0000000000000000
    [*]   REMAPBASE : 0x0000000000000000
    [*]   TOLUD     : 0x00000000
    [*]   TSEGMB    : 0x00000000
    
    [*] Memory Map:
    [*]   Top Of Upper Memory: 0x0000000000000000
    [*]   Remap Limit Address: 0x00000000000FFFFF
    [*]   Remap Base Address : 0x0000000000000000
    [*]   4GB                : 0x0000000100000000
    [*]   Top Of Low Memory  : 0x0000000000000000
    [*]   TSEG (SMRAM) Base  : 0x0000000000000000
    
    [*] checking memory remap configuration..
    [*]   Memory Remap is enabled
    [-]   Remap window configuration is not correct
    [+]   All addresses are 1MB aligned
    [*] checking if memory remap configuration is locked..
    [-]   TOUUD is not locked
    [-]   TOLUD is not locked
    [-]   REMAPBASE and REMAPLIMIT are not locked
    [-] FAILED: Memory Remap is not properly configured/locked. Remaping attack may be possible
#### common.spi_access
    
    [*] running module: chipsec.modules.common.spi_access
    [x][ =======================================================================
    [x][ Module: SPI Flash Region Access Control
    [x][ =======================================================================
    SPI Flash Region Access Permissions
    ------------------------------------------------------------
    
    BIOS Region Write Access Grant (FF):
      FREG0_FLASHD: 1
      FREG1_BIOS  : 1
      FREG2_ME    : 1
      FREG3_GBE   : 1
      FREG4_PD    : 1
      FREG5       : 1
    BIOS Region Read Access Grant (FF):
      FREG0_FLASHD: 1
      FREG1_BIOS  : 1
      FREG2_ME    : 1
      FREG3_GBE   : 1
      FREG4_PD    : 1
      FREG5       : 1
    BIOS Region Write Access (FF):
      FREG0_FLASHD: 1
      FREG1_BIOS  : 1
      FREG2_ME    : 1
      FREG3_GBE   : 1
      FREG4_PD    : 1
      FREG5       : 1
    BIOS Region Read Access (FF):
      FREG0_FLASHD: 1
      FREG1_BIOS  : 1
      FREG2_ME    : 1
      FREG3_GBE   : 1
      FREG4_PD    : 1
      FREG5       : 1
    [*] Software has write access to Platform Data region in SPI flash (it's platform specific)
    [!] WARNING: Software has write access to GBe region in SPI flash
    [-] Software has write access to SPI flash descriptor
    [-] Software has write access to Management Engine (ME) region in SPI flash
    [-] FAILED: SPI Flash Region Access Permissions are not programmed securely in flash descriptor
    [!] System may be using alternative protection by including descriptor region in SPI Protected Range Registers
#### common.spi_desc
    
    [*] running module: chipsec.modules.common.spi_desc
    [x][ =======================================================================
    [x][ Module: SPI Flash Region Access Control
    [x][ =======================================================================
    [*] FRAP = 0xFFFFFFFF << SPI Flash Regions Access Permissions Register (SPIBAR + 0x50)
        [00] BRRA             = FF << BIOS Region Read Access 
        [08] BRWA             = FF << BIOS Region Write Access 
        [16] BMRAG            = FF << BIOS Master Read Access Grant 
        [24] BMWAG            = FF << BIOS Master Write Access Grant 
    [*] Software access to SPI flash regions: read = 0xFF, write = 0xFF
    [-] Software has write access to SPI flash descriptor
    
    [-] FAILED: SPI flash permissions allow SW to write flash descriptor
    [!] System may be using alternative protection by including descriptor region in SPI Protected Range Registers

# Error:1
#### common.wsmt
    
    [*] running module: chipsec.modules.common.wsmt
    [x][ =======================================================================
    [x][ Module: WSMT Configuration
    [x][ =======================================================================
    ERROR: Exception occurred during chipsec.modules.common.wsmt.run(): ''NoneType' object has no attribute 'Revision''

# Warning:5
#### common.cpu.spectre_v2
    
    [*] running module: chipsec.modules.common.cpu.spectre_v2
    [x][ =======================================================================
    [x][ Module: Checks for Branch Target Injection / Spectre v2 (CVE-2017-5715)
    [x][ =======================================================================
    [*] CPUID.7H:EDX[26] = 1 Indirect Branch Restricted Speculation (IBRS) & Predictor Barrier (IBPB)
    [*] CPUID.7H:EDX[27] = 1 Single Thread Indirect Branch Predictors (STIBP)
    [*] CPUID.7H:EDX[29] = 1 IA32_ARCH_CAPABILITIES
    [+] CPU supports IBRS and IBPB
    [+] CPU supports STIBP
    [*] checking enhanced IBRS support in IA32_ARCH_CAPABILITIES...
    [*]   cpu0: IBRS_ALL = 0
    [-] CPU doesn't support enhanced IBRS
    [!] WARNING: CPU supports mitigation (IBRS) but doesn't support enhanced IBRS
    [!] OS may be using software based mitigation (eg. retpoline)
    [-] Retpoline is NOT enabled by the OS
#### common.rtclock
    
    [*] running module: chipsec.modules.common.rtclock
    [x][ =======================================================================
    [x][ Module: Protected RTC memory locations
    [x][ =======================================================================
    [!] WARNING: Unable to test lock bits without attempting to modify CMOS.
    [*] Run chipsec_main manually with the following commandline flags.
    [*] python chipsec_main -m common.rtclock -a modify
#### common.smm_code_chk
    
    [*] running module: chipsec.modules.common.smm_code_chk
    [x][ =======================================================================
    [x][ Module: SMM_Code_Chk_En (SMM Call-Out) Protection
    [x][ =======================================================================
    [*] MSR_SMM_FEATURE_CONTROL = 0x00000000 << Enhanced SMM Feature Control (MSR 0x4E0 Thread 0x0)
        [00] LOCK             = 0 << Lock bit 
        [02] SMM_Code_Chk_En  = 0 << Prevents SMM from executing code outside the ranges defined by the SMRR 
    [*] MSR_SMM_FEATURE_CONTROL = 0x00000000 << Enhanced SMM Feature Control (MSR 0x4E0 Thread 0x0)
        [00] LOCK             = 0 << Lock bit 
        [02] SMM_Code_Chk_En  = 0 << Prevents SMM from executing code outside the ranges defined by the SMRR 
    [*] MSR_SMM_FEATURE_CONTROL = 0x00000000 << Enhanced SMM Feature Control (MSR 0x4E0 Thread 0x0)
        [00] LOCK             = 0 << Lock bit 
        [02] SMM_Code_Chk_En  = 0 << Prevents SMM from executing code outside the ranges defined by the SMRR 
    [*] MSR_SMM_FEATURE_CONTROL = 0x00000000 << Enhanced SMM Feature Control (MSR 0x4E0 Thread 0x0)
        [00] LOCK             = 0 << Lock bit 
        [02] SMM_Code_Chk_En  = 0 << Prevents SMM from executing code outside the ranges defined by the SMRR 
    WARNING: [*] SMM_Code_Chk_En is not enabled.
    This can happen either because this feature is not supported by the CPU or because the BIOS forgot to enable it.
    Please consult the Intel SDM to determine whether or not your CPU supports SMM_Code_Chk_En.
#### common.smm_dma
    
    [*] running module: chipsec.modules.common.smm_dma
    [x][ =======================================================================
    [x][ Module: SMM TSEG Range Configuration Check
    [x][ =======================================================================
    [*] TSEG      : 0x0000000000000000 - 0x-000000000000001 (size = 0x00000000)
    [*] SMRR is not supported
    
    [*] checking TSEG range configuration..
    [!] WARNING: TSEG is properly configured but can't determine if it covers entire SMRAM
#### common.uefi.s3bootscript
    
    [*] running module: chipsec.modules.common.uefi.s3bootscript
    [x][ =======================================================================
    [x][ Module: S3 Resume Boot-Script Protections
    [x][ =======================================================================
    [*] SMRAM: Base = 0x0000000000000000, Limit = 0x-000000000000001, Size = 0x00000000
    [+] Didn't find any S3 boot-scripts in EFI variables
    [!] WARNING: S3 Boot-Script was not found. Firmware may be using other ways to store/locate it, or OS might be blocking access.

# Skipped:2
#### common.smm
    
    [*] running module: chipsec.modules.common.smm
    [x][ =======================================================================
    [x][ Module: Compatible SMM memory (SMRAM) Protection
    [x][ =======================================================================
    [*] PCI0.0.0_SMRAMC = 0x00 << System Management RAM Control (b:d.f 00:00.0 + 0x88)
        [00] C_BASE_SEG       = 0 << SMRAM Base Segment = 010b 
        [03] G_SMRAME         = 0 << SMRAM Enabled 
        [04] D_LCK            = 0 << SMRAM Locked 
        [05] D_CLS            = 0 << SMRAM Closed 
        [06] D_OPEN           = 0 << SMRAM Open 
    [*] Compatible SMRAM is not enabled. Skipping..
#### common.smrr
    
    [*] running module: chipsec.modules.common.smrr
    [x][ =======================================================================
    [x][ Module: CPU SMM Cache Poisoning / System Management Range Registers
    [x][ =======================================================================
    [!] CPU does not support SMRR range protection of SMRAM
    [*] NOT IMPLEMENTED: CPU does not support SMRR range protection of SMRAM

# Information:1
#### common.cpu.cpu_info
    
    [*] running module: chipsec.modules.common.cpu.cpu_info
    [x][ =======================================================================
    [x][ Module: Current Processor Information:
    [x][ =======================================================================
    [*] Thread 0000
    [*] Processor: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
    [*]            Family: 06 Model: 8E Stepping: 9
    [*]            Microcode: 000000B4
    [*]
    [*] Thread 0001
    [*] Processor: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
    [*]            Family: 06 Model: 8E Stepping: 9
    [*]            Microcode: 000000B4
    [*]
    [*] Thread 0002
    [*] Processor: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
    [*]            Family: 06 Model: 8E Stepping: 9
    [*]            Microcode: 000000B4
    [*]
    [*] Thread 0003
    [*] Processor: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
    [*]            Family: 06 Model: 8E Stepping: 9
    [*]            Microcode: 000000B4
    [*]
    [#] INFORMATION: Processor information displayed

# NotApplicable:4
#### common.cpu.ia_untrusted
    
    [*] running module: chipsec.modules.common.cpu.ia_untrusted
    Skipping module chipsec.modules.common.cpu.ia_untrusted since it is not supported in this platform
#### common.debugenabled
    
    [*] running module: chipsec.modules.common.debugenabled
    [*] NOT IMPLEMENTED: CPU Debug features are not supported on this platform
    Skipping module chipsec.modules.common.debugenabled since it is not supported in this platform
#### common.sgx_check
    
    [*] running module: chipsec.modules.common.sgx_check
    Skipping module chipsec.modules.common.sgx_check since it is not supported in this platform
#### common.spd_wd
    
    [*] running module: chipsec.modules.common.spd_wd
    [!] SMBUS device appears disabled.  Skipping module.
    Skipping module chipsec.modules.common.spd_wd since it is not supported in this platform

# Deprecated:0
