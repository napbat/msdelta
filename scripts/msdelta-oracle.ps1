<#
.SYNOPSIS
Create, apply and inspect PA30 deltas with the Windows msdelta.dll.

.DESCRIPTION
The tests do not use this script. Use it on Windows to make the test fixtures in
tests/fixtures/, and to compare the crate with msdelta.dll.

.EXAMPLE
./scripts/msdelta-oracle.ps1 create -Source a.bin -Target b.bin -Out a-b.delta
./scripts/msdelta-oracle.ps1 apply -Source a.bin -Delta a-b.delta -Out b2.bin
./scripts/msdelta-oracle.ps1 info -Delta a-b.delta
#>
param(
    [Parameter(Mandatory, Position = 0)][ValidateSet('create', 'apply', 'info')][string]$Command,
    [string]$Source,
    [string]$Target,
    [string]$Delta,
    [string]$Out,
    # DELTA_FILE_TYPE_SET_RAW_ONLY = 1, DELTA_FILE_TYPE_SET_EXECUTABLES = 0x0F,
    # DELTA_FILE_TYPE_SET_EXECUTABLES_2 = 0xFF, DELTA_FILE_TYPE_SET_EXECUTABLES_3 = 0x1FF.
    [UInt64]$FileTypeSet = 1,
    [UInt64]$SetFlags = 0,
    # CALG_MD5 = 0x8003, CALG_SHA_256 = 0x800C. Zero writes no target hash.
    [UInt32]$HashAlgId = 0x8003,
    [UInt64]$TargetFileTime = 0
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class MsDelta {
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_INPUT { public IntPtr lpStart; public UIntPtr uSize; public int Editable; }
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_OUTPUT { public IntPtr lpStart; public UIntPtr uSize; }
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_HASH {
        public uint HashSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] HashValue;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_HEADER_INFO {
        public ulong FileTypeSet; public ulong FileType; public ulong Flags;
        public UIntPtr TargetSize; public long TargetFileTime; public uint TargetHashAlgId;
        public DELTA_HASH TargetHash;
    }

    [DllImport("msdelta.dll", SetLastError = true)]
    static extern bool CreateDeltaB(ulong FileTypeSet, ulong SetFlags, ulong ResetFlags,
        DELTA_INPUT Source, DELTA_INPUT Target, DELTA_INPUT SourceOptions, DELTA_INPUT TargetOptions,
        DELTA_INPUT GlobalOptions, ref long lpTargetFileTime, uint HashAlgId, out DELTA_OUTPUT lpDelta);
    [DllImport("msdelta.dll", SetLastError = true)]
    static extern bool ApplyDeltaB(ulong ApplyFlags, DELTA_INPUT Source, DELTA_INPUT Delta,
        out DELTA_OUTPUT lpTarget);
    [DllImport("msdelta.dll", SetLastError = true)]
    static extern bool GetDeltaInfoB(DELTA_INPUT Delta, out DELTA_HEADER_INFO lpHeaderInfo);
    [DllImport("msdelta.dll")]
    static extern bool DeltaFree(IntPtr lpMemory);

    static DELTA_INPUT Input(GCHandle h, byte[] data) {
        return new DELTA_INPUT { lpStart = h.AddrOfPinnedObject(), uSize = (UIntPtr)data.Length, Editable = 0 };
    }

    static byte[] Take(DELTA_OUTPUT o) {
        var bytes = new byte[(long)o.uSize];
        if (bytes.Length > 0) Marshal.Copy(o.lpStart, bytes, 0, bytes.Length);
        DeltaFree(o.lpStart);
        return bytes;
    }

    public static byte[] Create(byte[] source, byte[] target, ulong fileTypeSet, ulong setFlags, uint hashAlgId, long fileTime) {
        // Pin an extra byte so that an empty array still has an address.
        var s = GCHandle.Alloc(source.Length == 0 ? new byte[1] : source, GCHandleType.Pinned);
        var t = GCHandle.Alloc(target.Length == 0 ? new byte[1] : target, GCHandleType.Pinned);
        try {
            var src = Input(s, source); var tgt = Input(t, target);
            var none = new DELTA_INPUT();
            DELTA_OUTPUT o;
            if (!CreateDeltaB(fileTypeSet, setFlags, 0, src, tgt, none, none, none, ref fileTime, hashAlgId, out o))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return Take(o);
        } finally { s.Free(); t.Free(); }
    }

    public static byte[] Apply(byte[] source, byte[] delta) {
        var s = GCHandle.Alloc(source.Length == 0 ? new byte[1] : source, GCHandleType.Pinned);
        var d = GCHandle.Alloc(delta, GCHandleType.Pinned);
        try {
            DELTA_OUTPUT o;
            if (!ApplyDeltaB(0, Input(s, source), Input(d, delta), out o))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return Take(o);
        } finally { s.Free(); d.Free(); }
    }

    public static DELTA_HEADER_INFO Info(byte[] delta) {
        var d = GCHandle.Alloc(delta, GCHandleType.Pinned);
        try {
            DELTA_HEADER_INFO info;
            if (!GetDeltaInfoB(Input(d, delta), out info))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return info;
        } finally { d.Free(); }
    }
}
'@

function Read-Bytes([string]$Path) {
    # The comma keeps PowerShell from unrolling an empty array to $null.
    if ([string]::IsNullOrEmpty($Path)) { return , [byte[]]::new(0) }
    , [System.IO.File]::ReadAllBytes((Resolve-Path $Path))
}

function Write-Bytes([string]$Path, [byte[]]$Bytes) {
    [System.IO.File]::WriteAllBytes([System.IO.Path]::GetFullPath($Path, (Get-Location).Path), $Bytes)
}

switch ($Command) {
    'create' {
        $bytes = [MsDelta]::Create((Read-Bytes $Source), (Read-Bytes $Target), $FileTypeSet, $SetFlags, $HashAlgId, [Int64]$TargetFileTime)
        Write-Bytes $Out $bytes
        "{0}: {1} bytes" -f $Out, $bytes.Length
    }
    'apply' {
        $bytes = [MsDelta]::Apply((Read-Bytes $Source), (Read-Bytes $Delta))
        Write-Bytes $Out $bytes
        "{0}: {1} bytes" -f $Out, $bytes.Length
    }
    'info' {
        $i = [MsDelta]::Info((Read-Bytes $Delta))
        $hash = ($i.TargetHash.HashValue[0..([int]$i.TargetHash.HashSize - 1)] | ForEach-Object { $_.ToString('x2') }) -join ''
        if ($i.TargetHash.HashSize -eq 0) { $hash = '' }
        [ordered]@{
            FileTypeSet = '0x{0:x}' -f $i.FileTypeSet
            FileType = '0x{0:x}' -f $i.FileType
            Flags = '0x{0:x}' -f $i.Flags
            TargetSize = [UInt64]$i.TargetSize
            TargetFileTime = '0x{0:x}' -f $i.TargetFileTime
            TargetHashAlgId = '0x{0:x}' -f $i.TargetHashAlgId
            TargetHash = $hash
        } | ConvertTo-Json
    }
}
