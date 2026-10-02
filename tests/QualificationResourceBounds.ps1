[CmdletBinding()]
param([switch] $Calibrate, [string] $OutputPath = '')
Set-StrictMode -Version Latest

function Initialize-QualificationNativeMemory {
    if ('WinPCInfo.Qualification.NativeMemory' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace WinPCInfo.Qualification {
    public sealed class MemorySnapshot {
        public long PrivateBytes, PeakPrivateBytes, WorkingSetBytes, PeakWorkingSetBytes;
        public int StructureBytes, PointerBytes;
    }
    public sealed class Calibration {
        public MemorySnapshot Before, During, After;
        public long AllocationBytes;
        public bool Released;
    }
    public static class NativeMemory {
        [StructLayout(LayoutKind.Sequential)]
        private struct Counters {
            public uint cb, faults;
            public UIntPtr peakWorking, working, peakPagedPool, pagedPool;
            public UIntPtr peakNonpagedPool, nonpagedPool, commit, peakCommit, privateCommit;
        }
        [DllImport("psapi.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessMemoryInfo(IntPtr process, ref Counters counters, uint bytes);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protection);
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);
        public static MemorySnapshot Read(IntPtr process) {
            if (process == IntPtr.Zero || process == new IntPtr(-1))
                throw new ArgumentException("An exact held process handle is required.");
            int size=Marshal.SizeOf<Counters>();
            if (size != (IntPtr.Size == 8 ? 80 : 44))
                throw new InvalidOperationException("Unexpected native counter layout.");
            var counters=new Counters { cb=(uint)size };
            if (!GetProcessMemoryInfo(process, ref counters, (uint)size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (counters.cb != size) throw new InvalidOperationException("Native counter size changed.");
            return new MemorySnapshot {
                PrivateBytes=checked((long)counters.privateCommit.ToUInt64()),
                PeakPrivateBytes=checked((long)counters.peakCommit.ToUInt64()),
                WorkingSetBytes=checked((long)counters.working.ToUInt64()),
                PeakWorkingSetBytes=checked((long)counters.peakWorking.ToUInt64()),
                StructureBytes=size, PointerBytes=IntPtr.Size
            };
        }
        public static Calibration Probe(IntPtr process) {
            const long bytes=256L*1024*1024;
            var result=new Calibration { Before=Read(process), AllocationBytes=bytes };
            IntPtr allocation=VirtualAlloc(IntPtr.Zero,new UIntPtr((ulong)bytes),0x3000,0x04);
            if(allocation == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                for(long offset=0;offset<bytes;offset+=4096)
                    Marshal.WriteByte(new IntPtr(allocation.ToInt64()+offset),0x5a);
                result.During=Read(process);
            } finally {
                result.Released=VirtualFree(allocation,UIntPtr.Zero,0x8000);
                if(!result.Released) throw new InvalidOperationException("Owned calibration allocation release is unverified.");
            }
            result.After=Read(process);
            return result;
        }
    }
}
'@
}

function Get-QualificationMemorySnapshot {
    Initialize-QualificationNativeMemory
    $process=[Diagnostics.Process]::GetCurrentProcess()
    try {
        $null=$process.Handle
        $result=[WinPCInfo.Qualification.NativeMemory]::Read($process.Handle)
        if($result.PrivateBytes -le 0 -or $result.PeakPrivateBytes -lt $result.PrivateBytes -or
            $result.PeakWorkingSetBytes -lt $result.WorkingSetBytes) { throw 'Native memory counter invariants failed.' }
        $result
    } finally { $process.Dispose() }
}

function Invoke-QualificationMemoryCalibration {
    Initialize-QualificationNativeMemory
    [GC]::Collect(2,[GCCollectionMode]::Aggressive,$true,$true)
    $process=[Diagnostics.Process]::GetCurrentProcess()
    try {
        $null=$process.Handle
        $result=[WinPCInfo.Qualification.NativeMemory]::Probe($process.Handle)
        $process.Refresh()
        $dotNetPeakPrivate=$process.PeakPagedMemorySize64
        $dotNetPeakWorking=$process.PeakWorkingSet64
        $bracket=[WinPCInfo.Qualification.NativeMemory]::Read($process.Handle)
        $accepted=$result.Released -and
            $result.During.PrivateBytes -ge ($result.Before.PrivateBytes+$result.AllocationBytes) -and
            $result.After.PrivateBytes -le ($result.During.PrivateBytes-$result.AllocationBytes+1MB) -and
            $result.After.PeakPrivateBytes -ge $result.During.PrivateBytes -and
            $result.After.PeakWorkingSetBytes -ge $result.During.WorkingSetBytes -and
            $dotNetPeakPrivate -ge $result.After.PeakPrivateBytes -and $dotNetPeakPrivate -le $bracket.PeakPrivateBytes -and
            $dotNetPeakWorking -ge $result.After.PeakWorkingSetBytes -and $dotNetPeakWorking -le $bracket.PeakWorkingSetBytes
        [ordered]@{
            kind='OwnedNativeLifetimeMemoryCalibration';accepted=$accepted
            calibratedAtUtc=[datetime]::UtcNow.ToString('o')
            moduleSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
            powerShellVersion=$PSVersionTable.PSVersion.ToString();dotNetVersion=[Environment]::Version.ToString()
            windowsVersion=[Environment]::OSVersion.Version.ToString();pointerBytes=[IntPtr]::Size
            runtimeSha256=(Get-FileHash -LiteralPath (Join-Path $PSHOME 'pwsh.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
            allocationBytes=$result.AllocationBytes;before=$result.Before;during=$result.During;after=$result.After;bracket=$bracket
            allocationReleased=$result.Released;dotNetPeakPrivateBytes=$dotNetPeakPrivate;dotNetPeakWorkingSetBytes=$dotNetPeakWorking
            observation='Native allocation committed and released between before/after observations; lifetime peaks retain it.'
        }
    } finally {$process.Dispose()}
}

function Test-QualificationNativeMemorySnapshot {
    param([AllowNull()] $Snapshot)
    try {
        foreach($name in @('PrivateBytes','PeakPrivateBytes','WorkingSetBytes','PeakWorkingSetBytes','StructureBytes','PointerBytes')){
            $value=$Snapshot.$name
            if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0){return $false}
        }
        $expectedBytes=if([IntPtr]::Size-eq8){80}else{44}
        return ($Snapshot.PointerBytes-eq[IntPtr]::Size -and $Snapshot.StructureBytes-eq$expectedBytes -and
            $Snapshot.PrivateBytes-gt0 -and $Snapshot.WorkingSetBytes-gt0 -and
            $Snapshot.PeakPrivateBytes-ge$Snapshot.PrivateBytes -and
            $Snapshot.PeakWorkingSetBytes-ge$Snapshot.WorkingSetBytes)
    } catch {return $false}
}

function Test-QualificationMemoryCalibration {
    param([Parameter(Mandatory)] [string] $Path)
    if(-not [IO.File]::Exists($Path)) {return $false}
    try {
        $record=[IO.File]::ReadAllText($Path)|ConvertFrom-Json
        if($record.kind-cne'OwnedNativeLifetimeMemoryCalibration'){return $false}
        foreach($name in @('allocationBytes','dotNetPeakPrivateBytes','dotNetPeakWorkingSetBytes','pointerBytes')){
            $value=$record.$name
            if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0){return $false}
        }
        $previous=$null
        foreach($name in @('before','during','after','bracket')){
            $snapshot=$record.$name
            if(-not(Test-QualificationNativeMemorySnapshot -Snapshot $snapshot)){return $false}
            if($null-ne$previous -and
                ($snapshot.PeakPrivateBytes-lt$previous.PeakPrivateBytes -or
                 $snapshot.PeakWorkingSetBytes-lt$previous.PeakWorkingSetBytes)){return $false}
            $previous=$snapshot
        }
        $module=Join-Path $PSScriptRoot 'QualificationResourceBounds.ps1'
        $age=[datetime]::UtcNow-([datetime]$record.calibratedAtUtc).ToUniversalTime()
        return ($record.accepted -is [bool] -and $record.accepted -eq $true -and
            $record.allocationReleased -is [bool] -and $record.allocationReleased -eq $true -and
            $record.allocationBytes -eq 268435456 -and
            $record.during.PrivateBytes -ge ($record.before.PrivateBytes+$record.allocationBytes) -and
            $record.after.PrivateBytes -le ($record.during.PrivateBytes-$record.allocationBytes+1MB) -and
            $record.after.PeakPrivateBytes -ge $record.during.PrivateBytes -and
            $record.after.PeakWorkingSetBytes -ge $record.during.WorkingSetBytes -and
            $record.dotNetPeakPrivateBytes -ge $record.after.PeakPrivateBytes -and
            $record.dotNetPeakPrivateBytes -le $record.bracket.PeakPrivateBytes -and
            $record.dotNetPeakWorkingSetBytes -ge $record.after.PeakWorkingSetBytes -and
            $record.dotNetPeakWorkingSetBytes -le $record.bracket.PeakWorkingSetBytes -and
            $age.TotalHours -ge 0 -and $age.TotalHours -lt 24 -and
            $record.moduleSha256 -eq (Get-FileHash -LiteralPath $module -Algorithm SHA256).Hash.ToLowerInvariant() -and
            $record.powerShellVersion -eq $PSVersionTable.PSVersion.ToString() -and
            $record.dotNetVersion -eq [Environment]::Version.ToString() -and
            $record.windowsVersion -eq [Environment]::OSVersion.Version.ToString() -and $record.pointerBytes -eq [IntPtr]::Size -and
            $record.runtimeSha256 -eq (Get-FileHash -LiteralPath (Join-Path $PSHOME 'pwsh.exe') -Algorithm SHA256).Hash.ToLowerInvariant())
    } catch {return $false}
}

if($Calibrate) {
    if(-not $OutputPath){throw 'Calibration requires a retained output path.'}
    $record=Invoke-QualificationMemoryCalibration
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($record|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    if(-not $record.accepted){throw 'Owned lifetime memory calibration failed.'}
    Write-Output 'PASS: native lifetime private/working-set peaks retain a released allocation; .NET counters agree within bracketed native observations.'
}
