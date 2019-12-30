using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows.Forms;

namespace MovieBrowser2
{
    class VLCReader
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
                            IntPtr hProcess,
                            uint lpBaseAddress,
                            [Out] byte[] lpBuffer,
                            int dwSize,
                            out uint lpNumberOfBytesRead);

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
                public static extern IntPtr OpenProcess(
             ProcessAccessFlags processAccess,
             bool bInheritHandle,
             int processId
        );
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
                                  IntPtr hProcess,
                                  IntPtr lpBaseAddress,
                                  byte[] lpBuffer,
                                  Int32 nSize,
                                  out uint lpNumberOfBytesWritten);


        Process p;

        bool hooked;

        IntPtr hProcess;

        uint progressAddress,
            fileNameAddress;

        public VLCReader()
        {

        }

        public bool FindPattern(byte[] buffer, string pattern, string mask, out uint result)
        {
            bool success;


            result = 0;
            success = false;

            for (uint i = 0; i < buffer.Length; i++)
            {
                for (uint k = 0; k < pattern.Length; k++)
                {
                    if (buffer[i + k] == (byte)pattern[(int)k] || mask[(int)k] == '?')
                    {
                        if (k == pattern.Length - 1)
                        {
                            result = i;

                            i = (uint)buffer.Length;
                            success = true;
                            break;
                        }
                    }
                    else
                        break;
                }
            }

            return success;
        }


        private bool FindPatternInProcess(IntPtr hProcess, uint startAddress, uint endAddress, string pattern, string mask, out uint result)
        {
            bool success = false;

            uint targetAddress = 0;


            result = 0;

            for (uint i = (uint)startAddress; i < (uint)endAddress;)
            {
                byte[] buffer = new byte[1024 * 1024];

                uint bytesRead = 0;

                ReadProcessMemory(hProcess, i, buffer, buffer.Length, out bytesRead);

                if (bytesRead > 0)
                {
                    if (FindPattern(buffer, pattern, mask, out targetAddress) == true)
                    {
                        success = true;
                        targetAddress += i;

                        result = targetAddress;
                        break;
                    }
                }

                // offset by the buffer size minus the pattern so it never misses it
                uint delta = (uint)buffer.Length - (uint)pattern.Length;

                if (i + delta < i)
                    break;

                i += delta;
            }

            return success;
        }


        private void HookProgress()
        {
            uint targetAddress = 0;

            string pattern = "\x8B\x4B\x08\x89\xD8\x89\x54\x24\x4C\x89\xF2\x89\x4C\x24\x48";//"\x8B\x43\x2C\x85\xC0\x74\x2E\x81\xFE\x01\x01\x00\x00\x74\x4F\x7E\x45\x81\xFE\x00\x02\x00\x00";

            string mask = new string('x', pattern.Length);

            foreach (ProcessModule a in p.Modules)
            {
                if (a.FileName.ToLower().IndexOf("libvlccore.dll") != -1)
                {
                    FindPatternInProcess(hProcess, (uint)a.BaseAddress, (uint)((uint)a.BaseAddress + a.ModuleMemorySize), "\x89\x54\x24\x00\x89\xf2\x89\x4c\x24\x00\xe8", "xxx?xxxxx?x", out targetAddress);

                    break;
                }
            }

            if (targetAddress != 0)
            {
                targetAddress -= 5;

                byte[] buffer = new byte[5];

                uint bytesRead = 0;

                ReadProcessMemory(hProcess, targetAddress, buffer, 5, out bytesRead);

                if (bytesRead == 5)
                {
                    // If its already been hooked, get the existing pointer
                    if (buffer[0] == 0xE8)
                    {
                        uint offset = BitConverter.ToUInt32(buffer, 1) + 5;

                        targetAddress += offset;
                        targetAddress += 100;

                        progressAddress = targetAddress;
                    }
                    else
                    {
                        // Otherwise hook it
                        IntPtr caveAddress = VirtualAllocEx(hProcess, IntPtr.Zero, 1024, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);

                        uint delta = ((uint)caveAddress - (uint)targetAddress) - 5;

                        uint bytesWritten = 0;

                        if (caveAddress != IntPtr.Zero)
                        {
                            List<byte> payload = new List<byte>();

                            // the cave payload
                            payload.AddRange(new byte[] { 0x8B, 0x4B, 0x08, 0x8B, 0xC3, 0x60, 0x9C, 0x8B, 0x03, 0x8B, 0x00, 0x3D, 0x70, 0x6F, 0x73, 0x69, 0x75, 0x12, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x25, 0x00, 0xFF, 0xFF, 0xFF, 0x83, 0xC0, 0x64, 0x8B, 0x5B, 0x08, 0x89, 0x18, 0x9D, 0x61, 0xC3, 0x8B, 0x04, 0x24, 0xC3 });

                            if (WriteProcessMemory(hProcess, caveAddress, payload.ToArray(), payload.Count, out bytesWritten) == true)
                            {
                                payload.Clear();

                                // Generate the call detour
                                payload.Add(0xe8);
                                payload.AddRange(BitConverter.GetBytes(delta));

                                // Write the detour
                                if (WriteProcessMemory(hProcess, (IntPtr)targetAddress, payload.ToArray(), payload.Count, out bytesWritten) == true)
                                {
                                    progressAddress = (uint)caveAddress + 0x64;
                                }
                            }
                        }
                    }
                }               
            }
        }

        private void HookFileName()
        {
            uint targetAddress = 0;

            string pattern = "\x8B\x43\x2C\x85\xC0\x74\x2E\x81\xFE\x01\x01\x00\x00\x74\x4F\x7E\x45\x81\xFE\x00\x02\x00\x00";//"\x8B\x4B\x08\x89\xD8\x89\x54\x24\x4C\x89\xF2\x89\x4C\x24\x48";

            string mask = new string('x', pattern.Length);

            foreach (ProcessModule a in p.Modules)
            {
                if (a.FileName.ToLower().IndexOf("libvlccore.dll") != -1)
                {
                    FindPatternInProcess(hProcess, (uint)a.BaseAddress, (uint)((uint)a.BaseAddress + a.ModuleMemorySize), "\x74\x00\x81\xfe\x00\x00\x00\x00\x74\x00\x7e", "x?xx????x?x", out targetAddress);

                    break;
                }
            }

            if (targetAddress != 0)
            {
                targetAddress -= 5;

                byte[] buffer = new byte[5];

                uint bytesRead = 0;

                ReadProcessMemory(hProcess, targetAddress, buffer, 5, out bytesRead);

                if (bytesRead == 5)
                {
                    // If its already been hooked, get the existing pointer
                    if (buffer[0] == 0xE8)
                    {
                        uint offset = BitConverter.ToUInt32(buffer, 1) + 5;

                        targetAddress += offset;
                        targetAddress += 100;

                        fileNameAddress = targetAddress;

                    }
                    else
                    {
                        IntPtr caveAddress = VirtualAllocEx(hProcess, IntPtr.Zero, 1024, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);

                        uint delta = ((uint)caveAddress - (uint)targetAddress) - 5;

                        uint bytesWritten = 0;

                        if (caveAddress != IntPtr.Zero)
                        {
                            List<byte> payload = new List<byte>();

                            // the cave payload
                            payload.AddRange(new byte[] { 0x8B, 0x43, 0x2C, 0x85, 0xC0, 0x60, 0x9C, 0xE8, 0x1B, 0x00, 0x00, 0x00, 0x8B, 0xD0, 0x81, 0xE2, 0x00, 0xFF, 0xFF, 0xFF, 0x83, 0xC2, 0x64, 0x8B, 0x4B, 0x28, 0x8A, 0x01, 0x88, 0x02, 0x42, 0x41, 0x3C, 0x00, 0x75, 0xF6, 0x9D, 0x61, 0xC3, 0x8B, 0x04, 0x24, 0xC3 });

                            if (WriteProcessMemory(hProcess, caveAddress, payload.ToArray(), payload.Count, out bytesWritten) == true)
                            {
                                payload.Clear();

                                // Generate the call detour
                                payload.Add(0xe8);
                                payload.AddRange(BitConverter.GetBytes(delta));

                                // Write the detour
                                if (WriteProcessMemory(hProcess, (IntPtr)targetAddress, payload.ToArray(), payload.Count, out bytesWritten) == true)
                                {
                                    fileNameAddress = (uint)caveAddress + 0x64;
                                }
                            }
                        }
                    }
                }
            }
        }

        public bool Read(ref string fileName, ref int progress)
        {
            bool result;


            result = false;

            try
            {
                // Get the newest vlc process
                if (p == null || p.HasExited == true)
                {
                    progressAddress = 0;
                    fileNameAddress = 0;

                    hooked = false;
                    p = Process.GetProcessesByName("vlc").FirstOrDefault();

                    if (p != null)
                    {
                        hProcess = OpenProcess(ProcessAccessFlags.All, false, p.Id);

                        if (hProcess != IntPtr.Zero)
                        {
                            HookProgress();

                            HookFileName();
                        }
                    }
                }

                if (p != null)
                {
                    if (progressAddress != 0 && fileNameAddress != 0)
                    {
                        byte[] buffer = new byte[1024];

                        uint bytesRead = 0;

                        ReadProcessMemory(hProcess, progressAddress, buffer, 4, out bytesRead);

                        if (bytesRead == 4) 
                        {
                            progress = (int)(BitConverter.ToSingle(buffer, 0) * 100);

                            bytesRead = 0;
                            buffer[0] = 0;

                            ReadProcessMemory(hProcess, fileNameAddress, buffer, buffer.Length, out bytesRead);

                            if (bytesRead > 0)
                            {
                                fileName = ASCIIEncoding.ASCII.GetString(buffer).Trim((char)0);
                                result = true;
                            }
                        }
                    }
                }
            }
            catch (Exception x)
            {
                MessageBox.Show(x.ToString());
            }

            return result;
        }
    }
}
