using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Memory_Seeker
{
    public partial class Form1 : Form
    {
        Kernel kernel = new Kernel();
        Dictionary<string, int> memoryList = new Dictionary<string, int>();

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (memoryList.Count > 0)
            {
                listView1.Items.Clear();
                memoryList = kernel.SearchMemoryByInt(textBox2.Text, int.Parse(textBox1.Text), 2147418111, memoryList);
                foreach (KeyValuePair<string, int> memory in memoryList)
                    listView1.Items.Add(memory.Key + ": " + memory.Value);
            }
            else
            {
                memoryList = kernel.SearchMemoryByInt(textBox2.Text, int.Parse(textBox1.Text), 2147418111);
                foreach (KeyValuePair<string, int> memory in memoryList)
                    listView1.Items.Add(memory.Key + ": " + memory.Value);
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            memoryList.Clear();
            listView1.Items.Clear();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (textBox3.Text.Substring(0, 2) == "0x")
                kernel.WriteMemory(textBox2.Text, int.Parse(textBox3.Text.Substring(2), System.Globalization.NumberStyles.HexNumber), int.Parse(textBox4.Text));
            else
                kernel.WriteMemory(textBox2.Text, int.Parse(textBox3.Text, System.Globalization.NumberStyles.HexNumber), int.Parse(textBox4.Text));
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {
                bool addCharacter = true;
                string address = "";

                for (int x = 0; x < listView1.SelectedItems[0].Text.Length; x++)
                {
                    if (addCharacter == true)
                    {
                        if (listView1.SelectedItems[0].Text[x] != ':')
                            address += listView1.SelectedItems[0].Text[x];
                        else
                            addCharacter = false;
                    }
                }

                textBox3.Text = address;
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            Thread thread = new Thread(new ThreadStart(ScrambleThread));
            thread.Start();
        }

        private void ScrambleThread()
        {
            Dictionary<string, int> addressList = kernel.SearchAllMemory(textBox2.Text, 2147418111);

            int scrambledCount = 0;
            foreach (KeyValuePair<string, int> pair in addressList)
            {
                kernel.WriteMemory(textBox2.Text, int.Parse(pair.Key.Substring(2), System.Globalization.NumberStyles.HexNumber), pair.Value + 1);

                scrambledCount += 1;
                Console.WriteLine(scrambledCount);

                Thread.Sleep(2);
            }
        }
    }

    class Kernel
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern Int32 CloseHandle(IntPtr hProcess);

        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_VM_READ = 0x0010;
        const int PROCESS_ALL_ACCESS = 0x001F0FFF;

        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        public void WriteMemory(string processName, int address, int value)
        {
            var process = OpenProcess(PROCESS_ALL_ACCESS, false, Process.GetProcessesByName(processName)[0].Id);
            var byteValue = new byte[] { (byte)value };

            int written = 0;
            WriteProcessMemory(process, new IntPtr(address), byteValue, (UInt32)byteValue.LongLength, out written);

            CloseHandle(process);
        }

        public Dictionary<string, int> SearchMemoryByInt(string processName, int value, int maxAddress)
        {
            Dictionary<string, int> memoryList = new Dictionary<string, int>();

            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            IntPtr proc_min_address = sys_info.minimumApplicationAddress;
            IntPtr proc_max_address = (IntPtr)(maxAddress);

            long proc_min_address_l = (long)proc_min_address;
            long proc_max_address_l = (long)proc_max_address;

            Process process;
            if (processName.EndsWith(".exe")) process = Process.GetProcessesByName(processName.Substring(0, processName.Length - 4))[0];
            else process = Process.GetProcessesByName(processName)[0];

            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);

            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            int bytesRead = 0;

            while (proc_min_address_l < proc_max_address_l)
            {
                VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[mem_basic_info.RegionSize];

                    ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                    for (int i = 0; i < mem_basic_info.RegionSize; i++)
                    {
                        if ((buffer[i]) == value)
                            memoryList.Add("0x" + (mem_basic_info.BaseAddress + i).ToString("X"), buffer[i]);
                    }
                }

                proc_min_address_l += mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }

            return memoryList;
        }

        public Dictionary<string, int> SearchMemoryByInt(string processName, int value, int maxAddress, Dictionary<string, int> memoryList)
        {
            Dictionary<string, int> newMemoryList = new Dictionary<string, int>();

            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            IntPtr proc_min_address = sys_info.minimumApplicationAddress;
            IntPtr proc_max_address = (IntPtr)(maxAddress);

            long proc_min_address_l = (long)proc_min_address;
            long proc_max_address_l = (long)proc_max_address;

            Process process;
            if (processName.EndsWith(".exe")) process = Process.GetProcessesByName(processName.Substring(0, processName.Length - 4))[0];
            else process = Process.GetProcessesByName(processName)[0];

            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);

            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            int bytesRead = 0;

            while (proc_min_address_l < proc_max_address_l)
            {
                VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[mem_basic_info.RegionSize];

                    ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                    for (int i = 0; i < mem_basic_info.RegionSize; i++)
                    {
                        if ((buffer[i]) == value)
                            if (memoryList.ContainsKey("0x" + (mem_basic_info.BaseAddress + i).ToString("X")))
                                newMemoryList.Add("0x" + (mem_basic_info.BaseAddress + i).ToString("X"), buffer[i]);
                    }
                }

                proc_min_address_l += mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }

            return newMemoryList;
        }

        public Dictionary<string, int> SearchAllMemory(string processName, int maxAddress)
        {
            Dictionary<string, int> memoryList = new Dictionary<string, int>();

            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            IntPtr proc_min_address = sys_info.minimumApplicationAddress;
            IntPtr proc_max_address = (IntPtr)(maxAddress);

            long proc_min_address_l = (long)proc_min_address;
            long proc_max_address_l = (long)proc_max_address;

            Process process;
            if (processName.EndsWith(".exe")) process = Process.GetProcessesByName(processName.Substring(0, processName.Length - 4))[0];
            else process = Process.GetProcessesByName(processName)[0];

            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);

            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            int bytesRead = 0;

            while (proc_min_address_l < proc_max_address_l)
            {
                VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[mem_basic_info.RegionSize];

                    ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                    for (int i = 0; i < mem_basic_info.RegionSize; i++)
                    {
                        if ((buffer[i]) != 0)
                            memoryList.Add("0x" + (mem_basic_info.BaseAddress + i).ToString("X"), buffer[i]);
                    }
                }

                proc_min_address_l += mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }

            return memoryList;
        }
    }
}
