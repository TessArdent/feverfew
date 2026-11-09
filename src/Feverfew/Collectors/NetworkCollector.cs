using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Feverfew.Collectors
{
    public static class NetworkCollector
    {
        public static void Collect(Report r)
        {
            var s = r.NewSection("Network");
            string gateway = null;
            bool hasLink = false;

            Guard.Try(s, "Adapters", () =>
            {
                var t = s.Table("Active network adapters", "Adapter", "Type", "Link speed", "Address", "Gateway", "DNS servers", "DHCP", "MAC");
                foreach (var n in NetworkInterface.GetAllNetworkInterfaces().Where(i => i.OperationalStatus == OperationalStatus.Up && i.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                {
                    var ip = n.GetIPProperties();
                    var v4 = ip.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).Select(a => a.Address).ToList();
                    var gw = ip.GatewayAddresses.Select(g => g.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any)).ToList();
                    var dns = ip.DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
                    foreach (var a in ip.UnicastAddresses.Select(u => u.Address).Concat(gw).Concat(dns).Where(IsPublic)) r.Private(a.ToString());
                    bool dhcp = false;
                    try { dhcp = ip.GetIPv4Properties().IsDhcpEnabled; } catch (NetworkInformationException) { }
                    var mac = string.Join("-", n.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));

                    t.Rows.Add(new[]
                    {
                        n.Description, n.NetworkInterfaceType.ToString(), n.Speed > 0 ? Fmt.Num(n.Speed / 1000000.0, "0") + " Mbps" : "-",
                        string.Join(", ", v4), string.Join(", ", gw), string.Join(", ", dns), dhcp ? "Yes" : "No", r.Private(mac)
                    });

                    if (gw.Count > 0)
                    {
                        hasLink = true;
                        if (gateway == null) gateway = gw[0].ToString();
                    }
                    if (v4.Any(a => a.ToString().StartsWith("169.254.")) && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel && gw.Count == 0)
                        r.Find(Severity.Warning, "No address from the router: " + n.Description, "The adapter fell back to a self-assigned 169.254 address, so DHCP failed.", "Restart the router, then check the cable or Wi-Fi connection.");
                }
            });

            if (r.NetworkTests)
            {
                Guard.Try(s, "Connection test", () =>
                {
                    var t = s.Table("Connection test", "Test", "Result");
                    var gw = gateway == null ? null : Ping(gateway);
                    var net = Ping("1.1.1.1");
                    string dnsResult = null;
                    try
                    {
                        var task = Dns.GetHostAddressesAsync("www.microsoft.com");
                        dnsResult = task.Wait(TimeSpan.FromSeconds(8)) && task.Result.Length > 0 ? "OK" : null;
                    }
                    catch (AggregateException) { }

                    t.Rows.Add(new[] { "Router", gateway == null ? "No gateway" : gw ?? "No reply" });
                    t.Rows.Add(new[] { "Internet (1.1.1.1)", net ?? "No reply" });
                    t.Rows.Add(new[] { "Name lookup (www.microsoft.com)", dnsResult ?? "Failed" });

                    if (!hasLink)
                        r.Find(Severity.Warning, "No network connection", "No adapter has a default gateway.", "Check the cable or Wi-Fi connection.");
                    else if (net == null && dnsResult == null)
                        r.Find(Severity.Warning, "No internet access", "Neither the ping nor the name lookup worked.", "Restart the router and check for VPN or firewall software.");
                    else if (net != null && dnsResult == null)
                        r.Find(Severity.Warning, "Name lookup (DNS) is failing", "The internet can be reached, but names don't resolve.", "Try different DNS servers, or run: ipconfig /flushdns");
                });
            }
            else s.Note("Connection tests were turned off for this scan.");

            Guard.Try(s, "Proxy", () =>
            {
                var enabled = Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable", 0);
                s.Add("Proxy turned on", enabled != null && Convert.ToInt32(enabled) == 1 ? "Yes" : "No");
                if (enabled != null && Convert.ToInt32(enabled) == 1)
                    r.Find(Severity.Info, "A web proxy is turned on", "Internet traffic goes through a proxy.", "If the owner didn't set this up, check for malware or leftover VPN software.");
            });

            Guard.Try(s, "Hosts file", () =>
            {
                var path = Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");
                var entries = File.ReadAllLines(path).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("#")).ToList();
                s.Add("Custom hosts file entries", entries.Count);
                if (entries.Count > 20)
                    r.Find(Severity.Info, "Large hosts file", entries.Count + " custom entries.", "This might be an ad blocker, but malware also uses this file to redirect sites.");
            });
        }

        private static bool IsPublic(IPAddress a)
        {
            if (IPAddress.IsLoopback(a)) return false;
            if (a.AddressFamily == AddressFamily.InterNetworkV6)
                return !(a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || (a.GetAddressBytes()[0] & 0xFE) == 0xFC);
            var b = a.GetAddressBytes();
            bool isPrivate = b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
            return !isPrivate;
        }

        private static string Ping(string host)
        {
            try
            {
                using (var p = new Ping())
                {
                    var reply = p.Send(host, 2500);
                    return reply.Status == IPStatus.Success ? "OK, " + reply.RoundtripTime + " ms" : null;
                }
            }
            catch (PingException) { return null; }
        }
    }
}
