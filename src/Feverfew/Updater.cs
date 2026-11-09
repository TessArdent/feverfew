using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Feverfew
{
    public sealed class UpdateInfo
    {
        public Version Current;
        public Version Latest;
        public string PageUrl;
        public string DownloadUrl;
        public string Sha256;
        public bool IsNewer { get { return Latest > Current; } }
        public bool CanDownload { get { return DownloadUrl != null && Sha256 != null; } }
    }

    /// <summary>Checks the project's GitHub releases. Only runs when the user asks.</summary>
    public static class Updater
    {
        public const string Repository = "TessArdent/feverfew";
        private const string AssetName = "setup.exe";
        private static readonly string LatestApi = "https://api.github.com/repos/" + Repository + "/releases/latest";
        private static readonly string DownloadPrefix = "https://github.com/" + Repository + "/releases/download/";

        public static Version CurrentVersion()
        {
            return Normalize(Assembly.GetExecutingAssembly().GetName().Version);
        }

        private static Version Normalize(Version v) { return new Version(v.Major, v.Minor, Math.Max(v.Build, 0)); }

        private static WebClient Client()
        {
            var client = new WebClient { Encoding = Encoding.UTF8 };
            client.Headers[HttpRequestHeader.UserAgent] = "Feverfew/" + CurrentVersion();
            return client;
        }

        public static UpdateInfo Check(Version current)
        {
            string body;
            using (var client = Client())
            {
                client.Headers[HttpRequestHeader.Accept] = "application/vnd.github+json";
                body = client.DownloadString(LatestApi);
            }

            var release = (Dictionary<string, object>)new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(body);
            var info = new UpdateInfo
            {
                Current = Normalize(current),
                Latest = Normalize(new Version(((string)release["tag_name"]).TrimStart('v', 'V'))),
                PageUrl = (string)release["html_url"]
            };

            var assets = ((IEnumerable)release["assets"]).Cast<Dictionary<string, object>>();
            var setup = assets.FirstOrDefault(a => (string)a["name"] == AssetName);
            if (setup != null)
            {
                var url = (string)setup["browser_download_url"];
                object digest;
                if (url.StartsWith(DownloadPrefix, StringComparison.Ordinal) && setup.TryGetValue("digest", out digest) && digest is string && ((string)digest).StartsWith("sha256:", StringComparison.Ordinal))
                {
                    info.DownloadUrl = url;
                    info.Sha256 = ((string)digest).Substring("sha256:".Length);
                }
            }
            return info;
        }

        /// <summary>Downloads the installer to a new private temp folder and rejects it unless its hash matches.</summary>
        public static string Download(UpdateInfo info)
        {
            var folder = Path.Combine(Path.GetTempPath(), "Feverfew-update-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, AssetName);
            using (var client = Client()) client.DownloadFile(info.DownloadUrl, path);

            string actual;
            using (var sha = SHA256.Create())
            using (var file = File.OpenRead(path))
                actual = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "");

            if (!string.Equals(actual, info.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                Directory.Delete(folder, true);
                throw new InvalidDataException("The downloaded installer failed its integrity check and was deleted.");
            }
            return path;
        }

        /// <summary>True when this copy is the per-user install, so running setup as this user replaces it.</summary>
        public static bool CanInstallInPlace()
        {
            var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Feverfew") + "\\";
            return Assembly.GetExecutingAssembly().Location.StartsWith(expected, StringComparison.OrdinalIgnoreCase);
        }
    }
}
