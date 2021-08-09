using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;

namespace EasyHash.PasswordFinder.RarPasswordChecker
{
    public class RarPasswordCheckerOnCpu : RarPasswordChecker
    {
        public RarPasswordCheckerOnCpu(string path, IEnumerable<string> passwords, Action<string> callback)
            : base(path, passwords, callback)
        {
        }

        protected override async Task StartLoop()
        {
            Parallel.ForEach(_passwords, async (password) =>
            {
                Debug.WriteLine(password);
                var buffer = Encoding.Unicode.GetBytes(password);
                var result = CalcDigest(buffer, _salt);

                if (password == "123")
                {
                    Console.WriteLine(string.Join(' ', result.digest));
                    Console.WriteLine(string.Join(' ', result.iv));
                }

                if (CheckPassword(_header, result.digest, result.iv))
                {
                    Debug.WriteLine("Found!");
                    _callback(password);
                }
            });
        }
    }
}