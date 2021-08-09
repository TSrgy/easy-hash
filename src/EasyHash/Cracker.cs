using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EasyHash.PasswordFinder;
using EasyHash.PasswordFinder.RarPasswordChecker;

namespace EasyHash
{
    public class Cracker
    {
        private readonly string _path;
        private readonly Action<string> _log;

        public Cracker(string path, Action<string> log)
        {
            _path = path;
            _log = log;
        }

        public async Task<string> FindPassword(string availableSymbols)
        {
            var cts = new CancellationTokenSource();
            string foundPassword = string.Empty;
            try
            {
                var generator = new PasswordGenerator(availableSymbols.ToCharArray(), cts.Token);
                var checker = new RarPasswordCheckerOnCpu(_path, generator, (password) =>
                {
                    foundPassword = password;
                    cts.Cancel();
                });

                await checker.StartCheckingAllPasswordsAsync();
            }
            catch (OperationCanceledException e)
            {
            }

            return foundPassword;
        }
    }
}