using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace EasyHash.PasswordFinder
{
    public abstract class AsyncPasswordChecker
    {
        protected readonly IEnumerable<string> _passwords;
        protected readonly Action<string> _callback;

        public AsyncPasswordChecker(IEnumerable<string> passwords, Action<string> callback)
        {
            _passwords = passwords;
            _callback = callback;
        }

        public abstract Task StartCheckingAllPasswordsAsync();
    }
}