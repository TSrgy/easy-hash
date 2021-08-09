using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace EasyHash.PasswordFinder
{
    public class PasswordGenerator : IEnumerable<string>
    {
        private readonly char[] _availableSymbols;
        private readonly CancellationToken _cancellationToken;
        private readonly uint? _maxLength;

        public PasswordGenerator(char[] availableSymbols, CancellationToken cancellationToken, uint? maxLength = null)
        {
            if (availableSymbols.Length == 0)
            {
                throw new ArgumentException("Available symbols should be", nameof(availableSymbols));
            }

            if (availableSymbols.Distinct().Count() != availableSymbols.Length)
            {
                throw new ArgumentException("Available symbols should be uniq", nameof(availableSymbols));
            }

            _availableSymbols = availableSymbols;
            _cancellationToken = cancellationToken;
            _maxLength = maxLength;
        }

        public IEnumerator<string> GetEnumerator()
        {
            return new Enumerator(_availableSymbols, _cancellationToken, _maxLength);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private class Enumerator : IEnumerator<string>
        {
            private readonly char[] _availableSymbols;
            private readonly CancellationToken _cancellationToken;
            private readonly uint? _maxLength;
            private int[]? _passwordMask;
            private char[]? _currentPassword;

            public Enumerator(char[] availableSymbols, CancellationToken cancellationToken, uint? maxLength)
            {
                _availableSymbols = availableSymbols;
                _cancellationToken = cancellationToken;
                _maxLength = maxLength;
                Reset();
            }

            public bool MoveNext()
            {
                if (_cancellationToken.IsCancellationRequested)
                {
                    return false;
                }
                if (_currentPassword == null || _passwordMask == null)
                {
                    _currentPassword = new[] { _availableSymbols[0] };
                    _passwordMask = new[] { 0 };
                }
                else
                {
                    var needAddNewSymbolToPassword = true;
                    for (int i = _currentPassword.Length - 1; i >= 0; i--)
                    {
                        _passwordMask[i]++;
                        if (_passwordMask[i] >= _availableSymbols.Length)
                        {
                            _passwordMask[i] = 0;
                            _currentPassword[i] = _availableSymbols[_passwordMask[i]];
                        }
                        else
                        {
                            _currentPassword[i] = _availableSymbols[_passwordMask[i]];
                            needAddNewSymbolToPassword = false;
                            break;
                        }
                    }

                    if (needAddNewSymbolToPassword)
                    {
                        _currentPassword = new char[_currentPassword.Length + 1];
                        _passwordMask = new int[_passwordMask.Length + 1];
                        for (int i = 0; i < _currentPassword.Length; i++)
                        {
                            _currentPassword[i] = _availableSymbols[0];
                        }
                    }
                }

                if (_maxLength.HasValue && _currentPassword.Length == _maxLength &&
                    _currentPassword.All(c => c == _availableSymbols.Last()))
                {
                    return false;
                }

                return true;
            }

            public void Reset()
            {
                _currentPassword = null;
                _passwordMask = null;
            }

            public string Current
            {
                get
                {
                    if (_currentPassword == null)
                    {
                        throw new InvalidOperationException();
                    }

                    Console.WriteLine(_currentPassword);

                    return new string(_currentPassword);
                }
            }

            object IEnumerator.Current => Current;

            public void Dispose()
            {
            }
        }
    }
}