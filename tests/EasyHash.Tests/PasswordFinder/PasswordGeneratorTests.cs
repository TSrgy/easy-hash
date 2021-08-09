using System;
using System.Linq;
using System.Threading;
using EasyHash.PasswordFinder;
using FluentAssertions;
using Xunit;

namespace EasyHash.Tests.PasswordFinder
{
    public class PasswordGeneratorTests
    {
        [Fact]
        public void WrongParameterTest()
        {
            Action createGenerator = () => new PasswordGenerator(new[] { '1', '1' }, CancellationToken.None);
            createGenerator.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void AlgorithmTest()
        {
            var availableSymbols = new[] { '1', '2', '3' };
            var passwords = new PasswordGenerator(availableSymbols, CancellationToken.None).Take(13);
            passwords.Should().BeEquivalentTo("1", "2", "3", "11", "12", "13", "21", "22", "23", "31", "32", "33", "111");
        }

        [Fact]
        public void CancelTest()
        {
            var cts = new CancellationTokenSource();
            var availableSymbols = new[] { '1', '2', '3' };
            var passwords = new PasswordGenerator(availableSymbols, cts.Token);
            passwords.Take(1).Should().ContainSingle();
            cts.Cancel();
            passwords.ToList().Should().BeEmpty();
        }
    }
}