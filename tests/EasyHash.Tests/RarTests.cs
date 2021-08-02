using System;
using System.IO;
using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace EasyHash.Tests
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
            var directory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            directory = Path.Join(directory, "rar files");
            var path = Path.Combine(directory, "123.rar");
            var cracker = new Cracker(path, (_) => { });
            var password = cracker.FindPassword();
            password.Should().Be("123");
        }

        [Fact]
        public void Test2()
        {
            var directory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            directory = Path.Join(directory, "rar files");
            var path = Path.Combine(directory, "test.rar");
            var cracker = new Cracker(path, (_) => { });
            var password = cracker.FindPassword();
            password.Should().Be("test");
        }
    }
}