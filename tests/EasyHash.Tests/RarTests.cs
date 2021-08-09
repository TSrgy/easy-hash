using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace EasyHash.Tests
{
    public class UnitTest1
    {
        [Fact]
        public async Task Test1()
        {
            var directory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            directory = Path.Join(directory, "rar files");
            var path = Path.Combine(directory, "123.rar");
            var cracker = new Cracker(path, (_) => { });
            var password = await cracker.FindPassword("123");
            password.Should().Be("123");
        }

        [Fact]
        public async Task Test2()
        {
            var directory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            directory = Path.Join(directory, "rar files");
            var path = Path.Combine(directory, "test.rar");
            var cracker = new Cracker(path, (_) => { });
            var password = await cracker.FindPassword("tes");
            password.Should().Be("test");
        }
    }
}