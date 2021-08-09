using System;
using System.Linq;
using FluentAssertions;
using Xunit;

namespace EasyHash.Algorithms.Tests
{
    public class UtilTests
    {
        [Fact]
        public void ConvertToIntsTest()
        {
            int number1 = 17833753;
            int number2 = 1246907465;
            var bytes1 = BitConverter.GetBytes(number1);
            var bytes2 = BitConverter.GetBytes(number2);
            var bytes = bytes1.Concat(bytes2);
            Utils.ConvertToInts(bytes.ToArray(), bytes.Count()).Should().BeEquivalentTo(new[] { number1, number2 });
        }
    }
}