using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EasyHash.PasswordFinder.RarPasswordChecker;
using FluentAssertions;
using ILGPU;
using ILGPU.Runtime;
using ILGPU.Runtime.CPU;
using ILGPU.Runtime.Cuda;
using Xunit;

namespace EasyHash.Tests.PasswordFinder
{
    public class RarPasswordCheckerOnGpuTests
    {
        [Fact]
        public async Task ReaderTest()
        {
            var passwords = new[] { "123", "test", "150" };
            var result = RarPasswordCheckerOnGpu.GetBulkPasswordChannel(passwords, out var task);
            await task;

            await foreach (var data in result.ReadAllAsync())
            {
                data.data.Should().BeEquivalentTo(passwords
                    .Select(p => Encoding.Unicode.GetBytes(p)).SelectMany(p => p));

                data.pointers[0].Should().Be(0);
                data.pointers[1].Should().Be(Encoding.Unicode.GetBytes(passwords[0]).Length);
                data.pointers[2].Should().Be(Encoding.Unicode.GetBytes(passwords[0]).Length +
                                             Encoding.Unicode.GetBytes(passwords[1]).Length);
            }
        }

        [Fact(Skip = "SHA1 with bug")]
        public async Task GpuDigestTest()
        {
            var password = Encoding.Unicode.GetBytes("1");
            var salt = new byte[]
            {
                65,
                208,
                217,
                77,
                120,
                166,
                33,
                109
            };

            var checkerForCpu = RarPasswordChecker.CalcDigest(password, salt);

            using var context = Context.CreateDefault();
            using var accelerator = context.CreateCudaAccelerator(0);
            var kernel = accelerator.LoadAutoGroupedStreamKernel<
                Index1D,
                ArrayView<byte>,
                ArrayView<byte>,
                ArrayView<int>,
                ArrayView<byte>
            >(TestKernel);

            using var digestBuffer = accelerator.Allocate1D<int>(RarPasswordChecker.sizeOfDigestInts);
            using var ivBuffer = accelerator.Allocate1D<byte>(RarPasswordChecker.sizeOfIV);


            kernel(1, accelerator.Allocate1D(password).View,
                accelerator.Allocate1D(salt).View,
                digestBuffer.View,
                ivBuffer.View
            );

            digestBuffer.GetAsArray1D()
                .Should().BeEquivalentTo(checkerForCpu.digest);
            ivBuffer.GetAsArray1D()
                .Should().BeEquivalentTo(checkerForCpu.iv);
        }

        public static void TestKernel(Index1D index, ArrayView<byte> buffer, ArrayView<byte> salt,
            ArrayView<int> digest,
            ArrayView<byte> iv)
        {
            var result = RarPasswordChecker.CalcDigestGpu(buffer, salt);
            for (int i = 0; i < result.digest.Length; i++)
            {
                digest[i] = result.digest[i];
            }

            for (int i = 0; i < result.iv.Length; i++)
            {
                iv[i] = result.iv[i];
            }
        }
    }
}