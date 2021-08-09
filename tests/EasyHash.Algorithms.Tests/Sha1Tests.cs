using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using ILGPU;
using ILGPU.Backends.PTX;
using ILGPU.IR;
using ILGPU.Runtime;
using ILGPU.Runtime.Cuda;
using Xunit;

namespace EasyHash.Algorithms.Tests
{
    public class Sha1Tests
    {
        [Fact]
        public void Sha1Test()
        {
            var data = Encoding.Unicode.GetBytes("testdata");
            var sha1 = new SHA1(1);
            sha1.Initialize();
            sha1.AppendData(data,0,data.Length);
            sha1.GetCurrentHash();
            sha1.AppendData(data,0,data.Length);
            var result = sha1.HashFinal();


            using var nativeSha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            nativeSha1.AppendData(data);
            nativeSha1.AppendData(data);
            var expectedResult = nativeSha1.GetCurrentHash();
            result.Should().BeEquivalentTo(expectedResult);
        }

        [Fact]
        public void Sha1OnGpuTest()
        {
            var data = Encoding.Unicode.GetBytes("testdata");

            using var nativeSha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            nativeSha1.AppendData(data);
            nativeSha1.AppendData(data);
            var expectedResult = nativeSha1.GetCurrentHash();


            using var context = Context
                .Create()
                .Cuda()
                .PTXBackend(PTXBackendMode.Enhanced)
                .Verify()
                .Profiling()
                .Math(MathMode.Default)
                .DebugSymbols(DebugSymbolsMode.KernelSourceAnnotations)
                .ToContext();
            using var accelerator = context.CreateCudaAccelerator(0);


            var kernel = accelerator.LoadAutoGroupedStreamKernel<
                Index1D,
                ArrayView<byte>,
                ArrayView<byte>
            >(TestKernel);

            var result = accelerator.Allocate1D<byte>(20);

            kernel(1, accelerator.Allocate1D(data).View, result.View);

            var array = result.GetAsArray1D();

            array.Should().BeEquivalentTo(expectedResult);
        }

        public static void TestKernel(Index1D index, ArrayView<byte> data, ArrayView<byte> output)
        {
            var sha = new SHA1Gpu(1);
            sha.AppendData(data);
            sha.AppendData(data);

            var result = sha.GetCurrentHash();
            for (int i = 0; i < result.Length; i++)
            {
                output[i] = result[i];
            }
        }
    }
}