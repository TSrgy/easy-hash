using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Mime;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;
using ILGPU;
using ILGPU.Runtime;
using ILGPU.Runtime.CPU;
using ILGPU.Runtime.Cuda;
using ILGPU.Runtime.OpenCL;

namespace EasyHash.PasswordFinder.RarPasswordChecker
{
    public class RarPasswordCheckerOnGpu : RarPasswordChecker
    {
        public RarPasswordCheckerOnGpu(string path, IEnumerable<string> passwords, Action<string> callback)
            : base(path, passwords, callback)
        {
        }

        protected override async Task StartLoop()
        {
            using var context = Context.CreateDefaultAutoAssertions();
            using var accelerator = context.CreateCudaAccelerator(0);
            var kernel = accelerator.LoadAutoGroupedStreamKernel<
                Index1D,
                ArrayView<byte>,
                ArrayView<byte>,
                ArrayView<int>,
                ArrayView<int>,
                ArrayView<byte>
            >(CheckPasswordKernel);
            Console.WriteLine("kernel ready");
            var passwordBatches = GetBulkPasswordChannel(_passwords, out var producer);
            var tasks = new Task[1];
            for (int i = 0; i < 1; i++)
            {
                tasks[0] = Task.Factory.StartNew(async () =>
                {
                    while (await passwordBatches.WaitToReadAsync())
                    {
                        if (passwordBatches.TryRead(out
                            var channelData))
                        {
                            var (dataList, pointers) = channelData;
                            var data = dataList.ToArray();
                            using var dataBuffer = accelerator.Allocate1D(data);
                            using var pointersBuffer = accelerator.Allocate1D(pointers);
                            using var digestBuffer = accelerator.Allocate1D<int>(pointers.Length * sizeOfDigestInts);
                            using var ivBuffer = accelerator.Allocate1D<byte>(pointers.Length * sizeOfIV);
                            kernel(pointers.Length,
                                accelerator.Allocate1D(_salt).View,
                                dataBuffer.View,
                                pointersBuffer.View,
                                digestBuffer.View,
                                ivBuffer.View
                            );

                            accelerator.Synchronize();


                            var digestInts = digestBuffer.GetAsArray1D();
                            var iv = ivBuffer.GetAsArray1D();


                            for (int j = 0; j < 20; j++)
                            {
                                Console.WriteLine(digestInts[j]);
                            }
                            Console.WriteLine("Step...");

                            for (int j = 0; j < pointers.Length; j++)
                            {
                                var digestArray = digestInts.AsSpan(j * sizeOfDigestInts, sizeOfDigestInts).ToArray();
                                var ivArray = iv.AsSpan(j * sizeOfIV, sizeOfIV).ToArray();
                                var foundFlag = CheckPassword(_header,
                                    digestArray, ivArray
                                );

                                if (digestArray.SequenceEqual(new[]
                                        { -1624351423, -1962329307, -113069700, 185728843, -1396225366 }) &&
                                    ivArray.SequenceEqual(new byte[]
                                        { 164, 140, 81, 185, 5, 103, 67, 120, 75, 150, 143, 158, 197, 179, 189, 10 })
                                )
                                {
                                    Console.WriteLine("YEAH");
                                }

                                if (foundFlag)
                                {
                                    Console.WriteLine("Found!...");
                                    var pointer = pointers[j];
                                    var nextPasswordPointer = j + 1 > pointers.Length
                                        ? data.Length
                                        : Math.Max(data.Length, pointers[j + 1]);
                                    var password =
                                        Encoding.Unicode.GetString(
                                            data.AsSpan(pointer, nextPasswordPointer - data[pointer]));
                                    _callback(password);
                                }
                            }
                        }
                    }
                });
            }

            producer.Wait();

            Task.WaitAll(tasks);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="index"></param>
        /// <param name="salt"></param>
        /// <param name="data"></param>
        /// <param name="pointers"></param>
        /// <param name="digestInt">Output</param>
        /// <param name="iv">Output</param>
        private static void CheckPasswordKernel(Index1D index, ArrayView<byte> salt,
            ArrayView<byte> data, ArrayView<int> pointers,
            ArrayView<int> digestInt, ArrayView<byte> iv)
        {
            var nextPasswordPointer = index + 1 >= pointers.Length
                ? data.Length
                : ILGPU.Algorithms.XMath.Min(data.Length, pointers[index + 1]);
            var pointer = pointers[index];
            var buffer = data.SubView(pointer, nextPasswordPointer - pointer);


            var result = CalcDigestGpu(buffer, salt);

            var ivPoint = index * sizeOfIV;
            for (int i = 0; i < sizeOfIV; i++)
            {
                iv[ivPoint + i] = result.iv[i];
            }

            var digestIntPoint = index * sizeOfDigestInts;
            for (int i = 0; i < sizeOfDigestInts; i++)
            {
                digestInt[digestIntPoint + i] = result.digest[i];
            }
        }

        public static ChannelReader<(List<byte> data, int[] pointers)> GetBulkPasswordChannel(IEnumerable<string> passwords, out Task producer)
        {
            var channel = Channel.CreateBounded<(List<byte> data, int[] pointers)>(new BoundedChannelOptions(1)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleWriter = true,
                SingleReader = false,
                AllowSynchronousContinuations = true
            });
            var writer = channel.Writer;
            producer = Task.Factory.StartNew(async () =>
            {
                List<byte> data;
                int[] pointers;
                int batchSize = 100;
                int lastElementSize = 2;

                data = new List<byte>(lastElementSize * batchSize);
                pointers = new int[batchSize];
                var i = 0;

                foreach (var password in passwords
                    .Select(p => Encoding.Unicode.GetBytes(p)))
                {
                    lastElementSize = password.Length;
                    pointers[i] = data.Count;
                    data.AddRange(password);
                    i++;

                    if(i < batchSize)
                        continue;;

                    var written = false;
                    do
                    {
                        if (await writer.WaitToWriteAsync())
                        {
                            written = writer.TryWrite((data, pointers));
                        }
                    } while (!written);
                    i = 0;
                    data = new List<byte>(lastElementSize * batchSize);
                    pointers = new int[batchSize];
                }

                if (data.Any())
                {
                    var written = false;
                    do
                    {
                        if (await writer.WaitToWriteAsync())
                        {
                            written = writer.TryWrite((data, pointers));
                        }
                    } while (!written);
                }
                writer.Complete();
            });
            return channel.Reader;
        }
    }
}