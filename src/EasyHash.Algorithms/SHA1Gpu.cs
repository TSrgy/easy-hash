using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using ILGPU;
using ILGPU.Runtime;
using Microsoft.VisualBasic.CompilerServices;

namespace EasyHash.Algorithms
{
    public struct SHA1Gpu
    {
        private ArrayView<byte> _buffer;
        private long _count;
        private ArrayView<uint> _expandedBuffer;
        private ArrayView<uint> _stateSHA1;

        // Methods
        public SHA1Gpu(byte hack)
        {
            _count = 0;
            _stateSHA1 = LocalMemory.Allocate<uint>(5);
            _buffer = LocalMemory.Allocate<byte>(0x40);
            _expandedBuffer = LocalMemory.Allocate<uint>(80);
            InitializeState();
        }

        private ArrayView<byte> _EndHash(bool finalize)
        {
            var stateSHA1 = LocalMemory.Allocate<uint>(5);
            for (int i = 0; i < 5; i++)
            {
                stateSHA1[i] = _stateSHA1[i];
            }

            var buffer = LocalMemory.Allocate<byte>(0x40);
            long count = _count;
            var block = LocalMemory.Allocate<byte>(20);
            if (!finalize)
            {
                InternalBlockCopy(_buffer, 0, buffer, 0, 0x40);
            }


            int num = 0x40 - ((int)(_count & 0x3fL));
            if (num <= 8)
            {
                num += 0x40;
            }


            var partIn = LocalMemory.Allocate<byte>(0x40 + 8);
            partIn[0] = 0x80;
            long num2 = _count * 8L;
            partIn[num - 8] = (byte)((num2 >> 56) & 0xffL);
            partIn[num - 7] = (byte)((num2 >> 48) & 0xffL);
            partIn[num - 6] = (byte)((num2 >> 40) & 0xffL);
            partIn[num - 5] = (byte)((num2 >> 32) & 0xffL);
            partIn[num - 4] = (byte)((num2 >> 24) & 0xffL);
            partIn[num - 3] = (byte)((num2 >> 16) & 0xffL);
            partIn[num - 2] = (byte)((num2 >> 8) & 0xffL);
            partIn[num - 1] = (byte)(num2 & 0xffL);


            _HashData(partIn.SubView(0, num), 0, num);
            DWORDToBigEndian(block, _stateSHA1, 5);
            if (!finalize)
            {
                _stateSHA1 = stateSHA1;
                _buffer = buffer;
                _count = count;
            }

            return block;
        }


        private void _HashData(ArrayView<byte> partIn, int ibStart, int cbSize)
        {
            int byteCount = cbSize;
            int srcOffsetBytes = ibStart;
            int dstOffsetBytes = (int)(_count & 0x3fL);
            _count += byteCount;
            if ((dstOffsetBytes > 0) && ((dstOffsetBytes + byteCount) >= 0x40))
            {
                InternalBlockCopy(partIn, srcOffsetBytes, _buffer, dstOffsetBytes,
                    0x40 - dstOffsetBytes);
                srcOffsetBytes += 0x40 - dstOffsetBytes;
                byteCount -= 0x40 - dstOffsetBytes;
                SHATransform(_expandedBuffer, _stateSHA1, _buffer);
                dstOffsetBytes = 0;
            }

            while (byteCount >= 0x40)
            {
                InternalBlockCopy(partIn, srcOffsetBytes, _buffer, 0, 0x40);
                srcOffsetBytes += 0x40;
                byteCount -= 0x40;
                SHATransform(_expandedBuffer, _stateSHA1, _buffer);
            }

            if (byteCount > 0)
            {
                InternalBlockCopy(partIn, srcOffsetBytes, _buffer, dstOffsetBytes, byteCount);
            }
        }

        public void AppendData(ArrayView<byte> data)
        {
            _HashData(data, 0, data.IntLength);
        }

        public ArrayView<byte> HashFinal()
        {
            return _EndHash(true);
        }

        public ArrayView<byte> GetCurrentHash()
        {
            return _EndHash(false);
        }

        public void Initialize()
        {
            InitializeState();
            for (int i = 0; i < _buffer.Length; i++)
            {
                _buffer[i] = default;
            }

            for (int i = 0; i < _expandedBuffer.Length; i++)
            {
                _expandedBuffer[i] = default;
            }
        }

        private void InitializeState()
        {
            _count = 0L;
            _stateSHA1[0] = 0x67452301;
            _stateSHA1[1] = 0xefcdab89;
            _stateSHA1[2] = 0x98badcfe;
            _stateSHA1[3] = 0x10325476;
            _stateSHA1[4] = 0xc3d2e1f0;
        }

        private static void SHAExpand(ArrayView<uint> x)
        {
            for (int i = 0x10; i < 80; i++)
            {
                uint num2 = ((x[i - 3] ^ x[i - 8]) ^ x[i - 14]) ^ x[i - 0x10];
                x[i] = (num2 << 1) | (num2 >> 0x1f);
            }
        }

        private static void SHATransform(ArrayView<uint> expandedBuffer, ArrayView<uint> state, ArrayView<byte> block)
        {
            uint num = state[0];
            uint num2 = state[1];
            uint num3 = state[2];
            uint num4 = state[3];
            uint num5 = state[4];
            DWORDFromBigEndian(expandedBuffer, 0x10, block);
            SHAExpand(expandedBuffer);
            int index = 0;
            while (index < 20)
            {
                num5 += ((((num << 5) | (num >> 0x1b)) + (num4 ^ (num2 & (num3 ^ num4)))) + expandedBuffer[index]) +
                        0x5a827999;
                num2 = (num2 << 30) | (num2 >> 2);
                num4 +=
                    ((((num5 << 5) | (num5 >> 0x1b)) + (num3 ^ (num & (num2 ^ num3)))) + expandedBuffer[index + 1]) +
                    0x5a827999;
                num = (num << 30) | (num >> 2);
                num3 +=
                    ((((num4 << 5) | (num4 >> 0x1b)) + (num2 ^ (num5 & (num ^ num2)))) + expandedBuffer[index + 2]) +
                    0x5a827999;
                num5 = (num5 << 30) | (num5 >> 2);
                num2 += ((((num3 << 5) | (num3 >> 0x1b)) + (num ^ (num4 & (num5 ^ num)))) + expandedBuffer[index + 3]) +
                        0x5a827999;
                num4 = (num4 << 30) | (num4 >> 2);
                num +=
                    ((((num2 << 5) | (num2 >> 0x1b)) + (num5 ^ (num3 & (num4 ^ num5)))) + expandedBuffer[index + 4]) +
                    0x5a827999;
                num3 = (num3 << 30) | (num3 >> 2);
                index += 5;
            }

            while (index < 40)
            {
                num5 += ((((num << 5) | (num >> 0x1b)) + ((num2 ^ num3) ^ num4)) + expandedBuffer[index]) + 0x6ed9eba1;
                num2 = (num2 << 30) | (num2 >> 2);
                num4 += ((((num5 << 5) | (num5 >> 0x1b)) + ((num ^ num2) ^ num3)) + expandedBuffer[index + 1]) +
                        0x6ed9eba1;
                num = (num << 30) | (num >> 2);
                num3 += ((((num4 << 5) | (num4 >> 0x1b)) + ((num5 ^ num) ^ num2)) + expandedBuffer[index + 2]) +
                        0x6ed9eba1;
                num5 = (num5 << 30) | (num5 >> 2);
                num2 += ((((num3 << 5) | (num3 >> 0x1b)) + ((num4 ^ num5) ^ num)) + expandedBuffer[index + 3]) +
                        0x6ed9eba1;
                num4 = (num4 << 30) | (num4 >> 2);
                num += ((((num2 << 5) | (num2 >> 0x1b)) + ((num3 ^ num4) ^ num5)) + expandedBuffer[index + 4]) +
                       0x6ed9eba1;
                num3 = (num3 << 30) | (num3 >> 2);
                index += 5;
            }

            while (index < 60)
            {
                num5 += ((((num << 5) | (num >> 0x1b)) + ((num2 & num3) | (num4 & (num2 | num3)))) +
                         expandedBuffer[index]) + 0x8f1bbcdc;
                num2 = (num2 << 30) | (num2 >> 2);
                num4 += ((((num5 << 5) | (num5 >> 0x1b)) + ((num & num2) | (num3 & (num | num2)))) +
                         expandedBuffer[index + 1]) + 0x8f1bbcdc;
                num = (num << 30) | (num >> 2);
                num3 += ((((num4 << 5) | (num4 >> 0x1b)) + ((num5 & num) | (num2 & (num5 | num)))) +
                         expandedBuffer[index + 2]) + 0x8f1bbcdc;
                num5 = (num5 << 30) | (num5 >> 2);
                num2 += ((((num3 << 5) | (num3 >> 0x1b)) + ((num4 & num5) | (num & (num4 | num5)))) +
                         expandedBuffer[index + 3]) + 0x8f1bbcdc;
                num4 = (num4 << 30) | (num4 >> 2);
                num += ((((num2 << 5) | (num2 >> 0x1b)) + ((num3 & num4) | (num5 & (num3 | num4)))) +
                        expandedBuffer[index + 4]) + 0x8f1bbcdc;
                num3 = (num3 << 30) | (num3 >> 2);
                index += 5;
            }

            while (index < 80)
            {
                num5 += ((((num << 5) | (num >> 0x1b)) + ((num2 ^ num3) ^ num4)) + expandedBuffer[index]) + 0xca62c1d6;
                num2 = (num2 << 30) | (num2 >> 2);
                num4 += ((((num5 << 5) | (num5 >> 0x1b)) + ((num ^ num2) ^ num3)) + expandedBuffer[index + 1]) +
                        0xca62c1d6;
                num = (num << 30) | (num >> 2);
                num3 += ((((num4 << 5) | (num4 >> 0x1b)) + ((num5 ^ num) ^ num2)) + expandedBuffer[index + 2]) +
                        0xca62c1d6;
                num5 = (num5 << 30) | (num5 >> 2);
                num2 += ((((num3 << 5) | (num3 >> 0x1b)) + ((num4 ^ num5) ^ num)) + expandedBuffer[index + 3]) +
                        0xca62c1d6;
                num4 = (num4 << 30) | (num4 >> 2);
                num += ((((num2 << 5) | (num2 >> 0x1b)) + ((num3 ^ num4) ^ num5)) + expandedBuffer[index + 4]) +
                       0xca62c1d6;
                num3 = (num3 << 30) | (num3 >> 2);
                index += 5;
            }

            state[0] += num;
            state[1] += num2;
            state[2] += num3;
            state[3] += num4;
            state[4] += num5;
        }

        public static void DWORDToBigEndian(ArrayView<byte> block, ArrayView<uint> x, int digits)
        {
            int i;
            int j;

            for (i = 0, j = 0; i < digits; i++, j += 4)
            {
                block[j] = (byte)((x[i] >> 24) & 0xff);
                block[j + 1] = (byte)((x[i] >> 16) & 0xff);
                block[j + 2] = (byte)((x[i] >> 8) & 0xff);
                block[j + 3] = (byte)(x[i] & 0xff);
            }
        }

        public static void DWORDFromBigEndian(ArrayView<uint> x, int digits, ArrayView<byte> block)
        {
            int i;
            int j;

            for (i = 0, j = 0; i < digits; i++, j += 4)
                x[i] = (uint)((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]);
        }

        public static void InternalBlockCopy(ArrayView<byte> src, int srcOffsetBytes,
            ArrayView<byte> dst, int dstOffsetBytes, int byteCount)
        {
            for (int i = 0; i < byteCount; i++)
            {
                dst[i + dstOffsetBytes] = src[i + srcOffsetBytes];
            }
        }
    }
}