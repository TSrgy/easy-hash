using System.Runtime.CompilerServices;
using ILGPU;

namespace EasyHash.Algorithms
{
    public static class Utils
    {
        // [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int[] ConvertToInts(byte[] bytes, int length)
        {
            var ints = new int[length / sizeof(int)];
            for (var index = 0; index < length / sizeof(int); index++)
            {
                ints[index] = bytes[index * sizeof(int)]
                              | bytes[index * sizeof(int) + 1] << 8
                              | bytes[index * sizeof(int) + 2] << 16
                              | bytes[index * sizeof(int) + 3] << 24;
            }

            return ints;
        }

        public static ArrayView<int> ConvertToInts(ArrayView<byte> bytes, int length)
        {
            return bytes.Cast<int>();
        }
    }
}