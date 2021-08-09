using ILGPU;

namespace EasyHash.PasswordFinder.RarPasswordChecker
{
    public struct AesParams
    {
        public ArrayView<int> digest;
        public ArrayView<byte> iv;
    }
}