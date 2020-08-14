using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Secure
{
    public class SecureInt : SecureValue<int>
    {
        public SecureInt() : base() {}
        public SecureInt(int value) : base(value) {}
    }

    public class SecureFloat : SecureValue<float>
    {
        public SecureFloat() : base() {}
        public SecureFloat(float value) : base(value) {}
    }

    public class SecureDouble : SecureValue<double>
    {
        public SecureDouble() : base() {}
        public SecureDouble(double value) : base(value) {}
    }

    public class SecureBool : SecureValue<bool>
    {
        private byte binary;
        public SecureBool() : base() {}
        public SecureBool(bool value) : base(value) {}

        public override bool Value
        {
            get
            {
                return Xor(binary, seed) > 0;
            }
            set
            {
                TamperDetector.Instance.CheckInternal(this);
                this.binary = Xor(value ? (byte)1 : (byte)0, seed);
                TamperDetector.Instance.UpdateInternal(this);
            }
        }

        private byte Xor(byte v, byte[] seed)
        {
            return (byte)(v ^ seed[0]);
        }

#if UNITY_EDITOR
        public override string ToString()
        {
            return $"[{typeof(bool).Name}] value: {Value}, mem: {binary}";
        }
#endif
    }

    public class SecureShort : SecureValue<short>
    {
        public SecureShort() : base() {}
        public SecureShort(short value) : base(value) {}
    }

    public class SecureByte : SecureValue<byte>
    {
        public SecureByte() : base() {}
        public SecureByte(byte value) : base(value) {}
    }

    public class SecureLong : SecureValue<long>
    {
        public SecureLong() : base() {}
        public SecureLong(long value) : base(value) {}
    }

    public class SecureDecimal : SecureValue<decimal>
    {
        public SecureDecimal() : base() {}
        public SecureDecimal(decimal value) : base(value) {}
    }

    public class SecureString : SecureValue<string>
    {
        public SecureString() : base() {}
        public SecureString(string value) : base(value) {}

        protected override string Xor(string v, byte[] seed)
        {
            var c = v.ToCharArray();
            for (var i = 0; i < c.Length; i++)
            {
                c[i] ^= (char)seed[i % 4];
            }
            return new string(c);
        }

        public override long Sum()
        {
            if (value != null)
            {
                var buf = Encoding.ASCII.GetBytes(value);

                long sum = 0;
                var len = buf.Length;
                for (var i = 0; i < len; i++) sum += buf[i];
            }
            return BitConverter.ToInt32(seed, 0);
        }

        public override uint CRC()
        {
            if (value != null)
            {
                var buf = Encoding.ASCII.GetBytes(value);

                int len = buf.Length;
                var res = new byte[len + 4];
                Array.Copy(buf, 0, res, 0, len);
                Array.Copy(seed, 0, res, len, 4);

                return CRC32.Instance.Calc(res);
            }
            return CRC32.Instance.Calc(seed);
        }

        public override string Hash()
        {
            if (value != null)
            {
                var buf = Encoding.ASCII.GetBytes(value);

                int len = buf.Length;
                var res = new byte[len + 4];
                Array.Copy(buf, 0, res, 0, len);
                Array.Copy(seed, 0, res, len, 4);

                var hash = sha256.ComputeHash(res);
                var sb = new StringBuilder();
                len = hash.Length;
                for (int i = 0; i < len; i++)
                {
                    sb.AppendFormat("{0:X2}", hash[i]);
                }

                return sb.ToString();
            }
            else
            {
                var hash = sha256.ComputeHash(seed);
                var sb = new StringBuilder();
                var len = hash.Length;
                for (int i = 0; i < len; i++)
                {
                    sb.AppendFormat("{0:X2}", hash[i]);
                }

                return sb.ToString();
            }
        }
    }

    public class SecureDateTime : SecureValue<DateTime>
    {
        private long binary;
        public SecureDateTime() : base() {}
        public SecureDateTime(DateTime value) : base(value) {}

        public override DateTime Value
        {
            get
            {
                TamperDetector.Instance.CheckInternal(this);
                return DateTime.FromBinary(Xor(binary, seed));
            }
            set
            {
                TamperDetector.Instance.CheckInternal(this);
                var b = value.ToBinary();
                this.binary = Xor(b, seed);
                TamperDetector.Instance.UpdateInternal(this);
            }
        }

        private long Xor(long v, byte[] seed)
        {
            if (ptr == IntPtr.Zero)
            {
                ptr = Marshal.AllocHGlobal(buffer.Length);
            }

            int size = Marshal.SizeOf(v);
            Marshal.StructureToPtr(v, ptr, false);
            Marshal.Copy(ptr, buffer, 0, size);

            for (var i = 0; i < size; i++)
            {
                buffer[i] ^= seed[i % 4];
            }

            Marshal.Copy(buffer, 0, ptr, size);
            return (long)Marshal.PtrToStructure(ptr, typeof(long));
        }

        public override long Sum()
        {
            return Sum(binary, seed);
        }

        public override uint CRC()
        {
            return CRC(binary, seed);
        }

        public override string Hash()
        {
            return Hash(binary, seed);
        }

#if UNITY_EDITOR
        public override string ToString()
        {
            return $"[{typeof(DateTime).Name}] value: {Value}, mem: {binary}";
        }
#endif
    }

    public interface ISecureValue
    {
        long Sum();
        uint CRC();
        string Hash();
    }

    public class SecureValue<T> : ISecureValue
    {
        protected static readonly System.Random rand = new System.Random();
        protected static readonly SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
        protected static readonly byte[] buffer = new byte[1024];
        protected static IntPtr ptr;

        protected T value = default;
        protected readonly byte[] seed = BitConverter.GetBytes(rand.Next());

        public SecureValue() : this(default){}
        public SecureValue(T value)
        {
            Value = value;
            TamperDetector.Instance.AddSecureValue(this);
        }

        public bool Invalid
        {
            get
            {
                return TamperDetector.Instance.DetectCheck(this);
            }
        }

        public virtual T Value
        {
            get
            {
                TamperDetector.Instance.CheckInternal(this);
                return Xor(value, seed);
            }
            set
            {
                TamperDetector.Instance.CheckInternal(this);
                this.value = Xor(value, seed);
                TamperDetector.Instance.UpdateInternal(this);
            }
        }

        protected virtual T Xor(T v, byte[] seed)
        {
            if (ptr == IntPtr.Zero)
            {
                ptr = Marshal.AllocHGlobal(buffer.Length);
            }

            int size = Marshal.SizeOf(v);
            Marshal.StructureToPtr(v, ptr, false);
            Marshal.Copy(ptr, buffer, 0, size);

            for (var i = 0; i < size; i++)
            {
                buffer[i] ^= seed[i % 4];
            }

            Marshal.Copy(buffer, 0, ptr, size);
            return (T)Marshal.PtrToStructure(ptr, typeof(T));
        }

#if UNITY_EDITOR
        public override string ToString()
        {
            return $"[{typeof(T).Name}] value: {Value}, mem: {value}";
        }
#endif

        protected long Sum<T1>(T1 value, byte[] seed)
        {
            if (ptr == IntPtr.Zero)
            {
                ptr = Marshal.AllocHGlobal(buffer.Length);
            }

            int size = Marshal.SizeOf(value);
            Marshal.StructureToPtr(value, ptr, false);
            Marshal.Copy(ptr, buffer, 0, size);

            long sum = 0;
            if (size == 1)
            {
                sum += buffer[0];
            }
            else if (size == 2)
            {
                sum += BitConverter.ToInt16(buffer, 0);
            }
            else if (size == 4)
            {
                sum += BitConverter.ToInt32(buffer, 0);
            }
            else
            {
                var len = size >> 3;
                for (var i = 0; i < len; i++)
                {
                    sum += BitConverter.ToInt64(buffer, i * 8);
                }
            }

            sum += BitConverter.ToInt32(seed, 0);

            return sum;
        }

        public virtual long Sum()
        {
            return Sum(value, seed);
        }

        protected uint CRC<T1>(T1 value, byte[] seed)
        {
            if (ptr == IntPtr.Zero)
            {
                ptr = Marshal.AllocHGlobal(buffer.Length);
            }

            int size = Marshal.SizeOf(value);
            var buf = new byte[size + 4];
            Marshal.StructureToPtr(value, ptr, false);
            Marshal.Copy(ptr, buf, 0, size);
            Array.Copy(seed, 0, buf, size, 4);

            return CRC32.Instance.Calc(buf);
        }

        public virtual uint CRC()
        {
            return CRC(value, seed);
        }

        protected string Hash<T1>(T1 value, byte[] seed)
        {
            if (ptr == IntPtr.Zero)
            {
                ptr = Marshal.AllocHGlobal(buffer.Length);
            }

            int size = Marshal.SizeOf(value);
            var buf = new byte[size + 4];
            Marshal.StructureToPtr(value, ptr, false);
            Marshal.Copy(ptr, buf, 0, size);
            Array.Copy(seed, 0, buf, size, 4);

            var hash = sha256.ComputeHash(buf);
            var sb = new StringBuilder();
            var len = hash.Length;
            for (int i = 0; i < len; i++)
            {
                sb.AppendFormat("{0:X2}", hash[i]);
            }

            return sb.ToString();
        }

        public virtual string Hash()
        {
            return Hash(value, seed);
        }

        protected class CRC32
        {
            private static CRC32 inst;
            public static CRC32 Instance
            {
                get
                {
                    if (inst == null) inst = new CRC32();
                    return inst;
                }
            }
            private uint[] crcTable;

            private CRC32()
            {
                crcTable = new uint[256];
                for (uint i = 0; i < 256; i++)
                {
                    var x = i;
                    for (var j = 0; j < 8; j++)
                    {
                        x = (uint)((x & 1) == 0 ? x >> 1 : -306674912 ^ x >> 1);
                    }
                    crcTable[i] = x;
                }
            }

            public uint Calc(byte[] buf)
            {
                uint num = uint.MaxValue;
                for (var i = 0; i < buf.Length; i++)
                {
                    num = crcTable[(num ^ buf[i]) & 255] ^ num >> 8;
                }

                return (uint)(num ^ -1);
            }
        }
    }
}