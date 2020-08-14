using System.Collections;
using System.Collections.Generic;

namespace Secure
{
    public enum TamperDetectionMode
    {
        CheckSum,
        CRC,
        Hash
    }

    public delegate void SecureValueDelegate(ISecureValue value);

    public class TamperDetector
    {
        private static TamperDetector inst;
        public static TamperDetector Instance
        {
            get
            {
                if (inst == null) inst = new TamperDetector();
                return inst;
            }
        }
        private TamperDetector() {}

        private Dictionary<ISecureValue, long> checkSumDic = new Dictionary<ISecureValue, long>();
        private Dictionary<ISecureValue, uint> crcDic = new Dictionary<ISecureValue, uint>();
        private Dictionary<ISecureValue, string> hashDic = new Dictionary<ISecureValue, string>();

        public bool Enable { get; set; } = true;

        private TamperDetectionMode mode = TamperDetectionMode.CheckSum;
        public TamperDetectionMode Mode
        {
            get
            {
                return mode;
            }
            set
            {
                mode = value;
                if (mode == TamperDetectionMode.CheckSum)
                {
                    foreach (var pair in checkSumDic)
                    {
                        checkSumDic[pair.Key] = pair.Key.Sum();
                    }
                }
                else if (mode == TamperDetectionMode.CRC)
                {
                    foreach (var pair in crcDic)
                    {
                        crcDic[pair.Key] = pair.Key.CRC();
                    }
                }
                else if (mode == TamperDetectionMode.Hash)
                {
                    foreach (var pair in hashDic)
                    {
                        hashDic[pair.Key] = pair.Key.Hash();
                    }
                }
            }
        } 

        public event SecureValueDelegate Detected = delegate(ISecureValue value){};

        internal void AddSecureValue(ISecureValue value)
        {
            checkSumDic[value] = (mode == TamperDetectionMode.CheckSum && Enable) ? value.Sum() : 0;
            crcDic[value] = (mode == TamperDetectionMode.CRC && Enable) ? value.CRC() : 0;
            hashDic[value] = (mode == TamperDetectionMode.Hash && Enable) ? value.Hash() : null;
        }

        public bool DetectCheck(ISecureValue value)
        {
            if (!Enable) return false;

            if (mode == TamperDetectionMode.CheckSum)
            {
                if(!checkSumDic.ContainsKey(value))
                {
                    checkSumDic[value] = value.Sum();
                    return false;
                }
                return checkSumDic[value] != value.Sum();
            }
            else if (mode == TamperDetectionMode.CRC)
            {
                if(!crcDic.ContainsKey(value))
                {
                    crcDic[value] = value.CRC();
                    return false;
                }
                return crcDic[value] != value.CRC();
            }
            else if (mode == TamperDetectionMode.Hash)
            {
                if(!hashDic.ContainsKey(value))
                {
                    hashDic[value] = value.Hash();
                    return false;
                }
                return hashDic[value] != value.Hash();
            }
            return false;
        }

        internal void CheckInternal(ISecureValue value)
        {
            if (DetectCheck(value))
            {
                Detected(value);
            }
        }

        internal void UpdateInternal(ISecureValue value)
        {
            if (!Enable) return;

            if (mode == TamperDetectionMode.CheckSum)
            {
                checkSumDic[value] = value.Sum();
            }
            else if (mode == TamperDetectionMode.CRC)
            {
                crcDic[value] = value.CRC();
            }
            else if (mode == TamperDetectionMode.Hash)
            {
                hashDic[value] = value.Hash();
            }
        }

        public bool DetectCheckAll()
        {
            if (!Enable) return false;

            if (mode == TamperDetectionMode.CheckSum)
            {
                foreach (var pair in checkSumDic)
                {
                    if (checkSumDic[pair.Key] != pair.Key.Sum()) return true;
                }
            }
            else if (mode == TamperDetectionMode.CRC)
            {
                foreach (var pair in crcDic)
                {
                    if (crcDic[pair.Key] != pair.Key.CRC()) return true;
                }
            }
            else if (mode == TamperDetectionMode.Hash)
            {
                foreach (var pair in hashDic)
                {
                    if (hashDic[pair.Key] != pair.Key.Hash()) return true;
                }
            }
            return false;
        }
    }
}