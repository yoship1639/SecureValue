using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using Secure;

public class Demo : MonoBehaviour
{
    void Start()
    {
        // 改ざん検出方法
        TamperDetector.Instance.Mode = TamperDetectionMode.CheckSum;

        // 改ざん検出時
        TamperDetector.Instance.Detected += value =>
        {
            Debug.Log("メモリ改ざんが検出されました!");
        };

        var v = new SecureValue<int>(1);
        Debug.Log(v);
        v.Value = 100;
        Debug.Log(v);

        var v2 = new SecureFloat(1.1f);
        Debug.Log(v2);

        var v3 = new SecureDouble(2.2);
        Debug.Log(v3);

        var v4 = new SecureDateTime(DateTime.UtcNow);
        Debug.Log(v4);

        var v5 = new SecureString("Hello world");
        Debug.Log(v5);

        var v6 = new SecureDecimal(3.3m);
        Debug.Log(v6);

        var v7 = new SecureBool(false);
        Debug.Log(v7);

        var v8 = new SecureLong(4);
        Debug.Log(v8);

        var v9 = new SecureShort(5);
        Debug.Log(v9);

        var v10 = new SecureByte(6);
        Debug.Log(v10);

        // 無理やりメモリ上の値を改ざん (valueをpublicにして確認可能)
        // 変数値にアクセスした時に改ざんイベントが発火される
        // v.value = 9999;
        // Debug.Log(v);

        // SecureValue全ての検証をする
        Debug.Log(TamperDetector.Instance.DetectCheckAll() ? "改ざんが検知されました！" : "改ざんは検知されませんでした。");

        // 個別に検証も可能
        Debug.Log(v.Invalid ? "改ざんが検知されました！" : "改ざんは検知されませんでした。");
    }
}
