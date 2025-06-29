package android.support.v4.app;

import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
/* loaded from: classes.dex */
public class BundleCompat {
    public static IBinder getBinder(Bundle bundle, String key) {
        return Build.VERSION.SDK_INT >= 18 ? BundleCompatJellybeanMR2.getBinder(bundle, key) : BundleCompatDonut.getBinder(bundle, key);
    }

    public static void putBinder(Bundle bundle, String key, IBinder binder) {
        if (Build.VERSION.SDK_INT >= 18) {
            BundleCompatJellybeanMR2.putBinder(bundle, key, binder);
        } else {
            BundleCompatDonut.putBinder(bundle, key, binder);
        }
    }
}
