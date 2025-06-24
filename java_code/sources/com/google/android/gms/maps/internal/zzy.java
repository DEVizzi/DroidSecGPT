package com.google.android.gms.maps.internal;

import android.content.Context;
import android.os.Build;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.maps.internal.zzc;
import com.google.android.gms.maps.model.RuntimeRemoteException;
/* loaded from: classes.dex */
public class zzy {
    private static Context zzaCM;
    private static zzc zzaCN;

    private static Context getRemoteContext(Context context) {
        if (zzaCM == null) {
            if (zzvE()) {
                zzaCM = context.getApplicationContext();
            } else {
                zzaCM = GooglePlayServicesUtil.getRemoteContext(context);
            }
        }
        return zzaCM;
    }

    private static <T> T zza(ClassLoader classLoader, String str) {
        try {
            return (T) zzc(((ClassLoader) com.google.android.gms.common.internal.zzu.zzu(classLoader)).loadClass(str));
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Unable to find dynamic class " + str);
        }
    }

    private static zzc zzaA(Context context) {
        if (zzvE()) {
            Log.i(zzy.class.getSimpleName(), "Making Creator statically");
            return (zzc) zzc(zzvF());
        }
        Log.i(zzy.class.getSimpleName(), "Making Creator dynamically");
        return zzc.zza.zzcg((IBinder) zza(getRemoteContext(context).getClassLoader(), "com.google.android.gms.maps.internal.CreatorImpl"));
    }

    public static zzc zzay(Context context) throws GooglePlayServicesNotAvailableException {
        com.google.android.gms.common.internal.zzu.zzu(context);
        if (zzaCN != null) {
            return zzaCN;
        }
        zzaz(context);
        zzaCN = zzaA(context);
        try {
            zzaCN.zzd(com.google.android.gms.dynamic.zze.zzw(getRemoteContext(context).getResources()), GooglePlayServicesUtil.GOOGLE_PLAY_SERVICES_VERSION_CODE);
            return zzaCN;
        } catch (RemoteException e) {
            throw new RuntimeRemoteException(e);
        }
    }

    private static void zzaz(Context context) throws GooglePlayServicesNotAvailableException {
        int isGooglePlayServicesAvailable = GooglePlayServicesUtil.isGooglePlayServicesAvailable(context);
        switch (isGooglePlayServicesAvailable) {
            case 0:
                return;
            default:
                throw new GooglePlayServicesNotAvailableException(isGooglePlayServicesAvailable);
        }
    }

    private static <T> T zzc(Class<?> cls) {
        try {
            return (T) cls.newInstance();
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Unable to call the default constructor of " + cls.getName());
        } catch (InstantiationException e2) {
            throw new IllegalStateException("Unable to instantiate the dynamic class " + cls.getName());
        }
    }

    public static boolean zzvE() {
        return false;
    }

    private static Class<?> zzvF() {
        try {
            return Build.VERSION.SDK_INT < 15 ? Class.forName("com.google.android.gms.maps.internal.CreatorImplGmm6") : Class.forName("com.google.android.gms.maps.internal.CreatorImpl");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
