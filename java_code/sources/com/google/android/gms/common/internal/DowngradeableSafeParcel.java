package com.google.android.gms.common.internal;

import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public abstract class DowngradeableSafeParcel implements SafeParcelable {
    private static final Object zzZZ = new Object();
    private static ClassLoader zzaaa = null;
    private static Integer zzaab = null;
    private boolean zzaac = false;

    private static boolean zza(Class<?> cls) {
        try {
            return SafeParcelable.NULL.equals(cls.getField("NULL").get(null));
        } catch (IllegalAccessException e) {
            return false;
        } catch (NoSuchFieldException e2) {
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static boolean zzca(String str) {
        ClassLoader zznD = zznD();
        if (zznD == null) {
            return true;
        }
        try {
            return zza(zznD.loadClass(str));
        } catch (Exception e) {
            return false;
        }
    }

    protected static ClassLoader zznD() {
        ClassLoader classLoader;
        synchronized (zzZZ) {
            classLoader = zzaaa;
        }
        return classLoader;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static Integer zznE() {
        Integer num;
        synchronized (zzZZ) {
            num = zzaab;
        }
        return num;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean zznF() {
        return this.zzaac;
    }
}
