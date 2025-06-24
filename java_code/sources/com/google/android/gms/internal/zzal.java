package com.google.android.gms.internal;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import com.google.android.gms.internal.zzar;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
/* loaded from: classes.dex */
public abstract class zzal extends zzak {
    private static Method zzmV;
    private static Method zzmW;
    private static Method zzmX;
    private static Method zzmY;
    private static Method zzmZ;
    private static Method zzna;
    private static Method zznb;
    private static Method zznc;
    private static Method zznd;
    private static Method zzne;
    private static Method zznf;
    private static Method zzng;
    private static Method zznh;
    private static String zzni;
    private static String zznj;
    private static String zznk;
    private static zzar zznl;
    private static long startTime = 0;
    static boolean zznm = false;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zza extends Exception {
        public zza() {
        }

        public zza(Throwable th) {
            super(th);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzal(Context context, zzap zzapVar, zzaq zzaqVar) {
        super(context, zzapVar, zzaqVar);
    }

    static String zzU() throws zza {
        if (zzni == null) {
            throw new zza();
        }
        return zzni;
    }

    static Long zzV() throws zza {
        if (zzmV == null) {
            throw new zza();
        }
        try {
            return (Long) zzmV.invoke(null, new Object[0]);
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static String zzW() throws zza {
        if (zzmX == null) {
            throw new zza();
        }
        try {
            return (String) zzmX.invoke(null, new Object[0]);
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static Long zzX() throws zza {
        if (zzmW == null) {
            throw new zza();
        }
        try {
            return (Long) zzmW.invoke(null, new Object[0]);
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static String zza(Context context, zzap zzapVar) throws zza {
        if (zznj != null) {
            return zznj;
        }
        if (zzmY == null) {
            throw new zza();
        }
        try {
            ByteBuffer byteBuffer = (ByteBuffer) zzmY.invoke(null, context);
            if (byteBuffer == null) {
                throw new zza();
            }
            zznj = zzapVar.zza(byteBuffer.array(), true);
            return zznj;
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static ArrayList<Long> zza(MotionEvent motionEvent, DisplayMetrics displayMetrics) throws zza {
        if (zzmZ == null || motionEvent == null) {
            throw new zza();
        }
        try {
            return (ArrayList) zzmZ.invoke(null, motionEvent, displayMetrics);
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static synchronized void zza(String str, Context context, zzap zzapVar) {
        synchronized (zzal.class) {
            if (!zznm) {
                try {
                    zznl = new zzar(zzapVar, null);
                    zzni = str;
                    zzl(context);
                    startTime = zzV().longValue();
                    zznm = true;
                } catch (zza e) {
                } catch (UnsupportedOperationException e2) {
                }
            }
        }
    }

    static String zzb(Context context, zzap zzapVar) throws zza {
        if (zznk != null) {
            return zznk;
        }
        if (zznb == null) {
            throw new zza();
        }
        try {
            ByteBuffer byteBuffer = (ByteBuffer) zznb.invoke(null, context);
            if (byteBuffer == null) {
                throw new zza();
            }
            zznk = zzapVar.zza(byteBuffer.array(), true);
            return zznk;
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    private static String zzb(byte[] bArr, String str) throws zza {
        try {
            return new String(zznl.zzc(bArr, str), "UTF-8");
        } catch (zzar.zza e) {
            throw new zza(e);
        } catch (UnsupportedEncodingException e2) {
            throw new zza(e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zze(Context context) throws zza {
        if (zzna == null) {
            throw new zza();
        }
        try {
            String str = (String) zzna.invoke(null, context);
            if (str == null) {
                throw new zza();
            }
            return str;
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static String zzf(Context context) throws zza {
        if (zzne == null) {
            throw new zza();
        }
        try {
            return (String) zzne.invoke(null, context);
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static Long zzg(Context context) throws zza {
        if (zznf == null) {
            throw new zza();
        }
        try {
            return (Long) zznf.invoke(null, context);
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static ArrayList<Long> zzh(Context context) throws zza {
        if (zznc == null) {
            throw new zza();
        }
        try {
            ArrayList<Long> arrayList = (ArrayList) zznc.invoke(null, context);
            if (arrayList == null || arrayList.size() != 2) {
                throw new zza();
            }
            return arrayList;
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static int[] zzi(Context context) throws zza {
        if (zznd == null) {
            throw new zza();
        }
        try {
            return (int[]) zznd.invoke(null, context);
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static int zzj(Context context) throws zza {
        if (zzng == null) {
            throw new zza();
        }
        try {
            return ((Integer) zzng.invoke(null, context)).intValue();
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    static int zzk(Context context) throws zza {
        if (zznh == null) {
            throw new zza();
        }
        try {
            return ((Integer) zznh.invoke(null, context)).intValue();
        } catch (IllegalAccessException e) {
            throw new zza(e);
        } catch (InvocationTargetException e2) {
            throw new zza(e2);
        }
    }

    private static void zzl(Context context) throws zza {
        try {
            byte[] zzl = zznl.zzl(zzat.getKey());
            byte[] zzc = zznl.zzc(zzl, zzat.zzad());
            File cacheDir = context.getCacheDir();
            if (cacheDir == null && (cacheDir = context.getDir("dex", 0)) == null) {
                throw new zza();
            }
            File file = cacheDir;
            File createTempFile = File.createTempFile("ads", ".jar", file);
            FileOutputStream fileOutputStream = new FileOutputStream(createTempFile);
            fileOutputStream.write(zzc, 0, zzc.length);
            fileOutputStream.close();
            try {
                DexClassLoader dexClassLoader = new DexClassLoader(createTempFile.getAbsolutePath(), file.getAbsolutePath(), null, context.getClassLoader());
                Class loadClass = dexClassLoader.loadClass(zzb(zzl, zzat.zzam()));
                Class loadClass2 = dexClassLoader.loadClass(zzb(zzl, zzat.zzaA()));
                Class loadClass3 = dexClassLoader.loadClass(zzb(zzl, zzat.zzau()));
                Class loadClass4 = dexClassLoader.loadClass(zzb(zzl, zzat.zzaq()));
                Class loadClass5 = dexClassLoader.loadClass(zzb(zzl, zzat.zzaC()));
                Class loadClass6 = dexClassLoader.loadClass(zzb(zzl, zzat.zzao()));
                Class loadClass7 = dexClassLoader.loadClass(zzb(zzl, zzat.zzay()));
                Class loadClass8 = dexClassLoader.loadClass(zzb(zzl, zzat.zzaw()));
                Class loadClass9 = dexClassLoader.loadClass(zzb(zzl, zzat.zzak()));
                Class loadClass10 = dexClassLoader.loadClass(zzb(zzl, zzat.zzai()));
                Class loadClass11 = dexClassLoader.loadClass(zzb(zzl, zzat.zzag()));
                Class loadClass12 = dexClassLoader.loadClass(zzb(zzl, zzat.zzas()));
                Class loadClass13 = dexClassLoader.loadClass(zzb(zzl, zzat.zzae()));
                zzmV = loadClass.getMethod(zzb(zzl, zzat.zzan()), new Class[0]);
                zzmW = loadClass2.getMethod(zzb(zzl, zzat.zzaB()), new Class[0]);
                zzmX = loadClass3.getMethod(zzb(zzl, zzat.zzav()), new Class[0]);
                zzmY = loadClass4.getMethod(zzb(zzl, zzat.zzar()), Context.class);
                zzmZ = loadClass5.getMethod(zzb(zzl, zzat.zzaD()), MotionEvent.class, DisplayMetrics.class);
                zzna = loadClass6.getMethod(zzb(zzl, zzat.zzap()), Context.class);
                zznb = loadClass7.getMethod(zzb(zzl, zzat.zzaz()), Context.class);
                zznc = loadClass8.getMethod(zzb(zzl, zzat.zzax()), Context.class);
                zznd = loadClass9.getMethod(zzb(zzl, zzat.zzal()), Context.class);
                zzne = loadClass10.getMethod(zzb(zzl, zzat.zzaj()), Context.class);
                zznf = loadClass11.getMethod(zzb(zzl, zzat.zzah()), Context.class);
                zzng = loadClass12.getMethod(zzb(zzl, zzat.zzat()), Context.class);
                zznh = loadClass13.getMethod(zzb(zzl, zzat.zzaf()), Context.class);
            } finally {
                String name = createTempFile.getName();
                createTempFile.delete();
                new File(file, name.replace(".jar", ".dex")).delete();
            }
        } catch (zzar.zza e) {
            throw new zza(e);
        } catch (FileNotFoundException e2) {
            throw new zza(e2);
        } catch (IOException e3) {
            throw new zza(e3);
        } catch (ClassNotFoundException e4) {
            throw new zza(e4);
        } catch (NoSuchMethodException e5) {
            throw new zza(e5);
        } catch (NullPointerException e6) {
            throw new zza(e6);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.internal.zzak
    public void zzc(Context context) {
        try {
            try {
                zza(1, zzW());
            } catch (zza e) {
            }
            try {
                zza(2, zzU());
            } catch (zza e2) {
            }
            try {
                long longValue = zzV().longValue();
                zza(25, longValue);
                if (startTime != 0) {
                    zza(17, longValue - startTime);
                    zza(23, startTime);
                }
            } catch (zza e3) {
            }
            try {
                ArrayList<Long> zzh = zzh(context);
                zza(31, zzh.get(0).longValue());
                zza(32, zzh.get(1).longValue());
            } catch (zza e4) {
            }
            try {
                zza(33, zzX().longValue());
            } catch (zza e5) {
            }
            try {
                zza(27, zza(context, this.zzmT));
            } catch (zza e6) {
            }
            try {
                zza(29, zzb(context, this.zzmT));
            } catch (zza e7) {
            }
            try {
                int[] zzi = zzi(context);
                zza(5, zzi[0]);
                zza(6, zzi[1]);
            } catch (zza e8) {
            }
            try {
                zza(12, zzj(context));
            } catch (zza e9) {
            }
            try {
                zza(3, zzk(context));
            } catch (zza e10) {
            }
            try {
                zza(34, zzf(context));
            } catch (zza e11) {
            }
            try {
                zza(35, zzg(context).longValue());
            } catch (zza e12) {
            }
        } catch (IOException e13) {
        }
    }

    @Override // com.google.android.gms.internal.zzak
    protected void zzd(Context context) {
        try {
            try {
                zza(2, zzU());
            } catch (zza e) {
            }
            try {
                zza(1, zzW());
            } catch (zza e2) {
            }
            try {
                zza(25, zzV().longValue());
            } catch (zza e3) {
            }
            try {
                ArrayList<Long> zza2 = zza(this.zzmR, this.zzmS);
                zza(14, zza2.get(0).longValue());
                zza(15, zza2.get(1).longValue());
                if (zza2.size() >= 3) {
                    zza(16, zza2.get(2).longValue());
                }
            } catch (zza e4) {
            }
            try {
                zza(34, zzf(context));
            } catch (zza e5) {
            }
            try {
                zza(35, zzg(context).longValue());
            } catch (zza e6) {
            }
        } catch (IOException e7) {
        }
    }
}
