package com.google.android.gms.internal;

import android.content.Context;
import android.content.res.Resources;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.zzqf;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
/* loaded from: classes.dex */
public class zzqh {
    public static final Integer zzaPM = 0;
    public static final Integer zzaPN = 1;
    private final Context mContext;
    private final ExecutorService zzaNb;

    public zzqh(Context context) {
        this(context, Executors.newSingleThreadExecutor());
    }

    zzqh(Context context, ExecutorService executorService) {
        this.mContext = context;
        this.zzaNb = executorService;
    }

    private String zzfc(String str) {
        return "resource_" + str;
    }

    private byte[] zzm(InputStream inputStream) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            try {
                zzlg.zza(inputStream, byteArrayOutputStream);
            } catch (IOException e) {
                com.google.android.gms.tagmanager.zzbg.zzaC("Failed to read the resource from disk");
                try {
                    inputStream.close();
                } catch (IOException e2) {
                    com.google.android.gms.tagmanager.zzbg.zzaC("Error closing stream for reading resource from disk");
                    return null;
                }
            }
            try {
                inputStream.close();
                return byteArrayOutputStream.toByteArray();
            } catch (IOException e3) {
                com.google.android.gms.tagmanager.zzbg.zzaC("Error closing stream for reading resource from disk");
                return null;
            }
        } catch (Throwable th) {
            try {
                inputStream.close();
                throw th;
            } catch (IOException e4) {
                com.google.android.gms.tagmanager.zzbg.zzaC("Error closing stream for reading resource from disk");
                return null;
            }
        }
    }

    public void zza(final String str, final Integer num, final zzqb zzqbVar, final zzqg zzqgVar) {
        this.zzaNb.execute(new Runnable() { // from class: com.google.android.gms.internal.zzqh.1
            @Override // java.lang.Runnable
            public void run() {
                zzqh.this.zzb(str, num, zzqbVar, zzqgVar);
            }
        });
    }

    void zzb(String str, Integer num, zzqb zzqbVar, zzqg zzqgVar) {
        Object zzt;
        com.google.android.gms.tagmanager.zzbg.zzaB("DiskLoader: Starting to load resource from Disk.");
        try {
            Object zzt2 = zzqbVar.zzt(zzm(new FileInputStream(zzfb(str))));
            if (zzt2 != null) {
                com.google.android.gms.tagmanager.zzbg.zzaB("Saved resource loaded: " + zzfc(str));
                zzqgVar.zza(Status.zzXP, zzt2, zzaPN, zzfa(str));
                return;
            }
        } catch (zzqf.zzg e) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Saved resource is corrupted: " + zzfc(str));
        } catch (FileNotFoundException e2) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Saved resource not found: " + zzfc(str));
        }
        if (num == null) {
            zzqgVar.zza(Status.zzXR, null, null, 0L);
            return;
        }
        try {
            InputStream openRawResource = this.mContext.getResources().openRawResource(num.intValue());
            if (openRawResource != null && (zzt = zzqbVar.zzt(zzm(openRawResource))) != null) {
                com.google.android.gms.tagmanager.zzbg.zzaB("Default resource loaded: " + this.mContext.getResources().getResourceEntryName(num.intValue()));
                zzqgVar.zza(Status.zzXP, zzt, zzaPM, 0L);
                return;
            }
        } catch (Resources.NotFoundException e3) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Default resource not found. ID: " + num);
        } catch (zzqf.zzg e4) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Default resource resource is corrupted: " + num);
        }
        zzqgVar.zza(Status.zzXR, null, null, 0L);
    }

    public void zze(final String str, final byte[] bArr) {
        this.zzaNb.execute(new Runnable() { // from class: com.google.android.gms.internal.zzqh.2
            @Override // java.lang.Runnable
            public void run() {
                zzqh.this.zzf(str, bArr);
            }
        });
    }

    void zzf(String str, byte[] bArr) {
        File zzfb = zzfb(str);
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(zzfb);
            try {
                try {
                    fileOutputStream.write(bArr);
                } catch (IOException e) {
                    com.google.android.gms.tagmanager.zzbg.zzaz("Error writing resource to disk. Removing resource from disk");
                    zzfb.delete();
                    try {
                        fileOutputStream.close();
                        com.google.android.gms.tagmanager.zzbg.zzaB("Resource " + str + " saved on Disk.");
                    } catch (IOException e2) {
                        com.google.android.gms.tagmanager.zzbg.zzaz("Error closing stream for writing resource to disk");
                    }
                }
            } finally {
                try {
                    fileOutputStream.close();
                    com.google.android.gms.tagmanager.zzbg.zzaB("Resource " + str + " saved on Disk.");
                } catch (IOException e3) {
                    com.google.android.gms.tagmanager.zzbg.zzaz("Error closing stream for writing resource to disk");
                }
            }
        } catch (FileNotFoundException e4) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Error opening resource file for writing");
        }
    }

    public long zzfa(String str) {
        File zzfb = zzfb(str);
        if (zzfb.exists()) {
            return zzfb.lastModified();
        }
        return 0L;
    }

    File zzfb(String str) {
        return new File(this.mContext.getDir("google_tagmanager", 0), zzfc(str));
    }
}
