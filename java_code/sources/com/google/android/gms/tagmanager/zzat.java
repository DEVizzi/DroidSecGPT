package com.google.android.gms.tagmanager;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.concurrent.LinkedBlockingQueue;
/* loaded from: classes.dex */
class zzat extends Thread implements zzas {
    private static zzat zzaLP;
    private volatile boolean mClosed;
    private final Context mContext;
    private volatile boolean zzKU;
    private final LinkedBlockingQueue<Runnable> zzaLO;
    private volatile zzau zzaLQ;

    private zzat(Context context) {
        super("GAThread");
        this.zzaLO = new LinkedBlockingQueue<>();
        this.zzKU = false;
        this.mClosed = false;
        if (context != null) {
            this.mContext = context.getApplicationContext();
        } else {
            this.mContext = context;
        }
        start();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static zzat zzaH(Context context) {
        if (zzaLP == null) {
            zzaLP = new zzat(context);
        }
        return zzaLP;
    }

    private String zzd(Throwable th) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(byteArrayOutputStream);
        th.printStackTrace(printStream);
        printStream.flush();
        return new String(byteArrayOutputStream.toByteArray());
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        while (!this.mClosed) {
            try {
                try {
                    Runnable take = this.zzaLO.take();
                    if (!this.zzKU) {
                        take.run();
                    }
                } catch (InterruptedException e) {
                    zzbg.zzaA(e.toString());
                }
            } catch (Throwable th) {
                zzbg.zzaz("Error on Google TagManager Thread: " + zzd(th));
                zzbg.zzaz("Google TagManager is shutting down.");
                this.zzKU = true;
            }
        }
    }

    @Override // com.google.android.gms.tagmanager.zzas
    public void zzew(String str) {
        zzh(str, System.currentTimeMillis());
    }

    @Override // com.google.android.gms.tagmanager.zzas
    public void zzf(Runnable runnable) {
        this.zzaLO.add(runnable);
    }

    void zzh(final String str, final long j) {
        zzf(new Runnable() { // from class: com.google.android.gms.tagmanager.zzat.1
            @Override // java.lang.Runnable
            public void run() {
                if (zzat.this.zzaLQ == null) {
                    zzcu zzzz = zzcu.zzzz();
                    zzzz.zza(zzat.this.mContext, this);
                    zzat.this.zzaLQ = zzzz.zzzC();
                }
                zzat.this.zzaLQ.zzg(j, str);
            }
        });
    }
}
