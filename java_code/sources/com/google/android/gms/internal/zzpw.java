package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.tagmanager.ContainerHolder;
import com.google.android.gms.tagmanager.TagManager;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public class zzpw {
    private static zzpw zzaOV;
    private Context mContext;
    private boolean mStarted;
    private final Set<zza> zzaOW = new HashSet();
    private TagManager zzaOX;
    private zzpv zzoY;

    /* loaded from: classes.dex */
    public interface zza {
        void zzbm();
    }

    zzpw(Context context, TagManager tagManager) {
        this.zzaOX = null;
        this.mContext = context;
        this.zzaOX = tagManager;
    }

    public static zzpw zzaK(Context context) {
        com.google.android.gms.common.internal.zzu.zzu(context);
        if (zzaOV == null) {
            synchronized (zzpw.class) {
                if (zzaOV == null) {
                    zzaOV = new zzpw(context, TagManager.getInstance(context.getApplicationContext()));
                }
            }
        }
        return zzaOV;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzgy() {
        synchronized (this) {
            for (zza zzaVar : this.zzaOW) {
                zzaVar.zzbm();
            }
        }
    }

    public void start() throws IllegalStateException {
        synchronized (this) {
            if (this.mStarted) {
                throw new IllegalStateException("Method start() has already been called");
            }
            if (this.zzoY == null) {
                throw new IllegalStateException("No settings configured");
            }
            this.mStarted = true;
            this.zzaOX.zzc(this.zzoY.zzzT(), -1, "admob").setResultCallback(new ResultCallback<ContainerHolder>() { // from class: com.google.android.gms.internal.zzpw.1
                @Override // com.google.android.gms.common.api.ResultCallback
                /* renamed from: zza */
                public void onResult(ContainerHolder containerHolder) {
                    zzpw.this.zzoY = new zzpu(zzpw.this.mContext, containerHolder.getStatus().isSuccess() ? containerHolder.getContainer() : null, zzpw.this.zzzX()).zzzR();
                    zzpw.this.zzgy();
                }
            });
        }
    }

    public void zza(zzpv zzpvVar) {
        synchronized (this) {
            if (this.mStarted) {
                throw new IllegalStateException("Settings can't be changed after TagManager has been started");
            }
            this.zzoY = zzpvVar;
        }
    }

    public void zza(zza zzaVar) {
        synchronized (this) {
            this.zzaOW.add(zzaVar);
        }
    }

    public zzpv zzzX() {
        zzpv zzpvVar;
        synchronized (this) {
            zzpvVar = this.zzoY;
        }
        return zzpvVar;
    }
}
