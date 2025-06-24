package com.google.android.gms.tagmanager;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.tagmanager.ContainerHolder;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzo implements ContainerHolder {
    private Status zzOt;
    private final Looper zzWt;
    private Container zzaKG;
    private Container zzaKH;
    private zzb zzaKI;
    private zza zzaKJ;
    private TagManager zzaKK;
    private boolean zzaea;

    /* loaded from: classes.dex */
    public interface zza {
        void zzej(String str);

        String zzyo();

        void zzyq();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zzb extends Handler {
        private final ContainerHolder.ContainerAvailableListener zzaKL;

        public zzb(ContainerHolder.ContainerAvailableListener containerAvailableListener, Looper looper) {
            super(looper);
            this.zzaKL = containerAvailableListener;
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 1:
                    zzel((String) msg.obj);
                    return;
                default:
                    zzbg.zzaz("Don't know how to handle this message.");
                    return;
            }
        }

        public void zzek(String str) {
            sendMessage(obtainMessage(1, str));
        }

        protected void zzel(String str) {
            this.zzaKL.onContainerAvailable(zzo.this, str);
        }
    }

    public zzo(Status status) {
        this.zzOt = status;
        this.zzWt = null;
    }

    public zzo(TagManager tagManager, Looper looper, Container container, zza zzaVar) {
        this.zzaKK = tagManager;
        this.zzWt = looper == null ? Looper.getMainLooper() : looper;
        this.zzaKG = container;
        this.zzaKJ = zzaVar;
        this.zzOt = Status.zzXP;
        tagManager.zza(this);
    }

    private void zzyp() {
        if (this.zzaKI != null) {
            this.zzaKI.zzek(this.zzaKH.zzym());
        }
    }

    @Override // com.google.android.gms.tagmanager.ContainerHolder
    public synchronized Container getContainer() {
        Container container = null;
        synchronized (this) {
            if (this.zzaea) {
                zzbg.zzaz("ContainerHolder is released.");
            } else {
                if (this.zzaKH != null) {
                    this.zzaKG = this.zzaKH;
                    this.zzaKH = null;
                }
                container = this.zzaKG;
            }
        }
        return container;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getContainerId() {
        if (this.zzaea) {
            zzbg.zzaz("getContainerId called on a released ContainerHolder.");
            return "";
        }
        return this.zzaKG.getContainerId();
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzOt;
    }

    @Override // com.google.android.gms.tagmanager.ContainerHolder
    public synchronized void refresh() {
        if (this.zzaea) {
            zzbg.zzaz("Refreshing a released ContainerHolder.");
        } else {
            this.zzaKJ.zzyq();
        }
    }

    @Override // com.google.android.gms.common.api.Releasable
    public synchronized void release() {
        if (this.zzaea) {
            zzbg.zzaz("Releasing a released ContainerHolder.");
        } else {
            this.zzaea = true;
            this.zzaKK.zzb(this);
            this.zzaKG.release();
            this.zzaKG = null;
            this.zzaKH = null;
            this.zzaKJ = null;
            this.zzaKI = null;
        }
    }

    @Override // com.google.android.gms.tagmanager.ContainerHolder
    public synchronized void setContainerAvailableListener(ContainerHolder.ContainerAvailableListener listener) {
        if (this.zzaea) {
            zzbg.zzaz("ContainerHolder is released.");
        } else if (listener == null) {
            this.zzaKI = null;
        } else {
            this.zzaKI = new zzb(listener, this.zzWt);
            if (this.zzaKH != null) {
                zzyp();
            }
        }
    }

    public synchronized void zza(Container container) {
        if (!this.zzaea) {
            if (container == null) {
                zzbg.zzaz("Unexpected null container.");
            } else {
                this.zzaKH = container;
                zzyp();
            }
        }
    }

    public synchronized void zzeh(String str) {
        if (!this.zzaea) {
            this.zzaKG.zzeh(str);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzej(String str) {
        if (this.zzaea) {
            zzbg.zzaz("setCtfeUrlPathAndQuery called on a released ContainerHolder.");
        } else {
            this.zzaKJ.zzej(str);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String zzyo() {
        if (this.zzaea) {
            zzbg.zzaz("setCtfeUrlPathAndQuery called on a released ContainerHolder.");
            return "";
        }
        return this.zzaKJ.zzyo();
    }
}
