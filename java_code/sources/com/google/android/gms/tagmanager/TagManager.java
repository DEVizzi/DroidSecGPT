package com.google.android.gms.tagmanager;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.tagmanager.DataLayer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
/* loaded from: classes.dex */
public class TagManager {
    private static TagManager zzaOb;
    private final Context mContext;
    private final DataLayer zzaKz;
    private final zzs zzaMV;
    private final zza zzaNY;
    private final zzct zzaNZ;
    private final ConcurrentMap<zzo, Boolean> zzaOa;

    /* loaded from: classes.dex */
    public interface zza {
        zzp zza(Context context, TagManager tagManager, Looper looper, String str, int i, zzs zzsVar);
    }

    TagManager(Context context, zza containerHolderLoaderProvider, DataLayer dataLayer, zzct serviceManager) {
        if (context == null) {
            throw new NullPointerException("context cannot be null");
        }
        this.mContext = context.getApplicationContext();
        this.zzaNZ = serviceManager;
        this.zzaNY = containerHolderLoaderProvider;
        this.zzaOa = new ConcurrentHashMap();
        this.zzaKz = dataLayer;
        this.zzaKz.zza(new DataLayer.zzb() { // from class: com.google.android.gms.tagmanager.TagManager.1
            @Override // com.google.android.gms.tagmanager.DataLayer.zzb
            public void zzF(Map<String, Object> map) {
                Object obj = map.get("event");
                if (obj != null) {
                    TagManager.this.zzeF(obj.toString());
                }
            }
        });
        this.zzaKz.zza(new zzd(this.mContext));
        this.zzaMV = new zzs();
        zzzE();
    }

    public static TagManager getInstance(Context context) {
        TagManager tagManager;
        synchronized (TagManager.class) {
            if (zzaOb == null) {
                if (context == null) {
                    zzbg.zzaz("TagManager.getInstance requires non-null context.");
                    throw new NullPointerException();
                }
                zzaOb = new TagManager(context, new zza() { // from class: com.google.android.gms.tagmanager.TagManager.2
                    @Override // com.google.android.gms.tagmanager.TagManager.zza
                    public zzp zza(Context context2, TagManager tagManager2, Looper looper, String str, int i, zzs zzsVar) {
                        return new zzp(context2, tagManager2, looper, str, i, zzsVar);
                    }
                }, new DataLayer(new zzw(context)), zzcu.zzzz());
            }
            tagManager = zzaOb;
        }
        return tagManager;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzeF(String str) {
        for (zzo zzoVar : this.zzaOa.keySet()) {
            zzoVar.zzeh(str);
        }
    }

    private void zzzE() {
        if (Build.VERSION.SDK_INT >= 14) {
            this.mContext.registerComponentCallbacks(new ComponentCallbacks2() { // from class: com.google.android.gms.tagmanager.TagManager.3
                @Override // android.content.ComponentCallbacks
                public void onConfigurationChanged(Configuration configuration) {
                }

                @Override // android.content.ComponentCallbacks
                public void onLowMemory() {
                }

                @Override // android.content.ComponentCallbacks2
                public void onTrimMemory(int i) {
                    if (i == 20) {
                        TagManager.this.dispatch();
                    }
                }
            });
        }
    }

    public void dispatch() {
        this.zzaNZ.dispatch();
    }

    public DataLayer getDataLayer() {
        return this.zzaKz;
    }

    public PendingResult<ContainerHolder> loadContainerDefaultOnly(String containerId, int defaultContainerResourceId) {
        zzp zza2 = this.zzaNY.zza(this.mContext, this, null, containerId, defaultContainerResourceId, this.zzaMV);
        zza2.zzyr();
        return zza2;
    }

    public PendingResult<ContainerHolder> loadContainerDefaultOnly(String containerId, int defaultContainerResourceId, Handler handler) {
        zzp zza2 = this.zzaNY.zza(this.mContext, this, handler.getLooper(), containerId, defaultContainerResourceId, this.zzaMV);
        zza2.zzyr();
        return zza2;
    }

    public PendingResult<ContainerHolder> loadContainerPreferFresh(String containerId, int defaultContainerResourceId) {
        zzp zza2 = this.zzaNY.zza(this.mContext, this, null, containerId, defaultContainerResourceId, this.zzaMV);
        zza2.zzyt();
        return zza2;
    }

    public PendingResult<ContainerHolder> loadContainerPreferFresh(String containerId, int defaultContainerResourceId, Handler handler) {
        zzp zza2 = this.zzaNY.zza(this.mContext, this, handler.getLooper(), containerId, defaultContainerResourceId, this.zzaMV);
        zza2.zzyt();
        return zza2;
    }

    public PendingResult<ContainerHolder> loadContainerPreferNonDefault(String containerId, int defaultContainerResourceId) {
        zzp zza2 = this.zzaNY.zza(this.mContext, this, null, containerId, defaultContainerResourceId, this.zzaMV);
        zza2.zzys();
        return zza2;
    }

    public PendingResult<ContainerHolder> loadContainerPreferNonDefault(String containerId, int defaultContainerResourceId, Handler handler) {
        zzp zza2 = this.zzaNY.zza(this.mContext, this, handler.getLooper(), containerId, defaultContainerResourceId, this.zzaMV);
        zza2.zzys();
        return zza2;
    }

    public void setVerboseLoggingEnabled(boolean enableVerboseLogging) {
        zzbg.setLogLevel(enableVerboseLogging ? 2 : 5);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zza(zzo zzoVar) {
        this.zzaOa.put(zzoVar, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean zzb(zzo zzoVar) {
        return this.zzaOa.remove(zzoVar) != null;
    }

    public PendingResult<ContainerHolder> zzc(String str, int i, String str2) {
        zzp zza2 = this.zzaNY.zza(this.mContext, this, null, str, i, this.zzaMV);
        zza2.load(str2);
        return zza2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized boolean zzl(Uri uri) {
        boolean z;
        zzcb zzzf = zzcb.zzzf();
        if (zzzf.zzl(uri)) {
            String containerId = zzzf.getContainerId();
            switch (zzzf.zzzg()) {
                case NONE:
                    for (zzo zzoVar : this.zzaOa.keySet()) {
                        if (zzoVar.getContainerId().equals(containerId)) {
                            zzoVar.zzej(null);
                            zzoVar.refresh();
                        }
                    }
                    break;
                case CONTAINER:
                case CONTAINER_DEBUG:
                    for (zzo zzoVar2 : this.zzaOa.keySet()) {
                        if (zzoVar2.getContainerId().equals(containerId)) {
                            zzoVar2.zzej(zzzf.zzzh());
                            zzoVar2.refresh();
                        } else if (zzoVar2.zzyo() != null) {
                            zzoVar2.zzej(null);
                            zzoVar2.refresh();
                        }
                    }
                    break;
            }
            z = true;
        } else {
            z = false;
        }
        return z;
    }
}
