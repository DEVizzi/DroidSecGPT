package com.google.android.gms.tagmanager;

import android.content.Context;
import com.google.android.gms.internal.zzaf;
import com.google.android.gms.internal.zzqf;
import com.google.android.gms.tagmanager.zzcb;
import com.google.android.gms.tagmanager.zzt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class Container {
    private final Context mContext;
    private zzcp zzaKA;
    private volatile long zzaKD;
    private final String zzaKy;
    private final DataLayer zzaKz;
    private Map<String, FunctionCallMacroCallback> zzaKB = new HashMap();
    private Map<String, FunctionCallTagCallback> zzaKC = new HashMap();
    private volatile String zzaKE = "";

    /* loaded from: classes.dex */
    public interface FunctionCallMacroCallback {
        Object getValue(String str, Map<String, Object> map);
    }

    /* loaded from: classes.dex */
    public interface FunctionCallTagCallback {
        void execute(String str, Map<String, Object> map);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zza implements zzt.zza {
        private zza() {
        }

        @Override // com.google.android.gms.tagmanager.zzt.zza
        public Object zzd(String str, Map<String, Object> map) {
            FunctionCallMacroCallback zzef = Container.this.zzef(str);
            if (zzef == null) {
                return null;
            }
            return zzef.getValue(str, map);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zzb implements zzt.zza {
        private zzb() {
        }

        @Override // com.google.android.gms.tagmanager.zzt.zza
        public Object zzd(String str, Map<String, Object> map) {
            FunctionCallTagCallback zzeg = Container.this.zzeg(str);
            if (zzeg != null) {
                zzeg.execute(str, map);
            }
            return zzdf.zzzP();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Container(Context context, DataLayer dataLayer, String containerId, long lastRefreshTime, zzaf.zzj resource) {
        this.mContext = context;
        this.zzaKz = dataLayer;
        this.zzaKy = containerId;
        this.zzaKD = lastRefreshTime;
        zza(resource.zziO);
        if (resource.zziN != null) {
            zza(resource.zziN);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Container(Context context, DataLayer dataLayer, String containerId, long lastRefreshTime, zzqf.zzc resource) {
        this.mContext = context;
        this.zzaKz = dataLayer;
        this.zzaKy = containerId;
        this.zzaKD = lastRefreshTime;
        zza(resource);
    }

    private void zza(zzaf.zzf zzfVar) {
        if (zzfVar == null) {
            throw new NullPointerException();
        }
        try {
            zza(zzqf.zzb(zzfVar));
        } catch (zzqf.zzg e) {
            zzbg.zzaz("Not loading resource: " + zzfVar + " because it is invalid: " + e.toString());
        }
    }

    private void zza(zzqf.zzc zzcVar) {
        this.zzaKE = zzcVar.getVersion();
        zza(new zzcp(this.mContext, zzcVar, this.zzaKz, new zza(), new zzb(), zzei(this.zzaKE)));
        if (getBoolean("_gtm.loadEventEnabled")) {
            this.zzaKz.pushEvent("gtm.load", DataLayer.mapOf("gtm.id", this.zzaKy));
        }
    }

    private synchronized void zza(zzcp zzcpVar) {
        this.zzaKA = zzcpVar;
    }

    private void zza(zzaf.zzi[] zziVarArr) {
        ArrayList arrayList = new ArrayList();
        for (zzaf.zzi zziVar : zziVarArr) {
            arrayList.add(zziVar);
        }
        zzyn().zzs(arrayList);
    }

    private synchronized zzcp zzyn() {
        return this.zzaKA;
    }

    public boolean getBoolean(String key) {
        zzcp zzyn = zzyn();
        if (zzyn == null) {
            zzbg.zzaz("getBoolean called for closed container.");
            return zzdf.zzzN().booleanValue();
        }
        try {
            return zzdf.zzk(zzyn.zzeD(key).getObject()).booleanValue();
        } catch (Exception e) {
            zzbg.zzaz("Calling getBoolean() threw an exception: " + e.getMessage() + " Returning default value.");
            return zzdf.zzzN().booleanValue();
        }
    }

    public String getContainerId() {
        return this.zzaKy;
    }

    public double getDouble(String key) {
        zzcp zzyn = zzyn();
        if (zzyn == null) {
            zzbg.zzaz("getDouble called for closed container.");
            return zzdf.zzzM().doubleValue();
        }
        try {
            return zzdf.zzj(zzyn.zzeD(key).getObject()).doubleValue();
        } catch (Exception e) {
            zzbg.zzaz("Calling getDouble() threw an exception: " + e.getMessage() + " Returning default value.");
            return zzdf.zzzM().doubleValue();
        }
    }

    public long getLastRefreshTime() {
        return this.zzaKD;
    }

    public long getLong(String key) {
        zzcp zzyn = zzyn();
        if (zzyn == null) {
            zzbg.zzaz("getLong called for closed container.");
            return zzdf.zzzL().longValue();
        }
        try {
            return zzdf.zzi(zzyn.zzeD(key).getObject()).longValue();
        } catch (Exception e) {
            zzbg.zzaz("Calling getLong() threw an exception: " + e.getMessage() + " Returning default value.");
            return zzdf.zzzL().longValue();
        }
    }

    public String getString(String key) {
        zzcp zzyn = zzyn();
        if (zzyn == null) {
            zzbg.zzaz("getString called for closed container.");
            return zzdf.zzzP();
        }
        try {
            return zzdf.zzg(zzyn.zzeD(key).getObject());
        } catch (Exception e) {
            zzbg.zzaz("Calling getString() threw an exception: " + e.getMessage() + " Returning default value.");
            return zzdf.zzzP();
        }
    }

    public boolean isDefault() {
        return getLastRefreshTime() == 0;
    }

    public void registerFunctionCallMacroCallback(String customMacroName, FunctionCallMacroCallback customMacroCallback) {
        if (customMacroCallback == null) {
            throw new NullPointerException("Macro handler must be non-null");
        }
        synchronized (this.zzaKB) {
            this.zzaKB.put(customMacroName, customMacroCallback);
        }
    }

    public void registerFunctionCallTagCallback(String customTagName, FunctionCallTagCallback customTagCallback) {
        if (customTagCallback == null) {
            throw new NullPointerException("Tag callback must be non-null");
        }
        synchronized (this.zzaKC) {
            this.zzaKC.put(customTagName, customTagCallback);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void release() {
        this.zzaKA = null;
    }

    public void unregisterFunctionCallMacroCallback(String customMacroName) {
        synchronized (this.zzaKB) {
            this.zzaKB.remove(customMacroName);
        }
    }

    public void unregisterFunctionCallTagCallback(String customTagName) {
        synchronized (this.zzaKC) {
            this.zzaKC.remove(customTagName);
        }
    }

    FunctionCallMacroCallback zzef(String str) {
        FunctionCallMacroCallback functionCallMacroCallback;
        synchronized (this.zzaKB) {
            functionCallMacroCallback = this.zzaKB.get(str);
        }
        return functionCallMacroCallback;
    }

    FunctionCallTagCallback zzeg(String str) {
        FunctionCallTagCallback functionCallTagCallback;
        synchronized (this.zzaKC) {
            functionCallTagCallback = this.zzaKC.get(str);
        }
        return functionCallTagCallback;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzeh(String str) {
        zzyn().zzeh(str);
    }

    zzah zzei(String str) {
        if (zzcb.zzzf().zzzg().equals(zzcb.zza.CONTAINER_DEBUG)) {
        }
        return new zzbo();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String zzym() {
        return this.zzaKE;
    }
}
