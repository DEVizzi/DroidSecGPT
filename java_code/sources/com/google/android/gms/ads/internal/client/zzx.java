package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.location.Location;
import android.os.Bundle;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.mediation.MediationAdapter;
import com.google.android.gms.ads.mediation.NetworkExtras;
import com.google.android.gms.ads.mediation.admob.AdMobExtras;
import com.google.android.gms.ads.mediation.customevent.CustomEvent;
import com.google.android.gms.ads.search.SearchAdRequest;
import com.google.android.gms.internal.zzgd;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
@zzgd
/* loaded from: classes.dex */
public final class zzx {
    public static final String DEVICE_ID_EMULATOR = zzk.zzcA().zzax("emulator");
    private final Date zzaQ;
    private final Set<String> zzaS;
    private final Location zzaU;
    private final String zzsB;
    private final int zzsC;
    private final boolean zzsD;
    private final Bundle zzsE;
    private final Map<Class<? extends NetworkExtras>, NetworkExtras> zzsF;
    private final String zzsG;
    private final String zzsH;
    private final SearchAdRequest zzsI;
    private final int zzsJ;
    private final Set<String> zzsK;
    private final Bundle zzsL;
    private final Set<String> zzsM;

    /* loaded from: classes.dex */
    public static final class zza {
        private Date zzaQ;
        private Location zzaU;
        private String zzsB;
        private String zzsG;
        private String zzsH;
        private final HashSet<String> zzsN = new HashSet<>();
        private final Bundle zzsE = new Bundle();
        private final HashMap<Class<? extends NetworkExtras>, NetworkExtras> zzsO = new HashMap<>();
        private final HashSet<String> zzsP = new HashSet<>();
        private final Bundle zzsL = new Bundle();
        private final HashSet<String> zzsQ = new HashSet<>();
        private int zzsC = -1;
        private boolean zzsD = false;
        private int zzsJ = -1;

        public void zzE(String str) {
            this.zzsN.add(str);
        }

        public void zzF(String str) {
            this.zzsP.add(str);
        }

        public void zzG(String str) {
            this.zzsP.remove(str);
        }

        public void zzH(String str) {
            this.zzsB = str;
        }

        public void zzI(String str) {
            this.zzsG = str;
        }

        public void zzJ(String str) {
            this.zzsH = str;
        }

        public void zzK(String str) {
            this.zzsQ.add(str);
        }

        public void zza(Location location) {
            this.zzaU = location;
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Deprecated
        public void zza(NetworkExtras networkExtras) {
            if (networkExtras instanceof AdMobExtras) {
                zza(AdMobAdapter.class, ((AdMobExtras) networkExtras).getExtras());
            } else {
                this.zzsO.put(networkExtras.getClass(), networkExtras);
            }
        }

        public void zza(Class<? extends MediationAdapter> cls, Bundle bundle) {
            this.zzsE.putBundle(cls.getName(), bundle);
        }

        public void zza(Date date) {
            this.zzaQ = date;
        }

        public void zzb(Class<? extends CustomEvent> cls, Bundle bundle) {
            if (this.zzsE.getBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter") == null) {
                this.zzsE.putBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter", new Bundle());
            }
            this.zzsE.getBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter").putBundle(cls.getName(), bundle);
        }

        public void zzb(String str, String str2) {
            this.zzsL.putString(str, str2);
        }

        public void zzj(boolean z) {
            this.zzsD = z;
        }

        public void zzk(boolean z) {
            this.zzsJ = z ? 1 : 0;
        }

        public void zzm(int i) {
            this.zzsC = i;
        }
    }

    public zzx(zza zzaVar) {
        this(zzaVar, null);
    }

    public zzx(zza zzaVar, SearchAdRequest searchAdRequest) {
        this.zzaQ = zzaVar.zzaQ;
        this.zzsB = zzaVar.zzsB;
        this.zzsC = zzaVar.zzsC;
        this.zzaS = Collections.unmodifiableSet(zzaVar.zzsN);
        this.zzaU = zzaVar.zzaU;
        this.zzsD = zzaVar.zzsD;
        this.zzsE = zzaVar.zzsE;
        this.zzsF = Collections.unmodifiableMap(zzaVar.zzsO);
        this.zzsG = zzaVar.zzsG;
        this.zzsH = zzaVar.zzsH;
        this.zzsI = searchAdRequest;
        this.zzsJ = zzaVar.zzsJ;
        this.zzsK = Collections.unmodifiableSet(zzaVar.zzsP);
        this.zzsL = zzaVar.zzsL;
        this.zzsM = Collections.unmodifiableSet(zzaVar.zzsQ);
    }

    public static void updateCorrelator() {
        zzk.zzcC().zzcG();
    }

    public Date getBirthday() {
        return this.zzaQ;
    }

    public String getContentUrl() {
        return this.zzsB;
    }

    public Bundle getCustomEventExtrasBundle(Class<? extends CustomEvent> adapterClass) {
        Bundle bundle = this.zzsE.getBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter");
        if (bundle != null) {
            return bundle.getBundle(adapterClass.getClass().getName());
        }
        return null;
    }

    public Bundle getCustomTargeting() {
        return this.zzsL;
    }

    public int getGender() {
        return this.zzsC;
    }

    public Set<String> getKeywords() {
        return this.zzaS;
    }

    public Location getLocation() {
        return this.zzaU;
    }

    public boolean getManualImpressionsEnabled() {
        return this.zzsD;
    }

    @Deprecated
    public <T extends NetworkExtras> T getNetworkExtras(Class<T> networkExtrasClass) {
        return (T) this.zzsF.get(networkExtrasClass);
    }

    public Bundle getNetworkExtrasBundle(Class<? extends MediationAdapter> adapterClass) {
        return this.zzsE.getBundle(adapterClass.getName());
    }

    public String getPublisherProvidedId() {
        return this.zzsG;
    }

    public boolean isTestDevice(Context context) {
        return this.zzsK.contains(zzk.zzcA().zzO(context));
    }

    public String zzcH() {
        return this.zzsH;
    }

    public SearchAdRequest zzcI() {
        return this.zzsI;
    }

    public Map<Class<? extends NetworkExtras>, NetworkExtras> zzcJ() {
        return this.zzsF;
    }

    public Bundle zzcK() {
        return this.zzsE;
    }

    public int zzcL() {
        return this.zzsJ;
    }

    public Set<String> zzcM() {
        return this.zzsM;
    }
}
