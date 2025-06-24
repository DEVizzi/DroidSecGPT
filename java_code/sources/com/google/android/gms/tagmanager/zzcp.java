package com.google.android.gms.tagmanager;

import android.content.Context;
import android.support.v4.view.accessibility.AccessibilityEventCompat;
import com.google.android.gms.internal.zzaf;
import com.google.android.gms.internal.zzag;
import com.google.android.gms.internal.zzqf;
import com.google.android.gms.tagmanager.zzm;
import com.google.android.gms.tagmanager.zzt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzcp {
    private static final zzbw<zzag.zza> zzaNe = new zzbw<>(zzdf.zzzQ(), true);
    private final DataLayer zzaKz;
    private final zzqf.zzc zzaNf;
    private final zzah zzaNg;
    private final Map<String, zzak> zzaNh;
    private final Map<String, zzak> zzaNi;
    private final Map<String, zzak> zzaNj;
    private final zzl<zzqf.zza, zzbw<zzag.zza>> zzaNk;
    private final zzl<String, zzb> zzaNl;
    private final Set<zzqf.zze> zzaNm;
    private final Map<String, zzc> zzaNn;
    private volatile String zzaNo;
    private int zzaNp;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface zza {
        void zza(zzqf.zze zzeVar, Set<zzqf.zza> set, Set<zzqf.zza> set2, zzck zzckVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzb {
        private zzbw<zzag.zza> zzaNv;
        private zzag.zza zzaNw;

        public zzb(zzbw<zzag.zza> zzbwVar, zzag.zza zzaVar) {
            this.zzaNv = zzbwVar;
            this.zzaNw = zzaVar;
        }

        public int getSize() {
            return (this.zzaNw == null ? 0 : this.zzaNw.zzBU()) + this.zzaNv.getObject().zzBU();
        }

        public zzbw<zzag.zza> zzzr() {
            return this.zzaNv;
        }

        public zzag.zza zzzs() {
            return this.zzaNw;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzc {
        private zzqf.zza zzaNB;
        private final Set<zzqf.zze> zzaNm = new HashSet();
        private final Map<zzqf.zze, List<zzqf.zza>> zzaNx = new HashMap();
        private final Map<zzqf.zze, List<String>> zzaNz = new HashMap();
        private final Map<zzqf.zze, List<zzqf.zza>> zzaNy = new HashMap();
        private final Map<zzqf.zze, List<String>> zzaNA = new HashMap();

        public void zza(zzqf.zze zzeVar) {
            this.zzaNm.add(zzeVar);
        }

        public void zza(zzqf.zze zzeVar, zzqf.zza zzaVar) {
            List<zzqf.zza> list = this.zzaNx.get(zzeVar);
            if (list == null) {
                list = new ArrayList<>();
                this.zzaNx.put(zzeVar, list);
            }
            list.add(zzaVar);
        }

        public void zza(zzqf.zze zzeVar, String str) {
            List<String> list = this.zzaNz.get(zzeVar);
            if (list == null) {
                list = new ArrayList<>();
                this.zzaNz.put(zzeVar, list);
            }
            list.add(str);
        }

        public void zzb(zzqf.zza zzaVar) {
            this.zzaNB = zzaVar;
        }

        public void zzb(zzqf.zze zzeVar, zzqf.zza zzaVar) {
            List<zzqf.zza> list = this.zzaNy.get(zzeVar);
            if (list == null) {
                list = new ArrayList<>();
                this.zzaNy.put(zzeVar, list);
            }
            list.add(zzaVar);
        }

        public void zzb(zzqf.zze zzeVar, String str) {
            List<String> list = this.zzaNA.get(zzeVar);
            if (list == null) {
                list = new ArrayList<>();
                this.zzaNA.put(zzeVar, list);
            }
            list.add(str);
        }

        public Set<zzqf.zze> zzzt() {
            return this.zzaNm;
        }

        public Map<zzqf.zze, List<zzqf.zza>> zzzu() {
            return this.zzaNx;
        }

        public Map<zzqf.zze, List<String>> zzzv() {
            return this.zzaNz;
        }

        public Map<zzqf.zze, List<String>> zzzw() {
            return this.zzaNA;
        }

        public Map<zzqf.zze, List<zzqf.zza>> zzzx() {
            return this.zzaNy;
        }

        public zzqf.zza zzzy() {
            return this.zzaNB;
        }
    }

    public zzcp(Context context, zzqf.zzc zzcVar, DataLayer dataLayer, zzt.zza zzaVar, zzt.zza zzaVar2, zzah zzahVar) {
        if (zzcVar == null) {
            throw new NullPointerException("resource cannot be null");
        }
        this.zzaNf = zzcVar;
        this.zzaNm = new HashSet(zzcVar.zzAq());
        this.zzaKz = dataLayer;
        this.zzaNg = zzahVar;
        this.zzaNk = new zzm().zza(AccessibilityEventCompat.TYPE_TOUCH_INTERACTION_START, new zzm.zza<zzqf.zza, zzbw<zzag.zza>>() { // from class: com.google.android.gms.tagmanager.zzcp.1
            @Override // com.google.android.gms.tagmanager.zzm.zza
            /* renamed from: zza */
            public int sizeOf(zzqf.zza zzaVar3, zzbw<zzag.zza> zzbwVar) {
                return zzbwVar.getObject().zzBU();
            }
        });
        this.zzaNl = new zzm().zza(AccessibilityEventCompat.TYPE_TOUCH_INTERACTION_START, new zzm.zza<String, zzb>() { // from class: com.google.android.gms.tagmanager.zzcp.2
            @Override // com.google.android.gms.tagmanager.zzm.zza
            /* renamed from: zza */
            public int sizeOf(String str, zzb zzbVar) {
                return str.length() + zzbVar.getSize();
            }
        });
        this.zzaNh = new HashMap();
        zzb(new zzj(context));
        zzb(new zzt(zzaVar2));
        zzb(new zzx(dataLayer));
        zzb(new zzdg(context, dataLayer));
        zzb(new zzdb(context, dataLayer));
        this.zzaNi = new HashMap();
        zzc(new zzr());
        zzc(new zzae());
        zzc(new zzaf());
        zzc(new zzam());
        zzc(new zzan());
        zzc(new zzbc());
        zzc(new zzbd());
        zzc(new zzcf());
        zzc(new zzcy());
        this.zzaNj = new HashMap();
        zza(new com.google.android.gms.tagmanager.zzb(context));
        zza(new com.google.android.gms.tagmanager.zzc(context));
        zza(new zze(context));
        zza(new zzf(context));
        zza(new zzg(context));
        zza(new zzh(context));
        zza(new zzi(context));
        zza(new zzn());
        zza(new zzq(this.zzaNf.getVersion()));
        zza(new zzt(zzaVar));
        zza(new zzv(dataLayer));
        zza(new zzaa(context));
        zza(new zzab());
        zza(new zzad());
        zza(new zzai(this));
        zza(new zzao());
        zza(new zzap());
        zza(new zzaw(context));
        zza(new zzay());
        zza(new zzbb());
        zza(new zzbi());
        zza(new zzbk(context));
        zza(new zzbx());
        zza(new zzbz());
        zza(new zzcc());
        zza(new zzce());
        zza(new zzcg(context));
        zza(new zzcq());
        zza(new zzcr());
        zza(new zzda());
        zza(new zzdh());
        this.zzaNn = new HashMap();
        for (zzqf.zze zzeVar : this.zzaNm) {
            if (zzahVar.zzyL()) {
                zza(zzeVar.zzAy(), zzeVar.zzAz(), "add macro");
                zza(zzeVar.zzAD(), zzeVar.zzAA(), "remove macro");
                zza(zzeVar.zzAw(), zzeVar.zzAB(), "add tag");
                zza(zzeVar.zzAx(), zzeVar.zzAC(), "remove tag");
            }
            for (int i = 0; i < zzeVar.zzAy().size(); i++) {
                zzqf.zza zzaVar3 = zzeVar.zzAy().get(i);
                String str = "Unknown";
                if (zzahVar.zzyL() && i < zzeVar.zzAz().size()) {
                    str = zzeVar.zzAz().get(i);
                }
                zzc zzh = zzh(this.zzaNn, zza(zzaVar3));
                zzh.zza(zzeVar);
                zzh.zza(zzeVar, zzaVar3);
                zzh.zza(zzeVar, str);
            }
            for (int i2 = 0; i2 < zzeVar.zzAD().size(); i2++) {
                zzqf.zza zzaVar4 = zzeVar.zzAD().get(i2);
                String str2 = "Unknown";
                if (zzahVar.zzyL() && i2 < zzeVar.zzAA().size()) {
                    str2 = zzeVar.zzAA().get(i2);
                }
                zzc zzh2 = zzh(this.zzaNn, zza(zzaVar4));
                zzh2.zza(zzeVar);
                zzh2.zzb(zzeVar, zzaVar4);
                zzh2.zzb(zzeVar, str2);
            }
        }
        for (Map.Entry<String, List<zzqf.zza>> entry : this.zzaNf.zzAr().entrySet()) {
            for (zzqf.zza zzaVar5 : entry.getValue()) {
                if (!zzdf.zzk(zzaVar5.zzAn().get(com.google.android.gms.internal.zzae.NOT_DEFAULT_MACRO.toString())).booleanValue()) {
                    zzh(this.zzaNn, entry.getKey()).zzb(zzaVar5);
                }
            }
        }
    }

    private zzbw<zzag.zza> zza(zzag.zza zzaVar, Set<String> set, zzdi zzdiVar) {
        if (zzaVar.zzjb) {
            switch (zzaVar.type) {
                case 2:
                    zzag.zza zzo = zzqf.zzo(zzaVar);
                    zzo.zziS = new zzag.zza[zzaVar.zziS.length];
                    for (int i = 0; i < zzaVar.zziS.length; i++) {
                        zzbw<zzag.zza> zza2 = zza(zzaVar.zziS[i], set, zzdiVar.zziU(i));
                        if (zza2 == zzaNe) {
                            return zzaNe;
                        }
                        zzo.zziS[i] = zza2.getObject();
                    }
                    return new zzbw<>(zzo, false);
                case 3:
                    zzag.zza zzo2 = zzqf.zzo(zzaVar);
                    if (zzaVar.zziT.length != zzaVar.zziU.length) {
                        zzbg.zzaz("Invalid serving value: " + zzaVar.toString());
                        return zzaNe;
                    }
                    zzo2.zziT = new zzag.zza[zzaVar.zziT.length];
                    zzo2.zziU = new zzag.zza[zzaVar.zziT.length];
                    for (int i2 = 0; i2 < zzaVar.zziT.length; i2++) {
                        zzbw<zzag.zza> zza3 = zza(zzaVar.zziT[i2], set, zzdiVar.zziV(i2));
                        zzbw<zzag.zza> zza4 = zza(zzaVar.zziU[i2], set, zzdiVar.zziW(i2));
                        if (zza3 == zzaNe || zza4 == zzaNe) {
                            return zzaNe;
                        }
                        zzo2.zziT[i2] = zza3.getObject();
                        zzo2.zziU[i2] = zza4.getObject();
                    }
                    return new zzbw<>(zzo2, false);
                case 4:
                    if (set.contains(zzaVar.zziV)) {
                        zzbg.zzaz("Macro cycle detected.  Current macro reference: " + zzaVar.zziV + ".  Previous macro references: " + set.toString() + ".");
                        return zzaNe;
                    }
                    set.add(zzaVar.zziV);
                    zzbw<zzag.zza> zza5 = zzdj.zza(zza(zzaVar.zziV, set, zzdiVar.zzyZ()), zzaVar.zzja);
                    set.remove(zzaVar.zziV);
                    return zza5;
                case 5:
                case 6:
                default:
                    zzbg.zzaz("Unknown type: " + zzaVar.type);
                    return zzaNe;
                case 7:
                    zzag.zza zzo3 = zzqf.zzo(zzaVar);
                    zzo3.zziZ = new zzag.zza[zzaVar.zziZ.length];
                    for (int i3 = 0; i3 < zzaVar.zziZ.length; i3++) {
                        zzbw<zzag.zza> zza6 = zza(zzaVar.zziZ[i3], set, zzdiVar.zziX(i3));
                        if (zza6 == zzaNe) {
                            return zzaNe;
                        }
                        zzo3.zziZ[i3] = zza6.getObject();
                    }
                    return new zzbw<>(zzo3, false);
            }
        }
        return new zzbw<>(zzaVar, true);
    }

    private zzbw<zzag.zza> zza(String str, Set<String> set, zzbj zzbjVar) {
        zzqf.zza next;
        this.zzaNp++;
        zzb zzbVar = this.zzaNl.get(str);
        if (zzbVar != null && !this.zzaNg.zzyL()) {
            zza(zzbVar.zzzs(), set);
            this.zzaNp--;
            return zzbVar.zzzr();
        }
        zzc zzcVar = this.zzaNn.get(str);
        if (zzcVar == null) {
            zzbg.zzaz(zzzq() + "Invalid macro: " + str);
            this.zzaNp--;
            return zzaNe;
        }
        zzbw<Set<zzqf.zza>> zza2 = zza(str, zzcVar.zzzt(), zzcVar.zzzu(), zzcVar.zzzv(), zzcVar.zzzx(), zzcVar.zzzw(), set, zzbjVar.zzyB());
        if (zza2.getObject().isEmpty()) {
            next = zzcVar.zzzy();
        } else {
            if (zza2.getObject().size() > 1) {
                zzbg.zzaC(zzzq() + "Multiple macros active for macroName " + str);
            }
            next = zza2.getObject().iterator().next();
        }
        if (next == null) {
            this.zzaNp--;
            return zzaNe;
        }
        zzbw<zzag.zza> zza3 = zza(this.zzaNj, next, set, zzbjVar.zzyR());
        zzbw<zzag.zza> zzbwVar = zza3 == zzaNe ? zzaNe : new zzbw<>(zza3.getObject(), zza2.zzza() && zza3.zzza());
        zzag.zza zzzs = next.zzzs();
        if (zzbwVar.zzza()) {
            this.zzaNl.zzf(str, new zzb(zzbwVar, zzzs));
        }
        zza(zzzs, set);
        this.zzaNp--;
        return zzbwVar;
    }

    private zzbw<zzag.zza> zza(Map<String, zzak> map, zzqf.zza zzaVar, Set<String> set, zzch zzchVar) {
        boolean z;
        boolean z2 = true;
        zzag.zza zzaVar2 = zzaVar.zzAn().get(com.google.android.gms.internal.zzae.FUNCTION.toString());
        if (zzaVar2 == null) {
            zzbg.zzaz("No function id in properties");
            return zzaNe;
        }
        String str = zzaVar2.zziW;
        zzak zzakVar = map.get(str);
        if (zzakVar == null) {
            zzbg.zzaz(str + " has no backing implementation.");
            return zzaNe;
        }
        zzbw<zzag.zza> zzbwVar = this.zzaNk.get(zzaVar);
        if (zzbwVar == null || this.zzaNg.zzyL()) {
            HashMap hashMap = new HashMap();
            boolean z3 = true;
            for (Map.Entry<String, zzag.zza> entry : zzaVar.zzAn().entrySet()) {
                zzbw<zzag.zza> zza2 = zza(entry.getValue(), set, zzchVar.zzez(entry.getKey()).zze(entry.getValue()));
                if (zza2 == zzaNe) {
                    return zzaNe;
                }
                if (zza2.zzza()) {
                    zzaVar.zza(entry.getKey(), zza2.getObject());
                    z = z3;
                } else {
                    z = false;
                }
                hashMap.put(entry.getKey(), zza2.getObject());
                z3 = z;
            }
            if (!zzakVar.zzg(hashMap.keySet())) {
                zzbg.zzaz("Incorrect keys for function " + str + " required " + zzakVar.zzyN() + " had " + hashMap.keySet());
                return zzaNe;
            }
            z2 = (z3 && zzakVar.zzyh()) ? false : false;
            zzbw<zzag.zza> zzbwVar2 = new zzbw<>(zzakVar.zzE(hashMap), z2);
            if (z2) {
                this.zzaNk.zzf(zzaVar, zzbwVar2);
            }
            zzchVar.zzd(zzbwVar2.getObject());
            return zzbwVar2;
        }
        return zzbwVar;
    }

    private zzbw<Set<zzqf.zza>> zza(Set<zzqf.zze> set, Set<String> set2, zza zzaVar, zzco zzcoVar) {
        Set<zzqf.zza> hashSet = new HashSet<>();
        Set<zzqf.zza> hashSet2 = new HashSet<>();
        boolean z = true;
        for (zzqf.zze zzeVar : set) {
            zzck zzyY = zzcoVar.zzyY();
            zzbw<Boolean> zza2 = zza(zzeVar, set2, zzyY);
            if (zza2.getObject().booleanValue()) {
                zzaVar.zza(zzeVar, hashSet, hashSet2, zzyY);
            }
            z = z && zza2.zzza();
        }
        hashSet.removeAll(hashSet2);
        zzcoVar.zzh(hashSet);
        return new zzbw<>(hashSet, z);
    }

    private static String zza(zzqf.zza zzaVar) {
        return zzdf.zzg(zzaVar.zzAn().get(com.google.android.gms.internal.zzae.INSTANCE_NAME.toString()));
    }

    private void zza(zzag.zza zzaVar, Set<String> set) {
        zzbw<zzag.zza> zza2;
        if (zzaVar == null || (zza2 = zza(zzaVar, set, new zzbu())) == zzaNe) {
            return;
        }
        Object zzl = zzdf.zzl(zza2.getObject());
        if (zzl instanceof Map) {
            this.zzaKz.push((Map) zzl);
        } else if (!(zzl instanceof List)) {
            zzbg.zzaC("pushAfterEvaluate: value not a Map or List");
        } else {
            for (Object obj : (List) zzl) {
                if (obj instanceof Map) {
                    this.zzaKz.push((Map) obj);
                } else {
                    zzbg.zzaC("pushAfterEvaluate: value not a Map");
                }
            }
        }
    }

    private static void zza(List<zzqf.zza> list, List<String> list2, String str) {
        if (list.size() != list2.size()) {
            zzbg.zzaA("Invalid resource: imbalance of rule names of functions for " + str + " operation. Using default rule name instead");
        }
    }

    private static void zza(Map<String, zzak> map, zzak zzakVar) {
        if (map.containsKey(zzakVar.zzyM())) {
            throw new IllegalArgumentException("Duplicate function type name: " + zzakVar.zzyM());
        }
        map.put(zzakVar.zzyM(), zzakVar);
    }

    private static zzc zzh(Map<String, zzc> map, String str) {
        zzc zzcVar = map.get(str);
        if (zzcVar == null) {
            zzc zzcVar2 = new zzc();
            map.put(str, zzcVar2);
            return zzcVar2;
        }
        return zzcVar;
    }

    private String zzzq() {
        if (this.zzaNp <= 1) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(Integer.toString(this.zzaNp));
        for (int i = 2; i < this.zzaNp; i++) {
            sb.append(' ');
        }
        sb.append(": ");
        return sb.toString();
    }

    zzbw<Boolean> zza(zzqf.zza zzaVar, Set<String> set, zzch zzchVar) {
        zzbw<zzag.zza> zza2 = zza(this.zzaNi, zzaVar, set, zzchVar);
        Boolean zzk = zzdf.zzk(zza2.getObject());
        zzchVar.zzd(zzdf.zzI(zzk));
        return new zzbw<>(zzk, zza2.zzza());
    }

    zzbw<Boolean> zza(zzqf.zze zzeVar, Set<String> set, zzck zzckVar) {
        boolean z = true;
        for (zzqf.zza zzaVar : zzeVar.zzAv()) {
            zzbw<Boolean> zza2 = zza(zzaVar, set, zzckVar.zzyS());
            if (zza2.getObject().booleanValue()) {
                zzckVar.zzf(zzdf.zzI(false));
                return new zzbw<>(false, zza2.zzza());
            }
            z = z && zza2.zzza();
        }
        for (zzqf.zza zzaVar2 : zzeVar.zzAu()) {
            zzbw<Boolean> zza3 = zza(zzaVar2, set, zzckVar.zzyT());
            if (!zza3.getObject().booleanValue()) {
                zzckVar.zzf(zzdf.zzI(false));
                return new zzbw<>(false, zza3.zzza());
            }
            z = z && zza3.zzza();
        }
        zzckVar.zzf(zzdf.zzI(true));
        return new zzbw<>(true, z);
    }

    zzbw<Set<zzqf.zza>> zza(String str, Set<zzqf.zze> set, final Map<zzqf.zze, List<zzqf.zza>> map, final Map<zzqf.zze, List<String>> map2, final Map<zzqf.zze, List<zzqf.zza>> map3, final Map<zzqf.zze, List<String>> map4, Set<String> set2, zzco zzcoVar) {
        return zza(set, set2, new zza() { // from class: com.google.android.gms.tagmanager.zzcp.3
            @Override // com.google.android.gms.tagmanager.zzcp.zza
            public void zza(zzqf.zze zzeVar, Set<zzqf.zza> set3, Set<zzqf.zza> set4, zzck zzckVar) {
                List<zzqf.zza> list = (List) map.get(zzeVar);
                List<String> list2 = (List) map2.get(zzeVar);
                if (list != null) {
                    set3.addAll(list);
                    zzckVar.zzyU().zzc(list, list2);
                }
                List<zzqf.zza> list3 = (List) map3.get(zzeVar);
                List<String> list4 = (List) map4.get(zzeVar);
                if (list3 != null) {
                    set4.addAll(list3);
                    zzckVar.zzyV().zzc(list3, list4);
                }
            }
        }, zzcoVar);
    }

    zzbw<Set<zzqf.zza>> zza(Set<zzqf.zze> set, zzco zzcoVar) {
        return zza(set, new HashSet(), new zza() { // from class: com.google.android.gms.tagmanager.zzcp.4
            @Override // com.google.android.gms.tagmanager.zzcp.zza
            public void zza(zzqf.zze zzeVar, Set<zzqf.zza> set2, Set<zzqf.zza> set3, zzck zzckVar) {
                set2.addAll(zzeVar.zzAw());
                set3.addAll(zzeVar.zzAx());
                zzckVar.zzyW().zzc(zzeVar.zzAw(), zzeVar.zzAB());
                zzckVar.zzyX().zzc(zzeVar.zzAx(), zzeVar.zzAC());
            }
        }, zzcoVar);
    }

    void zza(zzak zzakVar) {
        zza(this.zzaNj, zzakVar);
    }

    void zzb(zzak zzakVar) {
        zza(this.zzaNh, zzakVar);
    }

    void zzc(zzak zzakVar) {
        zza(this.zzaNi, zzakVar);
    }

    public zzbw<zzag.zza> zzeD(String str) {
        this.zzaNp = 0;
        zzag zzet = this.zzaNg.zzet(str);
        zzbw<zzag.zza> zza2 = zza(str, new HashSet(), zzet.zzyI());
        zzet.zzyK();
        return zza2;
    }

    synchronized void zzeE(String str) {
        this.zzaNo = str;
    }

    public synchronized void zzeh(String str) {
        zzeE(str);
        zzag zzeu = this.zzaNg.zzeu(str);
        zzu zzyJ = zzeu.zzyJ();
        for (zzqf.zza zzaVar : zza(this.zzaNm, zzyJ.zzyB()).getObject()) {
            zza(this.zzaNh, zzaVar, new HashSet(), zzyJ.zzyA());
        }
        zzeu.zzyK();
        zzeE(null);
    }

    public synchronized void zzs(List<zzaf.zzi> list) {
        for (zzaf.zzi zziVar : list) {
            if (zziVar.name == null || !zziVar.name.startsWith("gaExperiment:")) {
                zzbg.zzaB("Ignored supplemental: " + zziVar);
            } else {
                zzaj.zza(this.zzaKz, zziVar);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized String zzzp() {
        return this.zzaNo;
    }
}
