package com.google.android.gms.analytics;

import android.net.Uri;
import android.text.TextUtils;
import com.google.android.gms.analytics.ecommerce.Product;
import com.google.android.gms.analytics.ecommerce.ProductAction;
import com.google.android.gms.analytics.ecommerce.Promotion;
import com.google.android.gms.analytics.internal.zzab;
import com.google.android.gms.analytics.internal.zzam;
import com.google.android.gms.analytics.internal.zze;
import com.google.android.gms.analytics.internal.zzf;
import com.google.android.gms.analytics.internal.zzh;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzim;
import com.google.android.gms.internal.zzin;
import com.google.android.gms.internal.zzio;
import com.google.android.gms.internal.zzip;
import com.google.android.gms.internal.zzno;
import com.google.android.gms.internal.zznu;
import com.google.android.gms.internal.zznx;
import com.google.android.gms.internal.zzny;
import com.google.android.gms.internal.zznz;
import com.google.android.gms.internal.zzoa;
import com.google.android.gms.internal.zzob;
import com.google.android.gms.internal.zzoc;
import com.google.android.gms.internal.zzod;
import com.google.android.gms.internal.zzoe;
import com.google.android.gms.internal.zzof;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public class zzb extends com.google.android.gms.analytics.internal.zzc implements zznu {
    private static DecimalFormat zzIk;
    private final zzf zzIa;
    private final Uri zzIl;
    private final boolean zzIm;
    private final boolean zzIn;
    private final String zztd;

    public zzb(zzf zzfVar, String str) {
        this(zzfVar, str, true, false);
    }

    public zzb(zzf zzfVar, String str, boolean z, boolean z2) {
        super(zzfVar);
        zzu.zzcj(str);
        this.zzIa = zzfVar;
        this.zztd = str;
        this.zzIm = z;
        this.zzIn = z2;
        this.zzIl = zzaK(this.zztd);
    }

    static String zza(double d) {
        if (zzIk == null) {
            zzIk = new DecimalFormat("0.######");
        }
        return zzIk.format(d);
    }

    private static void zza(Map<String, String> map, String str, double d) {
        if (d != 0.0d) {
            map.put(str, zza(d));
        }
    }

    private static void zza(Map<String, String> map, String str, int i, int i2) {
        if (i <= 0 || i2 <= 0) {
            return;
        }
        map.put(str, i + "x" + i2);
    }

    private static void zza(Map<String, String> map, String str, String str2) {
        if (TextUtils.isEmpty(str2)) {
            return;
        }
        map.put(str, str2);
    }

    private static void zza(Map<String, String> map, String str, boolean z) {
        if (z) {
            map.put(str, "1");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Uri zzaK(String str) {
        zzu.zzcj(str);
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("uri");
        builder.authority("google-analytics.com");
        builder.path(str);
        return builder.build();
    }

    public static Map<String, String> zzc(zzno zznoVar) {
        HashMap hashMap = new HashMap();
        zzio zzioVar = (zzio) zznoVar.zzd(zzio.class);
        if (zzioVar != null) {
            for (Map.Entry<String, Object> entry : zzioVar.zzhv().entrySet()) {
                String zzh = zzh(entry.getValue());
                if (zzh != null) {
                    hashMap.put(entry.getKey(), zzh);
                }
            }
        }
        zzip zzipVar = (zzip) zznoVar.zzd(zzip.class);
        if (zzipVar != null) {
            zza(hashMap, "t", zzipVar.zzhw());
            zza(hashMap, "cid", zzipVar.getClientId());
            zza(hashMap, "uid", zzipVar.getUserId());
            zza(hashMap, "sc", zzipVar.zzhz());
            zza(hashMap, "sf", zzipVar.zzhB());
            zza(hashMap, "ni", zzipVar.zzhA());
            zza(hashMap, "adid", zzipVar.zzhx());
            zza(hashMap, "ate", zzipVar.zzhy());
        }
        zzod zzodVar = (zzod) zznoVar.zzd(zzod.class);
        if (zzodVar != null) {
            zza(hashMap, "cd", zzodVar.zzwB());
            zza(hashMap, "a", zzodVar.zzbn());
            zza(hashMap, "dr", zzodVar.zzwE());
        }
        zzob zzobVar = (zzob) zznoVar.zzd(zzob.class);
        if (zzobVar != null) {
            zza(hashMap, "ec", zzobVar.zzwy());
            zza(hashMap, "ea", zzobVar.getAction());
            zza(hashMap, "el", zzobVar.getLabel());
            zza(hashMap, "ev", zzobVar.getValue());
        }
        zzny zznyVar = (zzny) zznoVar.zzd(zzny.class);
        if (zznyVar != null) {
            zza(hashMap, "cn", zznyVar.getName());
            zza(hashMap, "cs", zznyVar.getSource());
            zza(hashMap, "cm", zznyVar.zzwj());
            zza(hashMap, "ck", zznyVar.zzwk());
            zza(hashMap, "cc", zznyVar.getContent());
            zza(hashMap, "ci", zznyVar.getId());
            zza(hashMap, "anid", zznyVar.zzwl());
            zza(hashMap, "gclid", zznyVar.zzwm());
            zza(hashMap, "dclid", zznyVar.zzwn());
            zza(hashMap, "aclid", zznyVar.zzwo());
        }
        zzoc zzocVar = (zzoc) zznoVar.zzd(zzoc.class);
        if (zzocVar != null) {
            zza(hashMap, "exd", zzocVar.getDescription());
            zza(hashMap, "exf", zzocVar.zzwz());
        }
        zzoe zzoeVar = (zzoe) zznoVar.zzd(zzoe.class);
        if (zzoeVar != null) {
            zza(hashMap, "sn", zzoeVar.zzwI());
            zza(hashMap, "sa", zzoeVar.getAction());
            zza(hashMap, "st", zzoeVar.getTarget());
        }
        zzof zzofVar = (zzof) zznoVar.zzd(zzof.class);
        if (zzofVar != null) {
            zza(hashMap, "utv", zzofVar.zzwJ());
            zza(hashMap, "utt", zzofVar.getTimeInMillis());
            zza(hashMap, "utc", zzofVar.zzwy());
            zza(hashMap, "utl", zzofVar.getLabel());
        }
        zzim zzimVar = (zzim) zznoVar.zzd(zzim.class);
        if (zzimVar != null) {
            for (Map.Entry<Integer, String> entry2 : zzimVar.zzht().entrySet()) {
                String zzO = zzc.zzO(entry2.getKey().intValue());
                if (!TextUtils.isEmpty(zzO)) {
                    hashMap.put(zzO, entry2.getValue());
                }
            }
        }
        zzin zzinVar = (zzin) zznoVar.zzd(zzin.class);
        if (zzinVar != null) {
            for (Map.Entry<Integer, Double> entry3 : zzinVar.zzhu().entrySet()) {
                String zzQ = zzc.zzQ(entry3.getKey().intValue());
                if (!TextUtils.isEmpty(zzQ)) {
                    hashMap.put(zzQ, zza(entry3.getValue().doubleValue()));
                }
            }
        }
        zzoa zzoaVar = (zzoa) zznoVar.zzd(zzoa.class);
        if (zzoaVar != null) {
            ProductAction zzwu = zzoaVar.zzwu();
            if (zzwu != null) {
                for (Map.Entry<String, String> entry4 : zzwu.build().entrySet()) {
                    if (entry4.getKey().startsWith("&")) {
                        hashMap.put(entry4.getKey().substring(1), entry4.getValue());
                    } else {
                        hashMap.put(entry4.getKey(), entry4.getValue());
                    }
                }
            }
            int i = 1;
            for (Promotion promotion : zzoaVar.zzwx()) {
                hashMap.putAll(promotion.zzaQ(zzc.zzU(i)));
                i++;
            }
            int i2 = 1;
            for (Product product : zzoaVar.zzwv()) {
                hashMap.putAll(product.zzaQ(zzc.zzS(i2)));
                i2++;
            }
            int i3 = 1;
            for (Map.Entry<String, List<Product>> entry5 : zzoaVar.zzww().entrySet()) {
                String zzX = zzc.zzX(i3);
                int i4 = 1;
                for (Product product2 : entry5.getValue()) {
                    hashMap.putAll(product2.zzaQ(zzX + zzc.zzV(i4)));
                    i4++;
                }
                if (!TextUtils.isEmpty(entry5.getKey())) {
                    hashMap.put(zzX + "nm", entry5.getKey());
                }
                i3++;
            }
        }
        zznz zznzVar = (zznz) zznoVar.zzd(zznz.class);
        if (zznzVar != null) {
            zza(hashMap, "ul", zznzVar.getLanguage());
            zza(hashMap, "sd", zznzVar.zzwp());
            zza(hashMap, "sr", zznzVar.zzwq(), zznzVar.zzwr());
            zza(hashMap, "vp", zznzVar.zzws(), zznzVar.zzwt());
        }
        zznx zznxVar = (zznx) zznoVar.zzd(zznx.class);
        if (zznxVar != null) {
            zza(hashMap, "an", zznxVar.zzjL());
            zza(hashMap, "aid", zznxVar.zzsK());
            zza(hashMap, "aiid", zznxVar.zzwi());
            zza(hashMap, "av", zznxVar.zzjN());
        }
        return hashMap;
    }

    private static String zzh(Object obj) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof String) {
            String str = (String) obj;
            if (TextUtils.isEmpty(str)) {
                return null;
            }
            return str;
        } else if (obj instanceof Double) {
            Double d = (Double) obj;
            if (d.doubleValue() != 0.0d) {
                return zza(d.doubleValue());
            }
            return null;
        } else if (obj instanceof Boolean) {
            if (obj != Boolean.FALSE) {
                return "1";
            }
            return null;
        } else {
            return String.valueOf(obj);
        }
    }

    private static String zzz(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (sb.length() != 0) {
                sb.append(", ");
            }
            sb.append(entry.getKey());
            sb.append("=");
            sb.append(entry.getValue());
        }
        return sb.toString();
    }

    @Override // com.google.android.gms.internal.zznu
    public void zzb(zzno zznoVar) {
        zzu.zzu(zznoVar);
        zzu.zzb(zznoVar.zzvU(), "Can't deliver not submitted measurement");
        zzu.zzbZ("deliver should be called on worker thread");
        zzno zzvP = zznoVar.zzvP();
        zzip zzipVar = (zzip) zzvP.zze(zzip.class);
        if (TextUtils.isEmpty(zzipVar.zzhw())) {
            zzhQ().zzg(zzc(zzvP), "Ignoring measurement without type");
        } else if (TextUtils.isEmpty(zzipVar.getClientId())) {
            zzhQ().zzg(zzc(zzvP), "Ignoring measurement without client id");
        } else if (this.zzIa.zzie().getAppOptOut()) {
        } else {
            double zzhB = zzipVar.zzhB();
            if (zzam.zza(zzhB, zzipVar.getClientId())) {
                zzb("Sampling enabled. Hit sampled out. sampling rate", Double.valueOf(zzhB));
                return;
            }
            Map<String, String> zzc = zzc(zzvP);
            zzc.put("v", "1");
            zzc.put("_v", zze.zzJB);
            zzc.put("tid", this.zztd);
            if (this.zzIa.zzie().isDryRunEnabled()) {
                zzc("Dry run is enabled. GoogleAnalytics would have sent", zzz(zzc));
                return;
            }
            HashMap hashMap = new HashMap();
            zzam.zzb(hashMap, "uid", zzipVar.getUserId());
            zznx zznxVar = (zznx) zznoVar.zzd(zznx.class);
            if (zznxVar != null) {
                zzam.zzb(hashMap, "an", zznxVar.zzjL());
                zzam.zzb(hashMap, "aid", zznxVar.zzsK());
                zzam.zzb(hashMap, "av", zznxVar.zzjN());
                zzam.zzb(hashMap, "aiid", zznxVar.zzwi());
            }
            zzc.put("_s", String.valueOf(zzhl().zza(new zzh(0L, zzipVar.getClientId(), this.zztd, !TextUtils.isEmpty(zzipVar.zzhx()), 0L, hashMap))));
            zzhl().zza(new zzab(zzhQ(), zzc, zznoVar.zzvS(), true));
        }
    }

    @Override // com.google.android.gms.internal.zznu
    public Uri zzhe() {
        return this.zzIl;
    }
}
