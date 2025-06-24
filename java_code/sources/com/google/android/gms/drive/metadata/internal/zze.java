package com.google.android.gms.drive.metadata.internal;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.internal.zzlo;
import com.google.android.gms.internal.zzlq;
import com.google.android.gms.internal.zzls;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public final class zze {
    private static final Map<String, MetadataField<?>> zzagH = new HashMap();

    static {
        zzb(zzlo.zzagK);
        zzb(zzlo.zzahp);
        zzb(zzlo.zzahg);
        zzb(zzlo.zzahn);
        zzb(zzlo.zzahq);
        zzb(zzlo.zzagX);
        zzb(zzlo.zzagW);
        zzb(zzlo.zzagY);
        zzb(zzlo.zzagZ);
        zzb(zzlo.zzagU);
        zzb(zzlo.zzahb);
        zzb(zzlo.zzahc);
        zzb(zzlo.zzahd);
        zzb(zzlo.zzahl);
        zzb(zzlo.zzagL);
        zzb(zzlo.zzahi);
        zzb(zzlo.zzagN);
        zzb(zzlo.zzagV);
        zzb(zzlo.zzagO);
        zzb(zzlo.zzagP);
        zzb(zzlo.zzagQ);
        zzb(zzlo.zzagR);
        zzb(zzlo.zzahf);
        zzb(zzlo.zzaha);
        zzb(zzlo.zzahh);
        zzb(zzlo.zzahj);
        zzb(zzlo.zzahk);
        zzb(zzlo.zzahm);
        zzb(zzlo.zzahr);
        zzb(zzlo.zzahs);
        zzb(zzlo.zzagT);
        zzb(zzlo.zzagS);
        zzb(zzlo.zzaho);
        zzb(zzlo.zzahe);
        zzb(zzlo.zzagM);
        zzb(zzlo.zzaht);
        zzb(zzlo.zzahu);
        zzb(zzlo.zzahv);
        zzb(zzlo.zzahw);
        zzb(zzlo.zzahx);
        zzb(zzlq.zzahy);
        zzb(zzlq.zzahA);
        zzb(zzlq.zzahB);
        zzb(zzlq.zzahC);
        zzb(zzlq.zzahz);
        zzb(zzls.zzahE);
        zzb(zzls.zzahF);
    }

    public static void zzb(DataHolder dataHolder) {
        zzlo.zzahl.zzd(dataHolder);
    }

    private static void zzb(MetadataField<?> metadataField) {
        if (zzagH.containsKey(metadataField.getName())) {
            throw new IllegalArgumentException("Duplicate field name registered: " + metadataField.getName());
        }
        zzagH.put(metadataField.getName(), metadataField);
    }

    public static MetadataField<?> zzcw(String str) {
        return zzagH.get(str);
    }

    public static Collection<MetadataField<?>> zzpW() {
        return Collections.unmodifiableCollection(zzagH.values());
    }
}
