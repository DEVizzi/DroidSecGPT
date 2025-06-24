package com.google.android.gms.analytics.internal;

import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Pair;
import java.util.UUID;
/* loaded from: classes.dex */
public class zzai extends zzd {
    private SharedPreferences zzMw;
    private long zzMx;
    private long zzMy;
    private final zza zzMz;

    /* loaded from: classes.dex */
    public final class zza {
        private final String mName;
        private final long zzMA;

        private zza(String str, long j) {
            com.google.android.gms.common.internal.zzu.zzcj(str);
            com.google.android.gms.common.internal.zzu.zzV(j > 0);
            this.mName = str;
            this.zzMA = j;
        }

        private void zzkq() {
            long currentTimeMillis = zzai.this.zzhP().currentTimeMillis();
            SharedPreferences.Editor edit = zzai.this.zzMw.edit();
            edit.remove(zzkv());
            edit.remove(zzkw());
            edit.putLong(zzku(), currentTimeMillis);
            edit.commit();
        }

        private long zzkr() {
            long zzkt = zzkt();
            if (zzkt == 0) {
                return 0L;
            }
            return Math.abs(zzkt - zzai.this.zzhP().currentTimeMillis());
        }

        private long zzkt() {
            return zzai.this.zzMw.getLong(zzku(), 0L);
        }

        private String zzku() {
            return this.mName + ":start";
        }

        private String zzkv() {
            return this.mName + ":count";
        }

        public void zzbg(String str) {
            if (zzkt() == 0) {
                zzkq();
            }
            if (str == null) {
                str = "";
            }
            synchronized (this) {
                long j = zzai.this.zzMw.getLong(zzkv(), 0L);
                if (j <= 0) {
                    SharedPreferences.Editor edit = zzai.this.zzMw.edit();
                    edit.putString(zzkw(), str);
                    edit.putLong(zzkv(), 1L);
                    edit.apply();
                    return;
                }
                boolean z = (UUID.randomUUID().getLeastSignificantBits() & Long.MAX_VALUE) < Long.MAX_VALUE / (j + 1);
                SharedPreferences.Editor edit2 = zzai.this.zzMw.edit();
                if (z) {
                    edit2.putString(zzkw(), str);
                }
                edit2.putLong(zzkv(), j + 1);
                edit2.apply();
            }
        }

        public Pair<String, Long> zzks() {
            long zzkr = zzkr();
            if (zzkr < this.zzMA) {
                return null;
            }
            if (zzkr > this.zzMA * 2) {
                zzkq();
                return null;
            }
            String string = zzai.this.zzMw.getString(zzkw(), null);
            long j = zzai.this.zzMw.getLong(zzkv(), 0L);
            zzkq();
            if (string == null || j <= 0) {
                return null;
            }
            return new Pair<>(string, Long.valueOf(j));
        }

        protected String zzkw() {
            return this.mName + ":value";
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzai(zzf zzfVar) {
        super(zzfVar);
        this.zzMy = -1L;
        this.zzMz = new zza("monitoring", zzhR().zzjC());
    }

    public void zzbf(String str) {
        zzhO();
        zzia();
        SharedPreferences.Editor edit = this.zzMw.edit();
        if (TextUtils.isEmpty(str)) {
            edit.remove("installation_campaign");
        } else {
            edit.putString("installation_campaign", str);
        }
        if (edit.commit()) {
            return;
        }
        zzaW("Failed to commit campaign data");
    }

    @Override // com.google.android.gms.analytics.internal.zzd
    protected void zzhn() {
        this.zzMw = getContext().getSharedPreferences("com.google.android.gms.analytics.prefs", 0);
    }

    public long zzkk() {
        zzhO();
        zzia();
        if (this.zzMx == 0) {
            long j = this.zzMw.getLong("first_run", 0L);
            if (j != 0) {
                this.zzMx = j;
            } else {
                long currentTimeMillis = zzhP().currentTimeMillis();
                SharedPreferences.Editor edit = this.zzMw.edit();
                edit.putLong("first_run", currentTimeMillis);
                if (!edit.commit()) {
                    zzaW("Failed to commit first run time");
                }
                this.zzMx = currentTimeMillis;
            }
        }
        return this.zzMx;
    }

    public zzaj zzkl() {
        return new zzaj(zzhP(), zzkk());
    }

    public long zzkm() {
        zzhO();
        zzia();
        if (this.zzMy == -1) {
            this.zzMy = this.zzMw.getLong("last_dispatch", 0L);
        }
        return this.zzMy;
    }

    public void zzkn() {
        zzhO();
        zzia();
        long currentTimeMillis = zzhP().currentTimeMillis();
        SharedPreferences.Editor edit = this.zzMw.edit();
        edit.putLong("last_dispatch", currentTimeMillis);
        edit.apply();
        this.zzMy = currentTimeMillis;
    }

    public String zzko() {
        zzhO();
        zzia();
        String string = this.zzMw.getString("installation_campaign", null);
        if (TextUtils.isEmpty(string)) {
            return null;
        }
        return string;
    }

    public zza zzkp() {
        return this.zzMz;
    }
}
