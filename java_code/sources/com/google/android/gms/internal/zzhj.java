package com.google.android.gms.internal;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import java.util.concurrent.Future;
@zzgd
/* loaded from: classes.dex */
public final class zzhj {

    /* loaded from: classes.dex */
    private static abstract class zza extends zzhh {
        private zza() {
        }

        @Override // com.google.android.gms.internal.zzhh
        public void onStop() {
        }
    }

    /* loaded from: classes.dex */
    public interface zzb {
        void zzc(Bundle bundle);
    }

    public static Future zza(final Context context, final int i) {
        return new zza() { // from class: com.google.android.gms.internal.zzhj.3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            @Override // com.google.android.gms.internal.zzhh
            public void zzdP() {
                SharedPreferences.Editor edit = zzhj.zzv(context).edit();
                edit.putInt("webview_cache_version", i);
                edit.commit();
            }
        }.zzgi();
    }

    public static Future zza(final Context context, final zzb zzbVar) {
        return new zza() { // from class: com.google.android.gms.internal.zzhj.2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            @Override // com.google.android.gms.internal.zzhh
            public void zzdP() {
                SharedPreferences zzv = zzhj.zzv(context);
                Bundle bundle = new Bundle();
                bundle.putBoolean("use_https", zzv.getBoolean("use_https", true));
                if (zzbVar != null) {
                    zzbVar.zzc(bundle);
                }
            }
        }.zzgi();
    }

    public static Future zza(final Context context, final boolean z) {
        return new zza() { // from class: com.google.android.gms.internal.zzhj.1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            @Override // com.google.android.gms.internal.zzhh
            public void zzdP() {
                SharedPreferences.Editor edit = zzhj.zzv(context).edit();
                edit.putBoolean("use_https", z);
                edit.commit();
            }
        }.zzgi();
    }

    public static Future zzb(final Context context, final zzb zzbVar) {
        return new zza() { // from class: com.google.android.gms.internal.zzhj.4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            @Override // com.google.android.gms.internal.zzhh
            public void zzdP() {
                SharedPreferences zzv = zzhj.zzv(context);
                Bundle bundle = new Bundle();
                bundle.putInt("webview_cache_version", zzv.getInt("webview_cache_version", 0));
                if (zzbVar != null) {
                    zzbVar.zzc(bundle);
                }
            }
        }.zzgi();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static SharedPreferences zzv(Context context) {
        return context.getSharedPreferences("admob", 0);
    }
}
