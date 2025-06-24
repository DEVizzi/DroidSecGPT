package com.google.android.gms.internal;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.drive.metadata.internal.AppVisibleCustomProperties;
import java.util.Arrays;
/* loaded from: classes.dex */
public class zzlp extends com.google.android.gms.drive.metadata.internal.zzj<AppVisibleCustomProperties> {
    public zzlp(int i) {
        super("customProperties", Arrays.asList("customProperties", "sqlId"), Arrays.asList("customPropertiesExtra"), i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.drive.metadata.zza
    /* renamed from: zzl */
    public AppVisibleCustomProperties zzc(DataHolder dataHolder, int i, int i2) {
        return (AppVisibleCustomProperties) dataHolder.zznb().getSparseParcelableArray("customPropertiesExtra").get(i, AppVisibleCustomProperties.zzagD);
    }
}
