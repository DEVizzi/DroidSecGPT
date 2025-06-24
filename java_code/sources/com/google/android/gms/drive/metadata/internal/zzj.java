package com.google.android.gms.drive.metadata.internal;

import android.os.Bundle;
import android.os.Parcelable;
import java.util.Collection;
/* loaded from: classes.dex */
public abstract class zzj<T extends Parcelable> extends com.google.android.gms.drive.metadata.zza<T> {
    public zzj(String str, Collection<String> collection, Collection<String> collection2, int i) {
        super(str, collection, collection2, i);
    }

    protected void zza(Bundle bundle, T t) {
        bundle.putParcelable(getName(), t);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.drive.metadata.zza
    protected /* bridge */ /* synthetic */ void zza(Bundle bundle, Object obj) {
        zza(bundle, (Bundle) obj);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.drive.metadata.zza
    /* renamed from: zzp */
    public T zzj(Bundle bundle) {
        return (T) bundle.getParcelable(getName());
    }
}
