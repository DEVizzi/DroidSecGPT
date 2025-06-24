package com.google.android.gms.drive.metadata.internal;

import android.os.Bundle;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.Collection;
/* loaded from: classes.dex */
public class zzi<T extends Parcelable> extends com.google.android.gms.drive.metadata.zzb<T> {
    public zzi(String str, Collection<String> collection, Collection<String> collection2, int i) {
        super(str, collection, collection2, i);
    }

    @Override // com.google.android.gms.drive.metadata.zza
    protected /* bridge */ /* synthetic */ void zza(Bundle bundle, Object obj) {
        zza(bundle, (Collection) ((Collection) obj));
    }

    protected void zza(Bundle bundle, Collection<T> collection) {
        bundle.putParcelableArrayList(getName(), collection instanceof ArrayList ? (ArrayList) collection : new ArrayList<>(collection));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.drive.metadata.zza
    /* renamed from: zzo */
    public Collection<T> zzj(Bundle bundle) {
        return bundle.getParcelableArrayList(getName());
    }
}
