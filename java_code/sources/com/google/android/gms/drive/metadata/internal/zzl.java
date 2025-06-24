package com.google.android.gms.drive.metadata.internal;

import android.os.Bundle;
import android.os.Parcelable;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.metadata.SearchableCollectionMetadataField;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
/* loaded from: classes.dex */
public class zzl extends zzi<DriveId> implements SearchableCollectionMetadataField<DriveId> {
    public zzl(int i) {
        super("parents", Collections.emptySet(), Arrays.asList("parentsExtra", "dbInstanceId", "parentsExtraHolder"), i);
    }

    private void zzc(DataHolder dataHolder) {
        synchronized (dataHolder) {
            DataHolder dataHolder2 = (DataHolder) dataHolder.zznb().getParcelable("parentsExtraHolder");
            if (dataHolder2 == null) {
                return;
            }
            int count = dataHolder.getCount();
            ArrayList<? extends Parcelable> arrayList = new ArrayList<>(count);
            HashMap hashMap = new HashMap(count);
            for (int i = 0; i < count; i++) {
                int zzbh = dataHolder.zzbh(i);
                ParentDriveIdSet parentDriveIdSet = new ParentDriveIdSet();
                arrayList.add(parentDriveIdSet);
                hashMap.put(Long.valueOf(dataHolder.zzb("sqlId", i, zzbh)), parentDriveIdSet);
            }
            Bundle zznb = dataHolder2.zznb();
            String string = zznb.getString("childSqlIdColumn");
            String string2 = zznb.getString("parentSqlIdColumn");
            String string3 = zznb.getString("parentResIdColumn");
            int count2 = dataHolder2.getCount();
            for (int i2 = 0; i2 < count2; i2++) {
                int zzbh2 = dataHolder2.zzbh(i2);
                ((ParentDriveIdSet) hashMap.get(Long.valueOf(dataHolder2.zzb(string, i2, zzbh2)))).zza(new PartialDriveId(dataHolder2.zzd(string3, i2, zzbh2), dataHolder2.zzb(string2, i2, zzbh2), 1));
            }
            dataHolder.zznb().putParcelableArrayList("parentsExtra", arrayList);
            dataHolder2.close();
            dataHolder.zznb().remove("parentsExtraHolder");
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.drive.metadata.zzb, com.google.android.gms.drive.metadata.zza
    /* renamed from: zzd */
    public Collection<DriveId> zzc(DataHolder dataHolder, int i, int i2) {
        Bundle zznb = dataHolder.zznb();
        ArrayList parcelableArrayList = zznb.getParcelableArrayList("parentsExtra");
        if (parcelableArrayList == null) {
            if (zznb.getParcelable("parentsExtraHolder") != null) {
                zzc(dataHolder);
                parcelableArrayList = zznb.getParcelableArrayList("parentsExtra");
            }
            if (parcelableArrayList == null) {
                return null;
            }
        }
        return ((ParentDriveIdSet) parcelableArrayList.get(i)).zzC(zznb.getLong("dbInstanceId"));
    }

    public void zzd(DataHolder dataHolder) {
        Bundle zznb = dataHolder.zznb();
        if (zznb == null) {
            return;
        }
        synchronized (dataHolder) {
            DataHolder dataHolder2 = (DataHolder) zznb.getParcelable("parentsExtraHolder");
            if (dataHolder2 != null) {
                dataHolder2.close();
                zznb.remove("parentsExtraHolder");
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.drive.metadata.internal.zzi, com.google.android.gms.drive.metadata.zza
    /* renamed from: zzo */
    public Collection<DriveId> zzj(Bundle bundle) {
        Collection zzj = super.zzj(bundle);
        if (zzj == null) {
            return null;
        }
        return new HashSet(zzj);
    }
}
