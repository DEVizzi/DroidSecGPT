package com.google.android.gms.drive.realtime.internal.event;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.List;
/* loaded from: classes.dex */
public class ParcelableEventList implements SafeParcelable {
    public static final Parcelable.Creator<ParcelableEventList> CREATOR = new zzd();
    final int zzCY;
    final DataHolder zzaiQ;
    final boolean zzaiR;
    final List<String> zzaiS;
    final List<ParcelableEvent> zzoB;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ParcelableEventList(int versionCode, List<ParcelableEvent> events, DataHolder eventData, boolean undoRedoStateChanged, List<String> affectedObjectIds) {
        this.zzCY = versionCode;
        this.zzoB = events;
        this.zzaiQ = eventData;
        this.zzaiR = undoRedoStateChanged;
        this.zzaiS = affectedObjectIds;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzd.zza(this, dest, flags);
    }
}
