package com.google.android.gms.drive.realtime.internal.event;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.List;
/* loaded from: classes.dex */
public class ParcelableEvent implements SafeParcelable {
    public static final Parcelable.Creator<ParcelableEvent> CREATOR = new zzc();
    final int zzCY;
    final String zzEO;
    final String zzFE;
    final List<String> zzaiC;
    final boolean zzaiD;
    final boolean zzaiE;
    final boolean zzaiF;
    final String zzaiG;
    final TextInsertedDetails zzaiH;
    final TextDeletedDetails zzaiI;
    final ValuesAddedDetails zzaiJ;
    final ValuesRemovedDetails zzaiK;
    final ValuesSetDetails zzaiL;
    final ValueChangedDetails zzaiM;
    final ReferenceShiftedDetails zzaiN;
    final ObjectChangedDetails zzaiO;
    final FieldChangedDetails zzaiP;
    final String zzaiw;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ParcelableEvent(int versionCode, String sessionId, String userId, List<String> compoundOperationNames, boolean isLocal, boolean isUndo, boolean isRedo, String objectId, String objectType, TextInsertedDetails textInsertedDetails, TextDeletedDetails textDeletedDetails, ValuesAddedDetails valuesAddedDetails, ValuesRemovedDetails valuesRemovedDetails, ValuesSetDetails valuesSetDetails, ValueChangedDetails valueChangedDetails, ReferenceShiftedDetails referenceShiftedDetails, ObjectChangedDetails objectChangedDetails, FieldChangedDetails fieldChangedDetails) {
        this.zzCY = versionCode;
        this.zzFE = sessionId;
        this.zzEO = userId;
        this.zzaiC = compoundOperationNames;
        this.zzaiD = isLocal;
        this.zzaiE = isUndo;
        this.zzaiF = isRedo;
        this.zzaiw = objectId;
        this.zzaiG = objectType;
        this.zzaiH = textInsertedDetails;
        this.zzaiI = textDeletedDetails;
        this.zzaiJ = valuesAddedDetails;
        this.zzaiK = valuesRemovedDetails;
        this.zzaiL = valuesSetDetails;
        this.zzaiM = valueChangedDetails;
        this.zzaiN = referenceShiftedDetails;
        this.zzaiO = objectChangedDetails;
        this.zzaiP = fieldChangedDetails;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }
}
