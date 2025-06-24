package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.events.ChangeEvent;
import com.google.android.gms.drive.events.ChangesAvailableEvent;
import com.google.android.gms.drive.events.CompletionEvent;
import com.google.android.gms.drive.events.DriveEvent;
import com.google.android.gms.drive.events.ProgressEvent;
import com.google.android.gms.drive.events.QueryResultEventParcelable;
/* loaded from: classes.dex */
public class OnEventResponse implements SafeParcelable {
    public static final Parcelable.Creator<OnEventResponse> CREATOR = new zzaz();
    final int zzCY;
    final int zzaca;
    final ChangeEvent zzagj;
    final CompletionEvent zzagk;
    final QueryResultEventParcelable zzagl;
    final ChangesAvailableEvent zzagm;
    final ProgressEvent zzagn;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OnEventResponse(int versionCode, int eventType, ChangeEvent changeEvent, CompletionEvent completionEvent, QueryResultEventParcelable queryResultEvent, ChangesAvailableEvent changesAvailableEvent, ProgressEvent progressEvent) {
        this.zzCY = versionCode;
        this.zzaca = eventType;
        this.zzagj = changeEvent;
        this.zzagk = completionEvent;
        this.zzagl = queryResultEvent;
        this.zzagm = changesAvailableEvent;
        this.zzagn = progressEvent;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzaz.zza(this, dest, flags);
    }

    public DriveEvent zzpO() {
        switch (this.zzaca) {
            case 1:
                return this.zzagj;
            case 2:
                return this.zzagk;
            case 3:
                return this.zzagl;
            case 4:
                return this.zzagm;
            case 5:
            case 6:
                return this.zzagn;
            default:
                throw new IllegalStateException("Unexpected event type " + this.zzaca);
        }
    }
}
