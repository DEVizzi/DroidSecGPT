package com.google.android.gms.fitness.result;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.fitness.data.Subscription;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class ListSubscriptionsResult implements Result, SafeParcelable {
    public static final Parcelable.Creator<ListSubscriptionsResult> CREATOR = new zzh();
    private final int zzCY;
    private final Status zzOt;
    private final List<Subscription> zzamW;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ListSubscriptionsResult(int versionCode, List<Subscription> subscriptions, Status status) {
        this.zzCY = versionCode;
        this.zzamW = subscriptions;
        this.zzOt = status;
    }

    public ListSubscriptionsResult(List<Subscription> subscriptions, Status status) {
        this.zzCY = 3;
        this.zzamW = Collections.unmodifiableList(subscriptions);
        this.zzOt = (Status) zzu.zzb(status, "status");
    }

    public static ListSubscriptionsResult zzN(Status status) {
        return new ListSubscriptionsResult(Collections.emptyList(), status);
    }

    private boolean zzb(ListSubscriptionsResult listSubscriptionsResult) {
        return this.zzOt.equals(listSubscriptionsResult.zzOt) && zzt.equal(this.zzamW, listSubscriptionsResult.zzamW);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object that) {
        return this == that || ((that instanceof ListSubscriptionsResult) && zzb((ListSubscriptionsResult) that));
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzOt;
    }

    public List<Subscription> getSubscriptions() {
        return this.zzamW;
    }

    public List<Subscription> getSubscriptions(DataType dataType) {
        ArrayList arrayList = new ArrayList();
        for (Subscription subscription : this.zzamW) {
            if (dataType.equals(subscription.zzqM())) {
                arrayList.add(subscription);
            }
        }
        return Collections.unmodifiableList(arrayList);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzOt, this.zzamW);
    }

    public String toString() {
        return zzt.zzt(this).zzg("status", this.zzOt).zzg("subscriptions", this.zzamW).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzh.zza(this, dest, flags);
    }
}
