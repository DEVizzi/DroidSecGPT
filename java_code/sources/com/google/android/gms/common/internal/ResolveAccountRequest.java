package com.google.android.gms.common.internal;

import android.accounts.Account;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class ResolveAccountRequest implements SafeParcelable {
    public static final Parcelable.Creator<ResolveAccountRequest> CREATOR = new zzv();
    final int zzCY;
    private final Account zzMY;
    private final int zzabc;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ResolveAccountRequest(int versionCode, Account account, int sessionId) {
        this.zzCY = versionCode;
        this.zzMY = account;
        this.zzabc = sessionId;
    }

    public ResolveAccountRequest(Account account, int sessionId) {
        this(1, account, sessionId);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public Account getAccount() {
        return this.zzMY;
    }

    public int getSessionId() {
        return this.zzabc;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzv.zza(this, dest, flags);
    }
}
