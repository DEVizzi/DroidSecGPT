package com.google.android.gms.appdatasearch;

import android.accounts.Account;
import android.os.Parcel;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.List;
/* loaded from: classes.dex */
public class GetRecentContextCall {

    /* loaded from: classes.dex */
    public static class Request implements SafeParcelable {
        public static final zzf CREATOR = new zzf();
        final int zzCY;
        public final Account zzNj;
        public final boolean zzNk;
        public final boolean zzNl;
        public final boolean zzNm;

        public Request() {
            this(null, false, false, false);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Request(int versionCode, Account filterAccount, boolean includeDeviceOnlyData, boolean includeThirdPartyContext, boolean includeUsageEnded) {
            this.zzCY = versionCode;
            this.zzNj = filterAccount;
            this.zzNk = includeDeviceOnlyData;
            this.zzNl = includeThirdPartyContext;
            this.zzNm = includeUsageEnded;
        }

        public Request(Account filterAccount, boolean includeDeviceOnlyData, boolean includeThirdPartyContext, boolean includeUsageEnded) {
            this(1, filterAccount, includeDeviceOnlyData, includeThirdPartyContext, includeUsageEnded);
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzf zzfVar = CREATOR;
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzf zzfVar = CREATOR;
            zzf.zza(this, out, flags);
        }
    }

    /* loaded from: classes.dex */
    public static class Response implements Result, SafeParcelable {
        public static final zzg CREATOR = new zzg();
        final int zzCY;
        public Status zzNn;
        public List<UsageInfo> zzNo;
        public String[] zzNp;

        public Response() {
            this.zzCY = 1;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Response(int versionCode, Status status, List<UsageInfo> usageInfo, String[] topRunningPackages) {
            this.zzCY = versionCode;
            this.zzNn = status;
            this.zzNo = usageInfo;
            this.zzNp = topRunningPackages;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzg zzgVar = CREATOR;
            return 0;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzNn;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzg zzgVar = CREATOR;
            zzg.zza(this, out, flags);
        }
    }
}
