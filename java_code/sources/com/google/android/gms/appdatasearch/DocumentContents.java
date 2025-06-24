package com.google.android.gms.appdatasearch;

import android.accounts.Account;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
/* loaded from: classes.dex */
public class DocumentContents implements SafeParcelable {
    public static final zzb CREATOR = new zzb();
    public final Account account;
    final int zzCY;
    final DocumentSection[] zzMS;
    public final String zzMT;
    public final boolean zzMU;

    /* loaded from: classes.dex */
    public static class zza {
        private List<DocumentSection> zzMV;
        private String zzMW;
        private boolean zzMX;
        private Account zzMY;

        public zza zzI(boolean z) {
            this.zzMX = z;
            return this;
        }

        public zza zza(Account account) {
            this.zzMY = account;
            return this;
        }

        public zza zza(DocumentSection documentSection) {
            if (this.zzMV == null) {
                this.zzMV = new ArrayList();
            }
            this.zzMV.add(documentSection);
            return this;
        }

        public zza zzbp(String str) {
            this.zzMW = str;
            return this;
        }

        public DocumentContents zzkJ() {
            return new DocumentContents(this.zzMW, this.zzMX, this.zzMY, this.zzMV != null ? (DocumentSection[]) this.zzMV.toArray(new DocumentSection[this.zzMV.size()]) : null);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DocumentContents(int versionCode, DocumentSection[] sectionContents, String schemaOrgType, boolean globalSearchEnabled, Account account) {
        this.zzCY = versionCode;
        this.zzMS = sectionContents;
        this.zzMT = schemaOrgType;
        this.zzMU = globalSearchEnabled;
        this.account = account;
    }

    DocumentContents(String schemaOrgType, boolean globalSearchEnabled, Account account, DocumentSection... sections) {
        this(1, sections, schemaOrgType, globalSearchEnabled, account);
        BitSet bitSet = new BitSet(zzh.zzkL());
        for (DocumentSection documentSection : sections) {
            int i = documentSection.zzNg;
            if (i != -1) {
                if (bitSet.get(i)) {
                    throw new IllegalArgumentException("Duplicate global search section type " + zzh.zzai(i));
                }
                bitSet.set(i);
            }
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzb zzbVar = CREATOR;
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzb zzbVar = CREATOR;
        zzb.zza(this, dest, flags);
    }
}
