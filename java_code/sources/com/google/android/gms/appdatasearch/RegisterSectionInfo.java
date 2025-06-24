package com.google.android.gms.appdatasearch;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
/* loaded from: classes.dex */
public class RegisterSectionInfo implements SafeParcelable {
    public static final zzi CREATOR = new zzi();
    public final String name;
    public final int weight;
    final int zzCY;
    public final String zzNs;
    public final boolean zzNt;
    public final boolean zzNu;
    public final String zzNv;
    public final Feature[] zzNw;
    final int[] zzNx;
    public final String zzNy;

    /* loaded from: classes.dex */
    public static final class zza {
        private final String mName;
        private boolean zzNA;
        private boolean zzNC;
        private String zzND;
        private BitSet zzNF;
        private String zzNG;
        private String zzNz;
        private int zzNB = 1;
        private final List<Feature> zzNE = new ArrayList();

        public zza(String str) {
            this.mName = str;
        }

        public zza zzJ(boolean z) {
            this.zzNA = z;
            return this;
        }

        public zza zzK(boolean z) {
            this.zzNC = z;
            return this;
        }

        public zza zzaj(int i) {
            if (this.zzNF == null) {
                this.zzNF = new BitSet();
            }
            this.zzNF.set(i);
            return this;
        }

        public zza zzbr(String str) {
            this.zzNz = str;
            return this;
        }

        public zza zzbs(String str) {
            this.zzNG = str;
            return this;
        }

        public RegisterSectionInfo zzkM() {
            int i = 0;
            int[] iArr = null;
            if (this.zzNF != null) {
                iArr = new int[this.zzNF.cardinality()];
                int nextSetBit = this.zzNF.nextSetBit(0);
                while (nextSetBit >= 0) {
                    iArr[i] = nextSetBit;
                    nextSetBit = this.zzNF.nextSetBit(nextSetBit + 1);
                    i++;
                }
            }
            return new RegisterSectionInfo(this.mName, this.zzNz, this.zzNA, this.zzNB, this.zzNC, this.zzND, (Feature[]) this.zzNE.toArray(new Feature[this.zzNE.size()]), iArr, this.zzNG);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RegisterSectionInfo(int versionCode, String name, String format, boolean noIndex, int weight, boolean indexPrefixes, String subsectionSeparator, Feature[] features, int[] semanticLabels, String schemaOrgProperty) {
        this.zzCY = versionCode;
        this.name = name;
        this.zzNs = format;
        this.zzNt = noIndex;
        this.weight = weight;
        this.zzNu = indexPrefixes;
        this.zzNv = subsectionSeparator;
        this.zzNw = features;
        this.zzNx = semanticLabels;
        this.zzNy = schemaOrgProperty;
    }

    RegisterSectionInfo(String name, String format, boolean noIndex, int weight, boolean indexPrefixes, String subsectionSeparator, Feature[] features, int[] semanticLabels, String schemaOrgProperty) {
        this(2, name, format, noIndex, weight, indexPrefixes, subsectionSeparator, features, semanticLabels, schemaOrgProperty);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzi zziVar = CREATOR;
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzi zziVar = CREATOR;
        zzi.zza(this, out, flags);
    }
}
