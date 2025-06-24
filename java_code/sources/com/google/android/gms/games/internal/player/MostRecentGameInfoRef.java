package com.google.android.gms.games.internal.player;

import android.net.Uri;
import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzc;
/* loaded from: classes.dex */
public final class MostRecentGameInfoRef extends zzc implements MostRecentGameInfo {
    private final PlayerColumnNames zzanX;

    public MostRecentGameInfoRef(DataHolder holder, int dataRow, PlayerColumnNames columnNames) {
        super(holder, dataRow);
        this.zzanX = columnNames;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.common.data.zzc
    public boolean equals(Object obj) {
        return MostRecentGameInfoEntity.zza(this, obj);
    }

    @Override // com.google.android.gms.common.data.zzc
    public int hashCode() {
        return MostRecentGameInfoEntity.zza(this);
    }

    public String toString() {
        return MostRecentGameInfoEntity.zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        ((MostRecentGameInfoEntity) freeze()).writeToParcel(dest, flags);
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zztA */
    public MostRecentGameInfo freeze() {
        return new MostRecentGameInfoEntity(this);
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public String zztu() {
        return getString(this.zzanX.zzato);
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public String zztv() {
        return getString(this.zzanX.zzatp);
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public long zztw() {
        return getLong(this.zzanX.zzatq);
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public Uri zztx() {
        return zzbW(this.zzanX.zzatr);
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public Uri zzty() {
        return zzbW(this.zzanX.zzats);
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public Uri zztz() {
        return zzbW(this.zzanX.zzatt);
    }
}
