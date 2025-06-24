package com.google.android.gms.games.internal.game;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzc;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.games.internal.constants.PlatformType;
/* loaded from: classes.dex */
public final class GameInstanceRef extends zzc implements GameInstance {
    /* JADX INFO: Access modifiers changed from: package-private */
    public GameInstanceRef(DataHolder holder, int dataRow) {
        super(holder, dataRow);
    }

    public String getApplicationId() {
        return getString("external_game_id");
    }

    public String getDisplayName() {
        return getString("instance_display_name");
    }

    public String getPackageName() {
        return getString("package_name");
    }

    public String toString() {
        return zzt.zzt(this).zzg("ApplicationId", getApplicationId()).zzg("DisplayName", getDisplayName()).zzg("SupportsRealTime", Boolean.valueOf(zztj())).zzg("SupportsTurnBased", Boolean.valueOf(zztk())).zzg("PlatformType", PlatformType.zzfG(zzqE())).zzg("PackageName", getPackageName()).zzg("PiracyCheckEnabled", Boolean.valueOf(zztl())).zzg("Installed", Boolean.valueOf(zztm())).toString();
    }

    public int zzqE() {
        return getInteger("platform_type");
    }

    public boolean zztj() {
        return getInteger("real_time_support") > 0;
    }

    public boolean zztk() {
        return getInteger("turn_based_support") > 0;
    }

    public boolean zztl() {
        return getInteger("piracy_check") > 0;
    }

    public boolean zztm() {
        return getInteger("installed") > 0;
    }
}
