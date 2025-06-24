package com.google.android.gms.games.internal.experience;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzc;
import com.google.android.gms.games.GameRef;
/* loaded from: classes.dex */
public final class ExperienceEventRef extends zzc implements ExperienceEvent {
    private final GameRef zzasN;

    public ExperienceEventRef(DataHolder holder, int dataRow) {
        super(holder, dataRow);
        if (zzbX("external_game_id")) {
            this.zzasN = null;
        } else {
            this.zzasN = new GameRef(this.zzWu, this.zzYs);
        }
    }

    @Override // com.google.android.gms.games.internal.experience.ExperienceEvent
    public String getIconImageUrl() {
        return getString("icon_url");
    }
}
