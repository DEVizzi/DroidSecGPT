package com.google.android.gms.games.internal.notification;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzc;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.plus.PlusShare;
/* loaded from: classes.dex */
public final class GameNotificationRef extends zzc implements GameNotification {
    /* JADX INFO: Access modifiers changed from: package-private */
    public GameNotificationRef(DataHolder holder, int dataRow) {
        super(holder, dataRow);
    }

    public long getId() {
        return getLong("_id");
    }

    public String getText() {
        return getString("text");
    }

    public String getTitle() {
        return getString(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_TITLE);
    }

    public int getType() {
        return getInteger("type");
    }

    public String toString() {
        return zzt.zzt(this).zzg("Id", Long.valueOf(getId())).zzg("NotificationId", zztp()).zzg("Type", Integer.valueOf(getType())).zzg("Title", getTitle()).zzg("Ticker", zztq()).zzg("Text", getText()).zzg("CoalescedText", zztr()).zzg("isAcknowledged", Boolean.valueOf(zzts())).zzg("isSilent", Boolean.valueOf(zztt())).toString();
    }

    public String zztp() {
        return getString("notification_id");
    }

    public String zztq() {
        return getString("ticker");
    }

    public String zztr() {
        return getString("coalesced_text");
    }

    public boolean zzts() {
        return getInteger("acknowledged") > 0;
    }

    public boolean zztt() {
        return getInteger("alert_level") == 0;
    }
}
