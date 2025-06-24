package com.google.android.gms.games.internal.notification;

import com.google.android.gms.common.data.AbstractDataBuffer;
/* loaded from: classes.dex */
public final class GameNotificationBuffer extends AbstractDataBuffer<GameNotification> {
    @Override // com.google.android.gms.common.data.AbstractDataBuffer, com.google.android.gms.common.data.DataBuffer
    /* renamed from: zzfN */
    public GameNotification get(int i) {
        return new GameNotificationRef(this.zzWu, i);
    }
}
