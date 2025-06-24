package com.google.android.gms.games.request;

import com.google.android.gms.common.data.AbstractDataBuffer;
/* loaded from: classes.dex */
public final class GameRequestSummaryBuffer extends AbstractDataBuffer<GameRequestSummary> {
    @Override // com.google.android.gms.common.data.AbstractDataBuffer, com.google.android.gms.common.data.DataBuffer
    /* renamed from: zzga */
    public GameRequestSummary get(int i) {
        return new GameRequestSummaryRef(this.zzWu, i);
    }
}
