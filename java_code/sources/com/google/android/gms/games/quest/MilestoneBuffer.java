package com.google.android.gms.games.quest;

import com.google.android.gms.common.data.AbstractDataBuffer;
/* loaded from: classes.dex */
public final class MilestoneBuffer extends AbstractDataBuffer<Milestone> {
    @Override // com.google.android.gms.common.data.AbstractDataBuffer, com.google.android.gms.common.data.DataBuffer
    public Milestone get(int position) {
        return new MilestoneRef(this.zzWu, position);
    }
}
