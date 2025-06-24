package com.google.android.gms.games.quest;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class MilestoneEntity implements SafeParcelable, Milestone {
    public static final Parcelable.Creator<MilestoneEntity> CREATOR = new MilestoneEntityCreator();
    private final int mState;
    private final int zzCY;
    private final String zzaoK;
    private final String zzapR;
    private final long zzauS;
    private final long zzauT;
    private final byte[] zzauU;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MilestoneEntity(int versionCode, String milestoneId, long currentProgress, long targetProgress, byte[] completionBlob, int state, String eventId) {
        this.zzCY = versionCode;
        this.zzapR = milestoneId;
        this.zzauS = currentProgress;
        this.zzauT = targetProgress;
        this.zzauU = completionBlob;
        this.mState = state;
        this.zzaoK = eventId;
    }

    public MilestoneEntity(Milestone milestone) {
        this.zzCY = 4;
        this.zzapR = milestone.getMilestoneId();
        this.zzauS = milestone.getCurrentProgress();
        this.zzauT = milestone.getTargetProgress();
        this.mState = milestone.getState();
        this.zzaoK = milestone.getEventId();
        byte[] completionRewardData = milestone.getCompletionRewardData();
        if (completionRewardData == null) {
            this.zzauU = null;
            return;
        }
        this.zzauU = new byte[completionRewardData.length];
        System.arraycopy(completionRewardData, 0, this.zzauU, 0, completionRewardData.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(Milestone milestone) {
        return zzt.hashCode(milestone.getMilestoneId(), Long.valueOf(milestone.getCurrentProgress()), Long.valueOf(milestone.getTargetProgress()), Integer.valueOf(milestone.getState()), milestone.getEventId());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(Milestone milestone, Object obj) {
        if (obj instanceof Milestone) {
            if (milestone != obj) {
                Milestone milestone2 = (Milestone) obj;
                return zzt.equal(milestone2.getMilestoneId(), milestone.getMilestoneId()) && zzt.equal(Long.valueOf(milestone2.getCurrentProgress()), Long.valueOf(milestone.getCurrentProgress())) && zzt.equal(Long.valueOf(milestone2.getTargetProgress()), Long.valueOf(milestone.getTargetProgress())) && zzt.equal(Integer.valueOf(milestone2.getState()), Integer.valueOf(milestone.getState())) && zzt.equal(milestone2.getEventId(), milestone.getEventId());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(Milestone milestone) {
        return zzt.zzt(milestone).zzg("MilestoneId", milestone.getMilestoneId()).zzg("CurrentProgress", Long.valueOf(milestone.getCurrentProgress())).zzg("TargetProgress", Long.valueOf(milestone.getTargetProgress())).zzg("State", Integer.valueOf(milestone.getState())).zzg("CompletionRewardData", milestone.getCompletionRewardData()).zzg("EventId", milestone.getEventId()).toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.gms.common.data.Freezable
    public Milestone freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.quest.Milestone
    public byte[] getCompletionRewardData() {
        return this.zzauU;
    }

    @Override // com.google.android.gms.games.quest.Milestone
    public long getCurrentProgress() {
        return this.zzauS;
    }

    @Override // com.google.android.gms.games.quest.Milestone
    public String getEventId() {
        return this.zzaoK;
    }

    @Override // com.google.android.gms.games.quest.Milestone
    public String getMilestoneId() {
        return this.zzapR;
    }

    @Override // com.google.android.gms.games.quest.Milestone
    public int getState() {
        return this.mState;
    }

    @Override // com.google.android.gms.games.quest.Milestone
    public long getTargetProgress() {
        return this.zzauT;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zza(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        MilestoneEntityCreator.zza(this, out, flags);
    }
}
