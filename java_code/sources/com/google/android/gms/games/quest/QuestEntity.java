package com.google.android.gms.games.quest;

import android.database.CharArrayBuffer;
import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.games.Game;
import com.google.android.gms.games.GameEntity;
import com.google.android.gms.internal.zzlc;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public final class QuestEntity implements SafeParcelable, Quest {
    public static final Parcelable.Creator<QuestEntity> CREATOR = new QuestEntityCreator();
    private final String mName;
    private final int mState;
    private final int zzCY;
    private final int zzSq;
    private final String zzakM;
    private final long zzaoj;
    private final String zzauV;
    private final long zzauW;
    private final Uri zzauX;
    private final String zzauY;
    private final long zzauZ;
    private final GameEntity zzaud;
    private final Uri zzava;
    private final String zzavb;
    private final long zzavc;
    private final long zzavd;
    private final ArrayList<MilestoneEntity> zzave;

    /* JADX INFO: Access modifiers changed from: package-private */
    public QuestEntity(int versionCode, GameEntity game, String questId, long acceptedTimestamp, Uri bannerImageUri, String bannerImageUrl, String description, long endTimestamp, long lastUpdatedTimestamp, Uri iconImageUri, String iconImageUrl, String name, long notifyTimestamp, long startTimestamp, int state, int type, ArrayList<MilestoneEntity> milestones) {
        this.zzCY = versionCode;
        this.zzaud = game;
        this.zzauV = questId;
        this.zzauW = acceptedTimestamp;
        this.zzauX = bannerImageUri;
        this.zzauY = bannerImageUrl;
        this.zzakM = description;
        this.zzauZ = endTimestamp;
        this.zzaoj = lastUpdatedTimestamp;
        this.zzava = iconImageUri;
        this.zzavb = iconImageUrl;
        this.mName = name;
        this.zzavc = notifyTimestamp;
        this.zzavd = startTimestamp;
        this.mState = state;
        this.zzSq = type;
        this.zzave = milestones;
    }

    public QuestEntity(Quest quest) {
        this.zzCY = 2;
        this.zzaud = new GameEntity(quest.getGame());
        this.zzauV = quest.getQuestId();
        this.zzauW = quest.getAcceptedTimestamp();
        this.zzakM = quest.getDescription();
        this.zzauX = quest.getBannerImageUri();
        this.zzauY = quest.getBannerImageUrl();
        this.zzauZ = quest.getEndTimestamp();
        this.zzava = quest.getIconImageUri();
        this.zzavb = quest.getIconImageUrl();
        this.zzaoj = quest.getLastUpdatedTimestamp();
        this.mName = quest.getName();
        this.zzavc = quest.zztO();
        this.zzavd = quest.getStartTimestamp();
        this.mState = quest.getState();
        this.zzSq = quest.getType();
        List<Milestone> zztN = quest.zztN();
        int size = zztN.size();
        this.zzave = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            this.zzave.add((MilestoneEntity) zztN.get(i).freeze());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(Quest quest) {
        return zzt.hashCode(quest.getGame(), quest.getQuestId(), Long.valueOf(quest.getAcceptedTimestamp()), quest.getBannerImageUri(), quest.getDescription(), Long.valueOf(quest.getEndTimestamp()), quest.getIconImageUri(), Long.valueOf(quest.getLastUpdatedTimestamp()), quest.zztN(), quest.getName(), Long.valueOf(quest.zztO()), Long.valueOf(quest.getStartTimestamp()), Integer.valueOf(quest.getState()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(Quest quest, Object obj) {
        if (obj instanceof Quest) {
            if (quest != obj) {
                Quest quest2 = (Quest) obj;
                return zzt.equal(quest2.getGame(), quest.getGame()) && zzt.equal(quest2.getQuestId(), quest.getQuestId()) && zzt.equal(Long.valueOf(quest2.getAcceptedTimestamp()), Long.valueOf(quest.getAcceptedTimestamp())) && zzt.equal(quest2.getBannerImageUri(), quest.getBannerImageUri()) && zzt.equal(quest2.getDescription(), quest.getDescription()) && zzt.equal(Long.valueOf(quest2.getEndTimestamp()), Long.valueOf(quest.getEndTimestamp())) && zzt.equal(quest2.getIconImageUri(), quest.getIconImageUri()) && zzt.equal(Long.valueOf(quest2.getLastUpdatedTimestamp()), Long.valueOf(quest.getLastUpdatedTimestamp())) && zzt.equal(quest2.zztN(), quest.zztN()) && zzt.equal(quest2.getName(), quest.getName()) && zzt.equal(Long.valueOf(quest2.zztO()), Long.valueOf(quest.zztO())) && zzt.equal(Long.valueOf(quest2.getStartTimestamp()), Long.valueOf(quest.getStartTimestamp())) && zzt.equal(Integer.valueOf(quest2.getState()), Integer.valueOf(quest.getState()));
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(Quest quest) {
        return zzt.zzt(quest).zzg("Game", quest.getGame()).zzg("QuestId", quest.getQuestId()).zzg("AcceptedTimestamp", Long.valueOf(quest.getAcceptedTimestamp())).zzg("BannerImageUri", quest.getBannerImageUri()).zzg("BannerImageUrl", quest.getBannerImageUrl()).zzg("Description", quest.getDescription()).zzg("EndTimestamp", Long.valueOf(quest.getEndTimestamp())).zzg("IconImageUri", quest.getIconImageUri()).zzg("IconImageUrl", quest.getIconImageUrl()).zzg("LastUpdatedTimestamp", Long.valueOf(quest.getLastUpdatedTimestamp())).zzg("Milestones", quest.zztN()).zzg("Name", quest.getName()).zzg("NotifyTimestamp", Long.valueOf(quest.zztO())).zzg("StartTimestamp", Long.valueOf(quest.getStartTimestamp())).zzg("State", Integer.valueOf(quest.getState())).toString();
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
    public Quest freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public long getAcceptedTimestamp() {
        return this.zzauW;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public Uri getBannerImageUri() {
        return this.zzauX;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public String getBannerImageUrl() {
        return this.zzauY;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public Milestone getCurrentMilestone() {
        return zztN().get(0);
    }

    @Override // com.google.android.gms.games.quest.Quest
    public String getDescription() {
        return this.zzakM;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public void getDescription(CharArrayBuffer dataOut) {
        zzlc.zzb(this.zzakM, dataOut);
    }

    @Override // com.google.android.gms.games.quest.Quest
    public long getEndTimestamp() {
        return this.zzauZ;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public Game getGame() {
        return this.zzaud;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public Uri getIconImageUri() {
        return this.zzava;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public String getIconImageUrl() {
        return this.zzavb;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public long getLastUpdatedTimestamp() {
        return this.zzaoj;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public String getName() {
        return this.mName;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public void getName(CharArrayBuffer dataOut) {
        zzlc.zzb(this.mName, dataOut);
    }

    @Override // com.google.android.gms.games.quest.Quest
    public String getQuestId() {
        return this.zzauV;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public long getStartTimestamp() {
        return this.zzavd;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public int getState() {
        return this.mState;
    }

    @Override // com.google.android.gms.games.quest.Quest
    public int getType() {
        return this.zzSq;
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

    @Override // com.google.android.gms.games.quest.Quest
    public boolean isEndingSoon() {
        return this.zzavc <= System.currentTimeMillis() + 1800000;
    }

    public String toString() {
        return zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        QuestEntityCreator.zza(this, out, flags);
    }

    @Override // com.google.android.gms.games.quest.Quest
    public List<Milestone> zztN() {
        return new ArrayList(this.zzave);
    }

    @Override // com.google.android.gms.games.quest.Quest
    public long zztO() {
        return this.zzavc;
    }
}
