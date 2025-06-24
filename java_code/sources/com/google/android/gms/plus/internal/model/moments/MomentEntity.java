package com.google.android.gms.plus.internal.model.moments;

import android.os.Parcel;
import com.google.android.gms.common.server.response.FastJsonResponse;
import com.google.android.gms.common.server.response.FastSafeParcelableJsonResponse;
import com.google.android.gms.plus.model.moments.ItemScope;
import com.google.android.gms.plus.model.moments.Moment;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
/* loaded from: classes.dex */
public final class MomentEntity extends FastSafeParcelableJsonResponse implements Moment {
    public static final zzb CREATOR = new zzb();
    private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
    final int zzCY;
    String zzEl;
    String zzKI;
    final Set<Integer> zzaHQ;
    String zzaID;
    ItemScopeEntity zzaIL;
    ItemScopeEntity zzaIM;

    static {
        zzaHP.put("id", FastJsonResponse.Field.zzl("id", 2));
        zzaHP.put("result", FastJsonResponse.Field.zza("result", 4, ItemScopeEntity.class));
        zzaHP.put("startDate", FastJsonResponse.Field.zzl("startDate", 5));
        zzaHP.put("target", FastJsonResponse.Field.zza("target", 6, ItemScopeEntity.class));
        zzaHP.put("type", FastJsonResponse.Field.zzl("type", 7));
    }

    public MomentEntity() {
        this.zzCY = 1;
        this.zzaHQ = new HashSet();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MomentEntity(Set<Integer> indicatorSet, int versionCode, String id, ItemScopeEntity result, String startDate, ItemScopeEntity target, String type) {
        this.zzaHQ = indicatorSet;
        this.zzCY = versionCode;
        this.zzKI = id;
        this.zzaIL = result;
        this.zzaID = startDate;
        this.zzaIM = target;
        this.zzEl = type;
    }

    public MomentEntity(Set<Integer> indicatorSet, String id, ItemScopeEntity result, String startDate, ItemScopeEntity target, String type) {
        this.zzaHQ = indicatorSet;
        this.zzCY = 1;
        this.zzKI = id;
        this.zzaIL = result;
        this.zzaID = startDate;
        this.zzaIM = target;
        this.zzEl = type;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzb zzbVar = CREATOR;
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof MomentEntity) {
            if (this == obj) {
                return true;
            }
            MomentEntity momentEntity = (MomentEntity) obj;
            for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                if (zza(field)) {
                    if (momentEntity.zza(field) && zzb(field).equals(momentEntity.zzb(field))) {
                    }
                    return false;
                } else if (momentEntity.zza(field)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public String getId() {
        return this.zzKI;
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public ItemScope getResult() {
        return this.zzaIL;
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public String getStartDate() {
        return this.zzaID;
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public ItemScope getTarget() {
        return this.zzaIM;
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public String getType() {
        return this.zzEl;
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasId() {
        return this.zzaHQ.contains(2);
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasResult() {
        return this.zzaHQ.contains(4);
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasStartDate() {
        return this.zzaHQ.contains(5);
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasTarget() {
        return this.zzaHQ.contains(6);
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasType() {
        return this.zzaHQ.contains(7);
    }

    public int hashCode() {
        int i = 0;
        Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
        while (true) {
            int i2 = i;
            if (!it.hasNext()) {
                return i2;
            }
            FastJsonResponse.Field<?, ?> next = it.next();
            if (zza(next)) {
                i = zzb(next).hashCode() + i2 + next.zzot();
            } else {
                i = i2;
            }
        }
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb zzbVar = CREATOR;
        zzb.zza(this, out, flags);
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse
    protected boolean zza(FastJsonResponse.Field field) {
        return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse
    protected Object zzb(FastJsonResponse.Field field) {
        switch (field.zzot()) {
            case 2:
                return this.zzKI;
            case 3:
            default:
                throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            case 4:
                return this.zzaIL;
            case 5:
                return this.zzaID;
            case 6:
                return this.zzaIM;
            case 7:
                return this.zzEl;
        }
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse
    /* renamed from: zzxF */
    public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
        return zzaHP;
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzxH */
    public MomentEntity freeze() {
        return this;
    }
}
