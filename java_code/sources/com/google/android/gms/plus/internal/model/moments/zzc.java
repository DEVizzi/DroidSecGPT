package com.google.android.gms.plus.internal.model.moments;

import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.plus.model.moments.ItemScope;
import com.google.android.gms.plus.model.moments.Moment;
/* loaded from: classes.dex */
public final class zzc extends com.google.android.gms.common.data.zzc implements Moment {
    private MomentEntity zzaIN;

    public zzc(DataHolder dataHolder, int i) {
        super(dataHolder, i);
    }

    private MomentEntity zzxI() {
        synchronized (this) {
            if (this.zzaIN == null) {
                byte[] byteArray = getByteArray("momentImpl");
                Parcel obtain = Parcel.obtain();
                obtain.unmarshall(byteArray, 0, byteArray.length);
                obtain.setDataPosition(0);
                this.zzaIN = MomentEntity.CREATOR.createFromParcel(obtain);
                obtain.recycle();
            }
        }
        return this.zzaIN;
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public String getId() {
        return zzxI().getId();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public ItemScope getResult() {
        return zzxI().getResult();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public String getStartDate() {
        return zzxI().getStartDate();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public ItemScope getTarget() {
        return zzxI().getTarget();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public String getType() {
        return zzxI().getType();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasId() {
        return zzxI().hasId();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasResult() {
        return zzxI().hasResult();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasStartDate() {
        return zzxI().hasStartDate();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasTarget() {
        return zzxI().hasTarget();
    }

    @Override // com.google.android.gms.plus.model.moments.Moment
    public boolean hasType() {
        return zzxI().hasType();
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzxH */
    public MomentEntity freeze() {
        return zzxI();
    }
}
