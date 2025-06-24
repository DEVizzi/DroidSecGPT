package com.google.android.gms.common.data;

import java.util.ArrayList;
/* loaded from: classes.dex */
public abstract class zzf<T> extends AbstractDataBuffer<T> {
    private boolean zzYK;
    private ArrayList<Integer> zzYL;

    /* JADX INFO: Access modifiers changed from: protected */
    public zzf(DataHolder dataHolder) {
        super(dataHolder);
        this.zzYK = false;
    }

    private void zznj() {
        synchronized (this) {
            if (!this.zzYK) {
                int count = this.zzWu.getCount();
                this.zzYL = new ArrayList<>();
                if (count > 0) {
                    this.zzYL.add(0);
                    String zzni = zzni();
                    String zzd = this.zzWu.zzd(zzni, 0, this.zzWu.zzbh(0));
                    int i = 1;
                    while (i < count) {
                        int zzbh = this.zzWu.zzbh(i);
                        String zzd2 = this.zzWu.zzd(zzni, i, zzbh);
                        if (zzd2 == null) {
                            throw new NullPointerException("Missing value for markerColumn: " + zzni + ", at row: " + i + ", for window: " + zzbh);
                        }
                        if (zzd2.equals(zzd)) {
                            zzd2 = zzd;
                        } else {
                            this.zzYL.add(Integer.valueOf(i));
                        }
                        i++;
                        zzd = zzd2;
                    }
                }
                this.zzYK = true;
            }
        }
    }

    @Override // com.google.android.gms.common.data.AbstractDataBuffer, com.google.android.gms.common.data.DataBuffer
    public final T get(int position) {
        zznj();
        return zzj(zzbk(position), zzbl(position));
    }

    @Override // com.google.android.gms.common.data.AbstractDataBuffer, com.google.android.gms.common.data.DataBuffer
    public int getCount() {
        zznj();
        return this.zzYL.size();
    }

    int zzbk(int i) {
        if (i < 0 || i >= this.zzYL.size()) {
            throw new IllegalArgumentException("Position " + i + " is out of bounds for this buffer");
        }
        return this.zzYL.get(i).intValue();
    }

    protected int zzbl(int i) {
        if (i < 0 || i == this.zzYL.size()) {
            return 0;
        }
        int count = i == this.zzYL.size() + (-1) ? this.zzWu.getCount() - this.zzYL.get(i).intValue() : this.zzYL.get(i + 1).intValue() - this.zzYL.get(i).intValue();
        if (count == 1) {
            int zzbk = zzbk(i);
            int zzbh = this.zzWu.zzbh(zzbk);
            String zznk = zznk();
            if (zznk == null || this.zzWu.zzd(zznk, zzbk, zzbh) != null) {
                return count;
            }
            return 0;
        }
        return count;
    }

    protected abstract T zzj(int i, int i2);

    protected abstract String zzni();

    protected String zznk() {
        return null;
    }
}
