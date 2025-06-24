package com.google.android.gms.tagmanager;
/* loaded from: classes.dex */
class zzde extends Number implements Comparable<zzde> {
    private double zzaOq;
    private long zzaOr;
    private boolean zzaOs = false;

    private zzde(double d) {
        this.zzaOq = d;
    }

    private zzde(long j) {
        this.zzaOr = j;
    }

    public static zzde zzT(long j) {
        return new zzde(j);
    }

    public static zzde zza(Double d) {
        return new zzde(d.doubleValue());
    }

    public static zzde zzeI(String str) throws NumberFormatException {
        try {
            return new zzde(Long.parseLong(str));
        } catch (NumberFormatException e) {
            try {
                return new zzde(Double.parseDouble(str));
            } catch (NumberFormatException e2) {
                throw new NumberFormatException(str + " is not a valid TypedNumber");
            }
        }
    }

    @Override // java.lang.Number
    public byte byteValue() {
        return (byte) longValue();
    }

    @Override // java.lang.Number
    public double doubleValue() {
        return zzzG() ? this.zzaOr : this.zzaOq;
    }

    public boolean equals(Object other) {
        return (other instanceof zzde) && compareTo((zzde) other) == 0;
    }

    @Override // java.lang.Number
    public float floatValue() {
        return (float) doubleValue();
    }

    public int hashCode() {
        return new Long(longValue()).hashCode();
    }

    @Override // java.lang.Number
    public int intValue() {
        return zzzI();
    }

    @Override // java.lang.Number
    public long longValue() {
        return zzzH();
    }

    @Override // java.lang.Number
    public short shortValue() {
        return zzzJ();
    }

    public String toString() {
        return zzzG() ? Long.toString(this.zzaOr) : Double.toString(this.zzaOq);
    }

    @Override // java.lang.Comparable
    /* renamed from: zza */
    public int compareTo(zzde zzdeVar) {
        return (zzzG() && zzdeVar.zzzG()) ? new Long(this.zzaOr).compareTo(Long.valueOf(zzdeVar.zzaOr)) : Double.compare(doubleValue(), zzdeVar.doubleValue());
    }

    public boolean zzzF() {
        return !zzzG();
    }

    public boolean zzzG() {
        return this.zzaOs;
    }

    public long zzzH() {
        return zzzG() ? this.zzaOr : (long) this.zzaOq;
    }

    public int zzzI() {
        return (int) longValue();
    }

    public short zzzJ() {
        return (short) longValue();
    }
}
