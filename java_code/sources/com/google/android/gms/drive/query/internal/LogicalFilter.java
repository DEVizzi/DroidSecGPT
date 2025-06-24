package com.google.android.gms.drive.query.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.drive.query.Filter;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class LogicalFilter extends AbstractFilter {
    public static final Parcelable.Creator<LogicalFilter> CREATOR = new zzk();
    final int zzCY;
    private List<Filter> zzahL;
    final Operator zzahQ;
    final List<FilterHolder> zzaif;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LogicalFilter(int versionCode, Operator operator, List<FilterHolder> filterHolders) {
        this.zzCY = versionCode;
        this.zzahQ = operator;
        this.zzaif = filterHolders;
    }

    public LogicalFilter(Operator operator, Filter filter, Filter... additionalFilters) {
        this.zzCY = 1;
        this.zzahQ = operator;
        this.zzaif = new ArrayList(additionalFilters.length + 1);
        this.zzaif.add(new FilterHolder(filter));
        this.zzahL = new ArrayList(additionalFilters.length + 1);
        this.zzahL.add(filter);
        for (Filter filter2 : additionalFilters) {
            this.zzaif.add(new FilterHolder(filter2));
            this.zzahL.add(filter2);
        }
    }

    public LogicalFilter(Operator operator, Iterable<Filter> filters) {
        this.zzCY = 1;
        this.zzahQ = operator;
        this.zzahL = new ArrayList();
        this.zzaif = new ArrayList();
        for (Filter filter : filters) {
            this.zzahL.add(filter);
            this.zzaif.add(new FilterHolder(filter));
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzk.zza(this, out, flags);
    }

    @Override // com.google.android.gms.drive.query.Filter
    public <T> T zza(zzf<T> zzfVar) {
        List<T> arrayList = new ArrayList<>();
        for (FilterHolder filterHolder : this.zzaif) {
            arrayList.add(filterHolder.getFilter().zza(zzfVar));
        }
        return zzfVar.zzb(this.zzahQ, arrayList);
    }
}
