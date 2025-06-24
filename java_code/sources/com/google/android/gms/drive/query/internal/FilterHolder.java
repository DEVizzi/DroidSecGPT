package com.google.android.gms.drive.query.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.drive.query.Filter;
/* loaded from: classes.dex */
public class FilterHolder implements SafeParcelable {
    public static final Parcelable.Creator<FilterHolder> CREATOR = new zzd();
    final int zzCY;
    private final Filter zzadx;
    final ComparisonFilter<?> zzahU;
    final FieldOnlyFilter zzahV;
    final LogicalFilter zzahW;
    final NotFilter zzahX;
    final InFilter<?> zzahY;
    final MatchAllFilter zzahZ;
    final HasFilter zzaia;
    final FullTextSearchFilter zzaib;
    final OwnedByMeFilter zzaic;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FilterHolder(int versionCode, ComparisonFilter<?> comparisonField, FieldOnlyFilter fieldOnlyFilter, LogicalFilter logicalFilter, NotFilter notFilter, InFilter<?> containsFilter, MatchAllFilter matchAllFilter, HasFilter<?> hasFilter, FullTextSearchFilter fullTextSearchFilter, OwnedByMeFilter ownedByMeFilter) {
        this.zzCY = versionCode;
        this.zzahU = comparisonField;
        this.zzahV = fieldOnlyFilter;
        this.zzahW = logicalFilter;
        this.zzahX = notFilter;
        this.zzahY = containsFilter;
        this.zzahZ = matchAllFilter;
        this.zzaia = hasFilter;
        this.zzaib = fullTextSearchFilter;
        this.zzaic = ownedByMeFilter;
        if (this.zzahU != null) {
            this.zzadx = this.zzahU;
        } else if (this.zzahV != null) {
            this.zzadx = this.zzahV;
        } else if (this.zzahW != null) {
            this.zzadx = this.zzahW;
        } else if (this.zzahX != null) {
            this.zzadx = this.zzahX;
        } else if (this.zzahY != null) {
            this.zzadx = this.zzahY;
        } else if (this.zzahZ != null) {
            this.zzadx = this.zzahZ;
        } else if (this.zzaia != null) {
            this.zzadx = this.zzaia;
        } else if (this.zzaib != null) {
            this.zzadx = this.zzaib;
        } else if (this.zzaic == null) {
            throw new IllegalArgumentException("At least one filter must be set.");
        } else {
            this.zzadx = this.zzaic;
        }
    }

    public FilterHolder(Filter filter) {
        zzu.zzb(filter, "Null filter.");
        this.zzCY = 2;
        this.zzahU = filter instanceof ComparisonFilter ? (ComparisonFilter) filter : null;
        this.zzahV = filter instanceof FieldOnlyFilter ? (FieldOnlyFilter) filter : null;
        this.zzahW = filter instanceof LogicalFilter ? (LogicalFilter) filter : null;
        this.zzahX = filter instanceof NotFilter ? (NotFilter) filter : null;
        this.zzahY = filter instanceof InFilter ? (InFilter) filter : null;
        this.zzahZ = filter instanceof MatchAllFilter ? (MatchAllFilter) filter : null;
        this.zzaia = filter instanceof HasFilter ? (HasFilter) filter : null;
        this.zzaib = filter instanceof FullTextSearchFilter ? (FullTextSearchFilter) filter : null;
        this.zzaic = filter instanceof OwnedByMeFilter ? (OwnedByMeFilter) filter : null;
        if (this.zzahU == null && this.zzahV == null && this.zzahW == null && this.zzahX == null && this.zzahY == null && this.zzahZ == null && this.zzaia == null && this.zzaib == null && this.zzaic == null) {
            throw new IllegalArgumentException("Invalid filter type.");
        }
        this.zzadx = filter;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public Filter getFilter() {
        return this.zzadx;
    }

    public String toString() {
        return String.format("FilterHolder[%s]", this.zzadx);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzd.zza(this, out, flags);
    }
}
