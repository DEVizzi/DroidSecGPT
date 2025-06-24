package com.google.android.gms.drive.query;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveSpace;
import com.google.android.gms.drive.query.internal.LogicalFilter;
import com.google.android.gms.drive.query.internal.MatchAllFilter;
import com.google.android.gms.drive.query.internal.Operator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
/* loaded from: classes.dex */
public class Query implements SafeParcelable {
    public static final Parcelable.Creator<Query> CREATOR = new zza();
    final int zzCY;
    final List<DriveSpace> zzadR;
    private final Set<DriveSpace> zzadS;
    final LogicalFilter zzahG;
    final String zzahH;
    final SortOrder zzahI;
    final List<String> zzahJ;
    final boolean zzahK;

    /* loaded from: classes.dex */
    public static class Builder {
        private Set<DriveSpace> zzadS;
        private String zzahH;
        private SortOrder zzahI;
        private List<String> zzahJ;
        private boolean zzahK;
        private final List<Filter> zzahL = new ArrayList();

        public Builder() {
        }

        public Builder(Query query) {
            this.zzahL.add(query.getFilter());
            this.zzahH = query.getPageToken();
            this.zzahI = query.getSortOrder();
            this.zzahJ = query.zzpZ();
            this.zzahK = query.zzqa();
            this.zzadS = query.zzqb();
        }

        public Builder addFilter(Filter filter) {
            if (!(filter instanceof MatchAllFilter)) {
                this.zzahL.add(filter);
            }
            return this;
        }

        public Query build() {
            return new Query(new LogicalFilter(Operator.zzaim, this.zzahL), this.zzahH, this.zzahI, this.zzahJ, this.zzahK, this.zzadS);
        }

        @Deprecated
        public Builder setPageToken(String token) {
            this.zzahH = token;
            return this;
        }

        public Builder setSortOrder(SortOrder sortOrder) {
            this.zzahI = sortOrder;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Query(int versionCode, LogicalFilter clause, String pageToken, SortOrder sortOrder, List<String> requestedMetadataFields, boolean shouldIncludeParents, List<DriveSpace> spacesList) {
        this(versionCode, clause, pageToken, sortOrder, requestedMetadataFields, shouldIncludeParents, spacesList, spacesList == null ? null : new HashSet(spacesList));
    }

    private Query(int versionCode, LogicalFilter clause, String pageToken, SortOrder sortOrder, List<String> requestedMetadataFields, boolean shouldIncludeParents, List<DriveSpace> spacesList, Set<DriveSpace> spaces) {
        this.zzCY = versionCode;
        this.zzahG = clause;
        this.zzahH = pageToken;
        this.zzahI = sortOrder;
        this.zzahJ = requestedMetadataFields;
        this.zzahK = shouldIncludeParents;
        this.zzadR = spacesList;
        this.zzadS = spaces;
    }

    private Query(LogicalFilter clause, String pageToken, SortOrder sortOrder, List<String> requestedMetadataFields, boolean shouldIncludeParents, Set<DriveSpace> spaces) {
        this(1, clause, pageToken, sortOrder, requestedMetadataFields, shouldIncludeParents, spaces == null ? null : new ArrayList(spaces), spaces);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public Filter getFilter() {
        return this.zzahG;
    }

    @Deprecated
    public String getPageToken() {
        return this.zzahH;
    }

    public SortOrder getSortOrder() {
        return this.zzahI;
    }

    public String toString() {
        return String.format(Locale.US, "Query[%s,%s,PageToken=%s,Spaces=%s]", this.zzahG, this.zzahI, this.zzahH, this.zzadR);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza.zza(this, out, flags);
    }

    public List<String> zzpZ() {
        return this.zzahJ;
    }

    public boolean zzqa() {
        return this.zzahK;
    }

    public Set<DriveSpace> zzqb() {
        return this.zzadS;
    }
}
