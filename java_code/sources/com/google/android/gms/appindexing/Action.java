package com.google.android.gms.appindexing;

import android.net.Uri;
import android.os.Bundle;
import com.google.android.gms.appindexing.Thing;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.fitness.FitnessActivities;
import com.google.android.gms.plus.PlusShare;
/* loaded from: classes.dex */
public final class Action extends Thing {
    public static final String STATUS_TYPE_ACTIVE = "http://schema.org/ActiveActionStatus";
    public static final String STATUS_TYPE_COMPLETED = "http://schema.org/CompletedActionStatus";
    public static final String STATUS_TYPE_FAILED = "http://schema.org/FailedActionStatus";
    public static final String TYPE_ACTIVATE = "http://schema.org/ActivateAction";
    public static final String TYPE_ADD = "http://schema.org/AddAction";
    public static final String TYPE_BOOKMARK = "http://schema.org/BookmarkAction";
    public static final String TYPE_COMMUNICATE = "http://schema.org/CommunicateAction";
    public static final String TYPE_FILM = "http://schema.org/FilmAction";
    public static final String TYPE_LIKE = "http://schema.org/LikeAction";
    public static final String TYPE_LISTEN = "http://schema.org/ListenAction";
    public static final String TYPE_PHOTOGRAPH = "http://schema.org/PhotographAction";
    public static final String TYPE_RESERVE = "http://schema.org/ReserveAction";
    public static final String TYPE_SEARCH = "http://schema.org/SearchAction";
    public static final String TYPE_VIEW = "http://schema.org/ViewAction";
    public static final String TYPE_WANT = "http://schema.org/WantAction";
    public static final String TYPE_WATCH = "http://schema.org/WatchAction";

    /* loaded from: classes.dex */
    public static final class Builder extends Thing.Builder {
        public Builder(String actionType) {
            zzu.zzu(actionType);
            super.put("type", actionType);
        }

        @Override // com.google.android.gms.appindexing.Thing.Builder
        public Action build() {
            zzu.zzb(this.zzNW.get("object"), "setObject is required before calling build().");
            zzu.zzb(this.zzNW.get("type"), "setType is required before calling build().");
            Bundle bundle = (Bundle) this.zzNW.getParcelable("object");
            zzu.zzb(bundle.get("name"), "Must call setObject() with a valid name. Example: setObject(new Thing.Builder().setName(name).setUrl(url))");
            zzu.zzb(bundle.get(PlusShare.KEY_CALL_TO_ACTION_URL), "Must call setObject() with a valid app URI. Example: setObject(new Thing.Builder().setName(name).setUrl(url))");
            return new Action(this.zzNW);
        }

        @Override // com.google.android.gms.appindexing.Thing.Builder
        public Builder put(String key, Thing value) {
            return (Builder) super.put(key, value);
        }

        @Override // com.google.android.gms.appindexing.Thing.Builder
        public Builder put(String key, String value) {
            return (Builder) super.put(key, value);
        }

        public Builder setActionStatus(String actionStatusType) {
            zzu.zzu(actionStatusType);
            return (Builder) super.put(FitnessActivities.EXTRA_STATUS, actionStatusType);
        }

        @Override // com.google.android.gms.appindexing.Thing.Builder
        public Builder setName(String name) {
            return (Builder) super.put("name", name);
        }

        public Builder setObject(Thing thing) {
            zzu.zzu(thing);
            return (Builder) super.put("object", thing);
        }

        @Override // com.google.android.gms.appindexing.Thing.Builder
        public Builder setUrl(Uri url) {
            if (url != null) {
                super.put(PlusShare.KEY_CALL_TO_ACTION_URL, url.toString());
            }
            return this;
        }
    }

    private Action(Bundle propertyBundle) {
        super(propertyBundle);
    }

    public static Action newAction(String actionType, String objectName, Uri objectAppUri) {
        return newAction(actionType, objectName, null, objectAppUri);
    }

    public static Action newAction(String actionType, String objectName, Uri objectId, Uri objectAppUri) {
        return new Builder(actionType).setObject(new Thing.Builder().setName(objectName).setId(objectId == null ? null : objectId.toString()).setUrl(objectAppUri).build()).build();
    }
}
