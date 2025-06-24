package com.google.android.gms.location;

import android.content.Intent;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class ActivityRecognitionResult implements SafeParcelable {
    public static final ActivityRecognitionResultCreator CREATOR = new ActivityRecognitionResultCreator();
    private final int zzCY;
    List<DetectedActivity> zzaxr;
    long zzaxs;
    long zzaxt;
    int zzaxu;

    public ActivityRecognitionResult(int versionCode, List<DetectedActivity> probableActivities, long timeMillis, long elapsedRealtimeMillis, int detectorInfoId) {
        this.zzCY = versionCode;
        this.zzaxr = probableActivities;
        this.zzaxs = timeMillis;
        this.zzaxt = elapsedRealtimeMillis;
        this.zzaxu = detectorInfoId;
    }

    public ActivityRecognitionResult(DetectedActivity mostProbableActivity, long time, long elapsedRealtimeMillis) {
        this(mostProbableActivity, time, elapsedRealtimeMillis, 0);
    }

    public ActivityRecognitionResult(DetectedActivity mostProbableActivity, long time, long elapsedRealtimeMillis, int detectorInfoId) {
        this(Collections.singletonList(mostProbableActivity), time, elapsedRealtimeMillis, detectorInfoId);
    }

    public ActivityRecognitionResult(List<DetectedActivity> probableActivities, long time, long elapsedRealtimeMillis) {
        this(probableActivities, time, elapsedRealtimeMillis, 0);
    }

    public ActivityRecognitionResult(List<DetectedActivity> probableActivities, long time, long elapsedRealtimeMillis, int detectorInfoId) {
        boolean z = true;
        zzu.zzb(probableActivities != null && probableActivities.size() > 0, "Must have at least 1 detected activity");
        zzu.zzb((time <= 0 || elapsedRealtimeMillis <= 0) ? false : z, "Must set times");
        this.zzCY = 2;
        this.zzaxr = probableActivities;
        this.zzaxs = time;
        this.zzaxt = elapsedRealtimeMillis;
        this.zzaxu = detectorInfoId;
    }

    public static ActivityRecognitionResult extractResult(Intent intent) {
        if (hasResult(intent)) {
            Object obj = intent.getExtras().get("com.google.android.location.internal.EXTRA_ACTIVITY_RESULT");
            if (!(obj instanceof byte[])) {
                if (obj instanceof ActivityRecognitionResult) {
                    return (ActivityRecognitionResult) obj;
                }
                return null;
            }
            Parcel obtain = Parcel.obtain();
            obtain.unmarshall((byte[]) obj, 0, ((byte[]) obj).length);
            obtain.setDataPosition(0);
            return CREATOR.createFromParcel(obtain);
        }
        return null;
    }

    public static boolean hasResult(Intent intent) {
        if (intent == null) {
            return false;
        }
        return intent.hasExtra("com.google.android.location.internal.EXTRA_ACTIVITY_RESULT");
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getActivityConfidence(int activityType) {
        for (DetectedActivity detectedActivity : this.zzaxr) {
            if (detectedActivity.getType() == activityType) {
                return detectedActivity.getConfidence();
            }
        }
        return 0;
    }

    public long getElapsedRealtimeMillis() {
        return this.zzaxt;
    }

    public DetectedActivity getMostProbableActivity() {
        return this.zzaxr.get(0);
    }

    public List<DetectedActivity> getProbableActivities() {
        return this.zzaxr;
    }

    public long getTime() {
        return this.zzaxs;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public String toString() {
        return "ActivityRecognitionResult [probableActivities=" + this.zzaxr + ", timeMillis=" + this.zzaxs + ", elapsedRealtimeMillis=" + this.zzaxt + "]";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        ActivityRecognitionResultCreator.zza(this, out, flags);
    }
}
