package android.support.v4.app;

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.RemoteInputCompatBase;
/* loaded from: classes.dex */
class RemoteInputCompatJellybean {
    public static final String EXTRA_RESULTS_DATA = "android.remoteinput.resultsData";
    private static final String KEY_ALLOW_FREE_FORM_INPUT = "allowFreeFormInput";
    private static final String KEY_CHOICES = "choices";
    private static final String KEY_EXTRAS = "extras";
    private static final String KEY_LABEL = "label";
    private static final String KEY_RESULT_KEY = "resultKey";
    public static final String RESULTS_CLIP_LABEL = "android.remoteinput.results";

    RemoteInputCompatJellybean() {
    }

    static RemoteInputCompatBase.RemoteInput fromBundle(Bundle data, RemoteInputCompatBase.RemoteInput.Factory factory) {
        return factory.build(data.getString(KEY_RESULT_KEY), data.getCharSequence(KEY_LABEL), data.getCharSequenceArray(KEY_CHOICES), data.getBoolean(KEY_ALLOW_FREE_FORM_INPUT), data.getBundle(KEY_EXTRAS));
    }

    static Bundle toBundle(RemoteInputCompatBase.RemoteInput remoteInput) {
        Bundle data = new Bundle();
        data.putString(KEY_RESULT_KEY, remoteInput.getResultKey());
        data.putCharSequence(KEY_LABEL, remoteInput.getLabel());
        data.putCharSequenceArray(KEY_CHOICES, remoteInput.getChoices());
        data.putBoolean(KEY_ALLOW_FREE_FORM_INPUT, remoteInput.getAllowFreeFormInput());
        data.putBundle(KEY_EXTRAS, remoteInput.getExtras());
        return data;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RemoteInputCompatBase.RemoteInput[] fromBundleArray(Bundle[] bundles, RemoteInputCompatBase.RemoteInput.Factory factory) {
        if (bundles == null) {
            return null;
        }
        RemoteInputCompatBase.RemoteInput[] remoteInputs = factory.newArray(bundles.length);
        for (int i = 0; i < bundles.length; i++) {
            remoteInputs[i] = fromBundle(bundles[i], factory);
        }
        return remoteInputs;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Bundle[] toBundleArray(RemoteInputCompatBase.RemoteInput[] remoteInputs) {
        if (remoteInputs == null) {
            return null;
        }
        Bundle[] bundles = new Bundle[remoteInputs.length];
        for (int i = 0; i < remoteInputs.length; i++) {
            bundles[i] = toBundle(remoteInputs[i]);
        }
        return bundles;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Bundle getResultsFromIntent(Intent intent) {
        ClipData clipData = intent.getClipData();
        if (clipData == null) {
            return null;
        }
        ClipDescription clipDescription = clipData.getDescription();
        if (clipDescription.hasMimeType("text/vnd.android.intent") && clipDescription.getLabel().equals("android.remoteinput.results")) {
            return (Bundle) clipData.getItemAt(0).getIntent().getExtras().getParcelable("android.remoteinput.resultsData");
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void addResultsToIntent(RemoteInputCompatBase.RemoteInput[] remoteInputs, Intent intent, Bundle results) {
        Bundle resultsBundle = new Bundle();
        for (RemoteInputCompatBase.RemoteInput remoteInput : remoteInputs) {
            Object result = results.get(remoteInput.getResultKey());
            if (result instanceof CharSequence) {
                resultsBundle.putCharSequence(remoteInput.getResultKey(), (CharSequence) result);
            }
        }
        Intent clipIntent = new Intent();
        clipIntent.putExtra("android.remoteinput.resultsData", resultsBundle);
        intent.setClipData(ClipData.newIntent("android.remoteinput.results", clipIntent));
    }
}
