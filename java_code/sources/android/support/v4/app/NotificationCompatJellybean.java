package android.support.v4.app;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.app.NotificationCompatBase;
import android.support.v4.app.RemoteInputCompatBase;
import android.util.Log;
import android.util.SparseArray;
import android.widget.RemoteViews;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
/* loaded from: classes.dex */
class NotificationCompatJellybean {
    static final String EXTRA_ACTION_EXTRAS = "android.support.actionExtras";
    static final String EXTRA_GROUP_KEY = "android.support.groupKey";
    static final String EXTRA_GROUP_SUMMARY = "android.support.isGroupSummary";
    static final String EXTRA_LOCAL_ONLY = "android.support.localOnly";
    static final String EXTRA_REMOTE_INPUTS = "android.support.remoteInputs";
    static final String EXTRA_SORT_KEY = "android.support.sortKey";
    static final String EXTRA_USE_SIDE_CHANNEL = "android.support.useSideChannel";
    private static final String KEY_ACTION_INTENT = "actionIntent";
    private static final String KEY_EXTRAS = "extras";
    private static final String KEY_ICON = "icon";
    private static final String KEY_REMOTE_INPUTS = "remoteInputs";
    private static final String KEY_TITLE = "title";
    public static final String TAG = "NotificationCompat";
    private static Class<?> sActionClass;
    private static Field sActionIconField;
    private static Field sActionIntentField;
    private static Field sActionTitleField;
    private static boolean sActionsAccessFailed;
    private static Field sActionsField;
    private static Field sExtrasField;
    private static boolean sExtrasFieldAccessFailed;
    private static final Object sExtrasLock = new Object();
    private static final Object sActionsLock = new Object();

    NotificationCompatJellybean() {
    }

    /* loaded from: classes.dex */
    public static class Builder implements NotificationBuilderWithBuilderAccessor, NotificationBuilderWithActions {
        private Notification.Builder b;
        private List<Bundle> mActionExtrasList = new ArrayList();
        private final Bundle mExtras;

        public Builder(Context context, Notification n, CharSequence contentTitle, CharSequence contentText, CharSequence contentInfo, RemoteViews tickerView, int number, PendingIntent contentIntent, PendingIntent fullScreenIntent, Bitmap largeIcon, int progressMax, int progress, boolean progressIndeterminate, boolean useChronometer, int priority, CharSequence subText, boolean localOnly, Bundle extras, String groupKey, boolean groupSummary, String sortKey) {
            this.b = new Notification.Builder(context).setWhen(n.when).setSmallIcon(n.icon, n.iconLevel).setContent(n.contentView).setTicker(n.tickerText, tickerView).setSound(n.sound, n.audioStreamType).setVibrate(n.vibrate).setLights(n.ledARGB, n.ledOnMS, n.ledOffMS).setOngoing((n.flags & 2) != 0).setOnlyAlertOnce((n.flags & 8) != 0).setAutoCancel((n.flags & 16) != 0).setDefaults(n.defaults).setContentTitle(contentTitle).setContentText(contentText).setSubText(subText).setContentInfo(contentInfo).setContentIntent(contentIntent).setDeleteIntent(n.deleteIntent).setFullScreenIntent(fullScreenIntent, (n.flags & 128) != 0).setLargeIcon(largeIcon).setNumber(number).setUsesChronometer(useChronometer).setPriority(priority).setProgress(progressMax, progress, progressIndeterminate);
            this.mExtras = new Bundle();
            if (extras != null) {
                this.mExtras.putAll(extras);
            }
            if (localOnly) {
                this.mExtras.putBoolean("android.support.localOnly", true);
            }
            if (groupKey != null) {
                this.mExtras.putString("android.support.groupKey", groupKey);
                if (groupSummary) {
                    this.mExtras.putBoolean("android.support.isGroupSummary", true);
                } else {
                    this.mExtras.putBoolean("android.support.useSideChannel", true);
                }
            }
            if (sortKey != null) {
                this.mExtras.putString("android.support.sortKey", sortKey);
            }
        }

        @Override // android.support.v4.app.NotificationBuilderWithActions
        public void addAction(NotificationCompatBase.Action action) {
            this.mActionExtrasList.add(NotificationCompatJellybean.writeActionAndGetExtras(this.b, action));
        }

        @Override // android.support.v4.app.NotificationBuilderWithBuilderAccessor
        public Notification.Builder getBuilder() {
            return this.b;
        }

        @Override // android.support.v4.app.NotificationBuilderWithBuilderAccessor
        public Notification build() {
            Notification notif = this.b.build();
            Bundle extras = NotificationCompatJellybean.getExtras(notif);
            Bundle mergeBundle = new Bundle(this.mExtras);
            for (String key : this.mExtras.keySet()) {
                if (extras.containsKey(key)) {
                    mergeBundle.remove(key);
                }
            }
            extras.putAll(mergeBundle);
            SparseArray<Bundle> actionExtrasMap = NotificationCompatJellybean.buildActionExtrasMap(this.mActionExtrasList);
            if (actionExtrasMap != null) {
                NotificationCompatJellybean.getExtras(notif).putSparseParcelableArray("android.support.actionExtras", actionExtrasMap);
            }
            return notif;
        }
    }

    public static void addBigTextStyle(NotificationBuilderWithBuilderAccessor b, CharSequence bigContentTitle, boolean useSummary, CharSequence summaryText, CharSequence bigText) {
        Notification.BigTextStyle style = new Notification.BigTextStyle(b.getBuilder()).setBigContentTitle(bigContentTitle).bigText(bigText);
        if (useSummary) {
            style.setSummaryText(summaryText);
        }
    }

    public static void addBigPictureStyle(NotificationBuilderWithBuilderAccessor b, CharSequence bigContentTitle, boolean useSummary, CharSequence summaryText, Bitmap bigPicture, Bitmap bigLargeIcon, boolean bigLargeIconSet) {
        Notification.BigPictureStyle style = new Notification.BigPictureStyle(b.getBuilder()).setBigContentTitle(bigContentTitle).bigPicture(bigPicture);
        if (bigLargeIconSet) {
            style.bigLargeIcon(bigLargeIcon);
        }
        if (useSummary) {
            style.setSummaryText(summaryText);
        }
    }

    public static void addInboxStyle(NotificationBuilderWithBuilderAccessor b, CharSequence bigContentTitle, boolean useSummary, CharSequence summaryText, ArrayList<CharSequence> texts) {
        Notification.InboxStyle style = new Notification.InboxStyle(b.getBuilder()).setBigContentTitle(bigContentTitle);
        if (useSummary) {
            style.setSummaryText(summaryText);
        }
        Iterator i$ = texts.iterator();
        while (i$.hasNext()) {
            CharSequence text = i$.next();
            style.addLine(text);
        }
    }

    public static SparseArray<Bundle> buildActionExtrasMap(List<Bundle> actionExtrasList) {
        SparseArray<Bundle> actionExtrasMap = null;
        int count = actionExtrasList.size();
        for (int i = 0; i < count; i++) {
            Bundle actionExtras = actionExtrasList.get(i);
            if (actionExtras != null) {
                if (actionExtrasMap == null) {
                    actionExtrasMap = new SparseArray<>();
                }
                actionExtrasMap.put(i, actionExtras);
            }
        }
        return actionExtrasMap;
    }

    public static Bundle getExtras(Notification notif) {
        synchronized (sExtrasLock) {
            if (sExtrasFieldAccessFailed) {
                return null;
            }
            try {
                if (sExtrasField == null) {
                    Field extrasField = Notification.class.getDeclaredField(KEY_EXTRAS);
                    if (!Bundle.class.isAssignableFrom(extrasField.getType())) {
                        Log.e(TAG, "Notification.extras field is not of type Bundle");
                        sExtrasFieldAccessFailed = true;
                        return null;
                    }
                    extrasField.setAccessible(true);
                    sExtrasField = extrasField;
                }
                Bundle extras = (Bundle) sExtrasField.get(notif);
                if (extras == null) {
                    extras = new Bundle();
                    sExtrasField.set(notif, extras);
                }
                return extras;
            } catch (IllegalAccessException e) {
                Log.e(TAG, "Unable to access notification extras", e);
                sExtrasFieldAccessFailed = true;
                return null;
            } catch (NoSuchFieldException e2) {
                Log.e(TAG, "Unable to access notification extras", e2);
                sExtrasFieldAccessFailed = true;
                return null;
            }
        }
    }

    public static NotificationCompatBase.Action readAction(NotificationCompatBase.Action.Factory factory, RemoteInputCompatBase.RemoteInput.Factory remoteInputFactory, int icon, CharSequence title, PendingIntent actionIntent, Bundle extras) {
        RemoteInputCompatBase.RemoteInput[] remoteInputs = null;
        if (extras != null) {
            remoteInputs = RemoteInputCompatJellybean.fromBundleArray(BundleUtil.getBundleArrayFromBundle(extras, "android.support.remoteInputs"), remoteInputFactory);
        }
        return factory.build(icon, title, actionIntent, extras, remoteInputs);
    }

    public static Bundle writeActionAndGetExtras(Notification.Builder builder, NotificationCompatBase.Action action) {
        builder.addAction(action.getIcon(), action.getTitle(), action.getActionIntent());
        Bundle actionExtras = new Bundle(action.getExtras());
        if (action.getRemoteInputs() != null) {
            actionExtras.putParcelableArray("android.support.remoteInputs", RemoteInputCompatJellybean.toBundleArray(action.getRemoteInputs()));
        }
        return actionExtras;
    }

    public static int getActionCount(Notification notif) {
        int length;
        synchronized (sActionsLock) {
            Object[] actionObjects = getActionObjectsLocked(notif);
            length = actionObjects != null ? actionObjects.length : 0;
        }
        return length;
    }

    public static NotificationCompatBase.Action getAction(Notification notif, int actionIndex, NotificationCompatBase.Action.Factory factory, RemoteInputCompatBase.RemoteInput.Factory remoteInputFactory) {
        NotificationCompatBase.Action readAction;
        SparseArray<Bundle> actionExtrasMap;
        synchronized (sActionsLock) {
            try {
                Object actionObject = getActionObjectsLocked(notif)[actionIndex];
                Bundle actionExtras = null;
                Bundle extras = getExtras(notif);
                if (extras != null && (actionExtrasMap = extras.getSparseParcelableArray("android.support.actionExtras")) != null) {
                    actionExtras = actionExtrasMap.get(actionIndex);
                }
                readAction = readAction(factory, remoteInputFactory, sActionIconField.getInt(actionObject), (CharSequence) sActionTitleField.get(actionObject), (PendingIntent) sActionIntentField.get(actionObject), actionExtras);
            } catch (IllegalAccessException e) {
                Log.e(TAG, "Unable to access notification actions", e);
                sActionsAccessFailed = true;
                return null;
            }
        }
        return readAction;
    }

    private static Object[] getActionObjectsLocked(Notification notif) {
        synchronized (sActionsLock) {
            if (ensureActionReflectionReadyLocked()) {
                try {
                    return (Object[]) sActionsField.get(notif);
                } catch (IllegalAccessException e) {
                    Log.e(TAG, "Unable to access notification actions", e);
                    sActionsAccessFailed = true;
                    return null;
                }
            }
            return null;
        }
    }

    private static boolean ensureActionReflectionReadyLocked() {
        if (sActionsAccessFailed) {
            return false;
        }
        try {
            if (sActionsField == null) {
                sActionClass = Class.forName("android.app.Notification$Action");
                sActionIconField = sActionClass.getDeclaredField(KEY_ICON);
                sActionTitleField = sActionClass.getDeclaredField(KEY_TITLE);
                sActionIntentField = sActionClass.getDeclaredField(KEY_ACTION_INTENT);
                sActionsField = Notification.class.getDeclaredField("actions");
                sActionsField.setAccessible(true);
            }
        } catch (ClassNotFoundException e) {
            Log.e(TAG, "Unable to access notification actions", e);
            sActionsAccessFailed = true;
        } catch (NoSuchFieldException e2) {
            Log.e(TAG, "Unable to access notification actions", e2);
            sActionsAccessFailed = true;
        }
        return sActionsAccessFailed ? false : true;
    }

    public static NotificationCompatBase.Action[] getActionsFromParcelableArrayList(ArrayList<Parcelable> parcelables, NotificationCompatBase.Action.Factory actionFactory, RemoteInputCompatBase.RemoteInput.Factory remoteInputFactory) {
        if (parcelables == null) {
            return null;
        }
        NotificationCompatBase.Action[] actions = actionFactory.newArray(parcelables.size());
        for (int i = 0; i < actions.length; i++) {
            actions[i] = getActionFromBundle((Bundle) parcelables.get(i), actionFactory, remoteInputFactory);
        }
        return actions;
    }

    private static NotificationCompatBase.Action getActionFromBundle(Bundle bundle, NotificationCompatBase.Action.Factory actionFactory, RemoteInputCompatBase.RemoteInput.Factory remoteInputFactory) {
        return actionFactory.build(bundle.getInt(KEY_ICON), bundle.getCharSequence(KEY_TITLE), (PendingIntent) bundle.getParcelable(KEY_ACTION_INTENT), bundle.getBundle(KEY_EXTRAS), RemoteInputCompatJellybean.fromBundleArray(BundleUtil.getBundleArrayFromBundle(bundle, KEY_REMOTE_INPUTS), remoteInputFactory));
    }

    public static ArrayList<Parcelable> getParcelableArrayListForActions(NotificationCompatBase.Action[] actions) {
        if (actions == null) {
            return null;
        }
        ArrayList<Parcelable> parcelables = new ArrayList<>(actions.length);
        for (NotificationCompatBase.Action action : actions) {
            parcelables.add(getBundleForAction(action));
        }
        return parcelables;
    }

    private static Bundle getBundleForAction(NotificationCompatBase.Action action) {
        Bundle bundle = new Bundle();
        bundle.putInt(KEY_ICON, action.getIcon());
        bundle.putCharSequence(KEY_TITLE, action.getTitle());
        bundle.putParcelable(KEY_ACTION_INTENT, action.getActionIntent());
        bundle.putBundle(KEY_EXTRAS, action.getExtras());
        bundle.putParcelableArray(KEY_REMOTE_INPUTS, RemoteInputCompatJellybean.toBundleArray(action.getRemoteInputs()));
        return bundle;
    }

    public static boolean getLocalOnly(Notification notif) {
        return getExtras(notif).getBoolean("android.support.localOnly");
    }

    public static String getGroup(Notification n) {
        return getExtras(n).getString("android.support.groupKey");
    }

    public static boolean isGroupSummary(Notification n) {
        return getExtras(n).getBoolean("android.support.isGroupSummary");
    }

    public static String getSortKey(Notification n) {
        return getExtras(n).getString("android.support.sortKey");
    }
}
