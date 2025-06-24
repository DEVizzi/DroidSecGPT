package com.google.android.gms.games.appcontent;

import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.internal.zzkx;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class AppContentUtils {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface AppContentRunner {
        void zzb(ArrayList<DataHolder> arrayList, int i);
    }

    public static ArrayList<AppContentAction> zza(DataHolder dataHolder, ArrayList<DataHolder> arrayList, String str, int i) {
        final ArrayList<AppContentAction> arrayList2 = new ArrayList<>();
        zza(dataHolder, 1, str, "action_id", i, new AppContentRunner() { // from class: com.google.android.gms.games.appcontent.AppContentUtils.1
            @Override // com.google.android.gms.games.appcontent.AppContentUtils.AppContentRunner
            public void zzb(ArrayList<DataHolder> arrayList3, int i2) {
                arrayList2.add(new AppContentActionRef(arrayList3, i2));
            }
        }, arrayList);
        return arrayList2;
    }

    private static void zza(DataHolder dataHolder, int i, String str, String str2, int i2, AppContentRunner appContentRunner, ArrayList<DataHolder> arrayList) {
        DataHolder dataHolder2 = arrayList.get(i);
        String zzd = dataHolder.zzd(str, i2, dataHolder.zzbh(i2));
        if (TextUtils.isEmpty(zzd)) {
            return;
        }
        int count = dataHolder2.getCount();
        String[] split = zzd.split(",");
        for (int i3 = 0; i3 < count; i3++) {
            String zzd2 = dataHolder2.zzd(str2, i3, dataHolder2.zzbh(i3));
            if (!TextUtils.isEmpty(zzd2) && zzkx.zzb(split, zzd2)) {
                appContentRunner.zzb(arrayList, i3);
            }
        }
    }

    public static ArrayList<AppContentAnnotation> zzb(DataHolder dataHolder, ArrayList<DataHolder> arrayList, String str, int i) {
        final ArrayList<AppContentAnnotation> arrayList2 = new ArrayList<>();
        zza(dataHolder, 2, str, "annotation_id", i, new AppContentRunner() { // from class: com.google.android.gms.games.appcontent.AppContentUtils.2
            @Override // com.google.android.gms.games.appcontent.AppContentUtils.AppContentRunner
            public void zzb(ArrayList<DataHolder> arrayList3, int i2) {
                arrayList2.add(new AppContentAnnotationRef(arrayList3, i2));
            }
        }, arrayList);
        return arrayList2;
    }

    public static ArrayList<AppContentCondition> zzc(DataHolder dataHolder, ArrayList<DataHolder> arrayList, String str, int i) {
        final ArrayList<AppContentCondition> arrayList2 = new ArrayList<>();
        zza(dataHolder, 4, str, "condition_id", i, new AppContentRunner() { // from class: com.google.android.gms.games.appcontent.AppContentUtils.3
            @Override // com.google.android.gms.games.appcontent.AppContentUtils.AppContentRunner
            public void zzb(ArrayList<DataHolder> arrayList3, int i2) {
                arrayList2.add(new AppContentConditionRef(arrayList3, i2));
            }
        }, arrayList);
        return arrayList2;
    }

    public static Bundle zzd(DataHolder dataHolder, ArrayList<DataHolder> arrayList, String str, int i) {
        final Bundle bundle = new Bundle();
        final DataHolder dataHolder2 = arrayList.get(3);
        zza(dataHolder, 3, str, "tuple_id", i, new AppContentRunner() { // from class: com.google.android.gms.games.appcontent.AppContentUtils.4
            @Override // com.google.android.gms.games.appcontent.AppContentUtils.AppContentRunner
            public void zzb(ArrayList<DataHolder> arrayList2, int i2) {
                AppContentTupleRef appContentTupleRef = new AppContentTupleRef(DataHolder.this, i2);
                bundle.putString(appContentTupleRef.getName(), appContentTupleRef.getValue());
            }
        }, arrayList);
        return bundle;
    }
}
