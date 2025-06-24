package com.google.android.gms.games.appcontent;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzc;
import java.util.ArrayList;
/* loaded from: classes.dex */
public abstract class MultiDataBufferRef extends zzc {
    protected final ArrayList<DataHolder> zzaoD;

    /* JADX INFO: Access modifiers changed from: protected */
    public MultiDataBufferRef(ArrayList<DataHolder> dataHolderCollection, int indexForRef, int dataRow) {
        super(dataHolderCollection.get(indexForRef), dataRow);
        this.zzaoD = dataHolderCollection;
    }
}
