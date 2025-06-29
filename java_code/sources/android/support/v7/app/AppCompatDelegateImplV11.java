package android.support.v7.app;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.Window;
/* loaded from: classes.dex */
class AppCompatDelegateImplV11 extends AppCompatDelegateImplV7 {
    /* JADX INFO: Access modifiers changed from: package-private */
    public AppCompatDelegateImplV11(Context context, Window window, AppCompatCallback callback) {
        super(context, window, callback);
    }

    @Override // android.support.v7.app.AppCompatDelegateImplV7
    View callActivityOnCreateView(View parent, String name, Context context, AttributeSet attrs) {
        return null;
    }
}
