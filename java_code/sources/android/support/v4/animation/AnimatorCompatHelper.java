package android.support.v4.animation;

import android.os.Build;
import android.view.View;
/* loaded from: classes.dex */
public abstract class AnimatorCompatHelper {
    static AnimatorProvider IMPL;

    static {
        if (Build.VERSION.SDK_INT >= 12) {
            IMPL = new HoneycombMr1AnimatorCompatProvider();
        } else {
            IMPL = new DonutAnimatorCompatProvider();
        }
    }

    public static ValueAnimatorCompat emptyValueAnimator() {
        return IMPL.emptyValueAnimator();
    }

    AnimatorCompatHelper() {
    }

    public static void clearInterpolator(View view) {
        IMPL.clearInterpolator(view);
    }
}
