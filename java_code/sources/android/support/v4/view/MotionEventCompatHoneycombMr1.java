package android.support.v4.view;

import android.view.MotionEvent;
/* loaded from: classes.dex */
class MotionEventCompatHoneycombMr1 {
    MotionEventCompatHoneycombMr1() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float getAxisValue(MotionEvent event, int axis) {
        return event.getAxisValue(axis);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float getAxisValue(MotionEvent event, int axis, int pointerIndex) {
        return event.getAxisValue(axis, pointerIndex);
    }
}
