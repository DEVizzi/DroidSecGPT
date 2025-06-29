package android.support.design.widget;

import android.graphics.Rect;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
/* loaded from: classes.dex */
class ViewGroupUtils {
    private static final ViewGroupUtilsImpl IMPL;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface ViewGroupUtilsImpl {
        void offsetDescendantRect(ViewGroup viewGroup, View view, Rect rect);
    }

    ViewGroupUtils() {
    }

    /* loaded from: classes.dex */
    private static class ViewGroupUtilsImplBase implements ViewGroupUtilsImpl {
        private ViewGroupUtilsImplBase() {
        }

        @Override // android.support.design.widget.ViewGroupUtils.ViewGroupUtilsImpl
        public void offsetDescendantRect(ViewGroup parent, View child, Rect rect) {
            parent.offsetDescendantRectToMyCoords(child, rect);
        }
    }

    /* loaded from: classes.dex */
    private static class ViewGroupUtilsImplHoneycomb implements ViewGroupUtilsImpl {
        private ViewGroupUtilsImplHoneycomb() {
        }

        @Override // android.support.design.widget.ViewGroupUtils.ViewGroupUtilsImpl
        public void offsetDescendantRect(ViewGroup parent, View child, Rect rect) {
            ViewGroupUtilsHoneycomb.offsetDescendantRect(parent, child, rect);
        }
    }

    static {
        int version = Build.VERSION.SDK_INT;
        if (version >= 11) {
            IMPL = new ViewGroupUtilsImplHoneycomb();
        } else {
            IMPL = new ViewGroupUtilsImplBase();
        }
    }

    static void offsetDescendantRect(ViewGroup parent, View descendant, Rect rect) {
        IMPL.offsetDescendantRect(parent, descendant, rect);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void getDescendantRect(ViewGroup parent, View descendant, Rect out) {
        out.set(0, 0, descendant.getWidth(), descendant.getHeight());
        offsetDescendantRect(parent, descendant, out);
    }
}
