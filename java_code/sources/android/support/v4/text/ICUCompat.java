package android.support.v4.text;

import android.os.Build;
import java.util.Locale;
/* loaded from: classes.dex */
public class ICUCompat {
    private static final ICUCompatImpl IMPL;

    /* loaded from: classes.dex */
    interface ICUCompatImpl {
        String maximizeAndGetScript(Locale locale);
    }

    /* loaded from: classes.dex */
    static class ICUCompatImplBase implements ICUCompatImpl {
        ICUCompatImplBase() {
        }

        @Override // android.support.v4.text.ICUCompat.ICUCompatImpl
        public String maximizeAndGetScript(Locale locale) {
            return null;
        }
    }

    /* loaded from: classes.dex */
    static class ICUCompatImplIcs implements ICUCompatImpl {
        ICUCompatImplIcs() {
        }

        @Override // android.support.v4.text.ICUCompat.ICUCompatImpl
        public String maximizeAndGetScript(Locale locale) {
            return ICUCompatIcs.maximizeAndGetScript(locale);
        }
    }

    /* loaded from: classes.dex */
    static class ICUCompatImplLollipop implements ICUCompatImpl {
        ICUCompatImplLollipop() {
        }

        @Override // android.support.v4.text.ICUCompat.ICUCompatImpl
        public String maximizeAndGetScript(Locale locale) {
            return ICUCompatApi23.maximizeAndGetScript(locale);
        }
    }

    static {
        int version = Build.VERSION.SDK_INT;
        if (version >= 21) {
            IMPL = new ICUCompatImplLollipop();
        } else if (version >= 14) {
            IMPL = new ICUCompatImplIcs();
        } else {
            IMPL = new ICUCompatImplBase();
        }
    }

    public static String maximizeAndGetScript(Locale locale) {
        return IMPL.maximizeAndGetScript(locale);
    }
}
