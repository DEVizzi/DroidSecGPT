package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class Field implements SafeParcelable {
    public static final int FORMAT_FLOAT = 2;
    public static final int FORMAT_INT32 = 1;
    public static final int FORMAT_MAP = 4;
    public static final int FORMAT_STRING = 3;
    public static final int MEAL_TYPE_BREAKFAST = 1;
    public static final int MEAL_TYPE_DINNER = 3;
    public static final int MEAL_TYPE_LUNCH = 2;
    public static final int MEAL_TYPE_SNACK = 4;
    public static final int MEAL_TYPE_UNKNOWN = 0;
    public static final String NUTRIENT_CALCIUM = "calcium";
    public static final String NUTRIENT_CHOLESTEROL = "cholesterol";
    public static final String NUTRIENT_DIETARY_FIBER = "dietary_fiber";
    public static final String NUTRIENT_IRON = "iron";
    public static final String NUTRIENT_MONOUNSATURATED_FAT = "fat.monounsaturated";
    public static final String NUTRIENT_POLYUNSATURATED_FAT = "fat.polyunsaturated";
    public static final String NUTRIENT_POTASSIUM = "potassium";
    public static final String NUTRIENT_PROTEIN = "protein";
    public static final String NUTRIENT_SATURATED_FAT = "fat.saturated";
    public static final String NUTRIENT_SODIUM = "sodium";
    public static final String NUTRIENT_SUGAR = "sugar";
    public static final String NUTRIENT_TOTAL_CARBS = "carbs.total";
    public static final String NUTRIENT_TOTAL_FAT = "fat.total";
    public static final String NUTRIENT_TRANS_FAT = "fat.trans";
    public static final String NUTRIENT_UNSATURATED_FAT = "fat.unsaturated";
    public static final String NUTRIENT_VITAMIN_A = "vitamin_a";
    public static final String NUTRIENT_VITAMIN_C = "vitamin_c";
    public static final int RESISTANCE_TYPE_BARBELL = 1;
    public static final int RESISTANCE_TYPE_BODY = 6;
    public static final int RESISTANCE_TYPE_CABLE = 2;
    public static final int RESISTANCE_TYPE_DUMBBELL = 3;
    public static final int RESISTANCE_TYPE_KETTLEBELL = 4;
    public static final int RESISTANCE_TYPE_MACHINE = 5;
    public static final int RESISTANCE_TYPE_UNKNOWN = 0;
    private final String mName;
    private final int zzCY;
    private final int zzakB;
    public static final Field FIELD_ACTIVITY = zzcH("activity");
    public static final Field FIELD_CONFIDENCE = zzcI("confidence");
    public static final Field zzakv = zzcK("activity_confidences");
    public static final Field FIELD_STEPS = zzcH("steps");
    public static final Field FIELD_DURATION = zzcH("duration");
    public static final Field FIELD_BPM = zzcI("bpm");
    public static final Field FIELD_LATITUDE = zzcI("latitude");
    public static final Field FIELD_LONGITUDE = zzcI("longitude");
    public static final Field FIELD_ACCURACY = zzcI("accuracy");
    public static final Field FIELD_ALTITUDE = zzcI("altitude");
    public static final Field zzakw = zzcI("elevation.gain");
    public static final Field FIELD_DISTANCE = zzcI("distance");
    public static final Field FIELD_HEIGHT = zzcI("height");
    public static final Field FIELD_WEIGHT = zzcI("weight");
    public static final Field FIELD_CIRCUMFERENCE = zzcI("circumference");
    public static final Field FIELD_PERCENTAGE = zzcI("percentage");
    public static final Field FIELD_SPEED = zzcI("speed");
    public static final Field FIELD_RPM = zzcI("rpm");
    public static final Field FIELD_REVOLUTIONS = zzcH("revolutions");
    public static final String NUTRIENT_CALORIES = "calories";
    public static final Field FIELD_CALORIES = zzcI(NUTRIENT_CALORIES);
    public static final Field FIELD_WATTS = zzcI("watts");
    public static final Field FIELD_MEAL_TYPE = zzcH("meal_type");
    public static final Field FIELD_FOOD_ITEM = zzcJ("food_item");
    public static final Field FIELD_NUTRIENTS = zzcK("nutrients");
    public static final Field FIELD_EXERCISE = zzcJ("exercise");
    public static final Field FIELD_REPETITIONS = zzcH("repetitions");
    public static final Field FIELD_RESISTANCE = zzcI("resistance");
    public static final Field FIELD_RESISTANCE_TYPE = zzcH("resistance_type");
    public static final Field FIELD_NUM_SEGMENTS = zzcH("num_segments");
    public static final Field FIELD_AVERAGE = zzcI("average");
    public static final Field FIELD_MAX = zzcI("max");
    public static final Field FIELD_MIN = zzcI("min");
    public static final Field FIELD_LOW_LATITUDE = zzcI("low_latitude");
    public static final Field FIELD_LOW_LONGITUDE = zzcI("low_longitude");
    public static final Field FIELD_HIGH_LATITUDE = zzcI("high_latitude");
    public static final Field FIELD_HIGH_LONGITUDE = zzcI("high_longitude");
    public static final Field zzakx = zzcH("edge_type");
    public static final Field zzaky = zzcI("x");
    public static final Field zzakz = zzcI("y");
    public static final Field zzakA = zzcI("z");
    public static final Parcelable.Creator<Field> CREATOR = new zzi();

    /* JADX INFO: Access modifiers changed from: package-private */
    public Field(int versionCode, String name, int format) {
        this.zzCY = versionCode;
        this.mName = (String) zzu.zzu(name);
        this.zzakB = format;
    }

    private Field(String name, int format) {
        this(1, name, format);
    }

    private boolean zza(Field field) {
        return this.mName.equals(field.mName) && this.zzakB == field.zzakB;
    }

    private static Field zzcH(String str) {
        return new Field(str, 1);
    }

    private static Field zzcI(String str) {
        return new Field(str, 2);
    }

    private static Field zzcJ(String str) {
        return new Field(str, 3);
    }

    private static Field zzcK(String str) {
        return new Field(str, 4);
    }

    public static Field zzn(String str, int i) {
        char c = 65535;
        switch (str.hashCode()) {
            case -2131707655:
                if (str.equals("accuracy")) {
                    c = 0;
                    break;
                }
                break;
            case -1992012396:
                if (str.equals("duration")) {
                    c = '\n';
                    break;
                }
                break;
            case -1655966961:
                if (str.equals("activity")) {
                    c = 1;
                    break;
                }
                break;
            case -1569430471:
                if (str.equals("num_segments")) {
                    c = 24;
                    break;
                }
                break;
            case -1439978388:
                if (str.equals("latitude")) {
                    c = 17;
                    break;
                }
                break;
            case -1221029593:
                if (str.equals("height")) {
                    c = 14;
                    break;
                }
                break;
            case -1110756780:
                if (str.equals("food_item")) {
                    c = '\r';
                    break;
                }
                break;
            case -921832806:
                if (str.equals("percentage")) {
                    c = 26;
                    break;
                }
                break;
            case -791592328:
                if (str.equals("weight")) {
                    c = '#';
                    break;
                }
                break;
            case -631448035:
                if (str.equals("average")) {
                    c = 4;
                    break;
                }
                break;
            case -626344110:
                if (str.equals("high_longitude")) {
                    c = 16;
                    break;
                }
                break;
            case -619868540:
                if (str.equals("low_longitude")) {
                    c = 20;
                    break;
                }
                break;
            case -494782871:
                if (str.equals("high_latitude")) {
                    c = 15;
                    break;
                }
                break;
            case -437053898:
                if (str.equals("meal_type")) {
                    c = 22;
                    break;
                }
                break;
            case -277306353:
                if (str.equals("circumference")) {
                    c = 7;
                    break;
                }
                break;
            case -266093204:
                if (str.equals("nutrients")) {
                    c = 25;
                    break;
                }
                break;
            case -168965370:
                if (str.equals(NUTRIENT_CALORIES)) {
                    c = 6;
                    break;
                }
                break;
            case -126538880:
                if (str.equals("resistance_type")) {
                    c = 29;
                    break;
                }
                break;
            case 120:
                if (str.equals("x")) {
                    c = '$';
                    break;
                }
                break;
            case 121:
                if (str.equals("y")) {
                    c = '%';
                    break;
                }
                break;
            case 122:
                if (str.equals("z")) {
                    c = '&';
                    break;
                }
                break;
            case 97759:
                if (str.equals("bpm")) {
                    c = 5;
                    break;
                }
                break;
            case 107876:
                if (str.equals("max")) {
                    c = 21;
                    break;
                }
                break;
            case 108114:
                if (str.equals("min")) {
                    c = 23;
                    break;
                }
                break;
            case 113135:
                if (str.equals("rpm")) {
                    c = 31;
                    break;
                }
                break;
            case 109641799:
                if (str.equals("speed")) {
                    c = ' ';
                    break;
                }
                break;
            case 109761319:
                if (str.equals("steps")) {
                    c = '!';
                    break;
                }
                break;
            case 112903913:
                if (str.equals("watts")) {
                    c = '\"';
                    break;
                }
                break;
            case 137365935:
                if (str.equals("longitude")) {
                    c = 18;
                    break;
                }
                break;
            case 198162679:
                if (str.equals("low_latitude")) {
                    c = 19;
                    break;
                }
                break;
            case 224520316:
                if (str.equals("edge_type")) {
                    c = 11;
                    break;
                }
                break;
            case 288459765:
                if (str.equals("distance")) {
                    c = '\t';
                    break;
                }
                break;
            case 811264586:
                if (str.equals("revolutions")) {
                    c = 30;
                    break;
                }
                break;
            case 829251210:
                if (str.equals("confidence")) {
                    c = '\b';
                    break;
                }
                break;
            case 984367650:
                if (str.equals("repetitions")) {
                    c = 27;
                    break;
                }
                break;
            case 1857734768:
                if (str.equals("elevation.gain")) {
                    c = 3;
                    break;
                }
                break;
            case 1863800889:
                if (str.equals("resistance")) {
                    c = 28;
                    break;
                }
                break;
            case 2036550306:
                if (str.equals("altitude")) {
                    c = 2;
                    break;
                }
                break;
            case 2056323544:
                if (str.equals("exercise")) {
                    c = '\f';
                    break;
                }
                break;
        }
        switch (c) {
            case 0:
                return FIELD_ACCURACY;
            case 1:
                return FIELD_ACTIVITY;
            case 2:
                return FIELD_ALTITUDE;
            case 3:
                return zzakw;
            case 4:
                return FIELD_AVERAGE;
            case 5:
                return FIELD_BPM;
            case 6:
                return FIELD_CALORIES;
            case 7:
                return FIELD_CIRCUMFERENCE;
            case '\b':
                return FIELD_CONFIDENCE;
            case '\t':
                return FIELD_DISTANCE;
            case '\n':
                return FIELD_DURATION;
            case 11:
                return zzakx;
            case '\f':
                return FIELD_EXERCISE;
            case '\r':
                return FIELD_FOOD_ITEM;
            case 14:
                return FIELD_HEIGHT;
            case 15:
                return FIELD_HIGH_LATITUDE;
            case 16:
                return FIELD_HIGH_LONGITUDE;
            case 17:
                return FIELD_LATITUDE;
            case 18:
                return FIELD_LONGITUDE;
            case 19:
                return FIELD_LOW_LATITUDE;
            case 20:
                return FIELD_LOW_LONGITUDE;
            case 21:
                return FIELD_MAX;
            case 22:
                return FIELD_MEAL_TYPE;
            case 23:
                return FIELD_MIN;
            case 24:
                return FIELD_NUM_SEGMENTS;
            case 25:
                return FIELD_NUTRIENTS;
            case 26:
                return FIELD_PERCENTAGE;
            case 27:
                return FIELD_REPETITIONS;
            case 28:
                return FIELD_RESISTANCE;
            case 29:
                return FIELD_RESISTANCE_TYPE;
            case 30:
                return FIELD_REVOLUTIONS;
            case 31:
                return FIELD_RPM;
            case ' ':
                return FIELD_SPEED;
            case '!':
                return FIELD_STEPS;
            case '\"':
                return FIELD_WATTS;
            case '#':
                return FIELD_WEIGHT;
            case '$':
                return zzaky;
            case '%':
                return zzakz;
            case '&':
                return zzakA;
            default:
                return new Field(str, i);
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object that) {
        return this == that || ((that instanceof Field) && zza((Field) that));
    }

    public int getFormat() {
        return this.zzakB;
    }

    public String getName() {
        return this.mName;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return this.mName.hashCode();
    }

    public String toString() {
        Object[] objArr = new Object[2];
        objArr[0] = this.mName;
        objArr[1] = this.zzakB == 1 ? "i" : "f";
        return String.format("%s(%s)", objArr);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzi.zza(this, dest, flags);
    }
}
