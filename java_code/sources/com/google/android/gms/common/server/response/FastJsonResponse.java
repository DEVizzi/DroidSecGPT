package com.google.android.gms.common.server.response;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.common.server.converter.ConverterWrapper;
import com.google.android.gms.internal.zzky;
import com.google.android.gms.internal.zzlh;
import com.google.android.gms.internal.zzli;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public abstract class FastJsonResponse {

    /* loaded from: classes.dex */
    public static class Field<I, O> implements SafeParcelable {
        public static final com.google.android.gms.common.server.response.zza CREATOR = new com.google.android.gms.common.server.response.zza();
        private final int zzCY;
        protected final int zzabG;
        protected final boolean zzabH;
        protected final int zzabI;
        protected final boolean zzabJ;
        protected final String zzabK;
        protected final int zzabL;
        protected final Class<? extends FastJsonResponse> zzabM;
        protected final String zzabN;
        private FieldMappingDictionary zzabO;
        private zza<I, O> zzabP;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Field(int versionCode, int typeIn, boolean typeInArray, int typeOut, boolean typeOutArray, String outputFieldName, int safeParcelableFieldId, String concreteTypeName, ConverterWrapper wrappedConverter) {
            this.zzCY = versionCode;
            this.zzabG = typeIn;
            this.zzabH = typeInArray;
            this.zzabI = typeOut;
            this.zzabJ = typeOutArray;
            this.zzabK = outputFieldName;
            this.zzabL = safeParcelableFieldId;
            if (concreteTypeName == null) {
                this.zzabM = null;
                this.zzabN = null;
            } else {
                this.zzabM = SafeParcelResponse.class;
                this.zzabN = concreteTypeName;
            }
            if (wrappedConverter == null) {
                this.zzabP = null;
            } else {
                this.zzabP = (zza<I, O>) wrappedConverter.zzoi();
            }
        }

        protected Field(int typeIn, boolean typeInArray, int typeOut, boolean typeOutArray, String outputFieldName, int safeParcelableFieldId, Class<? extends FastJsonResponse> concreteType, zza<I, O> converter) {
            this.zzCY = 1;
            this.zzabG = typeIn;
            this.zzabH = typeInArray;
            this.zzabI = typeOut;
            this.zzabJ = typeOutArray;
            this.zzabK = outputFieldName;
            this.zzabL = safeParcelableFieldId;
            this.zzabM = concreteType;
            if (concreteType == null) {
                this.zzabN = null;
            } else {
                this.zzabN = concreteType.getCanonicalName();
            }
            this.zzabP = converter;
        }

        public static Field zza(String str, int i, zza<?, ?> zzaVar, boolean z) {
            return new Field(zzaVar.zzok(), z, zzaVar.zzol(), false, str, i, null, zzaVar);
        }

        public static <T extends FastJsonResponse> Field<T, T> zza(String str, int i, Class<T> cls) {
            return new Field<>(11, false, 11, false, str, i, cls, null);
        }

        public static <T extends FastJsonResponse> Field<ArrayList<T>, ArrayList<T>> zzb(String str, int i, Class<T> cls) {
            return new Field<>(11, true, 11, true, str, i, cls, null);
        }

        public static Field<Integer, Integer> zzi(String str, int i) {
            return new Field<>(0, false, 0, false, str, i, null, null);
        }

        public static Field<Double, Double> zzj(String str, int i) {
            return new Field<>(4, false, 4, false, str, i, null, null);
        }

        public static Field<Boolean, Boolean> zzk(String str, int i) {
            return new Field<>(6, false, 6, false, str, i, null, null);
        }

        public static Field<String, String> zzl(String str, int i) {
            return new Field<>(7, false, 7, false, str, i, null, null);
        }

        public static Field<ArrayList<String>, ArrayList<String>> zzm(String str, int i) {
            return new Field<>(7, true, 7, true, str, i, null, null);
        }

        public I convertBack(O output) {
            return this.zzabP.convertBack(output);
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            com.google.android.gms.common.server.response.zza zzaVar = CREATOR;
            return 0;
        }

        public int getVersionCode() {
            return this.zzCY;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Field\n");
            sb.append("            versionCode=").append(this.zzCY).append('\n');
            sb.append("                 typeIn=").append(this.zzabG).append('\n');
            sb.append("            typeInArray=").append(this.zzabH).append('\n');
            sb.append("                typeOut=").append(this.zzabI).append('\n');
            sb.append("           typeOutArray=").append(this.zzabJ).append('\n');
            sb.append("        outputFieldName=").append(this.zzabK).append('\n');
            sb.append("      safeParcelFieldId=").append(this.zzabL).append('\n');
            sb.append("       concreteTypeName=").append(zzov()).append('\n');
            if (zzou() != null) {
                sb.append("     concreteType.class=").append(zzou().getCanonicalName()).append('\n');
            }
            sb.append("          converterName=").append(this.zzabP == null ? "null" : this.zzabP.getClass().getCanonicalName()).append('\n');
            return sb.toString();
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            com.google.android.gms.common.server.response.zza zzaVar = CREATOR;
            com.google.android.gms.common.server.response.zza.zza(this, out, flags);
        }

        public void zza(FieldMappingDictionary fieldMappingDictionary) {
            this.zzabO = fieldMappingDictionary;
        }

        public int zzok() {
            return this.zzabG;
        }

        public int zzol() {
            return this.zzabI;
        }

        public Field<I, O> zzop() {
            return new Field<>(this.zzCY, this.zzabG, this.zzabH, this.zzabI, this.zzabJ, this.zzabK, this.zzabL, this.zzabN, zzox());
        }

        public boolean zzoq() {
            return this.zzabH;
        }

        public boolean zzor() {
            return this.zzabJ;
        }

        public String zzos() {
            return this.zzabK;
        }

        public int zzot() {
            return this.zzabL;
        }

        public Class<? extends FastJsonResponse> zzou() {
            return this.zzabM;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public String zzov() {
            if (this.zzabN == null) {
                return null;
            }
            return this.zzabN;
        }

        public boolean zzow() {
            return this.zzabP != null;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public ConverterWrapper zzox() {
            if (this.zzabP == null) {
                return null;
            }
            return ConverterWrapper.zza(this.zzabP);
        }

        public Map<String, Field<?, ?>> zzoy() {
            zzu.zzu(this.zzabN);
            zzu.zzu(this.zzabO);
            return this.zzabO.zzco(this.zzabN);
        }
    }

    /* loaded from: classes.dex */
    public interface zza<I, O> {
        I convertBack(O o);

        int zzok();

        int zzol();
    }

    private void zza(StringBuilder sb, Field field, Object obj) {
        if (field.zzok() == 11) {
            sb.append(field.zzou().cast(obj).toString());
        } else if (field.zzok() != 7) {
            sb.append(obj);
        } else {
            sb.append("\"");
            sb.append(zzlh.zzcr((String) obj));
            sb.append("\"");
        }
    }

    private void zza(StringBuilder sb, Field field, ArrayList<Object> arrayList) {
        sb.append("[");
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            if (i > 0) {
                sb.append(",");
            }
            Object obj = arrayList.get(i);
            if (obj != null) {
                zza(sb, field, obj);
            }
        }
        sb.append("]");
    }

    public String toString() {
        Map<String, Field<?, ?>> zzom = zzom();
        StringBuilder sb = new StringBuilder(100);
        for (String str : zzom.keySet()) {
            Field<?, ?> field = zzom.get(str);
            if (zza(field)) {
                Object zza2 = zza(field, zzb(field));
                if (sb.length() == 0) {
                    sb.append("{");
                } else {
                    sb.append(",");
                }
                sb.append("\"").append(str).append("\":");
                if (zza2 == null) {
                    sb.append("null");
                } else {
                    switch (field.zzol()) {
                        case 8:
                            sb.append("\"").append(zzky.zzi((byte[]) zza2)).append("\"");
                            continue;
                        case 9:
                            sb.append("\"").append(zzky.zzj((byte[]) zza2)).append("\"");
                            continue;
                        case 10:
                            zzli.zza(sb, (HashMap) zza2);
                            continue;
                        default:
                            if (field.zzoq()) {
                                zza(sb, (Field) field, (ArrayList) zza2);
                                break;
                            } else {
                                zza(sb, field, zza2);
                                continue;
                            }
                    }
                }
            }
        }
        if (sb.length() > 0) {
            sb.append("}");
        } else {
            sb.append("{}");
        }
        return sb.toString();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Multi-variable type inference failed */
    public <O, I> I zza(Field<I, O> field, Object obj) {
        return ((Field) field).zzabP != null ? field.convertBack(obj) : obj;
    }

    protected boolean zza(Field field) {
        return field.zzol() == 11 ? field.zzor() ? zzcn(field.zzos()) : zzcm(field.zzos()) : zzcl(field.zzos());
    }

    protected Object zzb(Field field) {
        String zzos = field.zzos();
        if (field.zzou() != null) {
            zzu.zza(zzck(field.zzos()) == null, "Concrete field shouldn't be value object: %s", field.zzos());
            HashMap<String, Object> zzoo = field.zzor() ? zzoo() : zzon();
            if (zzoo != null) {
                return zzoo.get(zzos);
            }
            try {
                return getClass().getMethod("get" + Character.toUpperCase(zzos.charAt(0)) + zzos.substring(1), new Class[0]).invoke(this, new Object[0]);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return zzck(field.zzos());
    }

    protected abstract Object zzck(String str);

    protected abstract boolean zzcl(String str);

    protected boolean zzcm(String str) {
        throw new UnsupportedOperationException("Concrete types not supported");
    }

    protected boolean zzcn(String str) {
        throw new UnsupportedOperationException("Concrete type arrays not supported");
    }

    public abstract Map<String, Field<?, ?>> zzom();

    public HashMap<String, Object> zzon() {
        return null;
    }

    public HashMap<String, Object> zzoo() {
        return null;
    }
}
