package com.google.android.gms.tagmanager;

import android.content.Context;
import com.google.android.gms.analytics.Tracker;
import com.google.android.gms.analytics.ecommerce.Product;
import com.google.android.gms.analytics.ecommerce.ProductAction;
import com.google.android.gms.analytics.ecommerce.Promotion;
import com.google.android.gms.internal.zzag;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
/* loaded from: classes.dex */
public class zzdg extends zzdd {
    private static final String ID = com.google.android.gms.internal.zzad.UNIVERSAL_ANALYTICS.toString();
    private static final String zzaOC = com.google.android.gms.internal.zzae.ACCOUNT.toString();
    private static final String zzaOD = com.google.android.gms.internal.zzae.ANALYTICS_PASS_THROUGH.toString();
    private static final String zzaOE = com.google.android.gms.internal.zzae.ENABLE_ECOMMERCE.toString();
    private static final String zzaOF = com.google.android.gms.internal.zzae.ECOMMERCE_USE_DATA_LAYER.toString();
    private static final String zzaOG = com.google.android.gms.internal.zzae.ECOMMERCE_MACRO_DATA.toString();
    private static final String zzaOH = com.google.android.gms.internal.zzae.ANALYTICS_FIELDS.toString();
    private static final String zzaOI = com.google.android.gms.internal.zzae.TRACK_TRANSACTION.toString();
    private static final String zzaOJ = com.google.android.gms.internal.zzae.TRANSACTION_DATALAYER_MAP.toString();
    private static final String zzaOK = com.google.android.gms.internal.zzae.TRANSACTION_ITEM_DATALAYER_MAP.toString();
    private static final List<String> zzaOL = Arrays.asList(ProductAction.ACTION_DETAIL, ProductAction.ACTION_CHECKOUT, ProductAction.ACTION_CHECKOUT_OPTION, "click", ProductAction.ACTION_ADD, ProductAction.ACTION_REMOVE, ProductAction.ACTION_PURCHASE, ProductAction.ACTION_REFUND);
    private static final Pattern zzaOM = Pattern.compile("dimension(\\d+)");
    private static final Pattern zzaON = Pattern.compile("metric(\\d+)");
    private static Map<String, String> zzaOO;
    private static Map<String, String> zzaOP;
    private final DataLayer zzaKz;
    private final Set<String> zzaOQ;
    private final zzdc zzaOR;

    public zzdg(Context context, DataLayer dataLayer) {
        this(context, dataLayer, new zzdc(context));
    }

    zzdg(Context context, DataLayer dataLayer, zzdc zzdcVar) {
        super(ID, new String[0]);
        this.zzaKz = dataLayer;
        this.zzaOR = zzdcVar;
        this.zzaOQ = new HashSet();
        this.zzaOQ.add("");
        this.zzaOQ.add("0");
        this.zzaOQ.add("false");
    }

    private Double zzM(Object obj) {
        if (obj instanceof String) {
            try {
                return Double.valueOf((String) obj);
            } catch (NumberFormatException e) {
                throw new RuntimeException("Cannot convert the object to Double: " + e.getMessage());
            }
        } else if (obj instanceof Integer) {
            return Double.valueOf(((Integer) obj).doubleValue());
        } else {
            if (obj instanceof Double) {
                return (Double) obj;
            }
            throw new RuntimeException("Cannot convert the object to Double: " + obj.toString());
        }
    }

    private Integer zzN(Object obj) {
        if (obj instanceof String) {
            try {
                return Integer.valueOf((String) obj);
            } catch (NumberFormatException e) {
                throw new RuntimeException("Cannot convert the object to Integer: " + e.getMessage());
            }
        } else if (obj instanceof Double) {
            return Integer.valueOf(((Double) obj).intValue());
        } else {
            if (obj instanceof Integer) {
                return (Integer) obj;
            }
            throw new RuntimeException("Cannot convert the object to Integer: " + obj.toString());
        }
    }

    private Promotion zzO(Map<String, String> map) {
        Promotion promotion = new Promotion();
        String str = map.get("id");
        if (str != null) {
            promotion.setId(String.valueOf(str));
        }
        String str2 = map.get("name");
        if (str2 != null) {
            promotion.setName(String.valueOf(str2));
        }
        String str3 = map.get("creative");
        if (str3 != null) {
            promotion.setCreative(String.valueOf(str3));
        }
        String str4 = map.get("position");
        if (str4 != null) {
            promotion.setPosition(String.valueOf(str4));
        }
        return promotion;
    }

    private Product zzP(Map<String, Object> map) {
        Product product = new Product();
        Object obj = map.get("id");
        if (obj != null) {
            product.setId(String.valueOf(obj));
        }
        Object obj2 = map.get("name");
        if (obj2 != null) {
            product.setName(String.valueOf(obj2));
        }
        Object obj3 = map.get("brand");
        if (obj3 != null) {
            product.setBrand(String.valueOf(obj3));
        }
        Object obj4 = map.get("category");
        if (obj4 != null) {
            product.setCategory(String.valueOf(obj4));
        }
        Object obj5 = map.get("variant");
        if (obj5 != null) {
            product.setVariant(String.valueOf(obj5));
        }
        Object obj6 = map.get("coupon");
        if (obj6 != null) {
            product.setCouponCode(String.valueOf(obj6));
        }
        Object obj7 = map.get("position");
        if (obj7 != null) {
            product.setPosition(zzN(obj7).intValue());
        }
        Object obj8 = map.get("price");
        if (obj8 != null) {
            product.setPrice(zzM(obj8).doubleValue());
        }
        Object obj9 = map.get("quantity");
        if (obj9 != null) {
            product.setQuantity(zzN(obj9).intValue());
        }
        for (String str : map.keySet()) {
            Matcher matcher = zzaOM.matcher(str);
            if (matcher.matches()) {
                try {
                    product.setCustomDimension(Integer.parseInt(matcher.group(1)), String.valueOf(map.get(str)));
                } catch (NumberFormatException e) {
                    zzbg.zzaC("illegal number in custom dimension value: " + str);
                }
            } else {
                Matcher matcher2 = zzaON.matcher(str);
                if (matcher2.matches()) {
                    try {
                        product.setCustomMetric(Integer.parseInt(matcher2.group(1)), zzN(map.get(str)).intValue());
                    } catch (NumberFormatException e2) {
                        zzbg.zzaC("illegal number in custom metric value: " + str);
                    }
                }
            }
        }
        return product;
    }

    private Map<String, String> zzQ(Map<String, zzag.zza> map) {
        zzag.zza zzaVar = map.get(zzaOJ);
        if (zzaVar != null) {
            return zzc(zzaVar);
        }
        if (zzaOO == null) {
            HashMap hashMap = new HashMap();
            hashMap.put("transactionId", "&ti");
            hashMap.put("transactionAffiliation", "&ta");
            hashMap.put("transactionTax", "&tt");
            hashMap.put("transactionShipping", "&ts");
            hashMap.put("transactionTotal", "&tr");
            hashMap.put("transactionCurrency", "&cu");
            zzaOO = hashMap;
        }
        return zzaOO;
    }

    private Map<String, String> zzR(Map<String, zzag.zza> map) {
        zzag.zza zzaVar = map.get(zzaOK);
        if (zzaVar != null) {
            return zzc(zzaVar);
        }
        if (zzaOP == null) {
            HashMap hashMap = new HashMap();
            hashMap.put("name", "&in");
            hashMap.put("sku", "&ic");
            hashMap.put("category", "&iv");
            hashMap.put("price", "&ip");
            hashMap.put("quantity", "&iq");
            hashMap.put("currency", "&cu");
            zzaOP = hashMap;
        }
        return zzaOP;
    }

    private void zza(Tracker tracker, Map<String, zzag.zza> map) {
        String zzeO = zzeO("transactionId");
        if (zzeO == null) {
            zzbg.zzaz("Cannot find transactionId in data layer.");
            return;
        }
        LinkedList<Map<String, String>> linkedList = new LinkedList();
        try {
            Map<String, String> zzm = zzm(map.get(zzaOH));
            zzm.put("&t", "transaction");
            for (Map.Entry<String, String> entry : zzQ(map).entrySet()) {
                zzd(zzm, entry.getValue(), zzeO(entry.getKey()));
            }
            linkedList.add(zzm);
            List<Map<String, String>> zzeP = zzeP("transactionProducts");
            if (zzeP != null) {
                for (Map<String, String> map2 : zzeP) {
                    if (map2.get("name") == null) {
                        zzbg.zzaz("Unable to send transaction item hit due to missing 'name' field.");
                        return;
                    }
                    Map<String, String> zzm2 = zzm(map.get(zzaOH));
                    zzm2.put("&t", "item");
                    zzm2.put("&ti", zzeO);
                    for (Map.Entry<String, String> entry2 : zzR(map).entrySet()) {
                        zzd(zzm2, entry2.getValue(), map2.get(entry2.getKey()));
                    }
                    linkedList.add(zzm2);
                }
            }
            for (Map<String, String> map3 : linkedList) {
                tracker.send(map3);
            }
        } catch (IllegalArgumentException e) {
            zzbg.zzb("Unable to send transaction", e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x011d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void zzb(com.google.android.gms.analytics.Tracker r8, java.util.Map<java.lang.String, com.google.android.gms.internal.zzag.zza> r9) {
        /*
            Method dump skipped, instructions count: 461
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.tagmanager.zzdg.zzb(com.google.android.gms.analytics.Tracker, java.util.Map):void");
    }

    private Map<String, String> zzc(zzag.zza zzaVar) {
        Object zzl = zzdf.zzl(zzaVar);
        if (zzl instanceof Map) {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            for (Map.Entry entry : ((Map) zzl).entrySet()) {
                linkedHashMap.put(entry.getKey().toString(), entry.getValue().toString());
            }
            return linkedHashMap;
        }
        return null;
    }

    private void zzd(Map<String, String> map, String str, String str2) {
        if (str2 != null) {
            map.put(str, str2);
        }
    }

    private ProductAction zze(String str, Map<String, Object> map) {
        ProductAction productAction = new ProductAction(str);
        Object obj = map.get("id");
        if (obj != null) {
            productAction.setTransactionId(String.valueOf(obj));
        }
        Object obj2 = map.get("affiliation");
        if (obj2 != null) {
            productAction.setTransactionAffiliation(String.valueOf(obj2));
        }
        Object obj3 = map.get("coupon");
        if (obj3 != null) {
            productAction.setTransactionCouponCode(String.valueOf(obj3));
        }
        Object obj4 = map.get("list");
        if (obj4 != null) {
            productAction.setProductActionList(String.valueOf(obj4));
        }
        Object obj5 = map.get("option");
        if (obj5 != null) {
            productAction.setCheckoutOptions(String.valueOf(obj5));
        }
        Object obj6 = map.get("revenue");
        if (obj6 != null) {
            productAction.setTransactionRevenue(zzM(obj6).doubleValue());
        }
        Object obj7 = map.get("tax");
        if (obj7 != null) {
            productAction.setTransactionTax(zzM(obj7).doubleValue());
        }
        Object obj8 = map.get("shipping");
        if (obj8 != null) {
            productAction.setTransactionShipping(zzM(obj8).doubleValue());
        }
        Object obj9 = map.get("step");
        if (obj9 != null) {
            productAction.setCheckoutStep(zzN(obj9).intValue());
        }
        return productAction;
    }

    private String zzeO(String str) {
        Object obj = this.zzaKz.get(str);
        if (obj == null) {
            return null;
        }
        return obj.toString();
    }

    private List<Map<String, String>> zzeP(String str) {
        Object obj = this.zzaKz.get(str);
        if (obj == null) {
            return null;
        }
        if (obj instanceof List) {
            for (Object obj2 : (List) obj) {
                if (!(obj2 instanceof Map)) {
                    throw new IllegalArgumentException("Each element of transactionProducts should be of type Map.");
                }
            }
            return (List) obj;
        }
        throw new IllegalArgumentException("transactionProducts should be of type List.");
    }

    private boolean zzi(Map<String, zzag.zza> map, String str) {
        zzag.zza zzaVar = map.get(str);
        if (zzaVar == null) {
            return false;
        }
        return zzdf.zzk(zzaVar).booleanValue();
    }

    private Map<String, String> zzm(zzag.zza zzaVar) {
        Map<String, String> zzc;
        if (zzaVar != null && (zzc = zzc(zzaVar)) != null) {
            String str = zzc.get("&aip");
            if (str != null && this.zzaOQ.contains(str.toLowerCase())) {
                zzc.remove("&aip");
            }
            return zzc;
        }
        return new HashMap();
    }

    @Override // com.google.android.gms.tagmanager.zzdd, com.google.android.gms.tagmanager.zzak
    public /* bridge */ /* synthetic */ zzag.zza zzE(Map map) {
        return super.zzE(map);
    }

    @Override // com.google.android.gms.tagmanager.zzdd
    public void zzG(Map<String, zzag.zza> map) {
        Tracker zzeG = this.zzaOR.zzeG("_GTM_DEFAULT_TRACKER_");
        zzeG.enableAdvertisingIdCollection(zzi(map, "collect_adid"));
        if (zzi(map, zzaOE)) {
            zzb(zzeG, map);
        } else if (zzi(map, zzaOD)) {
            zzeG.send(zzm(map.get(zzaOH)));
        } else if (zzi(map, zzaOI)) {
            zza(zzeG, map);
        } else {
            zzbg.zzaC("Ignoring unknown tag.");
        }
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public /* bridge */ /* synthetic */ String zzyM() {
        return super.zzyM();
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public /* bridge */ /* synthetic */ Set zzyN() {
        return super.zzyN();
    }

    @Override // com.google.android.gms.tagmanager.zzdd, com.google.android.gms.tagmanager.zzak
    public /* bridge */ /* synthetic */ boolean zzyh() {
        return super.zzyh();
    }
}
