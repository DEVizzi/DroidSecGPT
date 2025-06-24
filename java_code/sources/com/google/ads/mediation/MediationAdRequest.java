package com.google.ads.mediation;

import android.location.Location;
import com.google.ads.AdRequest;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;
@Deprecated
/* loaded from: classes.dex */
public class MediationAdRequest {
    private final Date zzaQ;
    private final AdRequest.Gender zzaR;
    private final Set<String> zzaS;
    private final boolean zzaT;
    private final Location zzaU;

    public MediationAdRequest(Date birthday, AdRequest.Gender gender, Set<String> keywords, boolean isTesting, Location location) {
        this.zzaQ = birthday;
        this.zzaR = gender;
        this.zzaS = keywords;
        this.zzaT = isTesting;
        this.zzaU = location;
    }

    public Integer getAgeInYears() {
        if (this.zzaQ != null) {
            Calendar calendar = Calendar.getInstance();
            Calendar calendar2 = Calendar.getInstance();
            calendar.setTime(this.zzaQ);
            Integer valueOf = Integer.valueOf(calendar2.get(1) - calendar.get(1));
            return (calendar2.get(2) < calendar.get(2) || (calendar2.get(2) == calendar.get(2) && calendar2.get(5) < calendar.get(5))) ? Integer.valueOf(valueOf.intValue() - 1) : valueOf;
        }
        return null;
    }

    public Date getBirthday() {
        return this.zzaQ;
    }

    public AdRequest.Gender getGender() {
        return this.zzaR;
    }

    public Set<String> getKeywords() {
        return this.zzaS;
    }

    public Location getLocation() {
        return this.zzaU;
    }

    public boolean isTesting() {
        return this.zzaT;
    }
}
