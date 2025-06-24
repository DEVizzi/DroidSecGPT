.class public final Landroid/support/v7/media/MediaSessionStatus$Builder;
.super Ljava/lang/Object;
.source "MediaSessionStatus.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroid/support/v7/media/MediaSessionStatus;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation


# instance fields
.field private final mBundle:Landroid/os/Bundle;


# direct methods
.method public constructor <init>(I)V
    .locals 2
    .param p1, "sessionState"    # I

    .prologue
    .line 184
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 185
    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    iput-object v0, p0, Landroid/support/v7/media/MediaSessionStatus$Builder;->mBundle:Landroid/os/Bundle;

    .line 186
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    move-result-wide v0

    invoke-virtual {p0, v0, v1}, Landroid/support/v7/media/MediaSessionStatus$Builder;->setTimestamp(J)Landroid/support/v7/media/MediaSessionStatus$Builder;

    .line 187
    invoke-virtual {p0, p1}, Landroid/support/v7/media/MediaSessionStatus$Builder;->setSessionState(I)Landroid/support/v7/media/MediaSessionStatus$Builder;

    .line 188
    return-void
.end method

.method public constructor <init>(Landroid/support/v7/media/MediaSessionStatus;)V
    .locals 2
    .param p1, "status"    # Landroid/support/v7/media/MediaSessionStatus;

    .prologue
    .line 194
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 195
    if-nez p1, :cond_0

    .line 196
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "status must not be null"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 199
    :cond_0
    new-instance v0, Landroid/os/Bundle;

    invoke-static {p1}, Landroid/support/v7/media/MediaSessionStatus;->access$000(Landroid/support/v7/media/MediaSessionStatus;)Landroid/os/Bundle;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    iput-object v0, p0, Landroid/support/v7/media/MediaSessionStatus$Builder;->mBundle:Landroid/os/Bundle;

    .line 200
    return-void
.end method


# virtual methods
.method public build()Landroid/support/v7/media/MediaSessionStatus;
    .locals 3

    .prologue
    .line 241
    new-instance v0, Landroid/support/v7/media/MediaSessionStatus;

    iget-object v1, p0, Landroid/support/v7/media/MediaSessionStatus$Builder;->mBundle:Landroid/os/Bundle;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Landroid/support/v7/media/MediaSessionStatus;-><init>(Landroid/os/Bundle;Landroid/support/v7/media/MediaSessionStatus$1;)V

    return-object v0
.end method

.method public setExtras(Landroid/os/Bundle;)Landroid/support/v7/media/MediaSessionStatus$Builder;
    .locals 2
    .param p1, "extras"    # Landroid/os/Bundle;

    .prologue
    .line 233
    iget-object v0, p0, Landroid/support/v7/media/MediaSessionStatus$Builder;->mBundle:Landroid/os/Bundle;

    const-string v1, "extras"

    invoke-virtual {v0, v1, p1}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 234
    return-object p0
.end method

.method public setQueuePaused(Z)Landroid/support/v7/media/MediaSessionStatus$Builder;
    .locals 2
    .param p1, "queuePaused"    # Z

    .prologue
    .line 223
    iget-object v0, p0, Landroid/support/v7/media/MediaSessionStatus$Builder;->mBundle:Landroid/os/Bundle;

    const-string v1, "queuePaused"

    invoke-virtual {v0, v1, p1}, Landroid/os/Bundle;->putBoolean(Ljava/lang/String;Z)V

    .line 224
    return-object p0
.end method

.method public setSessionState(I)Landroid/support/v7/media/MediaSessionStatus$Builder;
    .locals 2
    .param p1, "sessionState"    # I

    .prologue
    .line 215
    iget-object v0, p0, Landroid/support/v7/media/MediaSessionStatus$Builder;->mBundle:Landroid/os/Bundle;

    const-string v1, "sessionState"

    invoke-virtual {v0, v1, p1}, Landroid/os/Bundle;->putInt(Ljava/lang/String;I)V

    .line 216
    return-object p0
.end method

.method public setTimestamp(J)Landroid/support/v7/media/MediaSessionStatus$Builder;
    .locals 3
    .param p1, "elapsedRealtimeTimestamp"    # J

    .prologue
    .line 207
    iget-object v0, p0, Landroid/support/v7/media/MediaSessionStatus$Builder;->mBundle:Landroid/os/Bundle;

    const-string v1, "timestamp"

    invoke-virtual {v0, v1, p1, p2}, Landroid/os/Bundle;->putLong(Ljava/lang/String;J)V

    .line 208
    return-object p0
.end method
