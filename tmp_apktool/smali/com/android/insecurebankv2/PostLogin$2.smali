.class Lcom/android/insecurebankv2/PostLogin$2;
.super Ljava/lang/Object;
.source "PostLogin.java"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/PostLogin;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/android/insecurebankv2/PostLogin;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/PostLogin;)V
    .locals 0
    .param p1, "this$0"    # Lcom/android/insecurebankv2/PostLogin;

    .prologue
    .line 66
    iput-object p1, p0, Lcom/android/insecurebankv2/PostLogin$2;->this$0:Lcom/android/insecurebankv2/PostLogin;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 1
    .param p1, "v"    # Landroid/view/View;

    .prologue
    .line 71
    iget-object v0, p0, Lcom/android/insecurebankv2/PostLogin$2;->this$0:Lcom/android/insecurebankv2/PostLogin;

    invoke-virtual {v0}, Lcom/android/insecurebankv2/PostLogin;->viewStatment()V

    .line 72
    return-void
.end method
