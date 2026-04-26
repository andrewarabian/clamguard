/*
 * clamguard.c — ClamAV front-end scanner
 *
 * Build:  make
 *         gcc -O2 -Wall -Wextra -pthread -D_GNU_SOURCE -o clamguard clamguard.c
 * Usage:  sudo ./clamguard [--theme NAME] [OPTIONS]
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════
 *  Tunables
 * ═══════════════════════════════════════════════════════════════════ */
#define APP_NAME      "ClamGuard"
#define APP_VER       "1.0"
#define LOGDIR        "/var/log/clamav"
#define LOGFILE       LOGDIR "/fullscan.log"
#define REPORTDIR     LOGDIR "/reports"
#define QUAR_BASE     "/var/quarantine/clamguard"

#define MAX_FOUND     8192
#define MAX_EXCLUDES  64
#define MAX_DBS       8
#define LINE_BUF      8192
#define DRAW_US       250000ULL
#define COUNT_TIMEOUT 20

/* ═══════════════════════════════════════════════════════════════════
 *  Theme system
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    const char *id;        /* CLI name             */
    const char *label;     /* display name         */
    const char *accent;    /* borders / headers    */
    const char *hi;        /* detections / alerts  */
    const char *ok;        /* clean / success      */
    const char *warn;      /* warnings             */
    const char *info;      /* info labels          */
    const char *muted;     /* secondary text       */
    const char *bold;
    const char *reset;
    char        sep;       /* horizontal rule char */
} Theme;

/*
 * Five built-in themes.  Add more by appending here and incrementing
 * N_THEMES — no other code changes needed.
 */
#define N_THEMES 5
static const Theme THEMES[N_THEMES] = {
    /*
     * Blue Team — Blue / White / Black (default).
     * Professional defensive security aesthetic.
     */
    { "blueteam", "Blue Team",
      "\033[34m",      /* accent  : blue             */
      "\033[1;31m",    /* hi      : bold red         */
      "\033[1;32m",    /* ok      : bold green       */
      "\033[33m",      /* warn    : yellow           */
      "\033[34m",      /* info    : blue             */
      "\033[2;37m",    /* muted   : dim white        */
      "\033[1m", "\033[0m", '-' },

    /*
     * Layer 8 — Red / Black / White.
     * Named for the OSI "user" layer: the human who clicked "run as admin".
     */
    { "layer8", "Layer 8",
      "\033[31m",      /* accent  : red              */
      "\033[1;31m",    /* hi      : bold red         */
      "\033[1;37m",    /* ok      : bold white       */
      "\033[31m",      /* warn    : red              */
      "\033[31m",      /* info    : red              */
      "\033[2;37m",    /* muted   : dim white        */
      "\033[1m", "\033[0m", '=' },

    /*
     * Hackerman — Green / Black.
     * The canonical aesthetic. You are in.
     */
    { "hackerman", "Hackerman",
      "\033[32m",      /* accent  : green            */
      "\033[1;32m",    /* hi      : bold green       */
      "\033[32m",      /* ok      : green            */
      "\033[33m",      /* warn    : yellow           */
      "\033[32m",      /* info    : green            */
      "\033[2;32m",    /* muted   : dim green        */
      "\033[1m", "\033[0m", '-' },

    /*
     * Retro Amber — Amber / Black.
     * Phosphor glow of a 1983 CRT.  No pixels were harmed.
     */
    { "retro", "Retro Amber",
      "\033[33m",      /* accent  : amber/yellow     */
      "\033[1;33m",    /* hi      : bold amber       */
      "\033[33m",      /* ok      : amber            */
      "\033[1;33m",    /* warn    : bold amber       */
      "\033[33m",      /* info    : amber            */
      "\033[2;33m",    /* muted   : dim amber        */
      "\033[1m", "\033[0m", '#' },

    /*
     * Arctic — Cyan / White / Dark.
     * Cold, clinical, quiet.  Incident response at 3 AM.
     */
    { "arctic", "Arctic",
      "\033[36m",      /* accent  : cyan             */
      "\033[1;37m",    /* hi      : bold white       */
      "\033[36m",      /* ok      : cyan             */
      "\033[1;33m",    /* warn    : yellow           */
      "\033[36m",      /* info    : cyan             */
      "\033[2;37m",    /* muted   : dim white        */
      "\033[1m", "\033[0m", '~' },
};

static int          g_color = 1;
static const Theme *g_theme = &THEMES[0];   /* default: blueteam */

/* Emit a color code only when color output is enabled */
static const char *tc(const char *s) { return g_color ? s : ""; }

#define ACCENT tc(g_theme->accent)
#define HI     tc(g_theme->hi)
#define OK     tc(g_theme->ok)
#define WARN   tc(g_theme->warn)
#define INFO   tc(g_theme->info)
#define MUTED  tc(g_theme->muted)
#define BOLD   tc(g_theme->bold)
#define RST    tc(g_theme->reset)

static const Theme *find_theme(const char *id) {
    for (int i = 0; i < N_THEMES; i++)
        if (strcmp(THEMES[i].id, id) == 0) return &THEMES[i];
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  SHA-256  (Brad Conte, public domain / CC0)
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} Sha256Ctx;

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SCH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define SMAJ(x,y,z)(((x)&(y))^((x)&(z))^((y)&(z)))
#define SS0(x) (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define SS1(x) (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define SG0(x) (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SG1(x) (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static const uint32_t SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(Sha256Ctx *ctx, const uint8_t *d) {
    uint32_t a,b,c,e,f,g,h,i,t1,t2,m[64];
    uint32_t dd = ctx->state[3];
    for (i=0;i<16;i++)
        m[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for (;i<64;i++) m[i]=SG1(m[i-2])+m[i-7]+SG0(m[i-15])+m[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (i=0;i<64;i++){
        t1=h+SS1(e)+SCH(e,f,g)+SHA_K[i]+m[i];
        t2=SS0(a)+SMAJ(a,b,c);
        h=g;g=f;f=e;e=dd+t1;dd=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=dd;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}
static void sha256_init(Sha256Ctx *ctx) {
    ctx->datalen=0; ctx->bitlen=0;
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
}
static void sha256_update(Sha256Ctx *ctx, const uint8_t *d, size_t len) {
    for (size_t i=0;i<len;i++){
        ctx->data[ctx->datalen++]=d[i];
        if (ctx->datalen==64){
            sha256_transform(ctx,ctx->data);
            ctx->bitlen+=512; ctx->datalen=0;
        }
    }
}
static void sha256_final(Sha256Ctx *ctx, uint8_t hash[32]) {
    uint32_t i=ctx->datalen;
    if (ctx->datalen<56){
        ctx->data[i++]=0x80;
        while(i<56) ctx->data[i++]=0;
    } else {
        ctx->data[i++]=0x80;
        while(i<64) ctx->data[i++]=0;
        sha256_transform(ctx,ctx->data);
        memset(ctx->data,0,56);
    }
    ctx->bitlen+=ctx->datalen*8;
    ctx->data[63]=ctx->bitlen;    ctx->data[62]=ctx->bitlen>>8;
    ctx->data[61]=ctx->bitlen>>16;ctx->data[60]=ctx->bitlen>>24;
    ctx->data[59]=ctx->bitlen>>32;ctx->data[58]=ctx->bitlen>>40;
    ctx->data[57]=ctx->bitlen>>48;ctx->data[56]=ctx->bitlen>>56;
    sha256_transform(ctx,ctx->data);
    for (i=0;i<4;i++){
        hash[i]   =(ctx->state[0]>>(24-i*8))&0xff;
        hash[i+4] =(ctx->state[1]>>(24-i*8))&0xff;
        hash[i+8] =(ctx->state[2]>>(24-i*8))&0xff;
        hash[i+12]=(ctx->state[3]>>(24-i*8))&0xff;
        hash[i+16]=(ctx->state[4]>>(24-i*8))&0xff;
        hash[i+20]=(ctx->state[5]>>(24-i*8))&0xff;
        hash[i+24]=(ctx->state[6]>>(24-i*8))&0xff;
        hash[i+28]=(ctx->state[7]>>(24-i*8))&0xff;
    }
}
static void sha256_file(const char *path, char out[65]) {
    strcpy(out,"ERROR");
    FILE *fp=fopen(path,"rb"); if(!fp) return;
    Sha256Ctx ctx; sha256_init(&ctx);
    uint8_t buf[65536]; size_t n;
    while ((n=fread(buf,1,sizeof(buf),fp))>0) sha256_update(&ctx,buf,n);
    fclose(fp);
    uint8_t h[32]; sha256_final(&ctx,h);
    for (int i=0;i<32;i++) sprintf(out+i*2,"%02x",h[i]);
    out[64]='\0';
}

/* ═══════════════════════════════════════════════════════════════════
 *  Timestamps / clock
 * ═══════════════════════════════════════════════════════════════════ */
static void ts_human(char *buf, size_t n) {
    time_t t=time(NULL); struct tm *tm=localtime(&t);
    strftime(buf,n,"%Y-%m-%d %H:%M:%S",tm);
}
static void ts_stamp(char *buf, size_t n) {
    time_t t=time(NULL); struct tm *tm=localtime(&t);
    strftime(buf,n,"%Y-%m-%d_%H%M%S",tm);
}
static uint64_t now_us(void) {
    struct timeval tv; gettimeofday(&tv,NULL);
    return (uint64_t)tv.tv_sec*1000000ULL+(uint64_t)tv.tv_usec;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Terminal helpers
 * ═══════════════════════════════════════════════════════════════════ */
static int g_tui = 0;
static void term_init(void)    { printf("\033[?1049h\033[?25l\033[2J\033[H"); fflush(stdout); g_tui=1; }
static void term_restore(void) { if(g_tui){printf("\033[?25h\033[?1049l");fflush(stdout);g_tui=0;} }
static int  term_cols(void) {
    struct winsize w;
    return (ioctl(STDOUT_FILENO,TIOCGWINSZ,&w)==0&&w.ws_col>0) ? w.ws_col : 80;
}

/* Print a horizontal rule of `width` `sep` chars in accent color */
static void hline(int width) {
    if (width<1) width=1;
    if (width>200) width=200;
    printf("%s",ACCENT);
    for (int i=0;i<width;i++) putchar(g_theme->sep);
    printf("%s\n",RST);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Config
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    char target[PATH_MAX];
    char profile[32];
    char excludes[2048];
    char action[32];
    int  accurate;
    int  no_update;
    int  i_accept_risk;
    int  noninteractive;
    int  excludes_explicit;
} Config;

static void config_defaults(Config *c) {
    snprintf(c->target,   sizeof(c->target),   "%s", "/");
    snprintf(c->profile,  sizeof(c->profile),  "%s", "recommended");
    snprintf(c->excludes, sizeof(c->excludes), "%s", "/proc /sys /dev /run");
    snprintf(c->action,   sizeof(c->action),   "%s", "quarantine");
    c->accurate=0; c->no_update=0; c->i_accept_risk=0; c->noninteractive=0; c->excludes_explicit=0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Global scan state
 * ═══════════════════════════════════════════════════════════════════ */
static volatile sig_atomic_t g_stop     = 0;
static pid_t                 g_clam_pgid = 0;

static char  *g_found[MAX_FOUND];
static int    g_found_n  = 0;
static long   g_scanned  = 0;
static char   g_last[PATH_MAX];

/* accurate-mode counter */
static volatile long g_total    = 0;
static volatile int  g_cnt_done = 0;

/* parsed exclude list (shared: counter thread + is_excluded) */
static char g_excl[MAX_EXCLUDES][PATH_MAX];
static int  g_excl_n = 0;

/* ═══════════════════════════════════════════════════════════════════
 *  Signals
 * ═══════════════════════════════════════════════════════════════════ */
static void sighandler(int sig) {
    (void)sig;
    g_stop = 1;
    if (g_clam_pgid > 0) killpg(g_clam_pgid, SIGTERM);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Path helpers
 * ═══════════════════════════════════════════════════════════════════ */
static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX]; snprintf(tmp,sizeof(tmp),"%s",path);
    for (char *p=tmp+1;*p;p++) {
        if (*p=='/') {
            *p='\0';
            if (mkdir(tmp,mode)!=0&&errno!=EEXIST) return -1;
            *p='/';
        }
    }
    return (mkdir(tmp,mode)!=0&&errno!=EEXIST) ? -1 : 0;
}

static int is_critical_path(const char *path) {
    static const char *const CRIT[] = {
        "/bin/","/sbin/","/usr/bin/","/usr/sbin/",
        "/boot/","/lib/","/lib64/","/lib32/","/libx32/",NULL
    };
    for (int i=0; CRIT[i]; i++)
        if (strncmp(path,CRIT[i],strlen(CRIT[i]))==0) return 1;
    return 0;
}

static void parse_excludes(const char *raw) {
    g_excl_n = 0;
    char tmp[2048]; snprintf(tmp,sizeof(tmp),"%s",raw);
    char *tok = strtok(tmp," ,\t");
    while (tok && g_excl_n<MAX_EXCLUDES) {
        if (tok[0]!='/') { tok=strtok(NULL," ,\t"); continue; }
        snprintf(g_excl[g_excl_n],PATH_MAX,"%s",tok);
        size_t l=strlen(g_excl[g_excl_n]);
        if (l>1&&g_excl[g_excl_n][l-1]=='/') g_excl[g_excl_n][l-1]='\0';
        if (strcmp(g_excl[g_excl_n],"/")==0) { tok=strtok(NULL," ,\t"); continue; }
        g_excl_n++;
        tok=strtok(NULL," ,\t");
    }
}

static int is_excluded(const char *path) {
    for (int i=0;i<g_excl_n;i++) {
        size_t l=strlen(g_excl[i]);
        if (strncmp(path,g_excl[i],l)==0&&(path[l]=='/'||path[l]=='\0')) return 1;
    }
    return 0;
}

static void build_exclude_regex(char *out, size_t sz) {
    out[0]='\0';
    if (g_excl_n==0) return;
    size_t n=0;
    n+=snprintf(out+n,sz-n,"^(");
    for (int i=0;i<g_excl_n;i++) {
        if (i>0) n+=snprintf(out+n,sz-n,"|");
        for (const char *p=g_excl[i]; *p&&n<sz-4; p++) {
            if (strchr(".[]\\^$*+?{}|()",*p)) out[n++]='\\';
            out[n++]=*p;
        }
    }
    n+=snprintf(out+n,sz-n,")(/|$)");
    out[sz-1]='\0';
}

/* ═══════════════════════════════════════════════════════════════════
 *  Log directory
 * ═══════════════════════════════════════════════════════════════════ */
static void prepare_logdir(void) {
    mode_t old=umask(0);
    mkdir_p(LOGDIR,0750);    chmod(LOGDIR,0750);
    mkdir_p(REPORTDIR,0750); chmod(REPORTDIR,0750);
    umask(old);
    FILE *f=fopen(LOGFILE,"a"); if(f) fclose(f);
    chmod(LOGFILE,0640);
}

/* ═══════════════════════════════════════════════════════════════════
 *  freshclam — visual status panel
 * ═══════════════════════════════════════════════════════════════════ */
typedef enum { DB_UNKNOWN=0, DB_UPTODATE=1, DB_UPDATED=2, DB_ERROR=3 } DbStatus;

typedef struct {
    char     name[32];
    DbStatus status;
    char     version[16];
} DbInfo;

static DbInfo g_dbs[MAX_DBS];
static int    g_db_n = 0;
static int    g_fc_error = 0;

static DbInfo *find_or_add_db(const char *name) {
    for (int i=0;i<g_db_n;i++)
        if (strcmp(g_dbs[i].name,name)==0) return &g_dbs[i];
    if (g_db_n>=MAX_DBS) return NULL;
    snprintf(g_dbs[g_db_n].name,sizeof(g_dbs[0].name),"%s",name);
    g_dbs[g_db_n].status=DB_UNKNOWN;
    g_dbs[g_db_n].version[0]='\0';
    return &g_dbs[g_db_n++];
}

/*
 * Parse one freshclam output line into g_dbs[].
 *
 * Patterns we handle:
 *   "main.cvd is up to date (version: 62, ...)"
 *   "daily.cld updated (version: 27375, ...)"
 *   "Downloading daily-27375.cdiff [100%]"
 *   "ERROR: ..."
 */
static void parse_fc_line(const char *line) {
    char name[32]="", ext[16]="", ver[16]="";

    /* "NAME.EXT is up to date (version: VER, ...)" */
    if (sscanf(line,"%31[^.].%15s is up to date (version: %15[^,]",name,ext,ver)==3) {
        DbInfo *db=find_or_add_db(name);
        if (db) { db->status=DB_UPTODATE; snprintf(db->version,sizeof(db->version),"%s",ver); }
        return;
    }

    /* "NAME.EXT updated (version: VER, ...)" */
    if (sscanf(line,"%31[^.].%15s updated (version: %15[^,]",name,ext,ver)==3) {
        DbInfo *db=find_or_add_db(name);
        if (db) { db->status=DB_UPDATED; snprintf(db->version,sizeof(db->version),"%s",ver); }
        return;
    }

    /* "Downloading NAME-VER.EXT ..." — creates a stub so we know something is happening */
    if (strncmp(line,"Downloading ",12)==0) {
        char fname[64]="";
        sscanf(line+12,"%63s",fname);
        /* strip extension to get base name */
        char *dash=strchr(fname,'-');
        if (dash) *dash='\0';
        char *dot=strchr(fname,'.');
        if (dot) *dot='\0';
        find_or_add_db(fname);   /* ensure entry exists, status stays UNKNOWN until "updated" line */
        return;
    }

    if (strstr(line,"ERROR")||strstr(line,"Can't connect")||strstr(line,"Failed")) {
        g_fc_error=1;
    }
}

/* Print the freshclam result panel */
static void print_fc_panel(int rc) {
    int cols=term_cols(); if(cols<50)cols=50; if(cols>78)cols=78;

    /* count outcomes */
    int n_uptodate=0, n_updated=0, n_error=0;
    for (int i=0;i<g_db_n;i++) {
        if      (g_dbs[i].status==DB_UPTODATE) n_uptodate++;
        else if (g_dbs[i].status==DB_UPDATED)  n_updated++;
        else                                    n_error++;
    }
    if (rc!=0) g_fc_error=1;

    printf("\n");
    hline(cols);

    /* header row */
    printf("%s%s  VIRUS DATABASE%s\n",BOLD,ACCENT,RST);

    hline(cols);

    if (g_db_n==0) {
        /* freshclam produced no parseable DB lines */
        if (g_fc_error || rc!=0) {
            printf("  %s  freshclam failed (rc=%d)%s\n",WARN,rc,RST);
            printf("  %s  Continuing with existing signatures.%s\n",MUTED,RST);
        } else {
            printf("  %s  Virus database is current.%s\n",OK,RST);
        }
    } else {
        /* one row per database */
        for (int i=0;i<g_db_n;i++) {
            const char *badge_color, *badge_text, *name_color;
            switch (g_dbs[i].status) {
                case DB_UPTODATE:
                    badge_color=OK;   badge_text=" OK  "; name_color=MUTED; break;
                case DB_UPDATED:
                    badge_color=INFO; badge_text=" UPD "; name_color=ACCENT; break;
                default:
                    badge_color=WARN; badge_text=" ??? "; name_color=MUTED; break;
            }
            printf("  %s%-10s%s  ",name_color,g_dbs[i].name,RST);
            if (g_dbs[i].version[0])
                printf("%sv%-6s%s  ",MUTED,g_dbs[i].version,RST);
            else
                printf("%s%-8s%s  ",MUTED,"",RST);
            printf("%s%s[%s]%s",BOLD,badge_color,badge_text,RST);
            if (g_dbs[i].status==DB_UPDATED)
                printf("  %supdated%s",INFO,RST);
            else if (g_dbs[i].status==DB_UPTODATE)
                printf("  %sup to date%s",MUTED,RST);
            putchar('\n');
        }
    }

    hline(cols);

    /* status line */
    printf("  %s%s  STATUS: ",BOLD,ACCENT);
    if (g_fc_error || (rc!=0&&g_db_n==0)) {
        printf("%sfreshclam failed — scanning with existing signatures%s",WARN,RST);
    } else if (n_updated>0) {
        printf("%s%d database%s updated%s",OK,n_updated,n_updated==1?"":"s",RST);
        if (n_uptodate>0) printf("  %s%d already current%s",MUTED,n_uptodate,RST);
    } else {
        printf("%sAll databases current%s",OK,RST);
    }
    printf("\n");

    hline(cols);
    printf("\n");
}

/* Run freshclam, parse output, print panel */
static int run_freshclam_ui(void) {
    g_db_n=0; g_fc_error=0;

    int pfd[2]; if(pipe(pfd)!=0) return 1;
    pid_t pid=fork();
    if (pid==0) {
        close(pfd[0]);
        dup2(pfd[1],STDOUT_FILENO); dup2(pfd[1],STDERR_FILENO);
        close(pfd[1]);
        const char *argv[]={"freshclam",NULL};
        execvp(argv[0],(char*const*)argv);
        _exit(127);
    }
    close(pfd[1]);

    /* stream output: parse each line for DB status */
    FILE *fp=fdopen(pfd[0],"r");
    char buf[LINE_BUF];
    while (fgets(buf,sizeof(buf),fp)) {
        buf[strcspn(buf,"\n")]='\0';
        parse_fc_line(buf);
    }
    fclose(fp);

    int st; waitpid(pid,&st,0);
    int rc=WIFEXITED(st)?WEXITSTATUS(st):1;

    print_fc_panel(rc);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Accurate file counter (background thread)
 * ═══════════════════════════════════════════════════════════════════ */
static time_t g_cnt_start;

static int count_cb(const char *fpath, const struct stat *sb,
                    int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    if (time(NULL)-g_cnt_start>COUNT_TIMEOUT) return FTW_STOP;
    if (typeflag==FTW_D&&is_excluded(fpath)) return FTW_SKIP_SUBTREE;
    if (typeflag==FTW_F) __atomic_fetch_add(&g_total,1,__ATOMIC_RELAXED);
    return FTW_CONTINUE;
}
static void *counter_thread(void *arg) {
    g_cnt_start=time(NULL);
    nftw((const char*)arg,count_cb,32,FTW_PHYS|FTW_ACTIONRETVAL);
    g_cnt_done=1;
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Safe string output — strips ANSI escape sequences from
 *  attacker-influenced strings (filenames) before printing
 * ═══════════════════════════════════════════════════════════════════ */
static void print_safe(const char *s) {
    for (; *s; s++) {
        unsigned char c=(unsigned char)*s;
        if (c==0x1B)       { fputs("\\033",stdout); }
        else if (c<0x20||c==0x7F) { /* skip */ }
        else putchar(c);
    }
}
static void fprint_safe(FILE *fp, const char *s) {
    for (; *s; s++) {
        unsigned char c=(unsigned char)*s;
        if (c==0x1B)       { fputs("\\033",fp); }
        else if (c<0x20||c==0x7F) { /* skip */ }
        else fputc(c,fp);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  TUI
 * ═══════════════════════════════════════════════════════════════════ */
static void draw_tui(const Config *cfg, long scanned, int found_n,
                     long total, double elapsed_s, double rate, int tick) {
    static const char SPIN[4]={'|','/','-','\\'};
    int cols=term_cols();

    printf("\033[H");  /* cursor top-left */

    /* ── header ── */
    printf("%s%s  %s%s\n",BOLD,ACCENT,APP_NAME,RST);

    hline(cols);

    printf("  %sTarget   :%s %s\n",   INFO,RST,cfg->target);
    printf("  %sProfile  :%s %s\n",   INFO,RST,cfg->profile);
    printf("  %sExcludes :%s %s\n",   INFO,RST,cfg->excludes[0]?cfg->excludes:"<none>");
    printf("  %sAction   :%s %s%s%s\n\n",INFO,RST,OK,cfg->action,RST);

    /* ── progress ── */
    if (total>0) {
        double pct=(scanned*100.0)/total;
        if (pct>100.0) pct=100.0;
        int pct_i=(int)pct;
        int bar_w=cols-28; if(bar_w<10)bar_w=10; if(bar_w>60)bar_w=60;
        int filled=(pct_i*bar_w)/100;

        printf("  %s%5.1f%%%s  %s[%s",BOLD,pct,RST,ACCENT,RST);
        printf("%s",OK);
        for(int i=0;i<filled;i++) putchar('#');
        printf("%s",MUTED);
        for(int i=filled;i<bar_w;i++) putchar('.');
        printf("%s%s]%s\n",RST,ACCENT,RST);

        printf("  %sScanned  :%s %ld / %ld   %s%.1f files/sec%s\n",
               INFO,RST,scanned,total,MUTED,rate,RST);
    } else {
        printf("  %s%c%s  scanned=%ld\n",
               ACCENT,SPIN[tick%4],RST,scanned);
        printf("  %s%.1f files/sec%s\n",MUTED,rate,RST);
    }

    printf("  %sElapsed  :%s %s%02d:%02d:%02d%s\n\n",
           INFO,RST,BOLD,
           (int)(elapsed_s/3600),(int)((int)elapsed_s%3600/60),(int)elapsed_s%60,
           RST);

    /* ── detections ── */
    hline(cols);
    if (found_n==0) {
        printf("  %sDETECTIONS:%s %snone%s\n",BOLD,RST,OK,RST);
    } else {
        printf("  %s%sDETECTIONS: %d FOUND%s\n",BOLD,HI,found_n,RST);
        int start=found_n>8?found_n-8:0;
        for(int i=start;i<found_n;i++) {
            printf("  %s",HI); print_safe(g_found[i]); printf("%s\n",RST);
        }
    }
    hline(cols);

    printf("\n%s  Last: %s",MUTED,RST); print_safe(g_last); printf("\n");
    printf("%s  Ctrl+C stops cleanly.%s\n",MUTED,RST);

    printf("\033[J"); fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════
 *  FOUND line parser
 * ═══════════════════════════════════════════════════════════════════ */
/*
 * Clamscan emits:   /path/to/file: Signature.Name FOUND
 * We split on the first colon and verify " FOUND" suffix.
 */
static int parse_found(const char *line, char *path, size_t psz,
                       char *sig, size_t ssz) {
    while (*line==' ') line++;
    const char *colon=strchr(line,':');
    if (!colon||colon==line) return 0;
    size_t llen=strlen(line);
    if (llen<6||strcmp(line+llen-6," FOUND")!=0) return 0;
    size_t plen=(size_t)(colon-line);
    if (plen==0||plen>=psz) return 0;
    memcpy(path,line,plen); path[plen]='\0';
    const char *sig_start=colon+2;
    const char *found_tag=line+llen-6;
    if (sig_start>=found_tag) return 0;
    size_t slen=(size_t)(found_tag-sig_start);
    if (slen==0||slen>=ssz) return 0;
    memcpy(sig,sig_start,slen); sig[slen]='\0';
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Quarantine
 * ═══════════════════════════════════════════════════════════════════ */
static int quarantine_file(const char *src, const char *qdir,
                           const char *sig, FILE *maplog) {
    if (!src||src[0]!='/') return -1;
    char dest[PATH_MAX*2];
    snprintf(dest,sizeof(dest),"%s%s",qdir,src);
    char destdir[PATH_MAX*2]; snprintf(destdir,sizeof(destdir),"%s",dest);
    char *slash=strrchr(destdir,'/');
    if (slash&&slash!=destdir) { *slash='\0'; mkdir_p(destdir,0700); }
    if (rename(src,dest)!=0) {
        FILE *in=fopen(src,"rb"); if(!in) return -1;
        FILE *out=fopen(dest,"wb");
        if (!out) { fclose(in); return -1; }
        char buf[65536]; size_t n; int ok=1;
        while ((n=fread(buf,1,sizeof(buf),in))>0)
            if (fwrite(buf,1,n,out)!=n) { ok=0; break; }
        if (ok && fsync(fileno(out))!=0) ok=0;
        fclose(in); fclose(out);
        if (!ok) { unlink(dest); return -1; }
        unlink(src);
    }
    /* CG-SEC-002: abort if rename moved a symlink into quarantine */
    struct stat qst;
    if (lstat(dest,&qst)!=0||S_ISLNK(qst.st_mode)) { unlink(dest); return -1; }
    chmod(dest,0000); chown(dest,0,0);
    char sha[65]; sha256_file(dest,sha);
    if (maplog) fprintf(maplog,"%s\t%s\t%s\t%s\n",sig,src,dest,sha);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Process detections
 * ═══════════════════════════════════════════════════════════════════ */
static void process_detections(const Config *cfg,
                               const char *stamp, FILE *report) {
    if (g_found_n==0) return;

    char qdir[PATH_MAX]="";
    FILE *maplog=NULL;

    if (strcmp(cfg->action,"quarantine")==0) {
        snprintf(qdir,sizeof(qdir),"%s/%s",QUAR_BASE,stamp);
        mkdir_p(QUAR_BASE,0700); chmod(QUAR_BASE,0700);
        mkdir_p(qdir,0700);      chmod(qdir,0700);
        char mappath[PATH_MAX];
        snprintf(mappath,sizeof(mappath),"%s/quarantine_map_%s.log",LOGDIR,stamp);
        maplog=fopen(mappath,"w");
        if (maplog) { fprintf(maplog,"run_dir=%s\n",qdir); chmod(mappath,0640); chown(mappath,0,0); }
    }

    for (int i=0;i<g_found_n;i++) {
        char path[PATH_MAX]="", sig[512]="";
        if (!parse_found(g_found[i],path,sizeof(path),sig,sizeof(sig))) continue;

        if (is_critical_path(path)) {
            printf("  %s%s[CRIT]%s %s — system-critical, manual review required\n",BOLD,WARN,RST,path);
            if (report) fprintf(report,"  [CRIT] %s — system-critical, manual review required\n",path);
            continue;
        }

        if (strcmp(cfg->action,"report")==0) {
            printf("  %s[LOG ]%s %s\n",INFO,RST,path);

        } else if (strcmp(cfg->action,"quarantine")==0) {
            if (quarantine_file(path,qdir,sig,maplog)==0) {
                char dest[PATH_MAX*2]; snprintf(dest,sizeof(dest),"%s%s",qdir,path);
                printf("  %s%s[QUAR]%s %s\n%s         → %s%s\n",BOLD,ACCENT,RST,path,MUTED,dest,RST);
                if (report) fprintf(report,"  [QUAR] %s\n         -> %s\n         sig=%s\n",path,dest,sig);
            } else {
                printf("  %s%s[ERR ]%s quarantine failed: %s\n",BOLD,HI,RST,path);
                if (report) fprintf(report,"  [ERR ] quarantine failed: %s\n",path);
            }
        }
    }

    if (maplog) fclose(maplog);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Report
 * ═══════════════════════════════════════════════════════════════════ */
static void write_report(const Config *cfg, long scanned, int found_n,
                         double elapsed_s, double rate, int clam_rc) {
    char stamp[32]; ts_stamp(stamp,sizeof(stamp));
    char rpath[PATH_MAX];
    snprintf(rpath,sizeof(rpath),"%s/%s.txt",REPORTDIR,stamp);

    FILE *fp=fopen(rpath,"w");
    if (!fp) { fprintf(stderr,"[WARN] cannot write report %s: %s\n",rpath,strerror(errno)); return; }

    char now[32]; ts_human(now,sizeof(now));
    char host[256]="unknown"; gethostname(host,sizeof(host));
    struct utsname un; uname(&un);

    fprintf(fp,"============================================================\n");
    fprintf(fp,"  %s v%s — SCAN REPORT\n",APP_NAME,APP_VER);
    fprintf(fp,"  Generated : %s\n",now);
    fprintf(fp,"============================================================\n\n");
    fprintf(fp,"[SCAN CONFIGURATION]\n");
    fprintf(fp,"  Host      : %s\n",host);
    fprintf(fp,"  Kernel    : %s\n",un.release);
    fprintf(fp,"  Profile   : %s\n",cfg->profile);
    fprintf(fp,"  Target    : %s\n",cfg->target);
    fprintf(fp,"  Excludes  : %s\n",cfg->excludes[0]?cfg->excludes:"<none>");
    fprintf(fp,"  Action    : %s\n\n",cfg->action);
    fprintf(fp,"[RESULTS]\n");
    fprintf(fp,"  Files scanned : %ld\n",scanned);
    fprintf(fp,"  Detections    : %d\n",found_n);
    fprintf(fp,"  Elapsed       : %02d:%02d:%02d\n",
            (int)(elapsed_s/3600),(int)((int)elapsed_s%3600/60),(int)elapsed_s%60);
    fprintf(fp,"  Throughput    : %.1f files/sec\n",rate);
    fprintf(fp,"  ClamAV rc     : %d\n\n",clam_rc);

    fprintf(fp,"[DETECTIONS]\n");
    if (found_n==0) {
        fprintf(fp,"  None.\n");
    } else {
        for (int i=0;i<found_n;i++) { fprintf(fp,"  "); fprint_safe(fp,g_found[i]); fprintf(fp,"\n"); }
    }

    fprintf(fp,"\n[LOG FILES]\n");
    fprintf(fp,"  ClamAV log : %s\n",LOGFILE);
    fprintf(fp,"  Report     : %s\n",rpath);
    fprintf(fp,"\n============================================================\n");
    fclose(fp);
    chmod(rpath,0640); chown(rpath,0,0);
    printf("\n%s  Report → %s%s\n",MUTED,rpath,RST);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Report export  (user-chosen path, md or txt)
 * ═══════════════════════════════════════════════════════════════════ */

/* forward declaration — prompt() is defined in the interactive-mode section below */
static void prompt(const char *label, const char *def, char *out, size_t sz);

static void write_report_md(const Config *cfg, long scanned, int found_n,
                             double elapsed_s, double rate, int clam_rc,
                             const char *path) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        printf("  %s%s[ERR]%s Cannot write to %s: %s\n", BOLD, HI, RST, path, strerror(errno));
        return;
    }

    char now[32]; ts_human(now, sizeof(now));
    char host[256] = "unknown"; gethostname(host, sizeof(host));
    struct utsname un; uname(&un);

    fprintf(fp, "# %s — Scan Report\n\n", APP_NAME);
    fprintf(fp, "**Generated:** %s  \n", now);
    fprintf(fp, "**Host:** %s  \n", host);
    fprintf(fp, "**Kernel:** %s  \n", un.release);

    fprintf(fp, "---\n\n");
    fprintf(fp, "## Scan Configuration\n\n");
    fprintf(fp, "| Field | Value |\n|---|---|\n");
    fprintf(fp, "| Profile | %s |\n", cfg->profile);
    fprintf(fp, "| Target | `%s` |\n", cfg->target);
    fprintf(fp, "| Excludes | %s |\n", cfg->excludes[0] ? cfg->excludes : "none");
    fprintf(fp, "| Action | %s |\n\n", cfg->action);

    fprintf(fp, "---\n\n");
    fprintf(fp, "## Results\n\n");
    fprintf(fp, "| Metric | Value |\n|---|---|\n");
    fprintf(fp, "| Files scanned | %ld |\n", scanned);
    fprintf(fp, "| Detections | %d |\n", found_n);
    fprintf(fp, "| Elapsed | %02d:%02d:%02d |\n",
            (int)(elapsed_s/3600),(int)((int)elapsed_s%3600/60),(int)elapsed_s%60);
    fprintf(fp, "| Throughput | %.1f files/sec |\n", rate);
    fprintf(fp, "| ClamAV exit code | %d |\n\n", clam_rc);

    fprintf(fp, "---\n\n");
    fprintf(fp, "## Verdict\n\n");
    if (found_n == 0) {
        fprintf(fp, "✅ **No detections**\n\n");
    } else {
        fprintf(fp, "🚨 **%d detection(s) found**\n\n", found_n);
        fprintf(fp, "### Detections\n\n");
        fprintf(fp, "| File | Signature |\n|---|---|\n");
        for (int i = 0; i < found_n; i++) {
            char fpath[PATH_MAX]="", sig[512]="";
            if (parse_found(g_found[i], fpath, sizeof(fpath), sig, sizeof(sig))) {
                fprintf(fp, "| `"); fprint_safe(fp, fpath);
                fprintf(fp, "` | `"); fprint_safe(fp, sig); fprintf(fp, "` |\n");
            } else {
                fprintf(fp, "| "); fprint_safe(fp, g_found[i]); fprintf(fp, " | |\n");
            }
        }
        fprintf(fp, "\n");
    }

    fprintf(fp, "---\n\n");
    fprintf(fp, "## Log Files\n\n");
    fprintf(fp, "- ClamAV log: `%s`\n", LOGFILE);
    fprintf(fp, "- Reports dir: `%s/`\n", REPORTDIR);
    if (strcmp(cfg->action,"quarantine")==0&&found_n>0)
        fprintf(fp, "- Quarantine: `%s/`\n", QUAR_BASE);
    fprintf(fp, "\n");

    fclose(fp);
    printf("  %s%s[SAVED]%s %s\n", BOLD, OK, RST, path);
}

static void write_report_txt_export(const Config *cfg, long scanned, int found_n,
                                     double elapsed_s, double rate, int clam_rc,
                                     const char *path) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        printf("  %s%s[ERR]%s Cannot write to %s: %s\n", BOLD, HI, RST, path, strerror(errno));
        return;
    }

    char now[32]; ts_human(now, sizeof(now));
    char host[256] = "unknown"; gethostname(host, sizeof(host));
    struct utsname un; uname(&un);

    fprintf(fp, "============================================================\n");
    fprintf(fp, "  %s v%s — SCAN REPORT\n", APP_NAME, APP_VER);
    fprintf(fp, "  Generated : %s\n", now);
    fprintf(fp, "============================================================\n\n");
    fprintf(fp, "[SCAN CONFIGURATION]\n");
    fprintf(fp, "  Host      : %s\n", host);
    fprintf(fp, "  Kernel    : %s\n", un.release);
    fprintf(fp, "  Profile   : %s\n", cfg->profile);
    fprintf(fp, "  Target    : %s\n", cfg->target);
    fprintf(fp, "  Excludes  : %s\n", cfg->excludes[0] ? cfg->excludes : "<none>");
    fprintf(fp, "  Action    : %s\n\n", cfg->action);
    fprintf(fp, "[RESULTS]\n");
    fprintf(fp, "  Files scanned : %ld\n", scanned);
    fprintf(fp, "  Detections    : %d\n", found_n);
    fprintf(fp, "  Elapsed       : %02d:%02d:%02d\n",
            (int)(elapsed_s/3600),(int)((int)elapsed_s%3600/60),(int)elapsed_s%60);
    fprintf(fp, "  Throughput    : %.1f files/sec\n", rate);
    fprintf(fp, "  ClamAV rc     : %d\n\n", clam_rc);
    fprintf(fp, "[DETECTIONS]\n");
    if (found_n == 0) {
        fprintf(fp, "  None.\n");
    } else {
        for (int i = 0; i < found_n; i++) fprintf(fp, "  %s\n", g_found[i]);
    }
    fprintf(fp, "\n[LOG FILES]\n");
    fprintf(fp, "  ClamAV log : %s\n", LOGFILE);
    fprintf(fp, "  Reports dir: %s/\n", REPORTDIR);
    fprintf(fp, "\n============================================================\n");

    fclose(fp);
    printf("  %s%s[SAVED]%s %s\n", BOLD, OK, RST, path);
}

static void prompt_report_export(const Config *cfg, long scanned, int found_n,
                                  double elapsed_s, double rate, int clam_rc) {
    if (!isatty(STDIN_FILENO)) return;

    int cols = term_cols(); if(cols<60)cols=60; if(cols>78)cols=78;

    printf("\n");
    hline(cols);
    printf("%s%s  EXPORT REPORT%s\n", BOLD, ACCENT, RST);
    hline(cols);
    printf("  %smd%s   Save as Markdown  (headers, tables)\n", ACCENT, RST);
    printf("  %stxt%s  Save as plain text\n", ACCENT, RST);
    printf("  %sEnter%s  Skip — do not save\n", MUTED, RST);
    hline(cols);
    printf("  %sType md or txt, then press Enter.  Press Enter alone to skip.%s\n\n",
           MUTED, RST);

    char fmt[16] = "";
    prompt("Save report as", NULL, fmt, sizeof(fmt));
    for (int i = 0; fmt[i]; i++) fmt[i] = (char)tolower((unsigned char)fmt[i]);

    if (strcmp(fmt,"md")!=0 && strcmp(fmt,"txt")!=0) {
        printf("\n");
        return;
    }

    /* default output path: $HOME/clamguard_TIMESTAMP.{md,txt} */
    char stamp[32]; ts_stamp(stamp, sizeof(stamp));
    const char *home = getenv("HOME");
    if (!home || home[0]=='\0') home = "/root";
    char defpath[PATH_MAX];
    snprintf(defpath, sizeof(defpath), "%s/clamguard_%s.%s", home, stamp, fmt);

    char outpath[PATH_MAX] = "";
    prompt("Save to", defpath, outpath, sizeof(outpath));
    if (!outpath[0]) snprintf(outpath, sizeof(outpath), "%s", defpath);

    printf("\n");
    if (strcmp(fmt,"md")==0)
        write_report_md(cfg, scanned, found_n, elapsed_s, rate, clam_rc, outpath);
    else
        write_report_txt_export(cfg, scanned, found_n, elapsed_s, rate, clam_rc, outpath);
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════
 *  Threat classifier
 * ═══════════════════════════════════════════════════════════════════ */
static void classify_threats(char *out, size_t sz) {
    if (sz == 0) return;
    static const struct { const char *kw; const char *label; } MAP[] = {
        {"Trojan",     "Trojan"},
        {"Ransomware", "Ransomware"},
        {"Adware",     "Adware"},
        {"Spyware",    "Spyware"},
        {"Worm",       "Worm"},
        {"Backdoor",   "Backdoor"},
        {"Rootkit",    "Rootkit"},
        {"Exploit",    "Exploit"},
        {"Miner",      "Cryptominer"},
        {"PUA",        "PUA"},
        {"PUP",        "PUA"},
        {NULL, NULL}
    };
    enum { MAX_LABELS = 16 };
    const char *labels[MAX_LABELS]; int n = 0;
    char path[PATH_MAX], sig[512];
    for (int i = 0; i < g_found_n; i++) {
        if (!parse_found(g_found[i], path, sizeof(path), sig, sizeof(sig))) continue;
        const char *label = "Malware";
        for (int m = 0; MAP[m].kw; m++)
            if (strcasestr(sig, MAP[m].kw)) { label = MAP[m].label; break; }
        int dup = 0;
        for (int j = 0; j < n; j++) if (strcmp(labels[j], label)==0) { dup=1; break; }
        if (!dup && n < MAX_LABELS) labels[n++] = label;
    }
    if (n == 0) { snprintf(out, sz, "Malware"); return; }
    out[0] = '\0';
    size_t pos = 0;
    for (int i = 0; i < n && pos + 1 < sz; i++) {
        int r = snprintf(out + pos, sz - pos, "%s%s", i > 0 ? ", " : "", labels[i]);
        if (r > 0 && (size_t)r < sz - pos) pos += (size_t)r; else break;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  Summary banner
 * ═══════════════════════════════════════════════════════════════════ */
static void print_summary(const Config *cfg, long scanned, int found_n,
                          double elapsed_s, double rate) {
    int cols=term_cols(); if(cols<60)cols=60; if(cols>78)cols=78;

    printf("\n");
    hline(cols);
    printf("%s%s  Scan Complete%s\n",BOLD,ACCENT,RST);
    hline(cols);

    printf("  %sTarget    :%s %s\n",   INFO,RST,cfg->target);
    printf("  %sProfile   :%s %s\n",   INFO,RST,cfg->profile);
    printf("  %sAction    :%s %s\n",   INFO,RST,cfg->action);
    printf("  %sExcludes  :%s %s\n\n", INFO,RST,cfg->excludes[0]?cfg->excludes:"<none>");

    printf("  %sScanned   :%s %ld files\n",INFO,RST,scanned);
    printf("  %sElapsed   :%s %02d:%02d:%02d\n",INFO,RST,
           (int)(elapsed_s/3600),(int)((int)elapsed_s%3600/60),(int)elapsed_s%60);
    printf("  %sRate      :%s %.1f files/sec\n\n",INFO,RST,rate);

    hline(cols);
    if (found_n==0)
        printf("  %s%sRESULT: No detections%s\n",BOLD,OK,RST);
    else {
        char types[256]=""; classify_threats(types,sizeof(types));
        printf("  %s%sRESULT: %d DETECTION(S) — %s%s\n",BOLD,HI,found_n,types,RST);
    }
    hline(cols);
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════
 *  Main scan
 * ═══════════════════════════════════════════════════════════════════ */
static int do_scan(const Config *cfg) {
    struct stat st;
    if (stat(cfg->target,&st)!=0) {
        fprintf(stderr,"%s%s[ERR]%s Target not found: %s: %s\n",BOLD,HI,RST,cfg->target,strerror(errno));
        return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr,"%s%s[ERR]%s Target is not a directory: %s\n",BOLD,HI,RST,cfg->target);
        return 1;
    }
    if (access("/usr/bin/clamscan",X_OK)!=0&&access("/usr/local/bin/clamscan",X_OK)!=0) {
        fprintf(stderr,"%s%s[ERR]%s clamscan not found. Install: dnf install clamav\n",BOLD,HI,RST);
        return 1;
    }

    parse_excludes(cfg->excludes);

    pthread_t cnt_tid=0;
    if (cfg->accurate) {
        printf("%s%s[INFO]%s Counting files (up to %ds)…\n",BOLD,INFO,RST,COUNT_TIMEOUT);
        fflush(stdout);
        pthread_create(&cnt_tid,NULL,counter_thread,(void*)cfg->target);
    }

    char exre[4096]="";
    build_exclude_regex(exre,sizeof(exre));
    char logarg[PATH_MAX+8]; snprintf(logarg,sizeof(logarg),"--log=%s",LOGFILE);
    char exarg[4096+16]="";
    if (exre[0]) snprintf(exarg,sizeof(exarg),"--exclude-dir=%s",exre);

    const char *argv[32]; int ai=0;
    argv[ai++]="clamscan";
    argv[ai++]="-r";
    argv[ai++]=cfg->target;
    argv[ai++]="--bell";
    argv[ai++]=logarg;
    if (exarg[0]) argv[ai++]=exarg;
    if (strcmp(cfg->action,"remove")==0) argv[ai++]="--remove";
    argv[ai]=NULL;

    int pfd[2]; if(pipe(pfd)!=0){ perror("pipe"); return 1; }
    pid_t cpid=fork();
    if (cpid==0) {
        close(pfd[0]);
        dup2(pfd[1],STDOUT_FILENO); dup2(pfd[1],STDERR_FILENO);
        close(pfd[1]);
        setsid();
        execvp(argv[0],(char*const*)argv);
        _exit(127);
    }
    close(pfd[1]);
    g_clam_pgid=cpid;
    fcntl(pfd[0],F_SETFL,O_NONBLOCK);

    term_init();

    uint64_t t_start=now_us(), t_last_draw=0;
    int tick=0;
    char linebuf[LINE_BUF]; int lbpos=0;
    g_scanned=0; g_found_n=0; g_last[0]='\0';

    while (1) {
        int status; pid_t w=waitpid(cpid,&status,WNOHANG);
        if (w==cpid) break;
        if (g_stop) break;

        fd_set rfds; FD_ZERO(&rfds); FD_SET(pfd[0],&rfds);
        struct timeval tv={0,50000};
        if (select(pfd[0]+1,&rfds,NULL,NULL,&tv)>0) {
            char chunk[LINE_BUF]; ssize_t nr=read(pfd[0],chunk,sizeof(chunk)-1);
            if (nr>0) {
                chunk[nr]='\0';
                for (int ci=0;ci<nr;ci++) {
                    char ch=chunk[ci];
                    if (ch=='\n'||ch=='\r') {
                        if (lbpos>0) {
                            linebuf[lbpos]='\0'; lbpos=0;
                            if (strstr(linebuf," OK")||strstr(linebuf," FOUND")) {
                                g_scanned++;
                                char *col=strchr(linebuf,':');
                                if (col) {
                                    size_t pl=(size_t)(col-linebuf);
                                    if(pl<sizeof(g_last)){memcpy(g_last,linebuf,pl);g_last[pl]='\0';}
                                }
                            }
                            if (strstr(linebuf," FOUND")&&g_found_n<MAX_FOUND) {
                                char *dup=strdup(linebuf);
                                if (dup) g_found[g_found_n++]=dup;
                            }
                        }
                    } else { if(lbpos<LINE_BUF-1) linebuf[lbpos++]=ch; }
                }
            }
        }

        uint64_t now=now_us();
        if (now-t_last_draw>=DRAW_US) {
            double el=(now-t_start)/1e6;
            double rate=el>0?g_scanned/el:0;
            draw_tui(cfg,g_scanned,g_found_n,(long)g_total,el,rate,tick++);
            t_last_draw=now;
        }
    }

    /* drain pipe */
    {
        char chunk[LINE_BUF]; ssize_t nr;
        while ((nr=read(pfd[0],chunk,sizeof(chunk)-1))>0) {
            chunk[nr]='\0';
            for (int ci=0;ci<nr;ci++) {
                char ch=chunk[ci];
                if (ch=='\n'||ch=='\r') {
                    if (lbpos>0) {
                        linebuf[lbpos]='\0'; lbpos=0;
                        if (strstr(linebuf," OK")||strstr(linebuf," FOUND")) g_scanned++;
                        if (strstr(linebuf," FOUND")&&g_found_n<MAX_FOUND) {
                            char *dup=strdup(linebuf);
                            if (dup) g_found[g_found_n++]=dup;
                        }
                    }
                } else { if(lbpos<LINE_BUF-1) linebuf[lbpos++]=ch; }
            }
        }
    }
    close(pfd[0]);

    int clam_status=0;
    waitpid(cpid,&clam_status,0);
    int clam_rc=WIFEXITED(clam_status)?WEXITSTATUS(clam_status):1;
    g_clam_pgid=0;

    if (cfg->accurate&&cnt_tid) { g_cnt_done=1; pthread_join(cnt_tid,NULL); }

    uint64_t fin=now_us();
    double elapsed_s=(fin-t_start)/1e6;
    double rate=elapsed_s>0?g_scanned/elapsed_s:0;

    draw_tui(cfg,g_scanned,g_found_n,(long)g_total,elapsed_s,rate,tick);
    term_restore();

    if (strcmp(cfg->action,"quarantine")==0&&g_found_n>0) {
        char stamp[32]; ts_stamp(stamp,sizeof(stamp));
        printf("\n%s%s[INFO]%s Processing %d detection(s)…\n",BOLD,INFO,RST,g_found_n);
        process_detections(cfg,stamp,NULL);
    }

    write_report(cfg,g_scanned,g_found_n,elapsed_s,rate,clam_rc);
    prompt_report_export(cfg,g_scanned,g_found_n,elapsed_s,rate,clam_rc);
    print_summary(cfg,g_scanned,g_found_n,elapsed_s,rate);
    return g_found_n>0?2:0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Usage
 * ═══════════════════════════════════════════════════════════════════ */
static void usage(const char *prog) {
    printf("%s%s%s  v%s%s\n\n",BOLD,ACCENT,APP_NAME,APP_VER,RST);
    printf("%sUSAGE%s\n  sudo %s [OPTIONS]\n\n",BOLD,RST,prog);
    printf("%sOPTIONS%s\n",BOLD,RST);
    printf("  %s--target%s PATH          Directory to scan (default: /)\n",ACCENT,RST);
    printf("  %s--profile%s NAME         recommended | full | custom (default: recommended)\n",ACCENT,RST);
    printf("  %s--exclude%s PATHS        Space/comma-separated paths to skip\n",ACCENT,RST);
    printf("  %s--action%s NAME          %sreport%s | %squarantine%s (default) | %sremove%s\n",
           ACCENT,RST,OK,RST,ACCENT,RST,HI,RST);
    printf("  %s--theme%s NAME           %sblueteam%s (default) | %slayer8%s | %shackerman%s | %sretro%s | %sarctic%s\n",
           ACCENT,RST,
           tc(THEMES[0].accent),RST,
           tc(THEMES[1].accent),RST,
           tc(THEMES[2].accent),RST,
           tc(THEMES[3].accent),RST,
           tc(THEMES[4].accent),RST);
    printf("  %s--accurate%s             Count files first for percentage progress\n",ACCENT,RST);
    printf("  %s--no-update%s            Skip freshclam before scanning\n",ACCENT,RST);
    printf("  %s--no-color%s             Disable ANSI output\n",ACCENT,RST);
    printf("  %s--i-accept-risk%s        Required gate for --action remove\n",ACCENT,RST);
    printf("  %s-h, --help%s             Show this help\n\n",ACCENT,RST);
    printf("%sTHEMES%s\n",BOLD,RST);
    for (int i=0;i<N_THEMES;i++)
        printf("  %s%-12s%s %s\n",tc(THEMES[i].accent),THEMES[i].id,RST,THEMES[i].label);
    printf("\n%sEXAMPLES%s\n",BOLD,RST);
    printf("  sudo %s\n",prog);
    printf("  sudo %s --theme hackerman --target /home --action quarantine\n",prog);
    printf("  sudo %s --theme arctic --profile full --accurate --action report\n",prog);
    printf("  sudo %s --theme retro --target /tmp --action remove --i-accept-risk\n",prog);
    printf("  sudo %s --no-update --target /var --action quarantine\n\n",prog);
    printf("%sOUTPUT%s\n",BOLD,RST);
    printf("  Reports   : %s/\n",REPORTDIR);
    printf("  ClamAV log: %s\n",LOGFILE);
    printf("  Quarantine: %s/\n",QUAR_BASE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Interactive prompts
 * ═══════════════════════════════════════════════════════════════════ */
static void prompt(const char *label, const char *def, char *out, size_t sz) {
    printf("  %s%s%s [%s%s%s]: ",BOLD,label,RST,MUTED,def?def:"",RST);
    fflush(stdout);
    char buf[2048]="";
    if (fgets(buf,sizeof(buf),stdin)) {
        buf[strcspn(buf,"\n")]='\0';
        if (buf[0]) snprintf(out,sz,"%s",buf);
        else if (def) snprintf(out,sz,"%s",def);
    } else if (def) snprintf(out,sz,"%s",def);
}

/* ═══════════════════════════════════════════════════════════════════
 *  main
 * ═══════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {
    if (!isatty(STDOUT_FILENO)||getenv("NO_COLOR")) g_color=0;

    /* pre-scan args: --no-color and --theme must apply to all output */
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i],"--no-color")) { g_color=0; }
        if (!strcmp(argv[i],"--theme")&&i+1<argc) {
            const Theme *t=find_theme(argv[i+1]);
            if (t) g_theme=t;
            else { fprintf(stderr,"Unknown theme '%s'\n",argv[i+1]); return 1; }
        }
    }

    if (geteuid()!=0) {
        fprintf(stderr,"%s%s[ERR]%s Must run as root.  Try: sudo %s\n",BOLD,HI,RST,argv[0]);
        return 1;
    }

    struct sigaction sa={.sa_handler=sighandler,.sa_flags=SA_RESTART};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL); sigaction(SIGTERM,&sa,NULL);
    signal(SIGPIPE,SIG_IGN);

    Config cfg; config_defaults(&cfg);

    for (int i=1;i<argc;i++) {
        if      (!strcmp(argv[i],"-h")||!strcmp(argv[i],"--help"))   { usage(argv[0]); return 0; }
        else if (!strcmp(argv[i],"--no-color"))                       { /* handled above */ }
        else if (!strcmp(argv[i],"--theme")    &&i+1<argc)           { i++; /* handled above */ }
        else if (!strcmp(argv[i],"--accurate"))                       { cfg.accurate=1;      }
        else if (!strcmp(argv[i],"--no-update"))                      { cfg.no_update=1;     }
        else if (!strcmp(argv[i],"--i-accept-risk"))                  { cfg.i_accept_risk=1; }
        else if (!strcmp(argv[i],"--target")  &&i+1<argc) { snprintf(cfg.target,  sizeof(cfg.target),  "%s",argv[++i]); cfg.noninteractive=1; }
        else if (!strcmp(argv[i],"--profile") &&i+1<argc) { snprintf(cfg.profile, sizeof(cfg.profile), "%s",argv[++i]); cfg.noninteractive=1; }
        else if (!strcmp(argv[i],"--exclude") &&i+1<argc) { snprintf(cfg.excludes,sizeof(cfg.excludes),"%s",argv[++i]); cfg.noninteractive=1; cfg.excludes_explicit=1; }
        else if (!strcmp(argv[i],"--action")  &&i+1<argc) { snprintf(cfg.action,  sizeof(cfg.action),  "%s",argv[++i]); cfg.noninteractive=1; }
    }

    /* apply profile defaults unless --exclude was explicitly provided */
    if (!cfg.excludes_explicit) {
        if      (strcmp(cfg.profile,"full")==0)        cfg.excludes[0]='\0';
        else if (strcmp(cfg.profile,"recommended")==0) snprintf(cfg.excludes,sizeof(cfg.excludes),"%s","/proc /sys /dev /run");
        else                                           cfg.excludes[0]='\0';
    }

    /* interactive mode */
    if (!cfg.noninteractive) {
        int cols=term_cols(); if(cols>78)cols=78;
        printf("\n");
        hline(cols);
        printf("%s%s  %s — AV Scanner%s\n",BOLD,ACCENT,APP_NAME,RST);
        hline(cols);
        printf("\n");

        char tmp[PATH_MAX]="";
        prompt("Target path",cfg.target,tmp,sizeof(tmp));
        if (tmp[0]) snprintf(cfg.target,sizeof(cfg.target),"%s",tmp);

        tmp[0]='\0';
        printf("  %sProfiles:%s %srecommended%s | full | custom\n",MUTED,RST,OK,RST);
        prompt("Profile",cfg.profile,tmp,sizeof(tmp));
        if (tmp[0]) {
            snprintf(cfg.profile,sizeof(cfg.profile),"%s",tmp);
            if      (strcmp(cfg.profile,"full")==0)        cfg.excludes[0]='\0';
            else if (strcmp(cfg.profile,"recommended")==0) snprintf(cfg.excludes,sizeof(cfg.excludes),"%s","/proc /sys /dev /run");
            else                                           cfg.excludes[0]='\0';
        }

        tmp[0]='\0';
        prompt("Exclude paths",cfg.excludes[0]?cfg.excludes:"<none>",tmp,sizeof(tmp));
        if (tmp[0]&&strcmp(tmp,"<none>")!=0) snprintf(cfg.excludes,sizeof(cfg.excludes),"%s",tmp);

        printf("  %sActions:%s %sreport%s | %squarantine%s | %sremove%s\n",
               MUTED,RST,OK,RST,ACCENT,RST,HI,RST);
        tmp[0]='\0';
        prompt("Action",cfg.action,tmp,sizeof(tmp));
        if (tmp[0]) snprintf(cfg.action,sizeof(cfg.action),"%s",tmp);

        tmp[0]='\0';
        prompt("Accurate progress — count files first [y/N]","N",tmp,sizeof(tmp));
        if (tmp[0]=='y'||tmp[0]=='Y') cfg.accurate=1;
        printf("\n");
    }

    /* validate action */
    if (strcmp(cfg.action,"report")!=0&&strcmp(cfg.action,"quarantine")!=0&&strcmp(cfg.action,"remove")!=0) {
        fprintf(stderr,"%s%s[ERR]%s Unknown action '%s'\n",BOLD,HI,RST,cfg.action);
        return 1;
    }

    /* remove mode gate */
    if (strcmp(cfg.action,"remove")==0) {
        int cols=term_cols(); if(cols>78)cols=78;
        printf("\n");
        hline(cols);
        printf("%s%s  DANGER: REMOVE MODE%s\n",BOLD,HI,RST);
        hline(cols);
        printf("  Remove permanently deletes infected files.\n");
        printf("  False positives can damage your system.\n");
        printf("  %sQuarantine is the safer default.%s\n",MUTED,RST);
        hline(cols);
        printf("\n");

        if (!cfg.i_accept_risk) {
            printf("%s%s[WARN]%s --i-accept-risk required. Switching to quarantine.\n",BOLD,WARN,RST);
            snprintf(cfg.action,sizeof(cfg.action),"quarantine");
        } else if (!strcmp(cfg.target,"/")||!strcmp(cfg.target,"/usr")||
                   !strcmp(cfg.target,"/bin")||!strcmp(cfg.target,"/sbin")) {
            printf("%s%s[WARN]%s Remove refused for system target '%s'. Switching to quarantine.\n",BOLD,WARN,RST,cfg.target);
            snprintf(cfg.action,sizeof(cfg.action),"quarantine");
        } else if (!isatty(STDIN_FILENO)) {
            printf("%s%s[WARN]%s Non-interactive stdin — switching to quarantine.\n",BOLD,WARN,RST);
            snprintf(cfg.action,sizeof(cfg.action),"quarantine");
        } else {
            printf("  %sType %sDELETE%s to confirm: ",MUTED,HI,RST);
            fflush(stdout);
            char confirm[32]=""; fgets(confirm,sizeof(confirm),stdin);
            confirm[strcspn(confirm,"\n")]='\0';
            if (strcmp(confirm,"DELETE")!=0) {
                printf("%s%s[INFO]%s Confirmation not given. Switching to quarantine.\n",BOLD,INFO,RST);
                snprintf(cfg.action,sizeof(cfg.action),"quarantine");
            }
        }
    }

    prepare_logdir();

    /* freshclam phase */
    if (!cfg.no_update) {
        if (access("/usr/bin/freshclam",X_OK)==0||access("/usr/local/bin/freshclam",X_OK)==0) {
            run_freshclam_ui();
        } else {
            printf("%s%s[WARN]%s freshclam not found — scanning with existing signatures.\n\n",BOLD,WARN,RST);
        }
    }

    return do_scan(&cfg);
}
