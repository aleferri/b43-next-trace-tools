// SPDX-License-Identifier: GPL-2.0
/*
 * wl_diag, variant for x86_64 with the hybrid wl of broadcom-sta
 * (6.30.223.271), on a current kernel, with kprobes.
 * The record format, the op codes, the queue, the stream and /proc/wl_diag
 * are those of ../4-4-arm/wl_diag.c, and so is the attaching through
 * kprobes; see ../README.md. What differs:
 * - the arguments come from regs_get_kernel_argument(): a1-a3 are the 2nd
 *   to 4th, the two nargx ones the 5th and 6th, in registers on x86_64;
 * - pointers are 64 bits wide: they are read whole and only the values
 *   recorded are cut to the record's 32 bits;
 * - kallsyms_lookup_name is not exported, so kprobes resolves "<target>:<n>"
 *   itself, and the dry run registers each probe disabled and removes it;
 * - the hook table is the x86 blob's, signatures checked on its disassembly;
 * - with bus=1 the stream has the register accesses too, see "bus" below.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kfifo.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/sched/clock.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/poll.h>
#include <linux/notifier.h>

#if !defined(CONFIG_KPROBES) || !defined(CONFIG_KRETPROBES)
#error "wl_diag needs CONFIG_KPROBES and CONFIG_KRETPROBES"
#endif

static int arm;
module_param(arm, int, 0444);
MODULE_PARM_DESC(arm, "0=dry run (log the plan only), 1=attach the probes");

static char *target = "wl";
module_param(target, charp, 0444);
MODULE_PARM_DESC(target, "name of the module to hook (default wl)");

static int delay;
module_param(delay, int, 0444);
MODULE_PARM_DESC(delay, "0=do not hook osl_delay (default), 1=hook it");

static int bus;
module_param(bus, int, 0444);
MODULE_PARM_DESC(bus, "0=function hooks only (default), 1=also every register access and PCI config write");

static int maxactive = 64;
module_param(maxactive, int, 0444);
MODULE_PARM_DESC(maxactive, "kretprobe instances per retcap hook (default 64)");

/* ---- record + queue -------------------------------------------------- */
enum wldiag_op {
	OP_PHY_R = 1, OP_PHY_W, OP_PHY_MOD,
	OP_RADIO_R, OP_RADIO_W, OP_RADIO_MOD,
	OP_PMU_CC, OP_PMU_RC, OP_PMU_PLL,
	OP_CC_GPIOCTL, OP_CC_GPIOOUT, OP_CC_GPIOOE,
	OP_TBL_R, OP_TBL_W, OP_DELAY,
	OP_MAC_MCTRL, OP_MAC_MHF_W, OP_MAC_MHF_R,
	OP_PHY_AND, OP_PHY_OR,
	OP_SI_COREREG,
	OP_ARGX, OP_RETVAL,
	OP_MAC_OBJ_R, OP_MAC_OBJ_W,
	OP_CHANSPEC,
	OP_TPL_PTRW, OP_TPL_DATW,
	OP_TPL_PTRR, OP_TPL_DATR, OP_TPL_RAMW,
	OP_OTP_INIT, OP_OTP_RDW, OP_OTP_RDR,
	OP_MAC_BW, OP_SROMCTL_R, OP_SROMCTL_W,
	OP_CAL_INIT,
	OP_MARK,
	OP_CHANSPEC_SHM,
	OP_MAC_OBJ_BULK_R, OP_MAC_OBJ_BULK_W,
	OP_AMT_W, OP_RCMTA_W, OP_ADDRMATCH,
	OP_PHY_WARR, OP_PHY_RDW, OP_PHY_WRW,
	OP_IHR_W, OP_OBJ_SET,
	OP_PHY_FGC,
	OP_IOCTL, OP_IOVAR_NAME, OP_IOVAR_SET,
	OP_TX_PKT, OP_TX_DATA,
	OP_TPL_DATA,
	OP_RX_PKT, OP_RX_DATA,
	/* 60-64 are wl-mmio-trap's; this variant writes 60 and 61 as it does */
	OP_MMIO_R = 60, OP_MMIO_W,
	OP_TXS = 65, OP_TXS_DATA,
	OP_PCICFG_W,
	OP_DROP = 255,
};
struct wldiag_rec {
	u64 ts_ns; u32 seq; u32 addr; u32 val; u32 aux;
	u8 op; u8 cpu; u16 _pad;
} __packed;

/* Sized and allocated as in ../4-4-arm, whose head explains the numbers. */
#define FIFO_RECS_DEF 131072
static int fifo_recs = FIFO_RECS_DEF;
module_param(fifo_recs, int, 0444);
static DECLARE_KFIFO_PTR(fifo, struct wldiag_rec);
static void *fifo_buf;
static DEFINE_RAW_SPINLOCK(fifo_lock);
static DECLARE_WAIT_QUEUE_HEAD(rq);
static atomic_t seq = ATOMIC_INIT(0);
static atomic_t drops = ATOMIC_INIT(0);
/* Set at unload: a reader blocked in wd_read() would hold the proc entry
 * and keep remove_proc_entry() waiting, so it is woken and gets EOF. */
static bool closing;

/* PHY register reads not to record, e.g. the radar detector's
 * skipphyrd="0x253,0x254" (../README.md, "DFS channels"). */
#define SKIP_MAX 16
static char *skipphyrd;
module_param(skipphyrd, charp, 0444);
static u32 skip_list[SKIP_MAX];
static int skip_n;
static atomic_t filtered = ATOMIC_INIT(0);

static void parse_skipphyrd(void)
{
	char buf[128], *p, *tok;

	if (!skipphyrd || !*skipphyrd)
		return;
	strscpy(buf, skipphyrd, sizeof(buf));
	p = buf;
	while ((tok = strsep(&p, ",")) && skip_n < SKIP_MAX) {
		u32 v;

		tok = strim(tok);
		if (!*tok)
			continue;
		if (kstrtou32(tok, 0, &v)) {
			pr_warn("wl_diag: skipphyrd: '%s' is not a number\n", tok);
			continue;
		}
		skip_list[skip_n++] = v;
	}
	if (skip_n)
		pr_info("wl_diag: %d PHY reads filtered by address\n", skip_n);
}

static u32 emit(u8 op, u32 addr, u32 val, u32 aux)
{
	struct wldiag_rec r;
	unsigned long flags;
	int i;

	if (op == OP_PHY_R) {
		for (i = 0; i < skip_n; i++) {
			if (addr == skip_list[i]) {
				atomic_inc(&filtered);
				return 0;
			}
		}
	}

	r.ts_ns = local_clock();
	r.seq = (u32)atomic_inc_return(&seq);
	r.addr = addr; r.val = val; r.aux = aux;
	r.op = op; r.cpu = (u8)raw_smp_processor_id(); r._pad = 0;

	raw_spin_lock_irqsave(&fifo_lock, flags);
	if (!kfifo_is_full(&fifo))
		kfifo_in(&fifo, &r, 1);
	else
		atomic_inc(&drops);
	raw_spin_unlock_irqrestore(&fifo_lock, flags);
	wake_up_interruptible(&rq);
	return r.seq;
}

/* A record and n bytes at src in data records, as in ../4-4-arm. */
static u32 emit_group(u8 op, u32 addr, u32 val, u32 aux, u8 dop,
		      const u8 *src, u32 n)
{
	struct wldiag_rec r;
	unsigned long flags;
	u32 nrec = 1 + (n + 11) / 12, i, k, first = 0;

	raw_spin_lock_irqsave(&fifo_lock, flags);
	if (kfifo_avail(&fifo) < nrec) {
		atomic_add(nrec, &drops);
		raw_spin_unlock_irqrestore(&fifo_lock, flags);
		return 0;
	}
	for (i = 0; i < nrec; i++) {
		r.ts_ns = local_clock();
		r.seq = (u32)atomic_inc_return(&seq);
		r.cpu = (u8)raw_smp_processor_id();
		r._pad = 0;
		if (!i) {
			r.op = op;
			r.addr = addr; r.val = val; r.aux = aux;
			first = r.seq;
		} else {
			u32 w[3] = { 0, 0, 0 }, o = (i - 1) * 12;
			u8 c[12];
			u32 m = n - o < 12 ? n - o : 12;

			if (copy_from_kernel_nofault(c, src + o, m))
				memset(c, 0, m);
			for (k = 0; k < m; k++)
				w[k / 4] |= (u32)c[k] << (24 - 8 * (k % 4));
			r.op = dop;
			r.addr = w[0]; r.val = w[1]; r.aux = w[2];
		}
		kfifo_in(&fifo, &r, 1);
	}
	raw_spin_unlock_irqrestore(&fifo_lock, flags);
	wake_up_interruptible(&rq);
	return first;
}

static bool readable(const void *p, u32 n)
{
	u8 c;

	return n && !copy_from_kernel_nofault(&c, p, 1) &&
	       !copy_from_kernel_nofault(&c, (const u8 *)p + n - 1, 1);
}

/* ---- markers ---------------------------------------------------------- */
static u32 pack4(const char *p)
{
	return ((u32)(u8)p[0] << 24) | ((u32)(u8)p[1] << 16) |
	       ((u32)(u8)p[2] << 8) | (u32)(u8)p[3];
}

static void emit_mark(const char *b12)
{
	emit(OP_MARK, pack4(b12), pack4(b12 + 4), pack4(b12 + 8));
}

static void mark(const char *s)
{
	char b[12] = { 0 };

	memcpy(b, s, strnlen(s, sizeof(b)));
	emit_mark(b);
}

/* ---- bus ------------------------------------------------------------- *
 * On this wl every register access goes through osl_read{b,w,l} and
 * osl_write{b,w,l}, functions of wl.ko's linux_osl.c. With bus=1 they are
 * hooked and recorded as wl-mmio-trap records them: MMIO.RD/WR with the
 * offset into BAR0, the value, and in aux the width and AUX_DEV_OFFSET, the
 * offset being the device's on a little-endian host. A read goes out at its
 * return, with its value. BAR0's mapping is the regs argument of si_attach(); an access
 * outside it, or before it, is counted and not recorded. The config writes
 * that move the window are PCICFG.WR: offset, value, size.
 */
#define AUX_DEV_OFFSET	0x200
#define BAR0_SIZE	0x4000		/* PCI_BAR0_WINSZ */
static unsigned long bar0;
static atomic_t unplaced = ATOMIC_INIT(0);

static u32 bus_rec(u8 op, unsigned long va, u32 val, u8 width)
{
	unsigned long base = READ_ONCE(bar0);

	if (!base || va < base || va - base >= BAR0_SIZE) {
		atomic_inc(&unplaced);
		return 0;
	}
	return emit(op, va - base, val, width | AUX_DEV_OFFSET);
}

/* ---- hook table ------------------------------------------------------- *
 * Each source field takes an argument: 0=absent(->0), 1=a1, 2=a2, 3=a3, the
 * 2nd to 4th. The entries are ../4-4-arm's that the 6.30.223.271 blob has,
 * with these differences:
 * - osl_delay(usec) takes its value from the 1st argument (wd_hook());
 * - the PHY tables: wlc_phy_read/write_table(pi, phytbl_info *, ...) is
 *   where the N-, HT-, LCN- and SSLPN-PHY accessors meet, the LP-PHY's take
 *   the same struct, the AC-PHY's have the arguments of the routers' entry;
 * - wlc_phy_chanspec_set, the PHYs' common entry on 6.30, as ../2-6-30;
 * - no fallbacks: the objmem16 accessors and hnddma's dma64_* have no
 *   symbol in this blob, so the shm thunks and wlc_txfifo are the hooks;
 * - the bus hooks, attached with bus=1 only.
 */
struct hook {
	const char *name;
	u8 op, addr_src, val_src, aux_src;
	bool retcap;		/* a RETVAL record with what the call returns */
	u8 nargx;		/* the 5th and 6th arguments in an ARGX record */
	bool txraw;		/* OP_TX_PKT: a1 is a buffer, a2 its length */
	bool tblinfo;		/* OP_TBL_*: a1 is a struct wd_phytbl_info * */
	u8 width;		/* OP_MMIO_*: osl_read*(r) or osl_write*(v, r) */
	bool bar0;		/* si_attach(): a2 is BAR0's mapping */
	/* state */
	bool armed;
	struct kprobe kp;
	struct kretprobe krp;
};
static struct hook hooks[] = {
	{ "phy_reg_read", OP_PHY_R, 1, 0, 0, .retcap = true },
	{ "phy_reg_write", OP_PHY_W, 1, 2, 0 },
	{ "phy_reg_mod", OP_PHY_MOD, 1, 3, 2 },
	{ "phy_reg_and", OP_PHY_AND, 1, 2, 0 },
	{ "phy_reg_or", OP_PHY_OR, 1, 2, 0 },
	{ "read_radio_reg", OP_RADIO_R, 1, 0, 0, .retcap = true },
	{ "write_radio_reg", OP_RADIO_W, 1, 2, 0 },
	{ "mod_radio_reg", OP_RADIO_MOD, 1, 3, 2 },
	{ "si_pmu_chipcontrol", OP_PMU_CC, 1, 3, 2, .retcap = true },
	{ "si_pmu_regcontrol", OP_PMU_RC, 1, 3, 2, .retcap = true },
	{ "si_pmu_pllcontrol", OP_PMU_PLL, 1, 3, 2, .retcap = true },
	{ "si_corereg", OP_SI_COREREG, 2, 0, 1, .retcap = true, .nargx = 1 },
	{ "si_gpiocontrol", OP_CC_GPIOCTL, 0, 2, 1 },
	{ "si_gpioout", OP_CC_GPIOOUT, 0, 2, 1 },
	{ "si_gpioouten", OP_CC_GPIOOE, 0, 2, 1 },
	{ "wlc_phy_read_table", OP_TBL_R, .tblinfo = true },
	{ "wlc_phy_write_table", OP_TBL_W, .tblinfo = true },
	{ "wlc_phy_table_read_lpphy", OP_TBL_R, .tblinfo = true },
	{ "wlc_phy_table_write_lpphy", OP_TBL_W, .tblinfo = true },
	{ "wlc_phy_table_read_acphy", OP_TBL_R, 1, 2, 3 },
	{ "wlc_phy_table_write_acphy", OP_TBL_W, 1, 2, 3 },
	{ "osl_delay", OP_DELAY },
	{ "wlc_bmac_mctrl", OP_MAC_MCTRL, 0, 2, 1 },
	{ "wlc_bmac_mhf", OP_MAC_MHF_W, 1, 3, 2, .nargx = 1 },
	{ "wlc_bmac_mhf_get", OP_MAC_MHF_R, 1, 0, 0, .retcap = true },
	{ "wlc_bmac_write_template_ram", OP_TPL_RAMW, 1, 2, 0 },
	{ "otp_init", OP_OTP_INIT, 0, 0, 0, .retcap = true },
	{ "otp_read_word", OP_OTP_RDW, 1, 0, 2, .retcap = true },
	{ "otp_read_region", OP_OTP_RDR, 1, 0, 3, .retcap = true },
	{ "wlc_phy_cal_init", OP_CAL_INIT },
	{ "wlc_bmac_bw_set", OP_MAC_BW, 0, 1, 0 },
	{ "si_get_sromctl", OP_SROMCTL_R, 0, 0, 0, .retcap = true },
	{ "si_set_sromctl", OP_SROMCTL_W, 0, 1, 0 },
	{ "wlc_phy_chanspec_set", OP_CHANSPEC, 1, 0, 0 },
	{ "wlc_phy_chanspec_shm_set", OP_CHANSPEC_SHM, 1, 0, 0 },
	{ "wlc_bmac_read_shm", OP_MAC_OBJ_R, 1, 0, 0, .retcap = true },
	{ "wlc_bmac_write_shm", OP_MAC_OBJ_W, 1, 2, 0 },
	{ "wlc_bmac_copyfrom_objmem", OP_MAC_OBJ_BULK_R, 1, 0, 3, .nargx = 1 },
	{ "wlc_bmac_copyto_objmem", OP_MAC_OBJ_BULK_W, 1, 0, 3, .nargx = 1 },
	{ "wlc_bmac_set_addrmatch", OP_ADDRMATCH, 1, 0, 0 },
	{ "wlc_bmac_write_amt", OP_AMT_W, 1, 0, 3 },
	{ "wlc_bmac_set_rcmta", OP_RCMTA_W, 1, 0, 0 },
	{ "phy_reg_write_array", OP_PHY_WARR, 0, 2, 0 },
	{ "phy_reg_read_wide", OP_PHY_RDW, 0, 0, 0, .retcap = true },
	{ "phy_reg_write_wide", OP_PHY_WRW, 0, 1, 0 },
	{ "wlc_bmac_write_ihr", OP_IHR_W, 1, 2, 0 },
	{ "wlc_bmac_set_shm", OP_OBJ_SET, 1, 2, 3 },
	{ "wlc_bmac_phyclk_fgc", OP_PHY_FGC, 0, 1, 0 },
	{ "wlc_ioctl", OP_IOCTL, 1, 2, 3 },
	{ "wlc_txfifo", OP_TX_PKT, 2, 0, 0 },
	{ "wlc_recv", OP_RX_PKT, 1, 0, 0 },
	{ "wlc_dotxstatus", OP_TXS, 1, 2, 0 },
	{ "si_attach", 0, .bar0 = true },
	{ "osl_readb", OP_MMIO_R, .width = 1, .retcap = true },
	{ "osl_readw", OP_MMIO_R, .width = 2, .retcap = true },
	{ "osl_readl", OP_MMIO_R, .width = 4, .retcap = true },
	{ "osl_writeb", OP_MMIO_W, .width = 1 },
	{ "osl_writew", OP_MMIO_W, .width = 2 },
	{ "osl_writel", OP_MMIO_W, .width = 4 },
	{ "osl_pci_write_config", OP_PCICFG_W, 1, 3, 2 },
};
#define NHOOK ARRAY_SIZE(hooks)

/* brcmsmac's struct phytbl_info, the layout the blob reads it with */
struct wd_phytbl_info {
	const void *tbl_ptr;
	u32 tbl_len;
	u32 tbl_id;
	u32 tbl_offset;
	u32 tbl_width;
};

static inline unsigned long pick(u8 src, const unsigned long *a)
{
	return src >= 1 && src <= 3 ? a[src] : 0;
}

/* wlc_ioctl(), as in ../4-4-arm. */
#define WD_WLC_GET_VAR		262
#define WD_WLC_SET_VAR		263
#define WD_IOVAR_NAME_MAX	36

static u32 ioctl_rec(u32 cmd, unsigned long buf, u32 len)
{
	u8 b[WD_IOVAR_NAME_MAX + 1 + 4];
	u32 n = len < sizeof(b) ? len : sizeof(b);
	u32 nl, i, v = 0;

	if (cmd == WD_WLC_GET_VAR)
		return 0;
	if (!buf || copy_from_kernel_nofault(b, (void *)buf, n))
		n = 0;

	if (cmd != WD_WLC_SET_VAR) {
		if (n >= 4)
			memcpy(&v, b, 4);
		return emit(OP_IOCTL, cmd, v, len);
	}

	for (nl = 0; nl < n && nl < WD_IOVAR_NAME_MAX && b[nl]; nl++)
		;
	for (i = 0; i < nl; i += 12) {
		u32 w[3] = { 0, 0, 0 };
		u32 k;

		for (k = 0; k < 12 && i + k < nl; k++)
			w[k / 4] |= (u32)b[i + k] << (24 - 8 * (k % 4));
		emit(OP_IOVAR_NAME, w[0], w[1], w[2]);
	}
	if (nl < n && !b[nl] && nl + 1 + 4 <= n)
		memcpy(&v, b + nl + 1, 4);
	return emit(OP_IOVAR_SET, v, len > nl + 1 ? len - nl - 1 : 0, 0);
}

/* Frames at the TX post and at the RX hand-over, as in ../4-4-arm. */
#define PKTDUMP_MAX 256
#define PKT_F_RAW	1	/* aux: a raw buffer, not an osl packet */

static uint txdump;
module_param(txdump, uint, 0644);
MODULE_PARM_DESC(txdump, "bytes of each frame posted to a TX ring to record, up to 256; 0=off (default)");

static uint txbudget = 256;
module_param(txbudget, uint, 0644);
MODULE_PARM_DESC(txbudget, "TX frames left to record; counts down to 0 (default 256)");

static uint rxdump;
module_param(rxdump, uint, 0644);
MODULE_PARM_DESC(rxdump, "bytes of each received frame to record, up to 256; 0=off (default)");

static uint rxbudget = 256;
module_param(rxbudget, uint, 0644);
MODULE_PARM_DESC(rxbudget, "RX frames left to record; counts down to 0 (default 256)");

static bool take_budget(uint *budget)
{
	uint left;

	do {
		left = READ_ONCE(*budget);
		if (!left)
			return false;
	} while (cmpxchg(budget, left, left - 1) != left);
	return true;
}

static u32 pkt_rec(const struct hook *h, const unsigned long *a,
		   u8 op, u8 dop, uint want, uint *budget)
{
	unsigned long p = pick(h->addr_src, a);
	const u8 *data;
	u32 len, lin, n;

	if (!want || !p || !take_budget(budget))
		return 0;

	if (h->txraw) {
		data = (const u8 *)p;
		len = lin = pick(h->val_src, a);
	} else {
		const struct sk_buff *skb = (const void *)p;
		unsigned int l, dl;

		if (copy_from_kernel_nofault(&data, &skb->data, sizeof(data)) ||
		    copy_from_kernel_nofault(&l, &skb->len, sizeof(l)) ||
		    copy_from_kernel_nofault(&dl, &skb->data_len, sizeof(dl)))
			return 0;
		len = l;
		lin = dl <= l ? l - dl : 0;
	}
	n = min_t(u32, want, lin);
	n = min_t(u32, n, PKTDUMP_MAX);
	if (!readable(data, n))
		n = 0;
	return emit_group(op, len, n, h->txraw ? PKT_F_RAW : 0, dop, data, n);
}

/* Template RAM content, as in ../4-4-arm. */
#define TPLDUMP_MAX 1024

static uint tpldump;
module_param(tpldump, uint, 0644);
MODULE_PARM_DESC(tpldump, "bytes of each template RAM write to record, up to 1024; 0=off (default)");

static uint tplbudget = 256;
module_param(tplbudget, uint, 0644);
MODULE_PARM_DESC(tplbudget, "template RAM writes left to record; counts down to 0 (default 256)");

static u32 tpl_rec(u32 off, u32 len, unsigned long buf)
{
	const u8 *src = (const u8 *)buf;
	u32 n = min_t(u32, READ_ONCE(tpldump), len);

	n = min_t(u32, n, TPLDUMP_MAX);
	if (!n || !buf || !take_budget(&tplbudget))
		return emit(OP_TPL_RAMW, off, len, 0);
	if (!readable(src, n))
		n = 0;
	return emit_group(OP_TPL_RAMW, off, len, n, OP_TPL_DATA, src, n);
}

/* TX statuses, as in ../4-4-arm. */
#define TXSDUMP_MAX 128

static uint txsdump;
module_param(txsdump, uint, 0644);
MODULE_PARM_DESC(txsdump, "bytes of each TX status structure to record, up to 128; 0=off (default)");

static uint txsbudget = 256;
module_param(txsbudget, uint, 0644);
MODULE_PARM_DESC(txsbudget, "TX statuses left to record; counts down to 0 (default 256)");

static u32 txs_rec(unsigned long txs, u32 a2)
{
	const u8 *src = (const u8 *)txs;
	u32 n = min_t(u32, READ_ONCE(txsdump), TXSDUMP_MAX);

	if (!n || !txs || !take_budget(&txsbudget))
		return 0;
	if (!readable(src, n))
		n = 0;
	return emit_group(OP_TXS, a2, n, 0, OP_TXS_DATA, src, n);
}

static u32 tbl_rec(u8 op, unsigned long info)
{
	struct wd_phytbl_info ti;

	if (copy_from_kernel_nofault(&ti, (const void *)info, sizeof(ti)))
		return 0;
	return emit(op, ti.tbl_id, ti.tbl_len, ti.tbl_offset);
}

/* ---- one call of an accessor ------------------------------------------ */

/* The call's records; returns the main record's seq, 0 if none went out. */
static u32 wd_hook(const struct hook *h, struct pt_regs *regs)
{
	unsigned long a[4];
	u32 s;
	int i;

	for (i = 0; i < 4; i++)
		a[i] = regs_get_kernel_argument(regs, i);

	if (h->bar0) {
		WRITE_ONCE(bar0, a[2]);
		s = 0;
	} else if (h->width) {
		s = bus_rec(h->op, a[1], a[0], h->width);
	} else if (h->tblinfo) {
		s = tbl_rec(h->op, a[1]);
	} else {
		switch (h->op) {
		case OP_DELAY:
			s = emit(h->op, 0, a[0], 0);
			break;
		case OP_IOCTL:
			s = ioctl_rec(a[1], a[2], a[3]);
			break;
		case OP_TX_PKT:
			s = pkt_rec(h, a, OP_TX_PKT, OP_TX_DATA,
				    READ_ONCE(txdump), &txbudget);
			break;
		case OP_RX_PKT:
			s = pkt_rec(h, a, OP_RX_PKT, OP_RX_DATA,
				    READ_ONCE(rxdump), &rxbudget);
			break;
		case OP_TXS:
			s = txs_rec(pick(h->addr_src, a), pick(h->val_src, a));
			break;
		case OP_TPL_RAMW:
			s = tpl_rec(a[1], a[2], a[3]);
			break;
		default:
			s = emit(h->op, pick(h->addr_src, a),
				 pick(h->val_src, a), pick(h->aux_src, a));
			break;
		}
	}

	if (h->nargx && s)
		emit(OP_ARGX, regs_get_kernel_argument(regs, 4),
		     h->nargx > 1 ? regs_get_kernel_argument(regs, 5) : 0, s);
	return s;
}

static int wd_pre(struct kprobe *p, struct pt_regs *regs)
{
	wd_hook(container_of(p, struct hook, kp), regs);
	return 0;
}

static int wd_ret_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook *h = container_of(get_kretprobe(ri), struct hook, krp);

	*(u32 *)ri->data = wd_hook(h, regs);
	return 0;
}

static int wd_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	u32 s = *(u32 *)ri->data;

	if (s)
		emit(OP_RETVAL, s, regs_return_value(regs), 0);
	return 0;
}

static int bus_ret_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	*(unsigned long *)ri->data = regs_get_kernel_argument(regs, 0);
	return 0;
}

static int bus_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const struct hook *h = container_of(get_kretprobe(ri), struct hook, krp);
	u32 mask = h->width == 4 ? ~0u : (1u << (8 * h->width)) - 1;

	bus_rec(h->op, *(unsigned long *)ri->data,
		regs_return_value(regs) & mask, h->width);
	return 0;
}

/* ---- plan, arming, disarming ------------------------------------------ */

static DEFINE_MUTEX(arm_lock);

/*
 * Registers h's probe on "<target>:<name>", which kprobes resolves; with
 * KPROBE_FLAG_DISABLED nothing is written to the target's text, which is
 * how the dry run checks a hook. Returns the probe, or NULL with *err set.
 */
static struct kprobe *attach(struct hook *h, char *sym, u32 flags, int *err)
{
	if (h->retcap) {
		memset(&h->krp, 0, sizeof(h->krp));
		h->krp.kp.symbol_name = sym;
		h->krp.kp.flags = flags;
		h->krp.entry_handler = h->width ? bus_ret_entry : wd_ret_entry;
		h->krp.handler = h->width ? bus_ret : wd_ret;
		h->krp.data_size = sizeof(unsigned long);
		h->krp.maxactive = maxactive;
		*err = register_kretprobe(&h->krp);
		return *err ? NULL : &h->krp.kp;
	}
	memset(&h->kp, 0, sizeof(h->kp));
	h->kp.symbol_name = sym;
	h->kp.flags = flags;
	h->kp.pre_handler = wd_pre;
	*err = register_kprobe(&h->kp);
	return *err ? NULL : &h->kp;
}

static void detach(struct hook *h)
{
	if (h->retcap)
		unregister_kretprobe(&h->krp);
	else
		unregister_kprobe(&h->kp);
}

/*
 * Every hook in the target and, with arm=1, attached. Returns the hooks
 * found: 0 means the target is not loaded. Called with arm_lock held.
 */
static int arma(void)
{
	static char syms[NHOOK][MODULE_NAME_LEN + 1 + 40];
	int i, found = 0, armed = 0;

	WRITE_ONCE(bar0, 0);
	for (i = 0; i < NHOOK; i++) {
		struct hook *h = &hooks[i];
		const char *kind = h->retcap ? "kretprobe" : "kprobe";
		struct kprobe *kp;
		int err;

		h->armed = false;
		if (h->op == OP_DELAY && !delay)
			continue;
		if ((h->width || h->bar0 || h->op == OP_PCICFG_W) && !bus)
			continue;
		snprintf(syms[i], sizeof(syms[i]), "%s:%s", target, h->name);
		kp = attach(h, syms[i], arm ? 0 : KPROBE_FLAG_DISABLED, &err);
		if (err == -ENOENT) {
			pr_info("wl_diag: %-28s absent\n", h->name);
			continue;
		}
		found++;
		if (!kp) {
			pr_warn("wl_diag: %-28s refused: %d\n", h->name, err);
			continue;
		}
		if (!arm) {
			pr_info("wl_diag: %-28s @%px %s (dry run)\n",
				h->name, kp->addr, kind);
			detach(h);
			continue;
		}
		h->armed = true;
		armed++;
		pr_info("wl_diag: %-28s @%px %s\n", h->name, kp->addr, kind);
	}
	if (found)
		pr_info("wl_diag: %s: %d of %d hooks found, %d attached%s\n",
			target, found, (int)NHOOK, armed,
			arm ? "" : " (arm=0: dry run)");
	return found;
}

/* Called with arm_lock held. */
static void disarma(void)
{
	struct kretprobe *krps[NHOOK];
	struct kprobe *kps[NHOOK];
	int i, nk = 0, nr = 0;

	for (i = 0; i < NHOOK; i++) {
		struct hook *h = &hooks[i];

		if (!h->armed)
			continue;
		if (h->retcap)
			krps[nr++] = &h->krp;
		else
			kps[nk++] = &h->kp;
	}
	if (nk)
		unregister_kprobes(kps, nk);
	if (nr)
		unregister_kretprobes(krps, nr);
	for (i = 0; i < NHOOK; i++) {
		struct hook *h = &hooks[i];

		if (h->armed && h->retcap && h->krp.nmissed)
			pr_warn("wl_diag: %s: %d return values lost (maxactive=%d)\n",
				h->name, h->krp.nmissed, maxactive);
		h->armed = false;
	}
	if (atomic_read(&unplaced))
		pr_warn("wl_diag: %d register accesses outside BAR0 not recorded\n",
			atomic_xchg(&unplaced, 0));
}

static int wd_mod_notify(struct notifier_block *nb, unsigned long ev, void *data)
{
	struct module *m = data;

	if (!m || strcmp(m->name, target))
		return NOTIFY_DONE;

	mutex_lock(&arm_lock);
	switch (ev) {
	case MODULE_STATE_COMING:
		disarma();
		mark("mod COMING");
		arma();
		break;
	case MODULE_STATE_GOING:
		mark("mod GOING");
		disarma();
		break;
	default:
		break;
	}
	mutex_unlock(&arm_lock);
	return NOTIFY_DONE;
}

static struct notifier_block wd_mod_nb = { .notifier_call = wd_mod_notify };

/* ---- /proc/wl_diag --------------------------------------------------- */
/* The stream is big-endian, as the MIPS variants write it natively. */
static void to_wire(struct wldiag_rec *r)
{
	r->ts_ns = (__force u64)cpu_to_be64(r->ts_ns);
	r->seq = (__force u32)cpu_to_be32(r->seq);
	r->addr = (__force u32)cpu_to_be32(r->addr);
	r->val = (__force u32)cpu_to_be32(r->val);
	r->aux = (__force u32)cpu_to_be32(r->aux);
	r->_pad = (__force u16)cpu_to_be16(r->_pad);
}

static ssize_t wd_read(struct file *f, char __user *ubuf, size_t len, loff_t *off)
{
	struct wldiag_rec r;
	unsigned long flags;
	u32 d;
	int ret;

	if (len < sizeof(r))
		return -EINVAL;

	d = atomic_xchg(&drops, 0);
	if (d) {
		memset(&r, 0, sizeof(r));
		r.ts_ns = local_clock();
		r.op = OP_DROP;
		r.aux = d;
		to_wire(&r);
		if (copy_to_user(ubuf, &r, sizeof(r)))
			return -EFAULT;
		return sizeof(r);
	}

	for (;;) {
		raw_spin_lock_irqsave(&fifo_lock, flags);
		ret = kfifo_out(&fifo, &r, 1);
		raw_spin_unlock_irqrestore(&fifo_lock, flags);
		if (ret)
			break;
		if (READ_ONCE(closing))
			return 0;
		if (f->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(rq, !kfifo_is_empty(&fifo) ||
					     atomic_read(&drops) ||
					     READ_ONCE(closing)))
			return -ERESTARTSYS;
		if (atomic_read(&drops))
			return 0;
	}
	to_wire(&r);
	if (copy_to_user(ubuf, &r, sizeof(r)))
		return -EFAULT;
	return sizeof(r);
}

static __poll_t wd_poll(struct file *f, poll_table *wait)
{
	poll_wait(f, &rq, wait);
	if (!kfifo_is_empty(&fifo) || atomic_read(&drops) || READ_ONCE(closing))
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}

/* A write injects a MARK with the label written, up to 12 characters. */
static ssize_t wd_write(struct file *f, const char __user *ubuf, size_t len,
			loff_t *off)
{
	char b[12] = { 0 };
	size_t n = min(len, sizeof(b));
	int i;

	if (n && copy_from_user(b, ubuf, n))
		return -EFAULT;
	for (i = 0; i < (int)sizeof(b); i++)
		if (b[i] == '\n' || b[i] == '\r')
			b[i] = 0;
	emit_mark(b);
	return len;
}

static const struct proc_ops wd_proc_ops = {
	.proc_read = wd_read,
	.proc_write = wd_write,
	.proc_poll = wd_poll,
};
#define WD_PROC "wl_diag"

/* ---- init/exit -------------------------------------------------------- */
static int __init wd_init(void)
{
	size_t bytes;
	int err;

	parse_skipphyrd();

	if (fifo_recs < 4096) {
		pr_warn("wl_diag: fifo_recs=%d too small, using 4096\n", fifo_recs);
		fifo_recs = 4096;
	}
	fifo_recs = 1 << (fls(fifo_recs) - 1);
	bytes = (size_t)fifo_recs * sizeof(struct wldiag_rec);
	fifo_buf = vmalloc(bytes);
	if (!fifo_buf) {
		pr_err("wl_diag: vmalloc of %zu KB for the queue failed\n",
		       bytes / 1024);
		return -ENOMEM;
	}
	err = kfifo_init(&fifo, fifo_buf, bytes);
	if (err) {
		pr_err("wl_diag: kfifo_init: %d\n", err);
		goto out_fifo;
	}
	pr_info("wl_diag: queue %d records (%zu KB)\n", fifo_recs, bytes / 1024);

	if (!proc_create(WD_PROC, 0600, NULL, &wd_proc_ops)) {
		pr_err("wl_diag: proc_create(/proc/%s) failed\n", WD_PROC);
		err = -ENOMEM;
		goto out_fifo;
	}

	err = register_module_notifier(&wd_mod_nb);
	if (err) {
		pr_err("wl_diag: register_module_notifier: %d\n", err);
		goto out_proc;
	}

	mutex_lock(&arm_lock);
	if (!arma())
		pr_info("wl_diag: waiting for '%s' to load\n", target);
	mutex_unlock(&arm_lock);
	return 0;

out_proc:
	remove_proc_entry(WD_PROC, NULL);
out_fifo:
	vfree(fifo_buf);
	fifo_buf = NULL;
	return err;
}

static void __exit wd_exit(void)
{
	unregister_module_notifier(&wd_mod_nb);
	mutex_lock(&arm_lock);
	disarma();
	mutex_unlock(&arm_lock);
	WRITE_ONCE(closing, true);
	wake_up_interruptible_all(&rq);
	remove_proc_entry(WD_PROC, NULL);
	vfree(fifo_buf);
	fifo_buf = NULL;
	pr_info("wl_diag: unloaded (lost: %d, filtered: %d)\n",
		atomic_read(&drops), atomic_read(&filtered));
}

module_init(wd_init);
module_exit(wd_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kprobes PHY/radio/PMU tracer for the hybrid Broadcom wl, x86_64");
