//
//@author sh4
//@category Dreamcast
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import generic.jar.ResourceFile;

public class DreamcastRE extends GhidraScript {
	Map<Long, SDKSymbol> sdk_symbols;

	public DreamcastRE() {

	}

	private void createBlock(String name, long start, long length, boolean read, boolean write, boolean execute) {
		try {
			MemoryBlock block = currentProgram.getMemory().createUninitializedBlock(name, toAddr(start), length, false);
			block.setVolatile(true);
			block.setPermissions(read, write, execute);
		} catch (Exception e) {
		}
	}

	private void createNamedU32(String name, long addr) {
		var address = toAddr(addr);
		try {
			createDWord(address);
		} catch (Exception e) {
		}

		try {
			getCurrentProgram().getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (Exception e) {
		}
	}

	void setupSH4MMIO() {
		createBlock("SH4 MMIO", 0xff00_0000L, 0x100_0000L, true, true, false);

		createNamedU32("PTEH", 0xff000000L);
		createNamedU32("PTEL", 0xff000004L);
		createNamedU32("TTB", 0xff000008L);
		createNamedU32("TEA", 0xff00000cL);
		createNamedU32("MMUCR", 0xff000010L);
		createNamedU32("BASRA", 0xff000014L);
		createNamedU32("BASRB", 0xff000018L);
		createNamedU32("CCR", 0xff00001cL);
		createNamedU32("TRA", 0xff000020L);
		createNamedU32("EXPEVT", 0xff000024L);
		createNamedU32("INTEVT", 0xff000028L);
		createNamedU32("VERSION", 0xff000030L);
		createNamedU32("PTEA", 0xff000034L);
		createNamedU32("QACR0", 0xff000038L);
		createNamedU32("QACR1", 0xff00003cL);
		createNamedU32("PRR", 0xff000044L);
		createNamedU32("BARA", 0xff200000L);
		createNamedU32("BAMRA", 0xff200004L);
		createNamedU32("BBRA", 0xff200008L);
		createNamedU32("BARB", 0xff20000cL);
		createNamedU32("BAMRB", 0xff200010L);
		createNamedU32("BBRB", 0xff200014L);
		createNamedU32("BDRB", 0xff200018L);
		createNamedU32("BDMRB", 0xff20001cL);
		createNamedU32("BRCR", 0xff200020L);
		createNamedU32("BCR1", 0xff800000L);
		createNamedU32("BCR2", 0xff800004L);
		createNamedU32("BCR3", 0xff800050L);
		createNamedU32("BCR4", 0xfe0a00f0L);
		createNamedU32("WCR1", 0xff800008L);
		createNamedU32("WCR2", 0xff80000cL);
		createNamedU32("WCR3", 0xff800010L);
		createNamedU32("MCR", 0xff800014L);
		createNamedU32("PCR", 0xff800018L);
		createNamedU32("RTCSR", 0xff80001cL);
		createNamedU32("RTCNT", 0xff800020L);
		createNamedU32("RTCOR", 0xff800024L);
		createNamedU32("RFCR", 0xff800028L);
		createNamedU32("PCTRA", 0xff80002cL);
		createNamedU32("PDTRA", 0xff800030L);
		createNamedU32("PCTRB", 0xff800040L);
		createNamedU32("PDTRB", 0xff800044L);
		createNamedU32("GPIOIC", 0xff800048L);
		createNamedU32("SDMR2", 0xff900000L);
		createNamedU32("SDMR3", 0xff940000L);
		createNamedU32("SAR0", 0xffa00000L);
		createNamedU32("DAR0", 0xffa00004L);
		createNamedU32("DMATCR0", 0xffa00008L);
		createNamedU32("CHCR0", 0xffa0000cL);
		createNamedU32("SAR1", 0xffa00010L);
		createNamedU32("DAR1", 0xffa00014L);
		createNamedU32("DMATCR1", 0xffa00018L);
		createNamedU32("CHCR1", 0xffa0001cL);
		createNamedU32("SAR2", 0xffa00020L);
		createNamedU32("DAR2", 0xffa00024L);
		createNamedU32("DMATCR2", 0xffa00028L);
		createNamedU32("CHCR2", 0xffa0002cL);
		createNamedU32("SAR3", 0xffa00030L);
		createNamedU32("DAR3", 0xffa00034L);
		createNamedU32("DMATCR3", 0xffa00038L);
		createNamedU32("CHCR3", 0xffa0003cL);
		createNamedU32("DMAOR", 0xffa00040L);
		createNamedU32("SAR4", 0xffa00050L);
		createNamedU32("DAR4", 0xffa00054L);
		createNamedU32("DMATCR4", 0xffa00058L);
		createNamedU32("CHCR4", 0xffa0005cL);
		createNamedU32("SAR5", 0xffa00060L);
		createNamedU32("DAR5", 0xffa00064L);
		createNamedU32("DMATCR5", 0xffa00068L);
		createNamedU32("CHCR5", 0xffa0006cL);
		createNamedU32("SAR6", 0xffa00070L);
		createNamedU32("DAR6", 0xffa00074L);
		createNamedU32("DMATCR6", 0xffa00078L);
		createNamedU32("CHCR6", 0xffa0007cL);
		createNamedU32("SAR7", 0xffa00080L);
		createNamedU32("DAR7", 0xffa00084L);
		createNamedU32("DMATCR7", 0xffa00088L);
		createNamedU32("CHCR7", 0xffa0008cL);
		createNamedU32("FRQCR", 0xffc00000L);
		createNamedU32("STBCR", 0xffc00004L);
		createNamedU32("WTCNT", 0xffc00008L);
		createNamedU32("WTCSR", 0xffc0000cL);
		createNamedU32("STBCR2", 0xffc00010L);
		createNamedU32("R64CNT", 0xffc80000L);
		createNamedU32("RSECCNT", 0xffc80004L);
		createNamedU32("RMINCNT", 0xffc80008L);
		createNamedU32("RHRCNT", 0xffc8000cL);
		createNamedU32("RWKCNT", 0xffc80010L);
		createNamedU32("RDAYCNT", 0xffc80014L);
		createNamedU32("RMONCNT", 0xffc80018L);
		createNamedU32("RYRCNT", 0xffc8001cL);
		createNamedU32("RSECAR", 0xffc80020L);
		createNamedU32("RMINAR", 0xffc80024L);
		createNamedU32("RHRAR", 0xffc80028L);
		createNamedU32("RWKAR", 0xffc8002cL);
		createNamedU32("RDAYAR", 0xffc80030L);
		createNamedU32("RMONAR", 0xffc80034L);
		createNamedU32("RCR1", 0xffc80038L);
		createNamedU32("RCR2", 0xffc8003cL);
		createNamedU32("RCR3", 0xffc80050L);
		createNamedU32("RYRAR", 0xffc80054L);
		createNamedU32("ICR", 0xffd00000L);
		createNamedU32("IPRA", 0xffd00004L);
		createNamedU32("IPRB", 0xffd00008L);
		createNamedU32("IPRC", 0xffd0000cL);
		createNamedU32("IPRD", 0xffd00010L);
		createNamedU32("INTPRI00", 0xfe080000L);
		createNamedU32("INTREQ00", 0xfe080020L);
		createNamedU32("INTMSK00", 0xfe080040L);
		createNamedU32("INTMSKCLR00", 0xfe080060L);
		createNamedU32("CLKSTP00", 0xfe0a0000L);
		createNamedU32("CLKSTPCLR00", 0xfe0a0008L);
		createNamedU32("TOCR", 0xffd80000L);
		createNamedU32("TSTR", 0xffd80004L);
		createNamedU32("TCOR0", 0xffd80008L);
		createNamedU32("TCNT0", 0xffd8000cL);
		createNamedU32("TCR0", 0xffd80010L);
		createNamedU32("TCOR1", 0xffd80014L);
		createNamedU32("TCNT1", 0xffd80018L);
		createNamedU32("TCR1", 0xffd8001cL);
		createNamedU32("TCOR2", 0xffd80020L);
		createNamedU32("TCNT2", 0xffd80024L);
		createNamedU32("TCR2", 0xffd80028L);
		createNamedU32("TCPR2", 0xffd8002cL);
		createNamedU32("TSTR2", 0xfe100004L);
		createNamedU32("TCOR3", 0xfe100008L);
		createNamedU32("TCNT3", 0xfe10000cL);
		createNamedU32("TCR3", 0xfe100010L);
		createNamedU32("TCOR4", 0xfe100014L);
		createNamedU32("TCNT4", 0xfe100018L);
		createNamedU32("TCR4", 0xfe10001cL);
		createNamedU32("SCSMR1", 0xffe00000L);
		createNamedU32("SCBRR1", 0xffe00004L);
		createNamedU32("SCSCR1", 0xffe00008L);
		createNamedU32("SCTDR1", 0xffe0000cL);
		createNamedU32("SCSSR1", 0xffe00010L);
		createNamedU32("SCRDR1", 0xffe00014L);
		createNamedU32("SCSCMR1", 0xffe00018L);
		createNamedU32("SCSPTR1", 0xffe0001cL);
		createNamedU32("SCSMR2", 0xffe80000L);
		createNamedU32("SCBRR2", 0xffe80004L);
		createNamedU32("SCSCR2", 0xffe80008L);
		createNamedU32("SCFTDR2", 0xffe8000cL);
		createNamedU32("SCFSR2", 0xffe80010L);
		createNamedU32("SCFRDR2", 0xffe80014L);
		createNamedU32("SCFCR2", 0xffe80018L);
		createNamedU32("SCFDR2", 0xffe8001cL);
		createNamedU32("SCSPTR2", 0xffe80020L);
		createNamedU32("SCLSR2", 0xffe80024L);
		createNamedU32("SDIR", 0xfff00000L);
		createNamedU32("SDDR", 0xfff00008L);
		createNamedU32("SDINT", 0xfff00014L);
	}

	private void setupHWMMIO() {
		createBlock("HW MMIO", 0xa05f_0000, 0x1_0000, true, true, false);

		createNamedU32("ID", 0xa05f8000);
		createNamedU32("REVISION", 0xa05f8004);
		createNamedU32("SOFTRESET", 0xa05f8008);
		createNamedU32("STARTRENDER", 0xa05f8014);
		createNamedU32("TEST_SELECT", 0xa05f8018);
		createNamedU32("PARAM_BASE", 0xa05f8020);
		createNamedU32("REGION_BASE", 0xa05f802c);
		createNamedU32("SPAN_SORT_CFG", 0xa05f8030);
		createNamedU32("VO_BORDER_COL", 0xa05f8040);
		createNamedU32("FB_R_CTRL", 0xa05f8044);
		createNamedU32("FB_W_CTRL", 0xa05f8048);
		createNamedU32("FB_W_LINESTRIDE", 0xa05f804c);
		createNamedU32("FB_R_SOF1", 0xa05f8050);
		createNamedU32("FB_R_SOF2", 0xa05f8054);
		createNamedU32("FB_R_SIZE", 0xa05f805c);
		createNamedU32("FB_W_SOF1", 0xa05f8060);
		createNamedU32("FB_W_SOF2", 0xa05f8064);
		createNamedU32("FB_X_CLIP", 0xa05f8068);
		createNamedU32("FB_Y_CLIP", 0xa05f806c);
		createNamedU32("FPU_SHAD_SCALE", 0xa05f8074);
		createNamedU32("FPU_CULL_VAL", 0xa05f8078);
		createNamedU32("FPU_PARAM_CFG", 0xa05f807c);
		createNamedU32("HALF_OFFSET", 0xa05f8080);
		createNamedU32("FPU_PERP_VAL", 0xa05f8084);
		createNamedU32("ISP_BACKGND_D", 0xa05f8088);
		createNamedU32("ISP_BACKGND_T", 0xa05f808c);
		createNamedU32("ISP_FEED_CFG", 0xa05f8098);
		createNamedU32("SDRAM_REFRESH", 0xa05f80a0);
		createNamedU32("SDRAM_ARB_CFG", 0xa05f80a4);
		createNamedU32("SDRAM_CFG", 0xa05f80a8);
		createNamedU32("FOG_COL_RAM", 0xa05f80b0);
		createNamedU32("FOG_COL_VERT", 0xa05f80b4);
		createNamedU32("FOG_DENSITY", 0xa05f80b8);
		createNamedU32("FOG_CLAMP_MAX", 0xa05f80bc);
		createNamedU32("FOG_CLAMP_MIN", 0xa05f80c0);
		createNamedU32("SPG_TRIGGER_POS", 0xa05f80c4);
		createNamedU32("SPG_HBLANK_INT", 0xa05f80c8);
		createNamedU32("SPG_VBLANK_INT", 0xa05f80cc);
		createNamedU32("SPG_CONTROL", 0xa05f80d0);
		createNamedU32("SPG_HBLANK", 0xa05f80d4);
		createNamedU32("SPG_LOAD", 0xa05f80d8);
		createNamedU32("SPG_VBLANK", 0xa05f80dc);
		createNamedU32("SPG_WIDTH", 0xa05f80e0);
		createNamedU32("TEXT_CONTROL", 0xa05f80e4);
		createNamedU32("VO_CONTROL", 0xa05f80e8);
		createNamedU32("VO_STARTX", 0xa05f80ec);
		createNamedU32("VO_STARTY", 0xa05f80f0);
		createNamedU32("SCALER_CTL", 0xa05f80f4);
		createNamedU32("PAL_RAM_CTRL", 0xa05f8108);
		createNamedU32("SPG_STATUS", 0xa05f810c);
		createNamedU32("FB_BURSTCTRL", 0xa05f8110);
		createNamedU32("FB_C_SOF", 0xa05f8114);
		createNamedU32("Y_COEFF", 0xa05f8118);
		createNamedU32("PT_ALPHA_REF", 0xa05f811c);
		createNamedU32("TA_OL_BASE", 0xa05f8124);
		createNamedU32("TA_ISP_BASE", 0xa05f8128);
		createNamedU32("TA_OL_LIMIT", 0xa05f812c);
		createNamedU32("TA_ISP_LIMIT", 0xa05f8130);
		createNamedU32("TA_NEXT_OPB", 0xa05f8134);
		createNamedU32("TA_ITP_CURRENT", 0xa05f8138);
		createNamedU32("TA_GLOB_TILE_CLIP", 0xa05f813c);
		createNamedU32("TA_ALLOC_CTRL", 0xa05f8140);
		createNamedU32("TA_LIST_INIT", 0xa05f8144);
		createNamedU32("TA_YUV_TEX_BASE", 0xa05f8148);
		createNamedU32("TA_YUV_TEX_CTRL", 0xa05f814c);
		createNamedU32("TA_YUV_TEX_CNT", 0xa05f8150);
		createNamedU32("TA_LIST_CONT", 0xa05f8160);
		createNamedU32("TA_NEXT_OPB_INIT", 0xa05f8164);
		createNamedU32("SB_C2DSTAT", 0xa05f6800);
		createNamedU32("SB_C2DLEN", 0xa05f6804);
		createNamedU32("SB_C2DST", 0xa05f6808);
		createNamedU32("SB_SDSTAW", 0xa05f6810);
		createNamedU32("SB_SDBAAW", 0xa05f6814);
		createNamedU32("SB_SDWLT", 0xa05f6818);
		createNamedU32("SB_SDLAS", 0xa05f681c);
		createNamedU32("SB_SDST", 0xa05f6820);
		createNamedU32("SB_DBREQM", 0xa05f6840);
		createNamedU32("SB_BAVLWC", 0xa05f6844);
		createNamedU32("SB_C2DPRYC", 0xa05f6848);
		createNamedU32("SB_C2DMAXL", 0xa05f684c);
		createNamedU32("SB_TFREM", 0xa05f6880);
		createNamedU32("SB_LMMODE0", 0xa05f6884);
		createNamedU32("SB_LMMODE1", 0xa05f6888);
		createNamedU32("SB_FFST", 0xa05f688c);
		createNamedU32("SB_SFRES", 0xa05f6890);
		createNamedU32("SB_SBREV", 0xa05f689c);
		createNamedU32("SB_RBSPLT", 0xa05f68a0);
		createNamedU32("SB_ISTNRM", 0xa05f6900);
		createNamedU32("SB_ISTEXT", 0xa05f6904);
		createNamedU32("SB_ISTERR", 0xa05f6908);
		createNamedU32("SB_IML2NRM", 0xa05f6910);
		createNamedU32("SB_IML2EXT", 0xa05f6914);
		createNamedU32("SB_IML2ERR", 0xa05f6918);
		createNamedU32("SB_IML4NRM", 0xa05f6920);
		createNamedU32("SB_IML4EXT", 0xa05f6924);
		createNamedU32("SB_IML4ERR", 0xa05f6928);
		createNamedU32("SB_IML6NRM", 0xa05f6930);
		createNamedU32("SB_IML6EXT", 0xa05f6934);
		createNamedU32("SB_IML6ERR", 0xa05f6938);
		createNamedU32("SB_PDTNRM", 0xa05f6940);
		createNamedU32("SB_PDTEXT", 0xa05f6944);
		createNamedU32("SB_G2DTNRM", 0xa05f6950);
		createNamedU32("SB_G2DTEXT", 0xa05f6954);
		createNamedU32("SB_MDSTAR", 0xa05f6c04);
		createNamedU32("SB_MDTSEL", 0xa05f6c10);
		createNamedU32("SB_MDEN", 0xa05f6c14);
		createNamedU32("SB_MDST", 0xa05f6c18);
		createNamedU32("SB_MSYS", 0xa05f6c80);
		createNamedU32("SB_MST", 0xa05f6c84);
		createNamedU32("SB_MSHTCL", 0xa05f6c88);
		createNamedU32("SB_MDAPRO", 0xa05f6c8c);
		createNamedU32("SB_MMSEL", 0xa05f6ce8);
		createNamedU32("SB_MTXDAD", 0xa05f6cf4);
		createNamedU32("SB_MRXDAD", 0xa05f6cf8);
		createNamedU32("SB_MRXDBD", 0xa05f6cfc);
		createNamedU32("GD_ALTSTAT_DEVCTRL", 0xa05f7018);
		createNamedU32("GD_DATA", 0xa05f7080);
		createNamedU32("GD_ERROR_FEATURES", 0xa05f7084);
		createNamedU32("GD_INTREASON", 0xa05f7088);
		createNamedU32("GD_SECTNUM", 0xa05f708c);
		createNamedU32("GD_BYCTLLO", 0xa05f7090);
		createNamedU32("GD_BYCTLHI", 0xa05f7094);
		createNamedU32("GD_DRVSEL", 0xa05f7098);
		createNamedU32("GD_STATUS_COMMAND", 0xa05f709c);
		createNamedU32("SB_GDSTAR", 0xa05f7404);
		createNamedU32("SB_GDLEN", 0xa05f7408);
		createNamedU32("SB_GDDIR", 0xa05f740c);
		createNamedU32("SB_GDEN", 0xa05f7414);
		createNamedU32("SB_GDST", 0xa05f7418);
		createNamedU32("SB_G1RRC", 0xa05f7480);
		createNamedU32("SB_G1RWC", 0xa05f7484);
		createNamedU32("SB_G1FRC", 0xa05f7488);
		createNamedU32("SB_G1FWC", 0xa05f748c);
		createNamedU32("SB_G1CRC", 0xa05f7490);
		createNamedU32("SB_G1CWC", 0xa05f7494);
		createNamedU32("SB_G1GDRC", 0xa05f74a0);
		createNamedU32("SB_G1GDWC", 0xa05f74a4);
		createNamedU32("SB_G1SYSM", 0xa05f74b0);
		createNamedU32("SB_G1CRDYC", 0xa05f74b4);
		createNamedU32("SB_GDAPRO", 0xa05f74b8);
		createNamedU32("SB_GDSTARD", 0xa05f74f4);
		createNamedU32("SB_GDLEND", 0xa05f74f8);
		createNamedU32("SB_ADSTAG", 0xa05f7800);
		createNamedU32("SB_ADSTAR", 0xa05f7804);
		createNamedU32("SB_ADLEN", 0xa05f7808);
		createNamedU32("SB_ADDIR", 0xa05f780c);
		createNamedU32("SB_ADTSEL", 0xa05f7810);
		createNamedU32("SB_ADEN", 0xa05f7814);
		createNamedU32("SB_ADST", 0xa05f7818);
		createNamedU32("SB_ADSUSP", 0xa05f781c);
		createNamedU32("SB_E1STAG", 0xa05f7820);
		createNamedU32("SB_E1STAR", 0xa05f7824);
		createNamedU32("SB_E1LEN", 0xa05f7828);
		createNamedU32("SB_E1DIR", 0xa05f782c);
		createNamedU32("SB_E1TSEL", 0xa05f7830);
		createNamedU32("SB_E1EN", 0xa05f7834);
		createNamedU32("SB_E1ST", 0xa05f7838);
		createNamedU32("SB_E1SUSP", 0xa05f783c);
		createNamedU32("SB_E2STAG", 0xa05f7840);
		createNamedU32("SB_E2STAR", 0xa05f7844);
		createNamedU32("SB_E2LEN", 0xa05f7848);
		createNamedU32("SB_E2DIR", 0xa05f784c);
		createNamedU32("SB_E2TSEL", 0xa05f7850);
		createNamedU32("SB_E2EN", 0xa05f7854);
		createNamedU32("SB_E2ST", 0xa05f7858);
		createNamedU32("SB_E2SUSP", 0xa05f785c);
		createNamedU32("SB_DDSTAG", 0xa05f7860);
		createNamedU32("SB_DDSTAR", 0xa05f7864);
		createNamedU32("SB_DDLEN", 0xa05f7868);
		createNamedU32("SB_DDDIR", 0xa05f786c);
		createNamedU32("SB_DDTSEL", 0xa05f7870);
		createNamedU32("SB_DDEN", 0xa05f7874);
		createNamedU32("SB_DDST", 0xa05f7878);
		createNamedU32("SB_DDSUSP", 0xa05f787c);
		createNamedU32("SB_G2ID", 0xa05f7880);
		createNamedU32("SB_G2DSTO", 0xa05f7890);
		createNamedU32("SB_G2TRTO", 0xa05f7894);
		createNamedU32("SB_G2MDMTO", 0xa05f7898);
		createNamedU32("SB_G2MDMW", 0xa05f789c);
		createNamedU32("SB_G2APRO", 0xa05f78bc);
		createNamedU32("SB_ADSTAGD", 0xa05f78c0);
		createNamedU32("SB_ADSTARD", 0xa05f78c4);
		createNamedU32("SB_ADLEND", 0xa05f78c8);
		createNamedU32("SB_E1STAGD", 0xa05f78d0);
		createNamedU32("SB_E1STARD", 0xa05f78d4);
		createNamedU32("SB_E1LEND", 0xa05f78d8);
		createNamedU32("SB_E2STAGD", 0xa05f78e0);
		createNamedU32("SB_E2STARD", 0xa05f78e4);
		createNamedU32("SB_E2LEND", 0xa05f78e8);
		createNamedU32("SB_DDSTAGD", 0xa05f78f0);
		createNamedU32("SB_DDSTARD", 0xa05f78f4);
		createNamedU32("SB_DDLEND", 0xa05f78f8);
		createNamedU32("SB_PDSTAP", 0xa05f7c00);
		createNamedU32("SB_PDSTAR", 0xa05f7c04);
		createNamedU32("SB_PDLEN", 0xa05f7c08);
		createNamedU32("SB_PDDIR", 0xa05f7c0c);
		createNamedU32("SB_PDTSEL", 0xa05f7c10);
		createNamedU32("SB_PDEN", 0xa05f7c14);
		createNamedU32("SB_PDST", 0xa05f7c18);
		createNamedU32("SB_PDAPRO", 0xa05f7c80);
		createNamedU32("SB_PDSTAPD", 0xa05f7cf0);
		createNamedU32("SB_PDSTARD", 0xa05f7cf4);
		createNamedU32("SB_PDLEND", 0xa05f7cf8);
	}

	private void markReadOnlyAsConstant(final Symbol sym) {
		// Check if the symbol has only Read-type references, i.e. it's never modified
		boolean all_read = true;
		for (final var ref : sym.getReferences()) {
			if (!ref.getReferenceType().isRead()) {
				all_read = false;
				break;
			}
		}
		if (all_read) {
			final Data data = getDataAt(sym.getAddress());
			if (data != null) {
				MutabilitySettingsDefinition.DEF.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
			}
		}
	}

	private void renameSDKFunctions(final Symbol sym) {
		CRC32 crc32 = new CRC32();
		for (SDKSymbol sdk_symbol : sdk_symbols.values()) {
			try {
				byte[] bytes = getBytes(sym.getAddress(), (int) sdk_symbol.total_length);
				crc32.reset();
				crc32.update(bytes);
				if (crc32.getValue() == sdk_symbol.total_hash) {
					println(String.format("Function %s looks like %s (Length %d)", sym.getName(), sdk_symbol.name,
							sdk_symbol.total_length));
					sym.setName(sdk_symbol.name, SourceType.USER_DEFINED);
				}
			} catch (Exception e) {
				println(e.toString());
			}
		}

	}

	public class SDKSymbol {
		public String name;
		public long total_hash;
		public long total_length;

		public SDKSymbol(long total_hash, long total_length, String name) {
			this.name = name;
			this.total_hash = total_hash;
			this.total_length = total_length;
		}
	}

	private void loadSDKSymbols(final String symbolDataPath) {
		this.sdk_symbols.clear();
		try {
			BufferedReader reader = new BufferedReader(new FileReader(symbolDataPath));
			String line = reader.readLine();
			while (line != null) {
				String symbol[] = line.split("@");

				final Long total_hash = Long.decode(symbol[0]);
				final Long total_length = Long.parseLong(symbol[1]);
				final String symbolName = String.format("%s.%s.%s", symbol[2], symbol[3], symbol[4]);

				if (total_length > 30) {
					final SDKSymbol sdk_symbol = new SDKSymbol(total_hash, total_length, symbolName);
					sdk_symbols.put(total_hash, sdk_symbol);
				}

				line = reader.readLine();
			}
			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		println("SDK symbols: " + sdk_symbols.size());
	}

	@Override
	protected void run() throws Exception {

		// Load SDK symbols from text file
		this.sdk_symbols = new HashMap<>();

		// loadSDKSymbols("/tmp/sdk-symbols.txt");

		// Load symbols from script directory
		ResourceFile scriptDir  = null;
		ResourceFile scriptFile = getSourceFile();
		if (scriptFile != null)
			scriptDir  = scriptFile.getParentFile();
		if (scriptDir == null) {
			printerr("Could not determine the script's source file path.");
		} else {
			loadSDKSymbols(scriptDir + "/sdk-symbols.txt");
        }

		// Setup SH4 MMIO block and registers
		setupSH4MMIO();

		// Setup Holly/PVR MMIO block and registers
		setupHWMMIO();

		// NOTE: You must have run analysis already for the below to do anything!

		// 1) Rename functions that seem to match SDK symbols
		// 2) Mark any symbol which is only read from as constant.
		final var symbols = currentProgram.getSymbolTable().getAllSymbols(true);
		for (final var sym : symbols) {

			// Only do this analysis on RAM
			final long symbolAddress = sym.getProgramLocation().getByteAddress().getUnsignedOffset();

			final long MEM_START = 0x8c00_0000L;
			final long MEM_END = MEM_START + 16 * 1024 * 1024L;
			if (symbolAddress > MEM_START || symbolAddress < MEM_END) {
				final String symName = sym.getName();
				if (symName.startsWith("FUN_")) {
					renameSDKFunctions(sym);
				} else {
					markReadOnlyAsConstant(sym);
				}
			}

		}
	}
}

