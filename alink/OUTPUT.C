#include "ALINK.H"

static unsigned char defaultStub[] = {
    0x4D, 0x5A, 0x6C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x11, 0x00, 0xFF, 0xFF, 0x03, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x00, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x72, 0x65, 0x71, 0x75, 0x69,
    0x72, 0x65, 0x73, 0x20, 0x57, 0x69, 0x6E, 0x33, 0x32, 0x0D, 0x0A, 0x24};

static UINT defaultStubSize = sizeof(defaultStub);

static long EnsureAbsolutePublicSegment(UINT value)
{
    UINT i;

    for (i = 0; i < segcount; i++)
    {
	if (!seglist[i])
	    continue;
	if ((seglist[i]->attr & SEG_ALIGN) != SEG_ABS)
	    continue;
	if (seglist[i]->base != value)
	    continue;
	return i;
    }

    seglist = (PPSEG)checkRealloc(seglist, (segcount + 1) * sizeof(PSEG));
    seglist[segcount] = (PSEG)checkMalloc(sizeof(SEG));
    memset(seglist[segcount], 0, sizeof(SEG));
    seglist[segcount]->nameindex = -1;
    seglist[segcount]->classindex = -1;
    seglist[segcount]->overlayindex = -1;
    seglist[segcount]->orderindex = -1;
    seglist[segcount]->attr = SEG_PRIVATE | SEG_ABS;
    seglist[segcount]->absframe = value >> 4;
    seglist[segcount]->absofs = value & 0xf;
    seglist[segcount]->base = value;
    return segcount++;
}

static PCHAR GetCOMFallbackEXEName(PCHAR outname)
{
    int i;
    PCHAR exename;

    exename = checkMalloc(strlen(outname) + 5);
    strcpy(exename, outname);
    i = strlen(exename) - 1;
    while ((i >= 0) && (exename[i] != '.') && !IS_PATH_CHAR(exename[i]) && (exename[i] != ':'))
    {
	i--;
    }
    if ((i >= 0) && (exename[i] == '.') && !stricmp(exename + i, ".com"))
    {
	strcpy(exename + i, ".exe");
    }
    else if ((i < 0) || (exename[i] != '.'))
    {
	strcat(exename, ".exe");
    }
    return exename;
}

void GetFixupTarget(PRELOC r, long *bseg, UINT *tofs, int isFlat)
{
    long baseseg = -1;
    long targseg = -1;
    UINT targofs = 0;

    r->outputPos = seglist[r->segnum]->base + r->ofs;
    switch (r->ftype)
    {
    case REL_SEGFRAME:
    case REL_LILEFRAME:
	baseseg = r->frame;
	break;
    case REL_GRPFRAME:
	baseseg = grplist[r->frame]->segnum;
	break;
    case REL_EXTFRAME:
	switch (externs[r->frame].flags)
	{
	case EXT_MATCHEDPUBLIC:
	    if (!externs[r->frame].pubdef)
	    {
		printf("Reloc:Unmatched extern %s\n", externs[r->frame].name);
		errcount++;
		break;
	    }

	    if (externs[r->frame].pubdef->segnum < 0)
	    {
		baseseg = EnsureAbsolutePublicSegment(externs[r->frame].pubdef->ofs);
	    }
	    else
	    {
		baseseg = externs[r->frame].pubdef->segnum;
	    }
	    break;
	case EXT_MATCHEDIMPORT:
	    baseseg = impdefs[externs[r->frame].impnum].segnum;
	    break;
	default:
	    printf("Reloc:Unmatched external referenced in frame\n");
	    errcount++;
	    break;
	}
	break;
    default:
	printf("Reloc:Unsupported FRAME type %i\n", r->ftype);
	errcount++;
    }
    if (baseseg < 0)
    {
	printf("Undefined base seg\n");
	exit(1);
    } /* this is a fix for TASM FLAT model, where FLAT group has no segments */

    switch (r->ttype)
    {
    case REL_EXTDISP:
	switch (externs[r->target].flags)
	{
	case EXT_MATCHEDPUBLIC:
	    if (!externs[r->target].pubdef)
	    {
		printf("Reloc:Unmatched extern %s\n", externs[r->frame].name);
		errcount++;
		break;
	    }

	    if (externs[r->target].pubdef->segnum < 0)
	    {
		targseg = EnsureAbsolutePublicSegment(externs[r->target].pubdef->ofs);
		targofs = 0;
	    }
	    else
	    {
		targseg = externs[r->target].pubdef->segnum;
		targofs = externs[r->target].pubdef->ofs;
	    }
	    break;
	case EXT_MATCHEDIMPORT:
	    targseg = impdefs[externs[r->target].impnum].segnum;
	    targofs = impdefs[externs[r->target].impnum].ofs;
	    break;
	default:
	    printf("Reloc:Unmatched external referenced in frame\n");
	    errcount++;
	    break;
	}
	targofs += r->disp;
	break;
    case REL_EXTONLY:
	switch (externs[r->target].flags)
	{
	case EXT_MATCHEDPUBLIC:
	    if (!externs[r->target].pubdef)
	    {
		printf("Reloc:Unmatched extern %s\n", externs[r->target].name);
		errcount++;
		break;
	    }

	    if (externs[r->target].pubdef->segnum < 0)
	    {
		targseg = EnsureAbsolutePublicSegment(externs[r->target].pubdef->ofs);
		targofs = 0;
	    }
	    else
	    {
		targseg = externs[r->target].pubdef->segnum;
		targofs = externs[r->target].pubdef->ofs;
	    }
	    break;
	case EXT_MATCHEDIMPORT:
	    targseg = impdefs[externs[r->target].impnum].segnum;
	    targofs = impdefs[externs[r->target].impnum].ofs;
	    break;
	default:
	    printf("Reloc:Unmatched external referenced in frame\n");
	    errcount++;
	    break;
	}
	break;
    case REL_SEGONLY:
	targseg = r->target;
	targofs = 0;
	break;
    case REL_SEGDISP:
	targseg = r->target;
	targofs = r->disp;
	break;
    case REL_GRPONLY:
	targseg = grplist[r->target]->segnum;
	targofs = 0;
	break;
    case REL_GRPDISP:
	targseg = grplist[r->target]->segnum;
	targofs = r->disp;
	break;
    default:
	printf("Reloc:Unsupported TARGET type %i\n", r->ttype);
	errcount++;
    }
    if (targseg < 0)
    {
	printf("undefined seg\n");
	exit(1);
    }
    if ((!errcount) && (!seglist[targseg]))
    {
	printf("Reloc: no target segment\n");

	errcount++;
    }
    if ((!errcount) && (!seglist[baseseg]))
    {
	printf("reloc: no base segment\n");

	errcount++;
    }

    if (!errcount)
    {
	/*
		if(((seglist[targseg]->attr&SEG_ALIGN)!=SEG_ABS) &&
		   ((seglist[baseseg]->attr&SEG_ALIGN)!=SEG_ABS))
		{
		    if(seglist[baseseg]->base>seglist[targseg]->base)
		    {
			printf("Reloc:Negative base address\n");
			errcount++;
		    }
		    targofs+=seglist[targseg]->base-seglist[baseseg]->base;
		}
	*/
	if ((seglist[baseseg]->attr & SEG_ALIGN) == SEG_ABS)
	{
	    printf("Warning: Reloc frame is absolute segment\n");
	    targseg = baseseg;
	}
	else if ((seglist[targseg]->attr & SEG_ALIGN) == SEG_ABS)
	{
	    printf("Warning: Reloc target is in absolute segment\n");
	    targseg = baseseg;
	}
	if (!isFlat || ((seglist[baseseg]->attr & SEG_ALIGN) == SEG_ABS))
	{
	    if (seglist[baseseg]->base > (seglist[targseg]->base + targofs))
	    {
		printf("Error: target address out of frame\n");
		printf("Base=%08X,target=%08X\n", seglist[baseseg]->base,
		       seglist[targseg]->base + targofs);
		errcount++;
	    }
	    targofs += seglist[targseg]->base - seglist[baseseg]->base;
	    *bseg = baseseg;
	    *tofs = targofs;
	}
	else
	{
	    *bseg = -1;
	    *tofs = targofs + seglist[targseg]->base;
	}
    }
    else
    {
	printf("relocation error occurred\n");
	*bseg = 0;
	*tofs = 0;
    }
}

void OutputCOMfile(PCHAR outname)
{
    long i, j;
    UINT started;
    UINT lastout;
    long targseg;
    UINT targofs;
    FILE *outfile;
    unsigned short temps;
    unsigned long templ;

    if (impsreq)
    {
	ReportError(ERR_ILLEGAL_IMPORTS);
    }

    errcount = 0;
    if (gotstart)
    {
	GetFixupTarget(&startaddr, &startaddr.segnum, &startaddr.ofs, FALSE);
	if (errcount)
	{
	    printf("Invalid start address record\n");
	    exit(1);
	}

	if ((startaddr.ofs + seglist[startaddr.segnum]->base) != 0x100)
	{
	    printf("Warning, start address not 0100h as required for COM file\n");
	}
    }
    else
    {
	printf("Warning, no entry point specified\n");
    }

    for (i = 0; i < fixcount; i++)
    {
	GetFixupTarget(relocs[i], &targseg, &targofs, FALSE);
	switch (relocs[i]->rtype)
	{
	case FIX_BASE:
	case FIX_PTR1616:
	case FIX_PTR1632:
	    if ((seglist[targseg]->attr & SEG_ALIGN) != SEG_ABS)
	    {
		PCHAR exename;

		exename = GetCOMFallbackEXEName(outname);
		printf("Warning, COM output needs runtime segment relocations; writing EXE file %s\n",
		       exename);
		OutputEXEfile(exename);
		free(exename);
		return;
	    }
	    break;
	default:
	    break;
	}
    }

    for (i = 0; i < fixcount; i++)
    {
	GetFixupTarget(relocs[i], &targseg, &targofs, FALSE);
	switch (relocs[i]->rtype)
	{
	case FIX_BASE:
	case FIX_PTR1616:
	case FIX_PTR1632:
	    if ((seglist[targseg]->attr & SEG_ALIGN) != SEG_ABS)
	    {
		printf("Reloc %li:Segment selector relocations are not supported in COM files\n",
		       i);
		errcount++;
	    }
	    else
	    {
		j = relocs[i]->ofs;
		if (relocs[i]->rtype == FIX_PTR1616)
		{
		    if (targofs > 0xffff)
		    {
			printf("Relocs %li:Offset out of range\n", i);
			errcount++;
		    }
		    temps = seglist[relocs[i]->segnum]->data[j];
		    temps += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		    temps += targofs;
		    temps += seglist[targseg]->base & 0xf; /* non-para seg */
		    seglist[relocs[i]->segnum]->data[j] = temps & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 1] = (temps >> 8) & 0xff;
		    j += 2;
		}
		else if (relocs[i]->rtype == FIX_PTR1632)
		{
		    templ = seglist[relocs[i]->segnum]->data[j];
		    templ += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		    templ += seglist[relocs[i]->segnum]->data[j + 2] << 16;
		    templ += seglist[relocs[i]->segnum]->data[j + 3] << 24;
		    templ += targofs;
		    templ += seglist[targseg]->base & 0xf; /* non-para seg */
		    seglist[relocs[i]->segnum]->data[j] = templ & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 1] = (templ >> 8) & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 2] = (templ >> 16) & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 3] = (templ >> 24) & 0xff;
		    j += 4;
		}
		temps = seglist[relocs[i]->segnum]->data[j];
		temps += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		temps += seglist[targseg]->absframe;
		seglist[relocs[i]->segnum]->data[j] = temps & 0xff;
		seglist[relocs[i]->segnum]->data[j + 1] = (temps >> 8) & 0xff;
	    }
	    break;
	case FIX_OFS32:
	case FIX_OFS32_2:
	    templ = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] << 16;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] << 24;
	    templ += targofs;
	    templ += seglist[targseg]->base & 0xf; /* non-para seg */
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = templ & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (templ >> 8) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] = (templ >> 16) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] = (templ >> 24) & 0xff;
	    break;
	case FIX_OFS16:
	case FIX_OFS16_2:
	    if (targofs > 0xffff)
	    {
		printf("Relocs %li:Offset out of range\n", i);
		errcount++;
	    }
	    temps = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
	    temps += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
	    temps += targofs;
	    temps += seglist[targseg]->base & 0xf; /* non-para seg */
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = temps & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (temps >> 8) & 0xff;
	    break;
	case FIX_LBYTE:
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] += targofs & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] +=
		seglist[targseg]->base & 0xf; /* non-para seg */
	    break;
	case FIX_HBYTE:
	    templ = targofs + (seglist[targseg]->base & 0xf); /* non-para seg */
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] += (templ >> 8) & 0xff;
	    break;
	case FIX_SELF_LBYTE:
	    if ((seglist[targseg]->attr & SEG_ALIGN) == SEG_ABS)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = seglist[targseg]->base + targofs;
		j -= seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 1;
		if ((j < -128) || (j > 127))
		{
		    printf("Error: Reloc %li out of range\n", i);
		}
		else
		{
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] += j;
		}
	    }
	    break;
	case FIX_SELF_OFS16:
	case FIX_SELF_OFS16_2:
	    if ((seglist[targseg]->attr & SEG_ALIGN) == SEG_ABS)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = seglist[targseg]->base + targofs;
		j -= seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 2;
		if ((j < -32768) || (j > 32767))
		{
		    printf("Error: Reloc %li out of range\n", i);
		}
		else
		{
		    temps = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
		    temps += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
		    temps += j;
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = temps & 0xff;
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (temps >> 8) & 0xff;
		}
	    }
	    break;
	case FIX_SELF_OFS32:
	case FIX_SELF_OFS32_2:
	    if ((seglist[targseg]->attr & SEG_ALIGN) == SEG_ABS)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = seglist[targseg]->base + targofs;
		j -= seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 4;
		templ = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] << 16;
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] << 24;
		templ += j;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = templ & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (templ >> 8) & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] = (templ >> 16) & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] = (templ >> 24) & 0xff;
	    }
	    break;
	default:
	    printf("Reloc %li:Relocation type %i not supported\n", i, relocs[i]->rtype);
	    errcount++;
	}
    }

    if (errcount != 0)
    {
	exit(1);
    }
    outfile = fopen(outname, "wb");
    if (!outfile)
    {
	printf("Error writing to file %s\n", outname);
	exit(1);
    }

    started = lastout = 0;

    for (i = 0; i < outcount; i++)
    {
	if (outlist[i] && ((outlist[i]->attr & SEG_ALIGN) != SEG_ABS))
	{
	    if (started > outlist[i]->base)
	    {
		printf("Segment overlap\n");
		fclose(outfile);
		exit(1);
	    }
	    if (padsegments)
	    {
		while (started < outlist[i]->base)
		{
		    fputc(0, outfile);
		    started++;
		}
	    }
	    else
	    {
		started = outlist[i]->base;
	    }
	    for (j = 0; j < outlist[i]->length; j++)
	    {
		if (started >= 0x100)
		{
		    if (GetNbit(outlist[i]->datmask, j))
		    {
			for (; lastout < started; lastout++)
			{
			    fputc(0, outfile);
			}
			fputc(outlist[i]->data[j], outfile);
			lastout = started + 1;
		    }
		    else if (padsegments)
		    {
			fputc(0, outfile);
			lastout = started + 1;
		    }
		}
		else
		{
		    lastout = started + 1;
		    if (GetNbit(outlist[i]->datmask, j))
		    {
			printf("Warning - data at offset %08X (%s:%08lX) discarded\n", started,
			       namelist[outlist[i]->nameindex], j);
		    }
		}
		started++;
	    }
	}
    }

    fclose(outfile);
}

void OutputEXEfile(PCHAR outname)
{
    long i, j;
    UINT started, lastout;
    long targseg;
    UINT targofs;
    FILE *outfile;
    PUCHAR headbuf;
    long relcount;
    int gotstack;
    UINT totlength;
    unsigned short temps;
    unsigned long templ;

    if (impsreq)
    {
	ReportError(ERR_ILLEGAL_IMPORTS);
    }

    errcount = 0;
    gotstack = 0;
    headbuf = checkMalloc(0x40 + 4 * fixcount);
    relcount = 0;

    for (i = 0; i < 0x40; i++)
    {
	headbuf[i] = 0;
    }

    headbuf[0x00] = 'M'; /* sig */
    headbuf[0x01] = 'Z';
    headbuf[0x0c] = maxalloc & 0xff;
    headbuf[0x0d] = maxalloc >> 8;
    headbuf[0x18] = 0x40;

    if (gotstart)
    {
	GetFixupTarget(&startaddr, &startaddr.segnum, &startaddr.ofs, FALSE);
	if (errcount)
	{
	    printf("Invalid start address record\n");
	    exit(1);
	}

	i = seglist[startaddr.segnum]->base;
	startaddr.ofs += i & 0xf;
	i >>= 4;
	if ((startaddr.ofs > 65535) || (i > 65535) ||
	    ((seglist[startaddr.segnum]->attr & SEG_ALIGN) == SEG_ABS))
	{
	    printf("Invalid start address\n");
	    errcount++;
	}
	else
	{
	    headbuf[0x14] = startaddr.ofs & 0xff;
	    headbuf[0x15] = startaddr.ofs >> 8;

	    headbuf[0x16] = i & 0xff;
	    headbuf[0x17] = i >> 8;
	}
    }
    else
    {
	printf("Warning, no entry point specified\n");
    }

    totlength = 0;

    for (i = 0; i < outcount; i++)
    {
	if ((outlist[i]->attr & SEG_ALIGN) != SEG_ABS)
	{
	    totlength = outlist[i]->base + outlist[i]->length;
	    if ((outlist[i]->attr & SEG_COMBINE) == SEG_STACK)
	    {
		if (gotstack)
		{
		    printf("Internal error - stack segments not combined\n");
		    exit(1);
		}
		gotstack = 1;
		if ((outlist[i]->length > 65536) || (outlist[i]->length == 0))
		{
		    printf("SP value out of range\n");
		    errcount++;
		}
		if ((outlist[i]->base > 0xfffff) || ((outlist[i]->base & 0xf) != 0))
		{
		    printf("SS value out of range\n");
		    errcount++;
		}
		if (!errcount)
		{
		    headbuf[0x0e] = (outlist[i]->base >> 4) & 0xff;
		    headbuf[0x0f] = outlist[i]->base >> 12;
		    headbuf[0x10] = outlist[i]->length & 0xff;
		    headbuf[0x11] = (outlist[i]->length >> 8) & 0xff;
		}
	    }
	}
    }

    if (!gotstack)
    {
	printf("Warning - no stack\n");
    }

    for (i = 0; i < fixcount; i++)
    {
	GetFixupTarget(relocs[i], &targseg, &targofs, FALSE);
	switch (relocs[i]->rtype)
	{
	case FIX_BASE:
	case FIX_PTR1616:
	case FIX_PTR1632:
	    j = relocs[i]->ofs;
	    if (relocs[i]->rtype == FIX_PTR1616)
	    {
		if (targofs > 0xffff)
		{
		    printf("Relocs %li:Offset out of range\n", i);
		    errcount++;
		}
		temps = seglist[relocs[i]->segnum]->data[j];
		temps += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		temps += targofs;
		temps += seglist[targseg]->base & 0xf; /* non-para seg */
		seglist[relocs[i]->segnum]->data[j] = temps & 0xff;
		seglist[relocs[i]->segnum]->data[j + 1] = (temps >> 8) & 0xff;
		j += 2;
	    }
	    else if (relocs[i]->rtype == FIX_PTR1632)
	    {
		templ = seglist[relocs[i]->segnum]->data[j];
		templ += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		templ += seglist[relocs[i]->segnum]->data[j + 2] << 16;
		templ += seglist[relocs[i]->segnum]->data[j + 3] << 24;
		templ += targofs;
		templ += seglist[targseg]->base & 0xf; /* non-para seg */
		seglist[relocs[i]->segnum]->data[j] = templ & 0xff;
		seglist[relocs[i]->segnum]->data[j + 1] = (templ >> 8) & 0xff;
		seglist[relocs[i]->segnum]->data[j + 2] = (templ >> 16) & 0xff;
		seglist[relocs[i]->segnum]->data[j + 3] = (templ >> 24) & 0xff;
		j += 4;
	    }
	    if ((seglist[targseg]->attr & SEG_ALIGN) != SEG_ABS)
	    {
		if (seglist[targseg]->base > 0xfffff)
		{
		    printf("Relocs %li:Segment base out of range\n", i);
		    errcount++;
		}
		temps = seglist[relocs[i]->segnum]->data[j];
		temps += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		temps += (seglist[targseg]->base >> 4);
		seglist[relocs[i]->segnum]->data[j] = temps & 0xff;
		seglist[relocs[i]->segnum]->data[j + 1] = (temps >> 8) & 0xff;
		templ = seglist[relocs[i]->segnum]->base >> 4;
		headbuf[0x40 + relcount * 4 + 2] = templ & 0xff;
		headbuf[0x40 + relcount * 4 + 3] = (templ >> 8) & 0xff;
		templ = (seglist[relocs[i]->segnum]->base & 0xf) + j;
		headbuf[0x40 + relcount * 4] = (templ) & 0xff;
		headbuf[0x40 + relcount * 4 + 1] = (templ >> 8) & 0xff;
		relcount++;
	    }
	    else
	    {
		temps = seglist[relocs[i]->segnum]->data[j];
		temps += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		temps += seglist[targseg]->absframe;
		seglist[relocs[i]->segnum]->data[j] = temps & 0xff;
		seglist[relocs[i]->segnum]->data[j + 1] = (temps >> 8) & 0xff;
	    }
	    break;
	case FIX_OFS32:
	case FIX_OFS32_2:
	    templ = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] << 16;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] << 24;
	    templ += targofs;
	    templ += seglist[targseg]->base & 0xf; /* non-para seg */
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = templ & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (templ >> 8) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] = (templ >> 16) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] = (templ >> 24) & 0xff;
	    break;
	case FIX_OFS16:
	case FIX_OFS16_2:
	    if (targofs > 0xffff)
	    {
		printf("Relocs %li:Offset out of range\n", i);
		errcount++;
	    }
	    temps = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
	    temps += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
	    temps += targofs;
	    temps += seglist[targseg]->base & 0xf; /* non-para seg */
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = temps & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (temps >> 8) & 0xff;
	    break;
	case FIX_LBYTE:
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] += targofs & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] +=
		seglist[targseg]->base & 0xf; /* non-para seg */
	    break;
	case FIX_HBYTE:
	    templ = targofs + (seglist[targseg]->base & 0xf); /* non-para seg */
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] += (templ >> 8) & 0xff;
	    break;
	case FIX_SELF_LBYTE:
	    if ((seglist[targseg]->attr & SEG_ALIGN) == SEG_ABS)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = seglist[targseg]->base + targofs;
		j -= seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 1;
		if ((j < -128) || (j > 127))
		{
		    printf("Error: Reloc %li out of range\n", i);
		}
		else
		{
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] += j;
		}
	    }
	    break;
	case FIX_SELF_OFS16:
	case FIX_SELF_OFS16_2:
	    if ((seglist[targseg]->attr & SEG_ALIGN) == SEG_ABS)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = seglist[targseg]->base + targofs;
		j -= seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 2;
		if ((j < -32768) || (j > 32767))
		{
		    printf("Error: Reloc %li out of range\n", i);
		}
		else
		{
		    temps = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
		    temps += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
		    temps += j;
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = temps & 0xff;
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (temps >> 8) & 0xff;
		}
	    }
	    break;
	case FIX_SELF_OFS32:
	case FIX_SELF_OFS32_2:
	    if ((seglist[targseg]->attr & SEG_ALIGN) == SEG_ABS)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = seglist[targseg]->base + targofs;
		j -= seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 4;
		templ = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] << 16;
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] << 24;
		templ += j;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = templ & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (templ >> 8) & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] = (templ >> 16) & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] = (templ >> 24) & 0xff;
	    }
	    break;
	default:
	    printf("Reloc %li:Relocation type %i not supported\n", i, relocs[i]->rtype);
	    errcount++;
	}
    }

    if (relcount > 65535)
    {
	printf("Too many relocations\n");
	exit(1);
    }

    headbuf[0x06] = relcount & 0xff;
    headbuf[0x07] = relcount >> 8;
    i = relcount * 4 + 0x4f;
    i >>= 4;
    totlength += i << 4;
    headbuf[0x08] = i & 0xff;
    headbuf[0x09] = i >> 8;
    i = totlength % 512;
    headbuf[0x02] = i & 0xff;
    headbuf[0x03] = i >> 8;
    i = (totlength + 0x1ff) >> 9;
    if (i > 65535)
    {
	printf("File too large\n");
	exit(1);
    }
    headbuf[0x04] = i & 0xff;
    headbuf[0x05] = i >> 8;

    if (errcount != 0)
    {
	exit(1);
    }

    outfile = fopen(outname, "wb");
    if (!outfile)
    {
	printf("Error writing to file %s\n", outname);
	exit(1);
    }

    i = (headbuf[0x08] + 256 * headbuf[0x09]) * 16;
    if (fwrite(headbuf, 1, i, outfile) != i)
    {
	printf("Error writing to file %s\n", outname);
	exit(1);
    }

    started = 0;
    lastout = 0;

    for (i = 0; i < outcount; i++)
    {
	if (outlist[i] && ((outlist[i]->attr & SEG_ALIGN) != SEG_ABS))
	{
	    if (started > outlist[i]->base)
	    {
		printf("Segment overlap\n");
		fclose(outfile);
		exit(1);
	    }
	    if (padsegments)
	    {
		while (started < outlist[i]->base)
		{
		    fputc(0, outfile);
		    started++;
		}
	    }
	    else
	    {
		started = outlist[i]->base;
	    }
	    for (j = 0; j < outlist[i]->length; j++)
	    {
		if (GetNbit(outlist[i]->datmask, j))
		{
		    for (; lastout < started; lastout++)
		    {
			fputc(0, outfile);
		    }
		    fputc(outlist[i]->data[j], outfile);
		    lastout = started + 1;
		}
		else if (padsegments)
		{
		    fputc(0, outfile);
		    lastout = started + 1;
		}
		started++;
	    }
	}
    }

    if (lastout != started)
    {
	fseek(outfile, 0, SEEK_SET);
	lastout += (headbuf[8] + 256 * headbuf[9]) << 4;
	i = lastout % 512;
	headbuf[0x02] = i & 0xff;
	headbuf[0x03] = i >> 8;
	i = (lastout + 0x1ff) >> 9;
	headbuf[0x04] = i & 0xff;
	headbuf[0x05] = i >> 8;
	i = ((totlength - lastout) + 0xf) >> 4;
	if (i > 65535)
	{
	    printf("Memory requirements too high\n");
	}
	headbuf[0x0a] = i & 0xff;
	headbuf[0x0b] = i >> 8;
	if (fwrite(headbuf, 1, 12, outfile) != 12)
	{
	    printf("Error writing to file\n");
	    exit(1);
	}
    }
    fclose(outfile);
}

long createOutputSection(char *name, UINT winFlags)
{
    UINT j;

    outlist = (PPSEG)checkRealloc(outlist, sizeof(PSEG) * (outcount + 1));
    outlist[outcount] = (PSEG)checkMalloc(sizeof(SEG));
    seglist = (PPSEG)checkRealloc(seglist, sizeof(PSEG) * (segcount + 1));
    seglist = (PPSEG)checkRealloc(seglist, (segcount + 1) * sizeof(PSEG));
    seglist[segcount] = outlist[outcount];
    namelist = (PPCHAR)checkRealloc(namelist, (namecount + 1) * sizeof(PCHAR));
    namelist[namecount] = checkStrdup(name);
    outlist[outcount]->nameindex = namecount;
    outlist[outcount]->classindex = -1;
    outlist[outcount]->overlayindex = -1;
    namecount++;
    j = outlist[outcount - 1]->base + outlist[outcount - 1]->length;
    j += (objectAlign - 1);
    j &= (0xffffffff - (objectAlign - 1));
    outlist[outcount]->base = j;
    outlist[outcount]->length = 0;
    outlist[outcount]->data = outlist[outcount]->datmask = NULL;
    outlist[outcount]->absofs = segcount;
    outlist[outcount]->attr = SEG_BYTE | SEG_PRIVATE;
    outlist[outcount]->winFlags = winFlags ^ WINF_NEG_FLAGS;
    segcount++;
    outcount++;
    return outcount - 1;
}

void BuildPEImports(long impsectNum, PUCHAR objectTable)
{
    long i, j, k;
    UINT *reqimps = NULL, reqcount = 0;
    char **dllNames = NULL;
    int *dllNumImps = NULL;
    int *dllImpsDone = NULL;
    int *dllImpNameSize = NULL;
    UINT dllCount = 0, dllNameSize = 0, namePos;
    SEG *impsect;
    UINT thunkPos, thunk2Pos, impNamePos;

    if (impsectNum < 0)
	return;
    for (i = 0; i < extcount; i++)
    {
	if (externs[i].flags != EXT_MATCHEDIMPORT)
	    continue;
	for (j = 0; j < reqcount; j++)
	{
	    if (reqimps[j] == externs[i].impnum)
		break;
	}
	if (j != reqcount)
	    continue;
	reqimps = (UINT *)checkRealloc(reqimps, (reqcount + 1) * sizeof(UINT));
	reqimps[reqcount] = externs[i].impnum;
	reqcount++;
	for (j = 0; j < dllCount; j++)
	{
	    if (!strcmp(impdefs[externs[i].impnum].mod_name, dllNames[j]))
		break;
	}
	if (j == dllCount)
	{
	    dllNames = (char **)checkRealloc(dllNames, (dllCount + 1) * sizeof(char *));
	    dllNumImps = (int *)checkRealloc(dllNumImps, (dllCount + 1) * sizeof(int));
	    dllImpsDone = (int *)checkRealloc(dllImpsDone, (dllCount + 1) * sizeof(int));
	    dllImpNameSize = (int *)checkRealloc(dllImpNameSize, (dllCount + 1) * sizeof(int));
	    dllNames[dllCount] = impdefs[externs[i].impnum].mod_name;
	    dllNumImps[dllCount] = 0;
	    dllImpsDone[dllCount] = 0;
	    dllImpNameSize[dllCount] = 0;
	    dllNameSize += strlen(dllNames[dllCount]) + 1;
	    if (dllNameSize & 1)
		dllNameSize++;
	    dllCount++;
	}
	dllNumImps[j]++;
	if (impdefs[externs[i].impnum].flags == 0) /* import by name? */
	{
	    dllImpNameSize[j] += strlen(impdefs[externs[i].impnum].imp_name) + 3;
	    /* the +3 ensure room for 2-byte hint and null terminator */
	    if (dllImpNameSize[j] & 1)
		dllImpNameSize[j]++;
	}
    }

    if (!reqcount || !dllCount)
	return;

    objectTable += PE_OBJECTENTRY_SIZE * impsectNum; /* point to import object entry */
    k = objectTable[-PE_OBJECTENTRY_SIZE + 20];	     /* get physical start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 21] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 22] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 23] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 16]; /* add physical length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 17] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 18] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 19] << 24;

    k += fileAlign - 1;
    k &= (0xffffffff - (fileAlign - 1)); /* aligned */

    /* k is now physical location of this object */

    objectTable[20] = (k) & 0xff; /* store physical file offset */
    objectTable[21] = (k >> 8) & 0xff;
    objectTable[22] = (k >> 16) & 0xff;
    objectTable[23] = (k >> 24) & 0xff;

    k = objectTable[-PE_OBJECTENTRY_SIZE + 12]; /* get virtual start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 13] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 14] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 15] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 8]; /* add virtual length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 9] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 10] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 11] << 24;

    /* store base address (RVA) of section */
    objectTable[12] = (k) & 0xff;
    objectTable[13] = (k >> 8) & 0xff;
    objectTable[14] = (k >> 16) & 0xff;
    objectTable[15] = (k >> 24) & 0xff;

    impsect = outlist[impsectNum];
    impsect->base = k + imageBase; /* get base address of section */

    impsect->length = (dllCount + 1) * PE_IMPORTDIRENTRY_SIZE + dllNameSize;
    if (impsect->length & 3)
	impsect->length += 4 - (impsect->length & 3); /* align to 4-byte boundary */
    thunkPos = impsect->base + impsect->length;
    for (j = 0, i = 0; j < dllCount; j++)
    {
	i += dllNumImps[j] + 1; /* add number of entries in DLL thunk table */
    }
    /* now i= number of entries in Thunk tables for all DLLs */
    /* get address of name tables, which follow thunk tables */
    impNamePos = thunkPos + i * 2 * 4; /* 2 thunk tables per DLL, 4 bytes per entry */
    impsect->length += i * 2 * 4;      /* update length of section too. */

    for (j = 0, i = 0; j < dllCount; j++)
    {
	i += dllImpNameSize[j]; /* add size of import names and hints */
    }

    impsect->length += i;

    impsect->data = (PUCHAR)checkMalloc(impsect->length);
    impsect->datmask = (PUCHAR)checkMalloc((impsect->length + 7) / 8);
    for (i = 0; i < (impsect->length + 7) / 8; i++)
    {
	impsect->datmask[i] = 0xff;
    }

    /* end of directory entries=name table */
    namePos = impsect->base + (dllCount + 1) * PE_IMPORTDIRENTRY_SIZE;
    for (i = 0; i < dllCount; i++)
    {
	/* add directory entry */
	j = i * PE_IMPORTDIRENTRY_SIZE;
	impsect->data[j + 0] = (thunkPos - imageBase) & 0xff; /* address of first thunk table */
	impsect->data[j + 1] = ((thunkPos - imageBase) >> 8) & 0xff;
	impsect->data[j + 2] = ((thunkPos - imageBase) >> 16) & 0xff;
	impsect->data[j + 3] = ((thunkPos - imageBase) >> 24) & 0xff;
	impsect->data[j + 4] = 0; /* zero out time stamp */
	impsect->data[j + 5] = 0;
	impsect->data[j + 6] = 0;
	impsect->data[j + 7] = 0;
	impsect->data[j + 8] = 0; /* zero out version number */
	impsect->data[j + 9] = 0;
	impsect->data[j + 10] = 0;
	impsect->data[j + 11] = 0;
	impsect->data[j + 12] = (namePos - imageBase) & 0xff; /* address of DLL name */
	impsect->data[j + 13] = ((namePos - imageBase) >> 8) & 0xff;
	impsect->data[j + 14] = ((namePos - imageBase) >> 16) & 0xff;
	impsect->data[j + 15] = ((namePos - imageBase) >> 24) & 0xff;
	thunk2Pos = thunkPos + (dllNumImps[i] + 1) * 4;		/* address of second thunk table */
	impsect->data[j + 16] = (thunk2Pos - imageBase) & 0xff; /* store it */
	impsect->data[j + 17] = ((thunk2Pos - imageBase) >> 8) & 0xff;
	impsect->data[j + 18] = ((thunk2Pos - imageBase) >> 16) & 0xff;
	impsect->data[j + 19] = ((thunk2Pos - imageBase) >> 24) & 0xff;
	/* add name to table */
	strcpy((char *)(impsect->data + namePos - impsect->base), dllNames[i]);
	namePos += strlen(dllNames[i]) + 1;
	if (namePos & 1)
	{
	    impsect->data[namePos - impsect->base] = 0;
	    namePos++;
	}
	/* add imported names to table */
	for (k = 0; k < reqcount; k++)
	{
	    if (strcmp(impdefs[reqimps[k]].mod_name, dllNames[i]) != 0)
		continue;
	    if (impdefs[reqimps[k]].flags == 0)
	    {
		/* store pointers to name entry in thunk tables */
		impsect->data[thunkPos - impsect->base] = (impNamePos - imageBase) & 0xff;
		impsect->data[thunkPos - impsect->base + 1] =
		    ((impNamePos - imageBase) >> 8) & 0xff;
		impsect->data[thunkPos - impsect->base + 2] =
		    ((impNamePos - imageBase) >> 16) & 0xff;
		impsect->data[thunkPos - impsect->base + 3] =
		    ((impNamePos - imageBase) >> 24) & 0xff;

		impsect->data[thunk2Pos - impsect->base] = (impNamePos - imageBase) & 0xff;
		impsect->data[thunk2Pos - impsect->base + 1] =
		    ((impNamePos - imageBase) >> 8) & 0xff;
		impsect->data[thunk2Pos - impsect->base + 2] =
		    ((impNamePos - imageBase) >> 16) & 0xff;
		impsect->data[thunk2Pos - impsect->base + 3] =
		    ((impNamePos - imageBase) >> 24) & 0xff;

		/* no hint */
		impsect->data[impNamePos - impsect->base] = 0;
		impsect->data[impNamePos - impsect->base + 1] = 0;
		impNamePos += 2;
		/* store name */
		strcpy((char *)(impsect->data + impNamePos - impsect->base),
		       impdefs[reqimps[k]].imp_name);
		impNamePos += strlen(impdefs[reqimps[k]].imp_name) + 1;
		if (impNamePos & 1)
		{
		    impsect->data[impNamePos - impsect->base] = 0;
		    impNamePos++;
		}
	    }
	    else
	    {
		/* store ordinal number in thunk tables */
		j = impdefs[reqimps[k]].ordinal + PE_ORDINAL_FLAG;
		impsect->data[thunkPos - impsect->base] = (j) & 0xff;
		impsect->data[thunkPos - impsect->base + 1] = (j >> 8) & 0xff;
		impsect->data[thunkPos - impsect->base + 2] = (j >> 16) & 0xff;
		impsect->data[thunkPos - impsect->base + 3] = (j >> 24) & 0xff;

		impsect->data[thunk2Pos - impsect->base] = (j) & 0xff;
		impsect->data[thunk2Pos - impsect->base + 1] = (j >> 8) & 0xff;
		impsect->data[thunk2Pos - impsect->base + 2] = (j >> 16) & 0xff;
		impsect->data[thunk2Pos - impsect->base + 3] = (j >> 24) & 0xff;
	    }
	    impdefs[reqimps[k]].segnum = impsect->absofs;
	    impdefs[reqimps[k]].ofs = thunk2Pos - impsect->base;
	    thunkPos += 4;
	    thunk2Pos += 4;
	}
	/* zero out end of thunk tables */
	impsect->data[thunkPos - impsect->base] = 0;
	impsect->data[thunkPos - impsect->base + 1] = 0;
	impsect->data[thunkPos - impsect->base + 2] = 0;
	impsect->data[thunkPos - impsect->base + 3] = 0;
	impsect->data[thunk2Pos - impsect->base] = 0;
	impsect->data[thunk2Pos - impsect->base + 1] = 0;
	impsect->data[thunk2Pos - impsect->base + 2] = 0;
	impsect->data[thunk2Pos - impsect->base + 3] = 0;
	thunkPos = thunk2Pos + 4;
    }
    /* zero out the final entry to mark the end of the table */
    j = i * PE_IMPORTDIRENTRY_SIZE;
    for (i = 0; i < PE_IMPORTDIRENTRY_SIZE; i++, j++)
    {
	impsect->data[j] = 0;
    }

    k = impsect->length;
    k += objectAlign - 1;
    k &= (0xffffffff - (objectAlign - 1));
    impsect->virtualSize = k;
    objectTable[8] = k & 0xff; /* store virtual size (in memory) of segment */
    objectTable[9] = (k >> 8) & 0xff;
    objectTable[10] = (k >> 16) & 0xff;
    objectTable[11] = (k >> 24) & 0xff;

    k = impsect->length;
    objectTable[16] = (k) & 0xff; /* store initialised data size */
    objectTable[17] = (k >> 8) & 0xff;
    objectTable[18] = (k >> 16) & 0xff;
    objectTable[19] = (k >> 16) & 0xff;

    return;
}

void BuildPERelocs(long relocSectNum, PUCHAR objectTable)
{
    int i, j;
    PRELOC r;
    PSEG relocSect;
    UINT curStartPos;
    UINT curBlockPos;
    UINT k;
    long targseg;
    UINT targofs;
    unsigned long templ;
    unsigned short temps;

    /* do fixups */
    for (i = 0; i < fixcount; i++)
    {
	GetFixupTarget(relocs[i], &targseg, &targofs, TRUE);
	switch (relocs[i]->rtype)
	{
	case FIX_BASE:
	case FIX_PTR1616:
	case FIX_PTR1632:
	    if (targseg < 0)
	    {
		printf("Reloc %i:Segment selector relocations are not supported in PE files\n", i);
		printf("rtype=%02X, frame=%04lX, target=%04lX, ftype=%02X, ttype=%02X\n",
		       relocs[i]->rtype, relocs[i]->frame, relocs[i]->target, relocs[i]->ftype,
		       relocs[i]->ttype);

		errcount++;
	    }
	    else
	    {
		j = relocs[i]->ofs;
		if (relocs[i]->rtype == FIX_PTR1616)
		{
		    if (targofs > 0xffff)
		    {
			printf("Relocs %i:Warning 32 bit offset in 16 bit field\n", i);
		    }
		    targofs &= 0xffff;
		    temps = seglist[relocs[i]->segnum]->data[j];
		    temps += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		    temps += targofs;
		    seglist[relocs[i]->segnum]->data[j] = temps & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 1] = (temps >> 8) & 0xff;
		    j += 2;
		}
		else if (relocs[i]->rtype == FIX_PTR1632)
		{
		    templ = seglist[relocs[i]->segnum]->data[j];
		    templ += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		    templ += seglist[relocs[i]->segnum]->data[j + 2] << 16;
		    templ += seglist[relocs[i]->segnum]->data[j + 3] << 24;
		    templ += targofs;
		    seglist[relocs[i]->segnum]->data[j] = templ & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 1] = (templ >> 8) & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 2] = (templ >> 16) & 0xff;
		    seglist[relocs[i]->segnum]->data[j + 3] = (templ >> 24) & 0xff;
		    j += 4;
		}
		temps = seglist[relocs[i]->segnum]->data[j];
		temps += seglist[relocs[i]->segnum]->data[j + 1] << 8;
		temps += seglist[targseg]->absframe;
		seglist[relocs[i]->segnum]->data[j] = temps & 0xff;
		seglist[relocs[i]->segnum]->data[j + 1] = (temps >> 8) & 0xff;
	    }
	    break;
	case FIX_OFS32:
	case FIX_OFS32_2:
	    templ = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] << 16;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] << 24;
	    templ += targofs;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = templ & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (templ >> 8) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] = (templ >> 16) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] = (templ >> 24) & 0xff;
	    break;
	case FIX_RVA32:
	    templ = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] << 16;
	    templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] << 24;
	    templ += targofs - imageBase;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = templ & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (templ >> 8) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] = (templ >> 16) & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] = (templ >> 24) & 0xff;
	    break;
	case FIX_OFS16:
	case FIX_OFS16_2:
	    if (targofs > 0xffff)
	    {
		printf("Relocs %i:Warning 32 bit offset in 16 bit field\n", i);
	    }
	    targofs &= 0xffff;
	    temps = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
	    temps += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
	    temps += targofs;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = temps & 0xff;
	    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (temps >> 8) & 0xff;
	    break;
	case FIX_LBYTE:
	case FIX_HBYTE:
	    printf("Error: Byte relocations not supported in PE files\n");
	    errcount++;
	    break;
	case FIX_SELF_LBYTE:
	    if (targseg >= 0)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = targofs;
		j -= (seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 1);
		if ((j < -128) || (j > 127))
		{
		    printf("Error: Reloc %i out of range\n", i);
		}
		else
		{
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] += j;
		}
	    }
	    break;
	case FIX_SELF_OFS16:
	case FIX_SELF_OFS16_2:
	    if (targseg >= 0)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = targofs;
		j -= (seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 2);
		if ((j < -32768) || (j > 32767))
		{
		    printf("Error: Reloc %i out of range\n", i);
		}
		else
		{
		    temps = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
		    temps += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
		    temps += j;
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = temps & 0xff;
		    seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (temps >> 8) & 0xff;
		}
	    }
	    break;
	case FIX_SELF_OFS32:
	case FIX_SELF_OFS32_2:
	    if (targseg >= 0)
	    {
		printf("Error: Absolute Reloc target not supported for self-relative fixups\n");
		errcount++;
	    }
	    else
	    {
		j = targofs;
		j -= (seglist[relocs[i]->segnum]->base + relocs[i]->ofs + 4);
		templ = seglist[relocs[i]->segnum]->data[relocs[i]->ofs];
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] << 8;
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] << 16;
		templ += seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] << 24;
		templ += j;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs] = templ & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 1] = (templ >> 8) & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 2] = (templ >> 16) & 0xff;
		seglist[relocs[i]->segnum]->data[relocs[i]->ofs + 3] = (templ >> 24) & 0xff;
	    }
	    break;
	default:
	    printf("Reloc %i:Relocation type %i not supported\n", i, relocs[i]->rtype);
	    errcount++;
	}
    }

    /* get reloc section */
    relocSect = outlist[relocSectNum]; /* get section structure */

    /* sort relocations into order of increasing address */
    for (i = 1; i < fixcount; i++)
    {
	r = relocs[i];		     /* save current reloc */
	for (j = i - 1; j >= 0; j--) /* search backwards through table */
	{
	    /* stop once we've found a target before current */
	    if (r->outputPos >= relocs[j]->outputPos)
		break;
	    /* otherwise move reloc entry up */
	    relocs[j + 1] = relocs[j];
	}
	j++;	       /* point to first entry after non-match */
	relocs[j] = r; /* put current reloc in position */
    }

    for (i = 0, curStartPos = 0, curBlockPos = 0; i < fixcount; i++)
    {
	switch (relocs[i]->rtype)
	{
	case FIX_SELF_OFS32:
	case FIX_SELF_OFS32_2:
	case FIX_SELF_OFS16:
	case FIX_SELF_OFS16_2:
	case FIX_SELF_LBYTE:
	case FIX_RVA32:
	    continue; /* self-relative fixups and RVA fixups don't relocate */
	default:
	    break;
	}
	if (relocs[i]->outputPos >= (curStartPos + 0x1000)) /* more than 4K past block start? */
	{
	    j = relocSect->length & 3;
	    if (j) /* unaligned block position */
	    {
		relocSect->length += 4 - j; /* update length to align block */
		/* and block memory */
		relocSect->data = (PUCHAR)checkRealloc(relocSect->data, relocSect->length);
		/* update size of current reloc block */
		k = relocSect->data[curBlockPos + 4];
		k += relocSect->data[curBlockPos + 5] << 8;
		k += relocSect->data[curBlockPos + 6] << 16;
		k += relocSect->data[curBlockPos + 7] << 24;
		k += 4 - j;
		relocSect->data[curBlockPos + 4] = k & 0xff;
		relocSect->data[curBlockPos + 5] = (k >> 8) & 0xff;
		relocSect->data[curBlockPos + 6] = (k >> 16) & 0xff;
		relocSect->data[curBlockPos + 7] = (k >> 24) & 0xff;
		for (j = 4 - j; j > 0; j--)
		{
		    relocSect->data[relocSect->length - j] = 0;
		}
	    }
	    curBlockPos = relocSect->length; /* get address in section of current block */
	    relocSect->length += 8;	     /* 8 bytes block header */
	    /* increase size of block */
	    relocSect->data = (PUCHAR)checkRealloc(relocSect->data, relocSect->length);
	    /* store reloc base address, and block size */
	    curStartPos = relocs[i]->outputPos & 0xfffff000; /* start of mem page */

	    /* start pos is relative to image base */
	    relocSect->data[curBlockPos] = (curStartPos - imageBase) & 0xff;
	    relocSect->data[curBlockPos + 1] = ((curStartPos - imageBase) >> 8) & 0xff;
	    relocSect->data[curBlockPos + 2] = ((curStartPos - imageBase) >> 16) & 0xff;
	    relocSect->data[curBlockPos + 3] = ((curStartPos - imageBase) >> 24) & 0xff;

	    relocSect->data[curBlockPos + 4] = 8; /* start size is 8 bytes */
	    relocSect->data[curBlockPos + 5] = 0;
	    relocSect->data[curBlockPos + 6] = 0;
	    relocSect->data[curBlockPos + 7] = 0;
	}
	relocSect->data = (PUCHAR)checkRealloc(relocSect->data, relocSect->length + 2);

	j = relocs[i]->outputPos - curStartPos; /* low 12 bits of address */
	switch (relocs[i]->rtype)
	{
	case FIX_PTR1616:
	case FIX_OFS16:
	case FIX_OFS16_2:
	    j |= PE_REL_LOW16;
	    break;
	case FIX_PTR1632:
	case FIX_OFS32:
	case FIX_OFS32_2:
	    j |= PE_REL_OFS32;
	}
	/* store relocation */
	relocSect->data[relocSect->length] = j & 0xff;
	relocSect->data[relocSect->length + 1] = (j >> 8) & 0xff;
	/* update block length */
	relocSect->length += 2;
	/* update size of current reloc block */
	k = relocSect->data[curBlockPos + 4];
	k += relocSect->data[curBlockPos + 5] << 8;
	k += relocSect->data[curBlockPos + 6] << 16;
	k += relocSect->data[curBlockPos + 7] << 24;
	k += 2;
	relocSect->data[curBlockPos + 4] = k & 0xff;
	relocSect->data[curBlockPos + 5] = (k >> 8) & 0xff;
	relocSect->data[curBlockPos + 6] = (k >> 16) & 0xff;
	relocSect->data[curBlockPos + 7] = (k >> 24) & 0xff;
    }
    /* if no fixups, then build NOP fixups, to make Windows NT happy */
    /* when it trys to relocate image */
    if (relocSect->length == 0)
    {
	/* 12 bytes for dummy section */
	relocSect->length = 12;
	relocSect->data = (PUCHAR)checkMalloc(12);
	/* zero it out for now */
	for (i = 0; i < 12; i++)
	    relocSect->data[i] = 0;
	relocSect->data[4] = 12; /* size of block */
    }

    relocSect->datmask = (PUCHAR)checkMalloc((relocSect->length + 7) / 8);
    for (i = 0; i < (relocSect->length + 7) / 8; i++)
    {
	relocSect->datmask[i] = 0xff;
    }

    objectTable += PE_OBJECTENTRY_SIZE * relocSectNum; /* point to reloc object entry */
    k = relocSect->length;
    k += objectAlign - 1;
    k &= (0xffffffff - (objectAlign - 1));
    relocSect->virtualSize = k;
    objectTable[8] = k & 0xff; /* store virtual size (in memory) of segment */
    objectTable[9] = (k >> 8) & 0xff;
    objectTable[10] = (k >> 16) & 0xff;
    objectTable[11] = (k >> 24) & 0xff;

    k = relocSect->length;
    objectTable[16] = (k) & 0xff; /* store initialised data size */
    objectTable[17] = (k >> 8) & 0xff;
    objectTable[18] = (k >> 16) & 0xff;
    objectTable[19] = (k >> 16) & 0xff;

    k = objectTable[-PE_OBJECTENTRY_SIZE + 20]; /* get physical start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 21] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 22] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 23] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 16]; /* add physical length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 17] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 18] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 19] << 24;

    k += fileAlign - 1;
    k &= (0xffffffff - (fileAlign - 1)); /* aligned */

    /* k is now physical location of this object */

    objectTable[20] = (k) & 0xff; /* store physical file offset */
    objectTable[21] = (k >> 8) & 0xff;
    objectTable[22] = (k >> 16) & 0xff;
    objectTable[23] = (k >> 24) & 0xff;

    k = objectTable[-PE_OBJECTENTRY_SIZE + 12]; /* get virtual start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 13] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 14] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 15] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 8]; /* add virtual length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 9] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 10] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 11] << 24;

    /* store base address (RVA) of section */
    objectTable[12] = (k) & 0xff;
    objectTable[13] = (k >> 8) & 0xff;
    objectTable[14] = (k >> 16) & 0xff;
    objectTable[15] = (k >> 24) & 0xff;

    relocSect->base = k + imageBase; /* relocate section */

    return;
}

void BuildPEExports(long SectNum, PUCHAR objectTable, PCHAR name)
{
    long i, j;
    UINT k;
    PSEG expSect;
    UINT namelen;
    UINT numNames = 0;
    UINT RVAStart;
    UINT nameRVAStart;
    UINT ordinalStart;
    UINT nameSpaceStart;
    UINT minOrd;
    UINT maxOrd;
    UINT numOrds;
    PPEXPREC nameList;
    PEXPREC curName;

    if (!expcount || (SectNum < 0))
	return; /* return if no exports */
    expSect = outlist[SectNum];

    if (name)
    {
	namelen = strlen(name);
	/* search backwards for path separator */
	for (i = namelen - 1; (i >= 0) && !IS_PATH_CHAR(name[i]); i--)
	    ;
	if (i >= 0) /* if found path separator */
	{
	    name += (i + 1);	/* update name pointer past path */
	    namelen -= (i + 1); /* and reduce length */
	}
    }
    else
	namelen = 0;

    expSect->length = PE_EXPORTHEADER_SIZE + 4 * expcount + namelen + 1;
    /* min section size= header size + num exports * pointer size */
    /* plus space for null-terminated name */

    minOrd = 0xffffffff; /* max ordinal num */
    maxOrd = 0;

    for (i = 0; i < expcount; i++)
    {
	/* check we've got an exported name */
	if (expdefs[i].exp_name && strlen(expdefs[i].exp_name))
	{
	    /* four bytes for name pointer */
	    /* two bytes for ordinal, 1 for null terminator */
	    expSect->length += strlen(expdefs[i].exp_name) + 7;
	    numNames++;
	}

	if (expdefs[i].flags & EXP_ORD) /* ordinal? */
	{
	    if (expdefs[i].ordinal < minOrd)
		minOrd = expdefs[i].ordinal;
	    if (expdefs[i].ordinal > maxOrd)
		maxOrd = expdefs[i].ordinal;
	}
    }

    numOrds = expcount;	  /* by default, number of RVAs=number of exports */
    if (maxOrd >= minOrd) /* actually got some ordinal references? */
    {
	i = maxOrd - minOrd + 1; /* get number of ordinals */
	if (i > expcount)	 /* if bigger range than number of exports */
	{
	    expSect->length += 4 * (i - expcount); /* up length */
	    numOrds = i;			   /* get new num RVAs */
	}
    }
    else
    {
	minOrd = 1; /* if none defined, min is set to 1 */
    }

    expSect->data = (PUCHAR)checkMalloc(expSect->length);

    objectTable += PE_OBJECTENTRY_SIZE * SectNum; /* point to reloc object entry */
    k = expSect->length;
    k += objectAlign - 1;
    k &= (0xffffffff - (objectAlign - 1));
    expSect->virtualSize = k;
    objectTable[8] = k & 0xff; /* store virtual size (in memory) of segment */
    objectTable[9] = (k >> 8) & 0xff;
    objectTable[10] = (k >> 16) & 0xff;
    objectTable[11] = (k >> 24) & 0xff;

    k = expSect->length;
    objectTable[16] = (k) & 0xff; /* store initialised data size */
    objectTable[17] = (k >> 8) & 0xff;
    objectTable[18] = (k >> 16) & 0xff;
    objectTable[19] = (k >> 16) & 0xff;

    k = objectTable[-PE_OBJECTENTRY_SIZE + 20]; /* get physical start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 21] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 22] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 23] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 16]; /* add physical length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 17] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 18] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 19] << 24;

    k += fileAlign - 1;
    k &= (0xffffffff - (fileAlign - 1)); /* aligned */

    /* k is now physical location of this object */

    objectTable[20] = (k) & 0xff; /* store physical file offset */
    objectTable[21] = (k >> 8) & 0xff;
    objectTable[22] = (k >> 16) & 0xff;
    objectTable[23] = (k >> 24) & 0xff;

    k = objectTable[-PE_OBJECTENTRY_SIZE + 12]; /* get virtual start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 13] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 14] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 15] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 8]; /* add virtual length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 9] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 10] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 11] << 24;

    /* store base address (RVA) of section */
    objectTable[12] = (k) & 0xff;
    objectTable[13] = (k >> 8) & 0xff;
    objectTable[14] = (k >> 16) & 0xff;
    objectTable[15] = (k >> 24) & 0xff;

    expSect->base = k + imageBase; /* relocate section */

    /* start with buf=all zero */
    for (i = 0; i < expSect->length; i++)
	expSect->data[i] = 0;

    /* store creation time of export data */
    k = (UINT)time(NULL);
    expSect->data[4] = k & 0xff;
    expSect->data[5] = (k >> 8) & 0xff;
    expSect->data[6] = (k >> 16) & 0xff;
    expSect->data[7] = (k >> 24) & 0xff;

    expSect->data[16] = (minOrd) & 0xff; /* store ordinal base */
    expSect->data[17] = (minOrd >> 8) & 0xff;
    expSect->data[18] = (minOrd >> 16) & 0xff;
    expSect->data[19] = (minOrd >> 24) & 0xff;

    /* store number of RVAs */
    expSect->data[20] = numOrds & 0xff;
    expSect->data[21] = (numOrds >> 8) & 0xff;
    expSect->data[22] = (numOrds >> 16) & 0xff;
    expSect->data[23] = (numOrds >> 24) & 0xff;

    RVAStart = PE_EXPORTHEADER_SIZE;		  /* start address of RVA table */
    nameRVAStart = RVAStart + numOrds * 4;	  /* start of name table entries */
    ordinalStart = nameRVAStart + numNames * 4;	  /* start of associated ordinal entries */
    nameSpaceStart = ordinalStart + numNames * 2; /* start of actual names */

    /* store number of named exports */
    expSect->data[24] = numNames & 0xff;
    expSect->data[25] = (numNames >> 8) & 0xff;
    expSect->data[26] = (numNames >> 16) & 0xff;
    expSect->data[27] = (numNames >> 24) & 0xff;

    /* store address of address table */
    expSect->data[28] = (RVAStart + expSect->base - imageBase) & 0xff;
    expSect->data[29] = ((RVAStart + expSect->base - imageBase) >> 8) & 0xff;
    expSect->data[30] = ((RVAStart + expSect->base - imageBase) >> 16) & 0xff;
    expSect->data[31] = ((RVAStart + expSect->base - imageBase) >> 24) & 0xff;

    /* store address of name table */
    expSect->data[32] = (nameRVAStart + expSect->base - imageBase) & 0xff;
    expSect->data[33] = ((nameRVAStart + expSect->base - imageBase) >> 8) & 0xff;
    expSect->data[34] = ((nameRVAStart + expSect->base - imageBase) >> 16) & 0xff;
    expSect->data[35] = ((nameRVAStart + expSect->base - imageBase) >> 24) & 0xff;

    /* store address of ordinal table */
    expSect->data[36] = (ordinalStart + expSect->base - imageBase) & 0xff;
    expSect->data[37] = ((ordinalStart + expSect->base - imageBase) >> 8) & 0xff;
    expSect->data[38] = ((ordinalStart + expSect->base - imageBase) >> 16) & 0xff;
    expSect->data[39] = ((ordinalStart + expSect->base - imageBase) >> 24) & 0xff;

    /* process numbered exports */
    for (i = 0; i < expcount; i++)
    {
	if (expdefs[i].flags & EXP_ORD)
	{
	    /* get current RVA */
	    k = expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd)];
	    k += expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd) + 1] << 8;
	    k += expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd) + 2] << 16;
	    k += expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd) + 3] << 24;
	    if (k) /* error if already used */
	    {
		printf("Duplicate export ordinal %u\n", expdefs[i].ordinal);
		exit(1);
	    }
	    /* get RVA of export entry */
	    k = expdefs[i].pubdef->ofs + seglist[expdefs[i].pubdef->segnum]->base - imageBase;
	    /* store it */
	    expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd)] = k & 0xff;
	    expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd) + 1] = (k >> 8) & 0xff;
	    expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd) + 2] = (k >> 16) & 0xff;
	    expSect->data[RVAStart + 4 * (expdefs[i].ordinal - minOrd) + 3] = (k >> 24) & 0xff;
	}
    }

    /* process non-numbered exports */
    for (i = 0, j = RVAStart; i < expcount; i++)
    {
	if (!(expdefs[i].flags & EXP_ORD))
	{
	    do
	    {
		k = expSect->data[j];
		k += expSect->data[j + 1] << 8;
		k += expSect->data[j + 2] << 16;
		k += expSect->data[j + 3] << 24;
		if (k)
		    j += 4;
	    } while (k); /* move through table until we find a free spot */
	    /* get RVA of export entry */
	    k = expdefs[i].pubdef->ofs;
	    k += seglist[expdefs[i].pubdef->segnum]->base;
	    k -= imageBase;
	    /* store RVA */
	    expSect->data[j] = k & 0xff;
	    expSect->data[j + 1] = (k >> 8) & 0xff;
	    expSect->data[j + 2] = (k >> 16) & 0xff;
	    expSect->data[j + 3] = (k >> 24) & 0xff;
	    expdefs[i].ordinal = (j - RVAStart) / 4 + minOrd; /* store ordinal */
	    j += 4;
	}
    }

    if (numNames) /* sort name table if present */
    {
	nameList = (PPEXPREC)checkMalloc(numNames * sizeof(PEXPREC));
	j = 0; /* no entries yet */
	for (i = 0; i < expcount; i++)
	{
	    if (expdefs[i].exp_name && expdefs[i].exp_name[0])
	    {
		/* make entry in name list */
		nameList[j] = &expdefs[i];
		j++;
	    }
	}
	/* sort them into order */
	for (i = 1; i < numNames; i++)
	{
	    curName = nameList[i];
	    for (j = i - 1; j >= 0; j--)
	    {
		/* break out if we're above previous entry */
		if (strcmp(curName->exp_name, nameList[j]->exp_name) >= 0)
		{
		    break;
		}
		/* else move entry up */
		nameList[j + 1] = nameList[j];
	    }
	    j++;		   /* move to one after better entry */
	    nameList[j] = curName; /* insert current entry into position */
	}
	/* and store */
	for (i = 0; i < numNames; i++)
	{
	    /* store ordinal */
	    expSect->data[ordinalStart] = (nameList[i]->ordinal - minOrd) & 0xff;
	    expSect->data[ordinalStart + 1] = ((nameList[i]->ordinal - minOrd) >> 8) & 0xff;
	    ordinalStart += 2;
	    /* store name RVA */
	    expSect->data[nameRVAStart] = (nameSpaceStart + expSect->base - imageBase) & 0xff;
	    expSect->data[nameRVAStart + 1] =
		((nameSpaceStart + expSect->base - imageBase) >> 8) & 0xff;
	    expSect->data[nameRVAStart + 2] =
		((nameSpaceStart + expSect->base - imageBase) >> 16) & 0xff;
	    expSect->data[nameRVAStart + 3] =
		((nameSpaceStart + expSect->base - imageBase) >> 24) & 0xff;
	    nameRVAStart += 4;
	    /* store name */
	    for (j = 0; nameList[i]->exp_name[j]; j++, nameSpaceStart++)
	    {
		expSect->data[nameSpaceStart] = nameList[i]->exp_name[j];
	    }
	    /* store NULL */
	    expSect->data[nameSpaceStart] = 0;
	    nameSpaceStart++;
	}
    }

    /* store library name */
    for (j = 0; j < namelen; j++)
    {
	expSect->data[nameSpaceStart + j] = name[j];
    }
    if (namelen)
    {
	expSect->data[nameSpaceStart + j] = 0;
	/* store name RVA */
	expSect->data[12] = (nameSpaceStart + expSect->base - imageBase) & 0xff;
	expSect->data[13] = ((nameSpaceStart + expSect->base - imageBase) >> 8) & 0xff;
	expSect->data[14] = ((nameSpaceStart + expSect->base - imageBase) >> 16) & 0xff;
	expSect->data[15] = ((nameSpaceStart + expSect->base - imageBase) >> 24) & 0xff;
    }

    expSect->datmask = (PUCHAR)checkMalloc((expSect->length + 7) / 8);
    for (i = 0; i < (expSect->length + 7) / 8; i++)
    {
	expSect->datmask[i] = 0xff;
    }

    return;
}

void BuildPEResources(long sectNum, PUCHAR objectTable)
{
    long i, j;
    UINT k;
    SEG *ressect;
    RESOURCE curres;
    int numtypes, numnamedtypes;
    int numPairs, numnames, numids;
    UINT nameSize, dataSize;
    UINT tableSize, dataListSize;
    UINT namePos, dataPos, tablePos, dataListPos;
    UINT curTypePos = 0, curNamePos = 0, curLangPos = 0;
    char *curTypeName = NULL, *curName = NULL;
    int curTypeId = -1, curId = -1;

    if ((sectNum < 0) || !rescount)
	return;

    objectTable += PE_OBJECTENTRY_SIZE * sectNum; /* point to import object entry */
    k = objectTable[-PE_OBJECTENTRY_SIZE + 20];	  /* get physical start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 21] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 22] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 23] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 16]; /* add physical length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 17] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 18] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 19] << 24;

    k += fileAlign - 1;
    k &= (0xffffffff - (fileAlign - 1)); /* aligned */

    /* k is now physical location of this object */

    objectTable[20] = (k) & 0xff; /* store physical file offset */
    objectTable[21] = (k >> 8) & 0xff;
    objectTable[22] = (k >> 16) & 0xff;
    objectTable[23] = (k >> 24) & 0xff;

    k = objectTable[-PE_OBJECTENTRY_SIZE + 12]; /* get virtual start of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 13] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 14] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 15] << 24;

    k += objectTable[-PE_OBJECTENTRY_SIZE + 8]; /* add virtual length of prev object */
    k += objectTable[-PE_OBJECTENTRY_SIZE + 9] << 8;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 10] << 16;
    k += objectTable[-PE_OBJECTENTRY_SIZE + 11] << 24;

    /* store base address (RVA) of section */
    objectTable[12] = (k) & 0xff;
    objectTable[13] = (k >> 8) & 0xff;
    objectTable[14] = (k >> 16) & 0xff;
    objectTable[15] = (k >> 24) & 0xff;

    ressect = outlist[sectNum];
    ressect->base = k; /* get base RVA of section */

    /* sort into type-id order */
    for (i = 1; i < rescount; i++)
    {
	curres = resource[i];
	for (j = i - 1; j >= 0; j--)
	{
	    if (resource[j].typename)
	    {
		if (!curres.typename)
		    break;
		if (wstricmp(curres.typename, resource[j].typename) > 0)
		    break;
		if (wstricmp(curres.typename, resource[j].typename) == 0)
		{
		    if (resource[j].name)
		    {
			if (!curres.name)
			    break;
			if (wstricmp(curres.name, resource[j].name) > 0)
			    break;
			if (wstricmp(curres.name, resource[j].name) == 0)
			{
			    if (resource[j].languageid > curres.languageid)
				break;
			    if (resource[j].languageid == curres.languageid)
			    {
				printf("Error duplicate resource ID\n");
				exit(1);
			    }
			}
		    }
		    else
		    {
			if (!curres.name)
			{
			    if (curres.id > resource[j].id)
				break;
			    if (curres.id == resource[j].id)
			    {
				if (resource[j].languageid > curres.languageid)
				    break;
				if (resource[j].languageid == curres.languageid)
				{
				    printf("Error duplicate resource ID\n");
				    exit(1);
				}
			    }
			}
		    }
		}
	    }
	    else
	    {
		if (!curres.typename)
		{
		    if (curres.typeid > resource[j].typeid)
			break;
		    if (curres.typeid == resource[j].typeid)
		    {
			if (resource[j].name)
			{
			    if (!curres.name)
				break;
			    if (wstricmp(curres.name, resource[j].name) > 0)
				break;
			    if (wstricmp(curres.name, resource[j].name) == 0)
			    {
				if (resource[j].languageid > curres.languageid)
				    break;
				if (resource[j].languageid == curres.languageid)
				{
				    printf("Error duplicate resource ID\n");
				    exit(1);
				}
			    }
			}
			else
			{
			    if (!curres.name)
			    {
				if (curres.id > resource[j].id)
				    break;
				if (curres.id == resource[j].id)
				{
				    if (resource[j].languageid > curres.languageid)
					break;
				    if (resource[j].languageid == curres.languageid)
				    {
					printf("Error duplicate resource ID\n");
					exit(1);
				    }
				}
			    }
			}
		    }
		}
	    }
	    resource[j + 1] = resource[j];
	}
	j++;
	resource[j] = curres;
    }

    nameSize = 0;
    dataSize = 0;
    for (i = 0; i < rescount; i++)
    {
	if (resource[i].typename)
	{
	    nameSize += 2 + 2 * wstrlen(resource[i].typename);
	}
	if (resource[i].name)
	{
	    nameSize += 2 + 2 * wstrlen(resource[i].name);
	}
	dataSize += resource[i].length + 3;
	dataSize &= 0xfffffffc;
    }

    /* count named types */
    numnamedtypes = 0;
    numPairs = rescount;
    for (i = 0; i < rescount; i++)
    {
	if (!resource[i].typename)
	    break;
	if ((i > 0) && !wstricmp(resource[i].typename, resource[i - 1].typename))
	{
	    if (resource[i].name)
	    {
		if (wstricmp(resource[i].name, resource[i - 1].name) == 0)
		    numPairs--;
	    }
	    else
	    {
		if (!resource[i - 1].name && (resource[i].id == resource[i - 1].id))
		    numPairs--;
	    }
	    continue;
	}
	numnamedtypes++;
    }
    numtypes = numnamedtypes;
    for (; i < rescount; i++)
    {
	if ((i > 0) && !resource[i - 1].typename && (resource[i].typeid == resource[i - 1].typeid))
	{
	    if (resource[i].name)
	    {
		if (wstricmp(resource[i].name, resource[i - 1].name) == 0)
		    numPairs--;
	    }
	    else
	    {
		if (!resource[i - 1].name && (resource[i].id == resource[i - 1].id))
		    numPairs--;
	    }
	    continue;
	}
	numtypes++;
    }

    tableSize = (rescount + numtypes + numPairs) * PE_RESENTRY_SIZE +
		(numtypes + numPairs + 1) * PE_RESDIR_SIZE;
    dataListSize = rescount * PE_RESDATAENTRY_SIZE;

    dataListPos = tableSize;
    namePos = tableSize + dataListSize;
    dataPos = tableSize + nameSize + dataListSize + 3;
    dataPos &= 0xfffffffc;

    ressect->length = dataPos + dataSize;

    ressect->data = (PUCHAR)checkMalloc(ressect->length);

    ressect->datmask = (PUCHAR)checkMalloc((ressect->length + 7) / 8);

    /* empty section to start with */
    for (i = 0; i < ressect->length; i++)
	ressect->data[i] = 0;

    /* build master directory */
    /* store time/date of creation */
    k = (UINT)time(NULL);
    ressect->data[4] = k & 0xff;
    ressect->data[5] = (k >> 8) & 0xff;
    ressect->data[6] = (k >> 16) & 0xff;
    ressect->data[7] = (k >> 24) & 0xff;

    ressect->data[12] = numnamedtypes & 0xff;
    ressect->data[13] = (numnamedtypes >> 8) & 0xff;
    ressect->data[14] = (numtypes - numnamedtypes) & 0xff;
    ressect->data[15] = ((numtypes - numnamedtypes) >> 8) & 0xff;

    tablePos = 16 + numtypes * PE_RESENTRY_SIZE;
    curTypePos = 16;
    curTypeName = NULL;
    curTypeId = -1;
    for (i = 0; i < rescount; i++)
    {
	if (!(resource[i].typename && curTypeName &&
	      !wstricmp(resource[i].typename, curTypeName)) &&
	    !(!resource[i].typename && !curTypeName && curTypeId == resource[i].typeid))
	{
	    if (resource[i].typename)
	    {
		ressect->data[curTypePos] = (namePos) & 0xff;
		ressect->data[curTypePos + 1] = ((namePos) >> 8) & 0xff;
		ressect->data[curTypePos + 2] = ((namePos) >> 16) & 0xff;
		ressect->data[curTypePos + 3] = (((namePos) >> 24) & 0xff) | 0x80;
		curTypeName = resource[i].typename;
		k = wstrlen(curTypeName);
		ressect->data[namePos] = k & 0xff;
		ressect->data[namePos + 1] = (k >> 8) & 0xff;
		namePos += 2;
		memcpy(ressect->data + namePos, curTypeName, k * 2);
		namePos += k * 2;
		curTypeId = -1;
	    }
	    else
	    {
		curTypeName = NULL;
		curTypeId = resource[i].typeid;
		ressect->data[curTypePos] = curTypeId & 0xff;
		ressect->data[curTypePos + 1] = (curTypeId >> 8) & 0xff;
		ressect->data[curTypePos + 2] = (curTypeId >> 16) & 0xff;
		ressect->data[curTypePos + 3] = (curTypeId >> 24) & 0xff;
	    }
	    ressect->data[curTypePos + 4] = (tablePos) & 0xff;
	    ressect->data[curTypePos + 5] = ((tablePos) >> 8) & 0xff;
	    ressect->data[curTypePos + 6] = ((tablePos) >> 16) & 0xff;
	    ressect->data[curTypePos + 7] = (((tablePos) >> 24) & 0x7f) | 0x80;

	    numnames = numids = 0;
	    for (j = i; j < rescount; j++)
	    {
		if (resource[i].typename)
		{
		    if (!resource[j].typename)
			break;
		    if (wstricmp(resource[i].typename, resource[j].typename) != 0)
			break;
		}
		else
		{
		    if (resource[j].typeid != resource[i].typeid)
			break;
		}
		if (resource[j].name)
		{
		    if (((j > i) && (wstricmp(resource[j].name, resource[j - 1].name) != 0)) ||
			(j == i))
			numnames++;
		}
		else
		{
		    if (((j > i) &&
			 (resource[j - 1].name || (resource[j].id != resource[j - 1].id))) ||
			(j == i))
			numids++;
		}
	    }
	    /* store time/date of creation */
	    k = (UINT)time(NULL);
	    ressect->data[tablePos + 4] = k & 0xff;
	    ressect->data[tablePos + 5] = (k >> 8) & 0xff;
	    ressect->data[tablePos + 6] = (k >> 16) & 0xff;
	    ressect->data[tablePos + 7] = (k >> 24) & 0xff;

	    ressect->data[tablePos + 12] = numnames & 0xff;
	    ressect->data[tablePos + 13] = (numnames >> 8) & 0xff;
	    ressect->data[tablePos + 14] = numids & 0xff;
	    ressect->data[tablePos + 15] = (numids >> 8) & 0xff;

	    curNamePos = tablePos + PE_RESDIR_SIZE;
	    curName = NULL;
	    curId = -1;
	    tablePos += PE_RESDIR_SIZE + (numids + numnames) * PE_RESENTRY_SIZE;
	    curTypePos += PE_RESENTRY_SIZE;
	}
	if (!(resource[i].name && curName && !wstricmp(resource[i].name, curName)) &&
	    !(!resource[i].name && !curName && curId == resource[i].id))
	{
	    if (resource[i].name)
	    {
		ressect->data[curNamePos] = (namePos) & 0xff;
		ressect->data[curNamePos + 1] = ((namePos) >> 8) & 0xff;
		ressect->data[curNamePos + 2] = ((namePos) >> 16) & 0xff;
		ressect->data[curNamePos + 3] = (((namePos) >> 24) & 0xff) | 0x80;
		curName = resource[i].name;
		k = wstrlen(curName);
		ressect->data[namePos] = k & 0xff;
		ressect->data[namePos + 1] = (k >> 8) & 0xff;
		namePos += 2;
		memcpy(ressect->data + namePos, curName, k * 2);
		namePos += k * 2;
		curId = -1;
	    }
	    else
	    {
		curName = NULL;
		curId = resource[i].id;
		ressect->data[curNamePos] = curId & 0xff;
		ressect->data[curNamePos + 1] = (curId >> 8) & 0xff;
		ressect->data[curNamePos + 2] = (curId >> 16) & 0xff;
		ressect->data[curNamePos + 3] = (curId >> 24) & 0xff;
	    }
	    ressect->data[curNamePos + 4] = (tablePos) & 0xff;
	    ressect->data[curNamePos + 5] = ((tablePos) >> 8) & 0xff;
	    ressect->data[curNamePos + 6] = ((tablePos) >> 16) & 0xff;
	    ressect->data[curNamePos + 7] = (((tablePos) >> 24) & 0x7f) | 0x80;

	    numids = 0;
	    for (j = i; j < rescount; j++)
	    {
		if (resource[i].typename)
		{
		    if (!resource[j].typename)
			break;
		    if (wstricmp(resource[i].typename, resource[j].typename) != 0)
			break;
		}
		else
		{
		    if (resource[j].typeid != resource[i].typeid)
			break;
		}
		if (resource[i].name)
		{
		    if (!resource[j].name)
			break;
		    if (wstricmp(resource[j].name, resource[i].name) != 0)
			break;
		}
		else
		{
		    if (resource[j].id != resource[i].id)
			break;
		}
		numids++;
	    }
	    numnames = 0; /* no names for languages */
	    /* store time/date of creation */
	    k = (UINT)time(NULL);
	    ressect->data[tablePos + 4] = k & 0xff;
	    ressect->data[tablePos + 5] = (k >> 8) & 0xff;
	    ressect->data[tablePos + 6] = (k >> 16) & 0xff;
	    ressect->data[tablePos + 7] = (k >> 24) & 0xff;

	    ressect->data[tablePos + 12] = numnames & 0xff;
	    ressect->data[tablePos + 13] = (numnames >> 8) & 0xff;
	    ressect->data[tablePos + 14] = numids & 0xff;
	    ressect->data[tablePos + 15] = (numids >> 8) & 0xff;

	    curLangPos = tablePos + PE_RESDIR_SIZE;
	    tablePos += PE_RESDIR_SIZE + numids * PE_RESENTRY_SIZE;
	    curNamePos += PE_RESENTRY_SIZE;
	}
	ressect->data[curLangPos] = resource[i].languageid & 0xff;
	ressect->data[curLangPos + 1] = (resource[i].languageid >> 8) & 0xff;
	ressect->data[curLangPos + 2] = (resource[i].languageid >> 16) & 0xff;
	ressect->data[curLangPos + 3] = (resource[i].languageid >> 24) & 0xff;

	ressect->data[curLangPos + 4] = (dataListPos) & 0xff;
	ressect->data[curLangPos + 5] = ((dataListPos) >> 8) & 0xff;
	ressect->data[curLangPos + 6] = ((dataListPos) >> 16) & 0xff;
	ressect->data[curLangPos + 7] = (((dataListPos) >> 24) & 0x7f);
	curLangPos += PE_RESENTRY_SIZE;

	ressect->data[dataListPos] = (dataPos + ressect->base) & 0xff;
	ressect->data[dataListPos + 1] = ((dataPos + ressect->base) >> 8) & 0xff;
	ressect->data[dataListPos + 2] = ((dataPos + ressect->base) >> 16) & 0xff;
	ressect->data[dataListPos + 3] = ((dataPos + ressect->base) >> 24) & 0xff;
	ressect->data[dataListPos + 4] = resource[i].length & 0xff;
	ressect->data[dataListPos + 5] = (resource[i].length >> 8) & 0xff;
	ressect->data[dataListPos + 6] = (resource[i].length >> 16) & 0xff;
	ressect->data[dataListPos + 7] = (resource[i].length >> 24) & 0xff;
	memcpy(ressect->data + dataPos, resource[i].data, resource[i].length);
	dataPos += resource[i].length + 3;
	dataPos &= 0xfffffffc;
	dataListPos += PE_RESDATAENTRY_SIZE;
    }

    /* mark whole section as required output */
    for (i = 0; i < (ressect->length + 7) / 8; i++)
	ressect->datmask[i] = 0xff;

    /* update object table */
    ressect->base += imageBase;

    k = ressect->length;
    k += objectAlign - 1;
    k &= (0xffffffff - (objectAlign - 1));
    ressect->virtualSize = k;
    objectTable[8] = k & 0xff; /* store virtual size (in memory) of segment */
    objectTable[9] = (k >> 8) & 0xff;
    objectTable[10] = (k >> 16) & 0xff;
    objectTable[11] = (k >> 24) & 0xff;

    k = ressect->length;
    objectTable[16] = (k) & 0xff; /* store initialised data size */
    objectTable[17] = (k >> 8) & 0xff;
    objectTable[18] = (k >> 16) & 0xff;
    objectTable[19] = (k >> 16) & 0xff;

    return;
}

void getStub(PUCHAR *pstubData, UINT *pstubSize)
{
    FILE *f;
    unsigned char headbuf[0x1c];
    PUCHAR buf;
    UINT imageSize;
    UINT headerSize;
    UINT relocSize;
    UINT relocStart;
    int i;

    if (stubName)
    {
	f = fopen(stubName, "rb");
	if (!f)
	{
	    printf("Unable to open stub file %s\n", stubName);
	    exit(1);
	}
	if (fread(headbuf, 1, 0x1c, f) != 0x1c) /* try and read 0x1c bytes */
	{
	    printf("Error reading from file %s\n", stubName);
	    exit(1);
	}
	if ((headbuf[0] != 0x4d) || (headbuf[1] != 0x5a))
	{
	    printf("Stub not valid EXE file\n");
	    exit(1);
	}
	/* get size of image */
	imageSize = headbuf[2] + (headbuf[3] << 8) + ((headbuf[4] + (headbuf[5] << 8)) << 9);
	if (imageSize % 512)
	    imageSize -= 512;
	headerSize = (headbuf[8] + (headbuf[9] << 8)) << 4;
	relocSize = (headbuf[6] + (headbuf[7] << 8)) << 2;
	imageSize -= headerSize;
	printf("imageSize=%u\n", imageSize);
	printf("header=%u\n", headerSize);
	printf("reloc=%u\n", relocSize);

	/* allocate buffer for load image */
	buf = (PUCHAR)checkMalloc(imageSize + 0x40 + ((relocSize + 0xf) & 0xfffffff0));
	/* copy header */
	for (i = 0; i < 0x1c; i++)
	    buf[i] = headbuf[i];

	relocStart = headbuf[0x18] + (headbuf[0x19] << 8);
	/* load relocs */
	fseek(f, relocStart, SEEK_SET);
	if (fread(buf + 0x40, 1, relocSize, f) != relocSize)
	{
	    printf("Error reading from file %s\n", stubName);
	    exit(1);
	}

	/* paragraph align reloc size */
	relocSize += 0xf;
	relocSize &= 0xfffffff0;

	/* move to start of data */
	fseek(f, headerSize, SEEK_SET);
	/* new header is 4 paragraphs long + relocSize*/
	relocSize >>= 4;
	relocSize += 4;
	buf[8] = relocSize & 0xff;
	buf[9] = (relocSize >> 8) & 0xff;
	headerSize = relocSize << 4;
	/* load data into correct position */
	if (fread(buf + headerSize, 1, imageSize, f) != imageSize)
	{
	    printf("Error reading from file %s\n", stubName);
	    exit(1);
	}
	/* relocations start at 0x40 */
	buf[0x18] = 0x40;
	buf[0x19] = 0;
	imageSize += headerSize; /* total file size */
	/* store pointer and size */
	(*pstubData) = buf;
	(*pstubSize) = imageSize;
	i = imageSize % 512;		    /* size mod 512 */
	imageSize = (imageSize + 511) >> 9; /* number of 512-byte pages */
	buf[2] = i & 0xff;
	buf[3] = (i >> 8) & 0xff;
	buf[4] = imageSize & 0xff;
	buf[5] = (imageSize >> 8) & 0xff;
    }
    else
    {
	(*pstubData) = defaultStub;
	(*pstubSize) = defaultStubSize;
    }
}

void OutputWin32file(PCHAR outname)
{
    long i, j, k;
    UINT started;
    UINT lastout;
    PUCHAR headbuf;
    PUCHAR stubData;
    FILE *outfile;
    UINT headerSize;
    UINT headerVirtSize;
    UINT stubSize;
    long nameIndex;
    UINT sectionStart;
    UINT headerStart;
    long relocSectNum, importSectNum, exportSectNum, resourceSectNum;
    UINT codeBase = 0;
    UINT dataBase = 0;
    UINT codeSize = 0;
    UINT dataSize = 0;

    printf("Generating PE file %s\n", outname);

    errcount = 0;

    /* allocate section entries for imports, exports and relocs if required */
    if (impsreq)
    {
	importSectNum = createOutputSection("imports", WINF_INITDATA | WINF_SHARED | WINF_READABLE);
    }
    else
    {
	importSectNum = -1;
    }

    if (expcount)
    {
	exportSectNum = createOutputSection("exports", WINF_INITDATA | WINF_SHARED | WINF_READABLE);
    }
    else
    {
	exportSectNum = -1;
    }

    /* Windows NT requires a reloc section to relocate image files, even */
    /* if it contains no actual fixups */
    relocSectNum = createOutputSection("relocs", WINF_INITDATA | WINF_SHARED | WINF_DISCARDABLE |
						     WINF_READABLE);

    if (rescount)
    {
	resourceSectNum =
	    createOutputSection("resource", WINF_INITDATA | WINF_SHARED | WINF_READABLE);
    }
    else
    {
	resourceSectNum = -1;
    }

    /* build header */
    getStub(&stubData, &stubSize);

    headerStart = stubSize; /* get start of PE header */
    headerStart += 7;
    headerStart &= 0xfffffff8; /* align PE header to 8 byte boundary */

    headerSize = PE_HEADBUF_SIZE + outcount * PE_OBJECTENTRY_SIZE + stubSize;
    headerVirtSize = headerSize + (objectAlign - 1);
    headerVirtSize &= (0xffffffff - (objectAlign - 1));
    headerSize += (fileAlign - 1);
    headerSize &= (0xffffffff - (fileAlign - 1));

    headbuf = checkMalloc(headerSize);

    for (i = 0; i < headerSize; i++)
    {
	headbuf[i] = 0;
    }

    for (i = 0; i < stubSize; i++) /* copy stub file */
	headbuf[i] = stubData[i];

    headbuf[0x3c] = headerStart & 0xff; /* store pointer to PE header */
    headbuf[0x3d] = (headerStart >> 8) & 0xff;
    headbuf[0x3e] = (headerStart >> 16) & 0xff;
    headbuf[0x3f] = (headerStart >> 24) & 0xff;

    headbuf[headerStart + PE_SIGNATURE] = 0x50;	    /* P */
    headbuf[headerStart + PE_SIGNATURE + 1] = 0x45; /* E */
    headbuf[headerStart + PE_SIGNATURE + 2] = 0x00; /* 0 */
    headbuf[headerStart + PE_SIGNATURE + 3] = 0x00; /* 0 */
    headbuf[headerStart + PE_MACHINEID] = PE_INTEL386 & 0xff;
    headbuf[headerStart + PE_MACHINEID + 1] = (PE_INTEL386 >> 8) & 0xff;
    /* store time/date of creation */
    k = (UINT)time(NULL);
    headbuf[headerStart + PE_DATESTAMP] = k & 0xff;
    headbuf[headerStart + PE_DATESTAMP + 1] = (k >> 8) & 0xff;
    headbuf[headerStart + PE_DATESTAMP + 2] = (k >> 16) & 0xff;
    headbuf[headerStart + PE_DATESTAMP + 3] = (k >> 24) & 0xff;

    headbuf[headerStart + PE_HDRSIZE] = PE_OPTIONAL_HEADER_SIZE & 0xff;
    headbuf[headerStart + PE_HDRSIZE + 1] = (PE_OPTIONAL_HEADER_SIZE >> 8) & 0xff;

    i = PE_FILE_EXECUTABLE | PE_FILE_32BIT; /* get flags */
    if (buildDll)
    {
	i |= PE_FILE_LIBRARY; /* if DLL, flag it */
    }
    headbuf[headerStart + PE_FLAGS] = i & 0xff; /* store them */
    headbuf[headerStart + PE_FLAGS + 1] = (i >> 8) & 0xff;

    headbuf[headerStart + PE_MAGIC] = PE_MAGICNUM & 0xff; /* store magic number */
    headbuf[headerStart + PE_MAGIC + 1] = (PE_MAGICNUM >> 8) & 0xff;

    headbuf[headerStart + PE_IMAGEBASE] = imageBase & 0xff; /* store image base */
    headbuf[headerStart + PE_IMAGEBASE + 1] = (imageBase >> 8) & 0xff;
    headbuf[headerStart + PE_IMAGEBASE + 2] = (imageBase >> 16) & 0xff;
    headbuf[headerStart + PE_IMAGEBASE + 3] = (imageBase >> 24) & 0xff;

    headbuf[headerStart + PE_FILEALIGN] = fileAlign & 0xff; /* store image base */
    headbuf[headerStart + PE_FILEALIGN + 1] = (fileAlign >> 8) & 0xff;
    headbuf[headerStart + PE_FILEALIGN + 2] = (fileAlign >> 16) & 0xff;
    headbuf[headerStart + PE_FILEALIGN + 3] = (fileAlign >> 24) & 0xff;

    headbuf[headerStart + PE_OBJECTALIGN] = objectAlign & 0xff; /* store image base */
    headbuf[headerStart + PE_OBJECTALIGN + 1] = (objectAlign >> 8) & 0xff;
    headbuf[headerStart + PE_OBJECTALIGN + 2] = (objectAlign >> 16) & 0xff;
    headbuf[headerStart + PE_OBJECTALIGN + 3] = (objectAlign >> 24) & 0xff;

    headbuf[headerStart + PE_OSMAJOR] = osMajor;
    headbuf[headerStart + PE_OSMINOR] = osMinor;

    headbuf[headerStart + PE_SUBSYSMAJOR] = subsysMajor;
    headbuf[headerStart + PE_SUBSYSMINOR] = subsysMinor;

    headbuf[headerStart + PE_SUBSYSTEM] = subSystem & 0xff;
    headbuf[headerStart + PE_SUBSYSTEM + 1] = (subSystem >> 8) & 0xff;

    headbuf[headerStart + PE_NUMRVAS] = PE_NUM_VAS & 0xff;
    headbuf[headerStart + PE_NUMRVAS + 1] = (PE_NUM_VAS >> 8) & 0xff;

    headbuf[headerStart + PE_HEADERSIZE] = headerSize & 0xff;
    headbuf[headerStart + PE_HEADERSIZE + 1] = (headerSize >> 8) & 0xff;
    headbuf[headerStart + PE_HEADERSIZE + 2] = (headerSize >> 16) & 0xff;
    headbuf[headerStart + PE_HEADERSIZE + 3] = (headerSize >> 24) & 0xff;

    headbuf[headerStart + PE_HEAPSIZE] = heapSize & 0xff;
    headbuf[headerStart + PE_HEAPSIZE + 1] = (heapSize >> 8) & 0xff;
    headbuf[headerStart + PE_HEAPSIZE + 2] = (heapSize >> 16) & 0xff;
    headbuf[headerStart + PE_HEAPSIZE + 3] = (heapSize >> 24) & 0xff;

    headbuf[headerStart + PE_HEAPCOMMSIZE] = heapCommitSize & 0xff;
    headbuf[headerStart + PE_HEAPCOMMSIZE + 1] = (heapCommitSize >> 8) & 0xff;
    headbuf[headerStart + PE_HEAPCOMMSIZE + 2] = (heapCommitSize >> 16) & 0xff;
    headbuf[headerStart + PE_HEAPCOMMSIZE + 3] = (heapCommitSize >> 24) & 0xff;

    headbuf[headerStart + PE_STACKSIZE] = stackSize & 0xff;
    headbuf[headerStart + PE_STACKSIZE + 1] = (stackSize >> 8) & 0xff;
    headbuf[headerStart + PE_STACKSIZE + 2] = (stackSize >> 16) & 0xff;
    headbuf[headerStart + PE_STACKSIZE + 3] = (stackSize >> 24) & 0xff;

    headbuf[headerStart + PE_STACKCOMMSIZE] = stackCommitSize & 0xff;
    headbuf[headerStart + PE_STACKCOMMSIZE + 1] = (stackCommitSize >> 8) & 0xff;
    headbuf[headerStart + PE_STACKCOMMSIZE + 2] = (stackCommitSize >> 16) & 0xff;
    headbuf[headerStart + PE_STACKCOMMSIZE + 3] = (stackCommitSize >> 24) & 0xff;

    /* shift segment start addresses up into place and build section headers */
    sectionStart = headerSize;
    j = headerStart + PE_HEADBUF_SIZE;

    for (i = 0; i < outcount; i++, j += PE_OBJECTENTRY_SIZE)
    {
	nameIndex = outlist[i]->nameindex;
	if (nameIndex >= 0)
	{
	    for (k = 0; (k < strlen(namelist[nameIndex])) && (k < 8); k++)
	    {
		headbuf[j + k] = namelist[nameIndex][k];
	    }
	}
	k = outlist[i]->virtualSize; /* get virtual size */
	headbuf[j + 8] = k & 0xff;   /* store virtual size (in memory) of segment */
	headbuf[j + 9] = (k >> 8) & 0xff;
	headbuf[j + 10] = (k >> 16) & 0xff;
	headbuf[j + 11] = (k >> 24) & 0xff;

	if (!padsegments) /* if not padding segments, reduce space consumption */
	{
	    for (k = outlist[i]->length - 1; (k >= 0) && !GetNbit(outlist[i]->datmask, k); k--)
		;
	    k++; /* k=initialised length */
	}
	headbuf[j + 16] = (k) & 0xff; /* store initialised data size */
	headbuf[j + 17] = (k >> 8) & 0xff;
	headbuf[j + 18] = (k >> 16) & 0xff;
	headbuf[j + 19] = (k >> 24) & 0xff;

	headbuf[j + 20] = (sectionStart) & 0xff; /* store physical file offset */
	headbuf[j + 21] = (sectionStart >> 8) & 0xff;
	headbuf[j + 22] = (sectionStart >> 16) & 0xff;
	headbuf[j + 23] = (sectionStart >> 24) & 0xff;

	k += fileAlign - 1;
	k &= (0xffffffff - (fileAlign - 1)); /* aligned initialised length */

	sectionStart += k; /* update section start address for next section */

	outlist[i]->base += headerVirtSize + imageBase;
	headbuf[j + 12] = (outlist[i]->base - imageBase) & 0xff;
	headbuf[j + 13] = ((outlist[i]->base - imageBase) >> 8) & 0xff;
	headbuf[j + 14] = ((outlist[i]->base - imageBase) >> 16) & 0xff;
	headbuf[j + 15] = ((outlist[i]->base - imageBase) >> 24) & 0xff;

	k = (outlist[i]->winFlags ^ WINF_NEG_FLAGS) &
	    WINF_IMAGE_FLAGS;	      /* get characteristice for section */
	headbuf[j + 36] = (k) & 0xff; /* store characteristics */
	headbuf[j + 37] = (k >> 8) & 0xff;
	headbuf[j + 38] = (k >> 16) & 0xff;
	headbuf[j + 39] = (k >> 24) & 0xff;
    }

    headbuf[headerStart + PE_NUMOBJECTS] = outcount & 0xff; /* store number of sections */
    headbuf[headerStart + PE_NUMOBJECTS + 1] = (outcount >> 8) & 0xff;

    /* build import, export and relocation sections */

    BuildPEImports(importSectNum, headbuf + headerStart + PE_HEADBUF_SIZE);
    BuildPEExports(exportSectNum, headbuf + headerStart + PE_HEADBUF_SIZE, outname);
    BuildPERelocs(relocSectNum, headbuf + headerStart + PE_HEADBUF_SIZE);
    BuildPEResources(resourceSectNum, headbuf + headerStart + PE_HEADBUF_SIZE);

    if (errcount)
    {
	exit(1);
    }

    /* get start address */
    if (gotstart)
    {
	GetFixupTarget(&startaddr, &startaddr.segnum, &startaddr.ofs, TRUE);
	if (errcount)
	{
	    printf("Invalid start address record\n");
	    exit(1);
	}
	i = startaddr.ofs;
	if (startaddr.segnum >= 0)
	{
	    i += seglist[startaddr.segnum]->base;
	}
	i -= imageBase; /* RVA */
	headbuf[headerStart + PE_ENTRYPOINT] = i & 0xff;
	headbuf[headerStart + PE_ENTRYPOINT + 1] = (i >> 8) & 0xff;
	headbuf[headerStart + PE_ENTRYPOINT + 2] = (i >> 16) & 0xff;
	headbuf[headerStart + PE_ENTRYPOINT + 3] = (i >> 24) & 0xff;
	if (buildDll) /* if library */
	{
	    /* flag that entry point should always be called */
	    headbuf[headerStart + PE_DLLFLAGS] = 0xf;
	    headbuf[headerStart + PE_DLLFLAGS + 1] = 0;
	}
    }
    else
    {
	printf("Warning, no entry point specified\n");
    }

    if (importSectNum >= 0) /* if imports, add section entry */
    {
	headbuf[headerStart + PE_IMPORTRVA] = (outlist[importSectNum]->base - imageBase) & 0xff;
	headbuf[headerStart + PE_IMPORTRVA + 1] =
	    ((outlist[importSectNum]->base - imageBase) >> 8) & 0xff;
	headbuf[headerStart + PE_IMPORTRVA + 2] =
	    ((outlist[importSectNum]->base - imageBase) >> 16) & 0xff;
	headbuf[headerStart + PE_IMPORTRVA + 3] =
	    ((outlist[importSectNum]->base - imageBase) >> 24) & 0xff;
	headbuf[headerStart + PE_IMPORTSIZE] = (outlist[importSectNum]->length) & 0xff;
	headbuf[headerStart + PE_IMPORTSIZE + 1] = (outlist[importSectNum]->length >> 8) & 0xff;
	headbuf[headerStart + PE_IMPORTSIZE + 2] = (outlist[importSectNum]->length >> 16) & 0xff;
	headbuf[headerStart + PE_IMPORTSIZE + 3] = (outlist[importSectNum]->length >> 24) & 0xff;
    }
    if (relocSectNum >= 0) /* if relocs, add section entry */
    {
	headbuf[headerStart + PE_FIXUPRVA] = (outlist[relocSectNum]->base - imageBase) & 0xff;
	headbuf[headerStart + PE_FIXUPRVA + 1] =
	    ((outlist[relocSectNum]->base - imageBase) >> 8) & 0xff;
	headbuf[headerStart + PE_FIXUPRVA + 2] =
	    ((outlist[relocSectNum]->base - imageBase) >> 16) & 0xff;
	headbuf[headerStart + PE_FIXUPRVA + 3] =
	    ((outlist[relocSectNum]->base - imageBase) >> 24) & 0xff;
	headbuf[headerStart + PE_FIXUPSIZE] = (outlist[relocSectNum]->length) & 0xff;
	headbuf[headerStart + PE_FIXUPSIZE + 1] = (outlist[relocSectNum]->length >> 8) & 0xff;
	headbuf[headerStart + PE_FIXUPSIZE + 2] = (outlist[relocSectNum]->length >> 16) & 0xff;
	headbuf[headerStart + PE_FIXUPSIZE + 3] = (outlist[relocSectNum]->length >> 24) & 0xff;
    }

    if (exportSectNum >= 0) /* if relocs, add section entry */
    {
	headbuf[headerStart + PE_EXPORTRVA] = (outlist[exportSectNum]->base - imageBase) & 0xff;
	headbuf[headerStart + PE_EXPORTRVA + 1] =
	    ((outlist[exportSectNum]->base - imageBase) >> 8) & 0xff;
	headbuf[headerStart + PE_EXPORTRVA + 2] =
	    ((outlist[exportSectNum]->base - imageBase) >> 16) & 0xff;
	headbuf[headerStart + PE_EXPORTRVA + 3] =
	    ((outlist[exportSectNum]->base - imageBase) >> 24) & 0xff;
	headbuf[headerStart + PE_EXPORTSIZE] = (outlist[exportSectNum]->length) & 0xff;
	headbuf[headerStart + PE_EXPORTSIZE + 1] = (outlist[exportSectNum]->length >> 8) & 0xff;
	headbuf[headerStart + PE_EXPORTSIZE + 2] = (outlist[exportSectNum]->length >> 16) & 0xff;
	headbuf[headerStart + PE_EXPORTSIZE + 3] = (outlist[exportSectNum]->length >> 24) & 0xff;
    }

    if (resourceSectNum >= 0) /* if relocs, add section entry */
    {
	headbuf[headerStart + PE_RESOURCERVA] = (outlist[resourceSectNum]->base - imageBase) & 0xff;
	headbuf[headerStart + PE_RESOURCERVA + 1] =
	    ((outlist[resourceSectNum]->base - imageBase) >> 8) & 0xff;
	headbuf[headerStart + PE_RESOURCERVA + 2] =
	    ((outlist[resourceSectNum]->base - imageBase) >> 16) & 0xff;
	headbuf[headerStart + PE_RESOURCERVA + 3] =
	    ((outlist[resourceSectNum]->base - imageBase) >> 24) & 0xff;
	headbuf[headerStart + PE_RESOURCESIZE] = (outlist[resourceSectNum]->length) & 0xff;
	headbuf[headerStart + PE_RESOURCESIZE + 1] = (outlist[resourceSectNum]->length >> 8) & 0xff;
	headbuf[headerStart + PE_RESOURCESIZE + 2] =
	    (outlist[resourceSectNum]->length >> 16) & 0xff;
	headbuf[headerStart + PE_RESOURCESIZE + 3] =
	    (outlist[resourceSectNum]->length >> 24) & 0xff;
    }

    j = headerStart + PE_HEADBUF_SIZE + (outcount - 1) * PE_OBJECTENTRY_SIZE;

    i = headbuf[j + 12]; /* get base of last section - image base */
    i += headbuf[j + 13] << 8;
    i += headbuf[j + 14] << 16;
    i += headbuf[j + 15] << 24;

    i += headbuf[j + 8]; /* add virtual size of section */
    i += headbuf[j + 9] << 8;
    i += headbuf[j + 10] << 16;
    i += headbuf[j + 11] << 24;

    headbuf[headerStart + PE_IMAGESIZE] = i & 0xff;
    headbuf[headerStart + PE_IMAGESIZE + 1] = (i >> 8) & 0xff;
    headbuf[headerStart + PE_IMAGESIZE + 2] = (i >> 16) & 0xff;
    headbuf[headerStart + PE_IMAGESIZE + 3] = (i >> 24) & 0xff;

    headbuf[headerStart + PE_CODEBASE] = codeBase & 0xff;
    headbuf[headerStart + PE_CODEBASE + 1] = (codeBase >> 8) & 0xff;
    headbuf[headerStart + PE_CODEBASE + 2] = (codeBase >> 16) & 0xff;
    headbuf[headerStart + PE_CODEBASE + 3] = (codeBase >> 24) & 0xff;

    headbuf[headerStart + PE_DATABASE] = dataBase & 0xff;
    headbuf[headerStart + PE_DATABASE + 1] = (dataBase >> 8) & 0xff;
    headbuf[headerStart + PE_DATABASE + 2] = (dataBase >> 16) & 0xff;
    headbuf[headerStart + PE_DATABASE + 3] = (dataBase >> 24) & 0xff;

    headbuf[headerStart + PE_CODESIZE] = codeSize & 0xff;
    headbuf[headerStart + PE_CODESIZE + 1] = (codeSize >> 8) & 0xff;
    headbuf[headerStart + PE_CODESIZE + 2] = (codeSize >> 16) & 0xff;
    headbuf[headerStart + PE_CODESIZE + 3] = (codeSize >> 24) & 0xff;

    headbuf[headerStart + PE_INITDATASIZE] = dataSize & 0xff;
    headbuf[headerStart + PE_INITDATASIZE + 1] = (dataSize >> 8) & 0xff;
    headbuf[headerStart + PE_INITDATASIZE + 2] = (dataSize >> 16) & 0xff;
    headbuf[headerStart + PE_INITDATASIZE + 3] = (dataSize >> 24) & 0xff;

    /* zero out section start for all zero-length segments */
    j = headerStart + PE_HEADBUF_SIZE;
    for (i = 0; i < outcount; i++, j += PE_OBJECTENTRY_SIZE)
    {
	/* check if size in file is zero */
	k = headbuf[j + 16] | headbuf[j + 17] | headbuf[j + 18] | headbuf[j + 19];
	if (!k)
	{
	    /* if so, zero section start */
	    headbuf[j + 20] = headbuf[j + 21] = headbuf[j + 22] = headbuf[j + 23] = 0;
	}
    }

    if (errcount != 0)
    {
	exit(1);
    }

    outfile = fopen(outname, "wb");
    if (!outfile)
    {
	printf("Error writing to file %s\n", outname);
	exit(1);
    }

    for (i = 0; i < headerSize; i++)
    {
	fputc(headbuf[i], outfile);
    }

    started = lastout = imageBase + headerVirtSize;

    for (i = 0; i < outcount; i++)
    {
	if (outlist[i] && ((outlist[i]->attr & SEG_ALIGN) != SEG_ABS))
	{
	    /* ensure section is aligned to file-Align */
	    while (ftell(outfile) & (fileAlign - 1))
	    {
		fputc(0, outfile);
	    }
	    if (started > outlist[i]->base)
	    {
		printf("Segment overlap\n");
		printf("Next addr=%08X,base=%08X\n", started, outlist[i]->base);
		fclose(outfile);
		exit(1);
	    }
	    if (padsegments)
	    {
		while (started < outlist[i]->base)
		{
		    fputc(0, outfile);
		    started++;
		}
	    }
	    else
	    {
		started = outlist[i]->base;
	    }
	    for (j = 0; j < outlist[i]->length; j++)
	    {
		if (GetNbit(outlist[i]->datmask, j))
		{
		    for (; lastout < started; lastout++)
		    {
			fputc(0, outfile);
		    }
		    fputc(outlist[i]->data[j], outfile);
		    lastout = started + 1;
		}
		else if (padsegments)
		{
		    fputc(0, outfile);
		    lastout = started + 1;
		}
		started++;
	    }
	    started = lastout = outlist[i]->base + outlist[i]->virtualSize;
	}
    }

    fclose(outfile);
}
