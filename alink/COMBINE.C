#include "ALINK.H"

void fixpubsegs(int src, int dest, UINT shift)
{
    UINT i, j;
    PPUBLIC q;

    for (i = 0; i < pubcount; ++i)
    {
	for (j = 0; j < publics[i].count; ++j)
	{
	    q = (PPUBLIC)publics[i].object[j];
	    if (q->segnum == src)
	    {
		q->segnum = dest;
		q->ofs += shift;
	    }
	}
    }
}

void fixpubgrps(int src, int dest)
{
    UINT i, j;
    PPUBLIC q;

    for (i = 0; i < pubcount; ++i)
    {
	for (j = 0; j < publics[i].count; ++j)
	{
	    q = (PPUBLIC)publics[i].object[j];
	    if (q->grpnum == src)
	    {
		q->grpnum = dest;
	    }
	}
    }
}

void redirect_segment(long dest, long src)
{
    UINT k, n;

    fixpubsegs(src, dest, 0);

    for (k = 0; k < fixcount; k++)
    {
	if (relocs[k]->segnum == src)
	{
	    relocs[k]->segnum = dest;
	}
	if ((relocs[k]->ttype == REL_SEGDISP) || (relocs[k]->ttype == REL_SEGONLY))
	{
	    if (relocs[k]->target == src)
	    {
		relocs[k]->target = dest;
	    }
	}
	if ((relocs[k]->ftype == REL_SEGFRAME) || (relocs[k]->ftype == REL_LILEFRAME))
	{
	    if (relocs[k]->frame == src)
	    {
		relocs[k]->frame = dest;
	    }
	}
    }

    if (gotstart)
    {
	if ((startaddr.ttype == REL_SEGDISP) || (startaddr.ttype == REL_SEGONLY))
	{
	    if (startaddr.target == src)
	    {
		startaddr.target = dest;
	    }
	}
	if ((startaddr.ftype == REL_SEGFRAME) || (startaddr.ftype == REL_LILEFRAME))
	{
	    if (startaddr.frame == src)
	    {
		startaddr.frame = dest;
	    }
	}
    }

    for (k = 0; k < grpcount; k++)
    {
	if (!grplist[k])
	    continue;
	for (n = 0; n < grplist[k]->numsegs; n++)
	{
	    if (grplist[k]->segindex[n] != src)
		continue;
	    grplist[k]->segindex[n] = dest;
	}
    }

    free(seglist[src]->data);
    free(seglist[src]->datmask);
    free(seglist[src]);
    seglist[src] = 0;
}

void combine_segments(long dest, long src)
{
    UINT k, n;
    PUCHAR p, q;
    long a1, a2;

    k = seglist[dest]->length;
    switch (seglist[src]->attr & SEG_ALIGN)
    {
    case SEG_WORD:
	a2 = 2;
	k = (k + 1) & 0xfffffffe;
	break;
    case SEG_PARA:
	a2 = 16;
	k = (k + 0xf) & 0xfffffff0;
	break;
    case SEG_PAGE:
	a2 = 0x100;
	k = (k + 0xff) & 0xffffff00;
	break;
    case SEG_DWORD:
	a2 = 4;
	k = (k + 3) & 0xfffffffc;
	break;
    case SEG_MEMPAGE:
	a2 = 0x1000;
	k = (k + 0xfff) & 0xfffff000;
	break;
    case SEG_8BYTE:
	a2 = 8;
	k = (k + 7) & 0xfffffff8;
	break;
    case SEG_32BYTE:
	a2 = 32;
	k = (k + 31) & 0xffffffe0;
	break;
    case SEG_64BYTE:
	a2 = 64;
	k = (k + 63) & 0xffffffc0;
	break;
    default:
	a2 = 1;
	break;
    }
    switch (seglist[dest]->attr & SEG_ALIGN)
    {
    case SEG_WORD:
	a1 = 2;
	break;
    case SEG_DWORD:
	a1 = 4;
	break;
    case SEG_8BYTE:
	a1 = 8;
	break;
    case SEG_PARA:
	a1 = 16;
	break;
    case SEG_32BYTE:
	a1 = 32;
	break;
    case SEG_64BYTE:
	a1 = 64;
	break;
    case SEG_PAGE:
	a1 = 0x100;
	break;
    case SEG_MEMPAGE:
	a1 = 0x1000;
	break;
    default:
	a1 = 1;
	break;
    }
    seglist[src]->base = k;
    p = checkMalloc(k + seglist[src]->length);
    q = checkMalloc((k + seglist[src]->length + 7) / 8);
    for (k = 0; k < seglist[dest]->length; k++)
    {
	if (GetNbit(seglist[dest]->datmask, k))
	{
	    SetNbit(q, k);
	    p[k] = seglist[dest]->data[k];
	}
	else
	{
	    ClearNbit(q, k);
	}
    }
    for (; k < seglist[src]->base; k++)
    {
	ClearNbit(q, k);
    }
    for (; k < (seglist[src]->base + seglist[src]->length); k++)
    {
	if (GetNbit(seglist[src]->datmask, k - seglist[src]->base))
	{
	    p[k] = seglist[src]->data[k - seglist[src]->base];
	    SetNbit(q, k);
	}
	else
	{
	    ClearNbit(q, k);
	}
    }
    seglist[dest]->length = k;
    if (a2 > a1)
	seglist[dest]->attr = seglist[src]->attr;
    seglist[dest]->winFlags |= seglist[src]->winFlags;
    free(seglist[dest]->data);
    free(seglist[src]->data);
    free(seglist[dest]->datmask);
    free(seglist[src]->datmask);
    seglist[dest]->data = p;
    seglist[dest]->datmask = q;

    fixpubsegs(src, dest, seglist[src]->base);

    for (k = 0; k < fixcount; k++)
    {
	if (relocs[k]->segnum == src)
	{
	    relocs[k]->segnum = dest;
	    relocs[k]->ofs += seglist[src]->base;
	}
	if (relocs[k]->ttype == REL_SEGDISP)
	{
	    if (relocs[k]->target == src)
	    {
		relocs[k]->target = dest;
		relocs[k]->disp += seglist[src]->base;
	    }
	}
	else if (relocs[k]->ttype == REL_SEGONLY)
	{
	    if (relocs[k]->target == src)
	    {
		relocs[k]->target = dest;
		relocs[k]->ttype = REL_SEGDISP;
		relocs[k]->disp = seglist[src]->base;
	    }
	}
	if ((relocs[k]->ftype == REL_SEGFRAME) || (relocs[k]->ftype == REL_LILEFRAME))
	{
	    if (relocs[k]->frame == src)
	    {
		relocs[k]->frame = dest;
	    }
	}
    }

    if (gotstart)
    {
	if (startaddr.ttype == REL_SEGDISP)
	{
	    if (startaddr.target == src)
	    {
		startaddr.target = dest;
		startaddr.disp += seglist[src]->base;
	    }
	}
	else if (startaddr.ttype == REL_SEGONLY)
	{
	    if (startaddr.target == src)
	    {
		startaddr.target = dest;
		startaddr.disp = seglist[src]->base;
		startaddr.ttype = REL_SEGDISP;
	    }
	}
	if ((startaddr.ftype == REL_SEGFRAME) || (startaddr.ftype == REL_LILEFRAME))
	{
	    if (startaddr.frame == src)
	    {
		startaddr.frame = dest;
	    }
	}
    }

    for (k = 0; k < grpcount; k++)
    {
	if (grplist[k])
	{
	    for (n = 0; n < grplist[k]->numsegs; n++)
	    {
		if (grplist[k]->segindex[n] == src)
		{
		    grplist[k]->segindex[n] = dest;
		}
	    }
	}
    }

    free(seglist[src]);
    seglist[src] = 0;
}

void combine_common(long i, long j)
{
    UINT k, n;
    PUCHAR p, q;

    if (seglist[j]->length > seglist[i]->length)
    {
	k = seglist[i]->length;
	seglist[i]->length = seglist[j]->length;
	seglist[j]->length = k;
	p = seglist[i]->data;
	q = seglist[i]->datmask;
	seglist[i]->data = seglist[j]->data;
	seglist[i]->datmask = seglist[j]->datmask;
    }
    else
    {
	p = seglist[j]->data;
	q = seglist[j]->datmask;
    }
    for (k = 0; k < seglist[j]->length; k++)
    {
	if (GetNbit(q, k))
	{
	    if (GetNbit(seglist[i]->datmask, k))
	    {
		if (seglist[i]->data[k] != p[k])
		{
		    ReportError(ERR_OVERWRITE);
		}
	    }
	    else
	    {
		SetNbit(seglist[i]->datmask, k);
		seglist[i]->data[k] = p[k];
	    }
	}
    }
    free(p);
    free(q);

    fixpubsegs(j, i, 0);

    for (k = 0; k < fixcount; k++)
    {
	if (relocs[k]->segnum == j)
	{
	    relocs[k]->segnum = i;
	}
	if (relocs[k]->ttype == REL_SEGDISP)
	{
	    if (relocs[k]->target == j)
	    {
		relocs[k]->target = i;
	    }
	}
	else if (relocs[k]->ttype == REL_SEGONLY)
	{
	    if (relocs[k]->target == j)
	    {
		relocs[k]->target = i;
	    }
	}
	if ((relocs[k]->ftype == REL_SEGFRAME) || (relocs[k]->ftype == REL_LILEFRAME))
	{
	    if (relocs[k]->frame == j)
	    {
		relocs[k]->frame = i;
	    }
	}
    }

    if (gotstart)
    {
	if (startaddr.ttype == REL_SEGDISP)
	{
	    if (startaddr.target == j)
	    {
		startaddr.target = i;
	    }
	}
	else if (startaddr.ttype == REL_SEGONLY)
	{
	    if (startaddr.target == j)
	    {
		startaddr.target = i;
	    }
	}
	if ((startaddr.ftype == REL_SEGFRAME) || (startaddr.ftype == REL_LILEFRAME))
	{
	    if (startaddr.frame == j)
	    {
		startaddr.frame = i;
	    }
	}
    }

    for (k = 0; k < grpcount; k++)
    {
	if (grplist[k])
	{
	    for (n = 0; n < grplist[k]->numsegs; n++)
	    {
		if (grplist[k]->segindex[n] == j)
		{
		    grplist[k]->segindex[n] = i;
		}
	    }
	}
    }

    free(seglist[j]);
    seglist[j] = 0;
}

void combine_groups(long i, long j)
{
    long n, m;
    char match;

    for (n = 0; n < grplist[j]->numsegs; n++)
    {
	match = 0;
	for (m = 0; m < grplist[i]->numsegs; m++)
	{
	    if (grplist[j]->segindex[n] == grplist[i]->segindex[m])
	    {
		match = 1;
	    }
	}
	if (!match)
	{
	    grplist[i]->numsegs++;
	    grplist[i]->segindex[grplist[i]->numsegs] = grplist[j]->segindex[n];
	}
    }
    free(grplist[j]);
    grplist[j] = 0;

    fixpubgrps(j, i);

    for (n = 0; n < fixcount; n++)
    {
	if (relocs[n]->ftype == REL_GRPFRAME)
	{
	    if (relocs[n]->frame == j)
	    {
		relocs[n]->frame = i;
	    }
	}
	if ((relocs[n]->ttype == REL_GRPONLY) || (relocs[n]->ttype == REL_GRPDISP))
	{
	    if (relocs[n]->target == j)
	    {
		relocs[n]->target = i;
	    }
	}
    }

    if (gotstart)
    {
	if ((startaddr.ttype == REL_GRPDISP) || (startaddr.ttype == REL_GRPONLY))
	{
	    if (startaddr.target == j)
	    {
		startaddr.target = i;
	    }
	}
	if (startaddr.ftype == REL_GRPFRAME)
	{
	    if (startaddr.frame == j)
	    {
		startaddr.frame = i;
	    }
	}
    }
}

void combineBlocks()
{
    long i, j, k;
    char *name;
    long attr;
    UINT count;
    UINT *slist;
    UINT curseg;

    for (i = 0; i < segcount; i++)
    {
	if (seglist[i] && ((seglist[i]->attr & SEG_ALIGN) != SEG_ABS))
	{
	    if (seglist[i]->winFlags & WINF_COMDAT)
		continue; /* don't combine COMDAT segments */
	    name = namelist[seglist[i]->nameindex];
	    attr = seglist[i]->attr & (SEG_COMBINE | SEG_USE32);
	    switch (attr & SEG_COMBINE)
	    {
	    case SEG_STACK:
		for (j = i + 1; j < segcount; j++)
		{
		    if (!seglist[j])
			continue;
		    if (seglist[j]->winFlags & WINF_COMDAT)
			continue;
		    if ((seglist[j]->attr & SEG_ALIGN) == SEG_ABS)
			continue;
		    if ((seglist[j]->attr & SEG_COMBINE) != SEG_STACK)
			continue;
		    combine_segments(i, j);
		}
		break;
	    case SEG_PUBLIC:
	    case SEG_PUBLIC2:
	    case SEG_PUBLIC3:
		slist = (UINT *)checkMalloc(sizeof(UINT));
		slist[0] = i;
		/* get list of segments to combine */
		for (j = i + 1, count = 1; j < segcount; j++)
		{
		    if (!seglist[j])
			continue;
		    if (seglist[j]->winFlags & WINF_COMDAT)
			continue;
		    if ((seglist[j]->attr & SEG_ALIGN) == SEG_ABS)
			continue;
		    if (attr != (seglist[j]->attr & (SEG_COMBINE | SEG_USE32)))
			continue;
		    if (strcmp(name, namelist[seglist[j]->nameindex]) != 0)
			continue;
		    slist = (UINT *)checkRealloc(slist, (count + 1) * sizeof(UINT));
		    slist[count] = j;
		    count++;
		}
		/* sort them by sortorder */
		for (j = 1; j < count; j++)
		{
		    curseg = slist[j];
		    for (k = j - 1; k >= 0; k--)
		    {
			if (seglist[slist[k]]->orderindex < 0)
			    break;
			if (seglist[curseg]->orderindex >= 0)
			{
			    if (strcmp(namelist[seglist[curseg]->orderindex],
				       namelist[seglist[slist[k]]->orderindex]) >= 0)
				break;
			}
			slist[k + 1] = slist[k];
		    }
		    k++;
		    slist[k] = curseg;
		}
		/* then combine in that order */
		for (j = 1; j < count; j++)
		{
		    combine_segments(i, slist[j]);
		}
		free(slist);
		break;
	    case SEG_COMMON:
		for (j = i + 1; j < segcount; j++)
		{
		    if ((seglist[j] && ((seglist[j]->attr & SEG_ALIGN) != SEG_ABS)) &&
			((seglist[i]->attr & (SEG_ALIGN | SEG_COMBINE | SEG_USE32)) ==
			 (seglist[j]->attr & (SEG_ALIGN | SEG_COMBINE | SEG_USE32))) &&
			(strcmp(name, namelist[seglist[j]->nameindex]) == 0) &&
			!(seglist[j]->winFlags & WINF_COMDAT))
		    {
			combine_common(i, j);
		    }
		}
		break;
	    default:
		break;
	    }
	}
    }

    for (i = 0; i < grpcount; i++)
    {
	if (grplist[i])
	{
	    for (j = i + 1; j < grpcount; j++)
	    {
		if (!grplist[j])
		    continue;
		if (strcmp(namelist[grplist[i]->nameindex], namelist[grplist[j]->nameindex]) == 0)
		{
		    combine_groups(i, j);
		}
	    }
	}
    }
}
